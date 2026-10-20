"""CVE reference parsing and source-repository discovery."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .cve import iter_record_containers

_GITHUB_HOSTS = {"github.com", "www.github.com", "api.github.com"}
_COMMIT_SHA = re.compile(r"^[0-9a-fA-F]{7,40}$")
_GITHUB_API = "https://api.github.com"

Fetcher = Callable[[str, dict[str, str]], dict[str, Any]]


class SourceError(Exception):
    """A source reference could not be parsed or resolved."""


@dataclass
class GitHubReference:
    url: str
    owner: str
    repo: str
    kind: str
    commit: str | None = None
    number: int | None = None
    ref: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "owner": self.owner,
            "repo": self.repo,
            "kind": self.kind,
            "commit": self.commit,
            "number": self.number,
            "ref": self.ref,
        }


@dataclass
class SourceEvidence:
    repository_url: str | None
    owner: str | None
    repo: str | None
    fix_commit: str | None
    fix_commit_source: str | None
    references: list[GitHubReference] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_url": self.repository_url,
            "owner": self.owner,
            "repo": self.repo,
            "fix_commit": self.fix_commit,
            "fix_commit_source": self.fix_commit_source,
            "references": [reference.to_dict() for reference in self.references],
            "warnings": list(self.warnings),
        }


def parse_github_url(url: str) -> GitHubReference | None:
    """Parse a GitHub commit, pull, issue, release, tree, or repository URL."""
    if not isinstance(url, str) or not url.strip():
        return None
    text = url.strip().split("#", 1)[0].split("?", 1)[0].rstrip("/")
    match = re.match(r"^https?://([^/]+)/([^/]+)/([^/]+)(?:/(.*))?$", text)
    if match is None:
        return None
    host = match.group(1).lower()
    if host not in _GITHUB_HOSTS:
        return None
    owner = match.group(2)
    repo = match.group(3)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return None
    rest = match.group(4) or ""

    base = GitHubReference(url=url, owner=owner, repo=repo, kind="repo")
    if not rest:
        return base

    if host == "api.github.com":
        segments = [match.group(2), match.group(3), *rest.split("/")]
        if len(segments) >= 3 and segments[0] == "repos":
            base.owner = segments[1]
            base.repo = segments[2].removesuffix(".git")
            parts = segments[3:]
        else:
            return base
    else:
        parts = rest.split("/")

    if (
        len(parts) >= 2
        and parts[0] in {"commit", "commits"}
        and _COMMIT_SHA.match(parts[1])
    ):
        return _with(base, kind="commit", commit=parts[1])
    if len(parts) >= 2 and parts[0] == "pulls" and parts[1].isdigit():
        return _with(base, kind="pull", number=int(parts[1]))
    if len(parts) >= 2 and parts[0] == "pull" and parts[1].isdigit():
        return _with(base, kind="pull", number=int(parts[1]))
    if len(parts) >= 2 and parts[0] == "issues" and parts[1].isdigit():
        return _with(base, kind="issue", number=int(parts[1]))
    if len(parts) >= 3 and parts[0] == "releases" and parts[1] == "tag":
        return _with(base, kind="tag", ref="/".join(parts[2:]))
    if len(parts) >= 2 and parts[0] == "tree":
        return _with(base, kind="tree", ref="/".join(parts[1:]))
    if len(parts) >= 2 and parts[0] == "blob":
        return _with(base, kind="blob", ref="/".join(parts[1:]))
    if len(parts) >= 2 and parts[0] == "security" and parts[1] == "advisories":
        return _with(base, kind="advisory")
    return base


def github_references(record: dict[str, Any]) -> list[GitHubReference]:
    """Extract unique GitHub references from all CVE containers."""
    references: list[GitHubReference] = []
    seen: set[tuple[str, str, str, str | None, int | None, str | None]] = set()
    for container in iter_record_containers(record):
        raw_references = container.get("references")
        if not isinstance(raw_references, list):
            continue
        for item in raw_references:
            if not isinstance(item, dict):
                continue
            url = item.get("url")
            if not isinstance(url, str):
                continue
            parsed = parse_github_url(url)
            if parsed is None:
                continue
            key = (
                parsed.owner.lower(),
                parsed.repo.lower(),
                parsed.kind,
                parsed.commit,
                parsed.number,
                parsed.ref,
            )
            if key in seen:
                continue
            seen.add(key)
            references.append(parsed)
    return references


def discover_source(
    record: dict[str, Any],
    *,
    github_token: str | None = None,
    fetcher: Fetcher | None = None,
    preferred_commit: str | None = None,
) -> SourceEvidence:
    """Choose a repository and fix commit from CVE references.

    PR references are resolved to merge commits through the GitHub API. The
    function never guesses a commit when only an issue or advisory is present.
    """
    if preferred_commit is not None and not _COMMIT_SHA.match(preferred_commit):
        raise SourceError(
            f"preferred commit {preferred_commit!r} is not a hexadecimal SHA"
        )

    references = github_references(record)
    warnings: list[str] = []
    if not references:
        return SourceEvidence(
            repository_url=None,
            owner=None,
            repo=None,
            fix_commit=None,
            fix_commit_source=None,
            warnings=["no GitHub references were found in the CVE record"],
        )

    commit_references = [reference for reference in references if reference.kind == "commit"]
    repository = _select_repository(references, commit_references, warnings)

    fix_commit: str | None = None
    fix_source: str | None = None
    if preferred_commit:
        fix_commit = preferred_commit
        fix_source = "user-specified"
    elif repository is not None and commit_references:
        same_repo = [
            reference
            for reference in commit_references
            if _same_repo(repository, reference)
        ]
        candidates = same_repo or commit_references
        if len({candidate.commit for candidate in candidates}) > 1:
            warnings.append(
                "multiple commit references found; using the first one"
            )
        fix_commit = candidates[0].commit
        fix_source = "cve-reference"

    if fix_commit is None and repository is not None:
        pull_references = [
            reference
            for reference in references
            if reference.kind == "pull" and _same_repo(repository, reference)
        ]
        if pull_references:
            resolved = _resolve_pull_commit(
                pull_references[0], github_token=github_token, fetcher=fetcher
            )
            if resolved is not None:
                fix_commit = resolved
                fix_source = "github-pull-merge-commit"
            else:
                warnings.append(
                    "a pull request reference was found but no merge commit could be resolved"
                )

    if fix_commit is None:
        warnings.append(
            "no fix commit could be determined; provide --fix-commit or a token-enabled PR resolution"
        )

    if repository is not None:
        other_repositories = {
            (reference.owner.lower(), reference.repo.lower())
            for reference in references
            if not _same_repo(repository, reference)
        }
        if other_repositories:
            warnings.append(
                "references span multiple repositories; using "
                f"{repository.owner}/{repository.repo}"
            )

    return SourceEvidence(
        repository_url=(
            f"https://github.com/{repository.owner}/{repository.repo}"
            if repository
            else None
        ),
        owner=repository.owner if repository else None,
        repo=repository.repo if repository else None,
        fix_commit=fix_commit,
        fix_commit_source=fix_source,
        references=references,
        warnings=warnings,
    )


def _resolve_pull_commit(
    reference: GitHubReference,
    *,
    github_token: str | None,
    fetcher: Fetcher | None,
) -> str | None:
    url = f"{_GITHUB_API}/repos/{reference.owner}/{reference.repo}/pulls/{reference.number}"
    try:
        payload = (
            fetcher(url, _github_headers(github_token))
            if fetcher is not None
            else _github_get(url, github_token)
        )
    except SourceError:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("merged") is False:
        return None
    commit = payload.get("merge_commit_sha")
    if isinstance(commit, str) and _COMMIT_SHA.match(commit):
        return commit
    return None


def _github_get(url: str, token: str | None) -> dict[str, Any]:
    request = Request(url, headers=_github_headers(token))
    try:
        with urlopen(request, timeout=20.0) as response:
            payload = response.read()
    except HTTPError as exc:
        raise SourceError(f"GitHub API returned HTTP {exc.code} for {url}") from exc
    except URLError as exc:
        raise SourceError(f"could not reach GitHub API: {exc.reason}") from exc
    except TimeoutError as exc:
        raise SourceError(f"timed out while contacting GitHub API for {url}") from exc
    try:
        decoded = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise SourceError("GitHub API returned invalid JSON") from exc
    if not isinstance(decoded, dict):
        raise SourceError("GitHub API returned a non-object response")
    return decoded


def _github_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "cve2checker/0.1",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _select_repository(
    references: list[GitHubReference],
    commits: list[GitHubReference],
    warnings: list[str],
) -> GitHubReference | None:
    for reference in commits:
        if reference.kind == "commit":
            return reference
    for reference in references:
        if reference.kind in {"pull", "repo", "tag"}:
            return reference
    for reference in references:
        if reference.kind not in {"advisory"}:
            return reference
    return references[0] if references else None


def _same_repo(first: GitHubReference, second: GitHubReference) -> bool:
    return (
        first.owner.lower() == second.owner.lower()
        and first.repo.lower() == second.repo.lower()
    )


def _with(reference: GitHubReference, **changes: Any) -> GitHubReference:
    values = reference.__dict__.copy()
    values.update(changes)
    return GitHubReference(**values)
