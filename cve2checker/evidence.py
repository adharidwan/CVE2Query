"""Build deterministic source evidence for a CVE."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .context import SourceSnippet, extract_context
from .cve import validate_cve_id
from .diff import diff_stats, parse_unified_diff
from .git_tools import (
    checkout_commit,
    clone_repository,
    diff_commits,
    is_git_repository,
    resolve_parent,
)
from .source import SourceEvidence, SourceError, discover_source


class EvidenceError(Exception):
    """Source evidence could not be produced."""


def build_evidence(
    cve_id: str,
    record: dict[str, Any],
    workspace: str | Path,
    *,
    repo_path: str | Path | None = None,
    fix_commit: str | None = None,
    source: SourceEvidence | None = None,
    github_token: str | None = None,
    context_lines: int = 8,
) -> dict[str, Any]:
    """Create source.json, diff.patch, and context.json for a CVE.

    When ``repo_path`` is supplied the repository must already exist; otherwise
    the repository is cloned from the first GitHub reference. The fix commit
    must come from ``fix_commit``, the CVE references, or PR resolution.
    """
    cve_id = validate_cve_id(cve_id)
    artifact_dir = Path(workspace) / cve_id
    artifact_dir.mkdir(parents=True, exist_ok=True)

    if source is None:
        try:
            source = discover_source(
                record,
                github_token=github_token,
                preferred_commit=fix_commit,
            )
        except SourceError as exc:
            raise EvidenceError(f"source discovery failed: {exc}") from exc

    selected_fix = fix_commit or source.fix_commit
    if not selected_fix:
        raise EvidenceError(
            "no fix commit was found; supply fix_commit or a resolvable PR reference"
        )

    repo = Path(repo_path) if repo_path is not None else None
    if repo is None:
        if not source.repository_url:
            raise EvidenceError(
                "no repository URL was found; supply repo_path or a GitHub reference"
            )
        repo = Path(workspace) / cve_id / "repo"
        if not repo.exists() or not any(repo.iterdir()):
            clone_repository(source.repository_url, repo)
    if not repo.is_dir():
        raise EvidenceError(f"repository path does not exist: {repo}")
    if not is_git_repository(repo):
        raise EvidenceError(f"not a git repository: {repo}")

    checkout_commit(repo, selected_fix)
    try:
        vulnerable_commit = resolve_parent(repo, selected_fix)
    except Exception as exc:
        raise EvidenceError(
            f"could not resolve the parent of fix commit {selected_fix}: {exc}"
        ) from exc

    diff_text = diff_commits(repo, vulnerable_commit, selected_fix)
    diffs = parse_unified_diff(diff_text)
    snippets = extract_context(repo, diffs, context_lines=context_lines)

    diff_path = artifact_dir / "diff.patch"
    diff_path.write_text(diff_text + ("\n" if diff_text and not diff_text.endswith("\n") else ""), encoding="utf-8")
    context_path = artifact_dir / "context.json"
    _write_json(
        context_path,
        {
            "snippets": [_snippet_to_dict(snippet) for snippet in snippets],
        },
    )

    source_data = source.to_dict()
    source_data.update(
        {
            "cve_id": cve_id,
            "repo_path": str(repo.resolve()),
            "vulnerable_commit": vulnerable_commit,
            "fix_commit": selected_fix,
            "diff_stats": diff_stats(diffs),
            "diff_path": str(diff_path.resolve()),
            "context_path": str(context_path.resolve()),
        }
    )
    source_path = artifact_dir / "source.json"
    _write_json(source_path, source_data)

    return {
        "artifact_dir": str(artifact_dir.resolve()),
        "source": source_data,
        "repo_path": str(repo.resolve()),
        "vulnerable_commit": vulnerable_commit,
        "fix_commit": selected_fix,
        "diff": diff_text,
        "diff_path": str(diff_path.resolve()),
        "context": [_snippet_to_dict(snippet) for snippet in snippets],
        "context_path": str(context_path.resolve()),
    }


def _snippet_to_dict(snippet: SourceSnippet) -> dict[str, Any]:
    return {
        "file": snippet.file,
        "start_line": snippet.start_line,
        "end_line": snippet.end_line,
        "text": snippet.text,
        "kind": snippet.kind,
    }


def _write_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(payload, output, indent=2, ensure_ascii=False)
        output.write("\n")
