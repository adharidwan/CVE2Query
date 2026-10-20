"""Small, shell-free wrappers around Git for evidence collection."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Sequence

_COMMITISH = re.compile(r"^[A-Za-z0-9_./~^@{}-]+$")


class GitError(RuntimeError):
    """A Git command failed or an argument was unsafe."""


def run_git(
    arguments: Sequence[str],
    *,
    cwd: str | os.PathLike[str],
    timeout: float = 300.0,
) -> str:
    """Run git without a shell and return stripped stdout."""
    command = ["git", *[str(argument) for argument in arguments]]
    environment = os.environ.copy()
    environment.setdefault("GIT_TERMINAL_PROMPT", "0")
    environment.setdefault("GIT_PAGER", "cat")
    try:
        result = subprocess.run(
            command,
            cwd=os.fspath(cwd),
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )
    except FileNotFoundError as exc:
        raise GitError("git executable was not found on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git command timed out after {timeout} seconds") from exc
    except OSError as exc:
        raise GitError(f"could not start git: {exc}") from exc

    if result.returncode != 0:
        diagnostic = (result.stderr or "").strip() or (result.stdout or "").strip()
        raise GitError(
            f"git {' '.join(arguments[:2])} failed with exit code "
            f"{result.returncode}: {diagnostic}"
        )
    return result.stdout.strip()


def clone_repository(
    url: str,
    destination: str | os.PathLike[str],
    *,
    timeout: float = 900.0,
) -> Path:
    """Clone a repository with a partial blob filter and no checkout."""
    _validate_remote(url)
    target = Path(destination).expanduser().resolve()
    if target.exists() and any(target.iterdir()):
        raise GitError(f"clone destination already exists and is not empty: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    run_git(
        ["clone", "--filter=blob:none", "--no-checkout", "--", url, str(target)],
        cwd=target.parent,
        timeout=timeout,
    )
    return target


def checkout_commit(
    repository: str | os.PathLike[str], commit: str, *, timeout: float = 300.0
) -> None:
    _validate_commitish(commit)
    run_git(
        ["checkout", "--detach", commit],
        cwd=repository,
        timeout=timeout,
    )


def resolve_parent(
    repository: str | os.PathLike[str], commit: str
) -> str:
    _validate_commitish(commit)
    return run_git(
        ["rev-parse", "--verify", f"{commit}^"], cwd=repository
    ).strip()


def current_commit(repository: str | os.PathLike[str]) -> str:
    return run_git(["rev-parse", "HEAD"], cwd=repository).strip()


def diff_commits(
    repository: str | os.PathLike[str],
    old_commit: str,
    new_commit: str,
    *,
    unified: int = 3,
    timeout: float = 300.0,
) -> str:
    _validate_commitish(old_commit)
    _validate_commitish(new_commit)
    return run_git(
        [
            "diff",
            "--no-color",
            "--find-renames",
            f"--unified={int(unified)}",
            old_commit,
            new_commit,
            "--",
        ],
        cwd=repository,
        timeout=timeout,
    )


def show_file(
    repository: str | os.PathLike[str], commit: str, path: str
) -> str:
    _validate_commitish(commit)
    if not isinstance(path, str) or not path or path.startswith("-"):
        raise GitError("file path must be a non-empty relative path")
    return run_git(["show", f"{commit}:{path}"], cwd=repository)


def is_git_repository(path: str | os.PathLike[str]) -> bool:
    try:
        return (
            run_git(["rev-parse", "--is-inside-work-tree"], cwd=path).strip()
            == "true"
        )
    except GitError:
        return False


def _validate_commitish(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GitError("commit must be a non-empty string")
    if value.startswith("-") or not _COMMITISH.match(value) or ".." in value:
        raise GitError(f"unsafe commit-ish rejected: {value!r}")
    return value


def _validate_remote(url: str) -> str:
    if not isinstance(url, str) or not url.strip():
        raise GitError("repository URL must be a non-empty string")
    if url.startswith("-") or any(character.isspace() for character in url):
        raise GitError(f"unsafe repository URL rejected: {url!r}")
    return url
