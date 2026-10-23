"""Small, deterministic wrappers for the CodeQL CLI."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Sequence


class CodeQLError(RuntimeError):
    """A CodeQL CLI command could not be started or completed successfully."""


def create_cpp_database(
    source_root: str | os.PathLike[str],
    database_path: str | os.PathLike[str],
    *,
    build_command: str | None = None,
    build_mode: str | None = None,
    codeql_path: str | os.PathLike[str] = "codeql",
) -> subprocess.CompletedProcess[str]:
    """Create a C/C++ CodeQL database.

    A custom traced ``build_command`` takes precedence. Otherwise ``build_mode``
    may be ``autobuild`` or ``none``; the default is autobuild. ``none`` is a
    documented fallback for projects that cannot be built, and can reduce the
    quality of the resulting database.
    """
    if build_command is not None and not build_command.strip():
        raise ValueError("build_command must be non-empty when provided")
    if build_command is not None and build_mode is not None:
        raise ValueError("build_command and build_mode are mutually exclusive")
    if build_mode is not None and build_mode not in {"autobuild", "none"}:
        raise ValueError("build_mode must be 'autobuild' or 'none'")

    Path(database_path).expanduser().resolve().parent.mkdir(
        parents=True, exist_ok=True
    )
    arguments = [
        "database",
        "create",
        "--language=cpp",
        f"--source-root={os.fspath(source_root)}",
    ]
    if build_command is not None:
        arguments.append(f"--command={build_command}")
    else:
        arguments.append(f"--build-mode={build_mode or 'autobuild'}")
    arguments.extend(("--", os.fspath(database_path)))
    return _run_codeql(arguments, codeql_path)


def compile_query(
    query_path: str | os.PathLike[str],
    *,
    codeql_path: str | os.PathLike[str] = "codeql",
) -> subprocess.CompletedProcess[str]:
    """Compile a QL query into CodeQL's compilation cache."""
    pack_root = _find_pack_root(query_path)
    query_argument = os.path.abspath(query_path) if pack_root else os.fspath(query_path)
    return _run_codeql(
        ["query", "compile", "--", query_argument], codeql_path, cwd=pack_root
    )


def analyze_query(
    database_path: str | os.PathLike[str],
    query_path: str | os.PathLike[str],
    sarif_path: str | os.PathLike[str],
    *,
    codeql_path: str | os.PathLike[str] = "codeql",
) -> subprocess.CompletedProcess[str]:
    """Analyze a query against a database and write SARIF 2.1.0 results."""
    Path(sarif_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
    pack_root = _find_pack_root(query_path)
    if pack_root:
        database_argument = os.path.abspath(database_path)
        query_argument = os.path.abspath(query_path)
        sarif_argument = os.path.abspath(sarif_path)
    else:
        database_argument = os.fspath(database_path)
        query_argument = os.fspath(query_path)
        sarif_argument = os.fspath(sarif_path)
    return _run_codeql(
        [
            "database",
            "analyze",
            "--format=sarifv2.1.0",
            f"--output={sarif_argument}",
            "--",
            database_argument,
            query_argument,
        ],
        codeql_path,
        cwd=pack_root,
    )


def ensure_query_pack(
    pack_root: str | os.PathLike[str],
    *,
    cpp_all_version: str = "12.2.0",
    codeql_path: str | os.PathLike[str] = "codeql",
) -> Path:
    """Ensure generated queries under ``pack_root`` can resolve CodeQL imports.

    Writes a minimal qlpack.yml when no pack (or ancestor pack) exists and
    installs its dependencies. Returns the resolved pack root.
    """
    root = Path(pack_root).expanduser().resolve()
    qlpack = root / "qlpack.yml"
    if qlpack.is_file():
        install_pack(root, codeql_path=codeql_path)
        return root
    for parent in root.parents:
        if (parent / "qlpack.yml").is_file():
            return root
    root.mkdir(parents=True, exist_ok=True)
    qlpack.write_text(
        "name: cve2checker/generated-queries\n"
        "version: 0.0.1\n"
        "dependencies:\n"
        f"  codeql/cpp-all: {cpp_all_version}\n"
        "extractor: cpp\n",
        encoding="utf-8",
    )
    install_pack(root, codeql_path=codeql_path)
    return root


def install_pack(
    pack_root: str | os.PathLike[str],
    *,
    codeql_path: str | os.PathLike[str] = "codeql",
) -> subprocess.CompletedProcess[str]:
    """Resolve a pack's dependencies and write/update its lock file."""
    resolved_root = Path(pack_root).resolve()
    return _run_codeql(
        ["pack", "install", "--", os.fspath(resolved_root)],
        codeql_path,
        cwd=os.fspath(resolved_root),
    )


def verify_pack(
    pack_root: str | os.PathLike[str],
    *,
    codeql_path: str | os.PathLike[str] = "codeql",
) -> subprocess.CompletedProcess[str]:
    """Verify a pack against its checked-in dependency lock file."""
    resolved_root = Path(pack_root).resolve()
    return _run_codeql(
        ["pack", "ci", "--", os.fspath(resolved_root)],
        codeql_path,
        cwd=os.fspath(resolved_root),
    )


def _run_codeql(
    arguments: Sequence[str],
    codeql_path: str | os.PathLike[str],
    *,
    cwd: str | os.PathLike[str] | None = None,
) -> subprocess.CompletedProcess[str]:
    executable = os.fspath(codeql_path)
    command = [executable, *arguments]
    try:
        result = subprocess.run(
            command,
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            cwd=None if cwd is None else os.fspath(cwd),
        )
    except FileNotFoundError as exc:
        raise CodeQLError(
            f"CodeQL CLI executable {executable!r} was not found. Install the CodeQL "
            "CLI, add it to PATH, or pass its executable path with codeql_path."
        ) from exc
    except OSError as exc:
        raise CodeQLError(
            f"Could not start CodeQL CLI executable {executable!r}: {exc}"
        ) from exc

    if result.returncode != 0:
        operation = " ".join(arguments[:2]) or "command"
        diagnostic = (result.stderr or "").strip() or (result.stdout or "").strip()
        message = (
            f"CodeQL {operation} failed with exit code {result.returncode}"
        )
        if diagnostic:
            message += f": {diagnostic}"
        else:
            message += "; no diagnostic output was produced"
        raise CodeQLError(message)

    return result


def _find_pack_root(query_path: str | os.PathLike[str]) -> str | None:
    query = Path(query_path).expanduser().resolve()
    for parent in query.parents:
        if (parent / "qlpack.yml").is_file():
            return os.fspath(parent)
    return None
