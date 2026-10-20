"""Directory indexing helpers for the CodeQL RAG collection."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator

from .rag import RagIndex

DEFAULT_EXTENSIONS = {".ql", ".qll", ".md", ".txt", ".yml", ".yaml"}
DEFAULT_EXCLUDES = {
    ".git",
    ".codeql",
    "__pycache__",
    ".cache",
    ".venv",
    "node_modules",
}


def iter_documents(
    source_dir: str | os.PathLike[str],
    *,
    extensions: Iterable[str] | None = None,
    exclude_dirs: Iterable[str] | None = None,
    max_file_bytes: int = 500_000,
    chunk_lines: int = 200,
) -> Iterator[dict]:
    """Yield RAG documents for matching files under a directory."""
    root = Path(source_dir).expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"source directory does not exist: {root}")
    allowed = {
        extension.lower() if extension.startswith(".") else f".{extension.lower()}"
        for extension in (extensions or DEFAULT_EXTENSIONS)
    }
    excluded = set(exclude_dirs or DEFAULT_EXCLUDES)
    if chunk_lines < 1:
        raise ValueError("chunk_lines must be at least 1")

    for directory, subdirectories, names in os.walk(root):
        subdirectories[:] = sorted(
            name for name in subdirectories if name not in excluded
        )
        for name in sorted(names):
            path = Path(directory) / name
            if path.suffix.lower() not in allowed:
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            relative = path.relative_to(root).as_posix()
            lines = text.splitlines()
            if not lines:
                continue
            metadata_base = {"path": relative, "extension": path.suffix.lower()}
            for index, offset in enumerate(
                range(0, len(lines), chunk_lines), start=1
            ):
                start_line = offset + 1
                end_line = min(offset + chunk_lines, len(lines))
                chunk = "\n".join(lines[offset:end_line])
                yield {
                    "id": f"{relative}#chunk-{index}",
                    "title": f"{relative}:{start_line}-{end_line}",
                    "text": chunk,
                    "metadata": {
                        **metadata_base,
                        "start_line": start_line,
                        "end_line": end_line,
                    },
                }


def index_directory(
    index: RagIndex,
    collection: str,
    source_dir: str | os.PathLike[str],
    *,
    extensions: Iterable[str] | None = None,
    exclude_dirs: Iterable[str] | None = None,
    max_file_bytes: int = 500_000,
    chunk_lines: int = 200,
) -> int:
    documents = iter_documents(
        source_dir,
        extensions=extensions,
        exclude_dirs=exclude_dirs,
        max_file_bytes=max_file_bytes,
        chunk_lines=chunk_lines,
    )
    return index.add_documents(collection, documents)
