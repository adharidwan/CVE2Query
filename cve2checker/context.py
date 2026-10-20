"""Source-context extraction around changed lines."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .diff import FileDiff, changed_ranges

_CONTROL_KEYWORDS = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "else",
        "do",
        "try",
        "return",
        "sizeof",
        "alignof",
        "decltype",
        "static_assert",
        "case",
        "throw",
        "new",
        "delete",
        "co_await",
        "co_return",
        "co_yield",
    }
)
_NON_FUNCTION_FIRST_WORDS = _CONTROL_KEYWORDS | frozenset(
    {"namespace", "class", "struct", "union", "enum", "typedef", "using"}
)
_IDENTIFIER_CALL = re.compile(r"([A-Za-z_]\w*)\s*\(")
_FIRST_WORD = re.compile(r"([A-Za-z_]\w*)")


@dataclass
class SourceSnippet:
    file: str
    start_line: int
    end_line: int
    text: str
    kind: str


def enclosing_function(
    lines: list[str], line_number: int
) -> tuple[int, int] | None:
    """Return the 1-based inclusive span of the function containing a line."""
    if (
        not lines
        or not isinstance(line_number, int)
        or line_number < 1
        or line_number > len(lines)
    ):
        return None

    sanitized = _sanitize_lines(lines)
    blocks: list[tuple[int, int, int]] = []
    stack: list[tuple[int, int]] = []
    for line_index, text in enumerate(sanitized):
        for column, character in enumerate(text):
            if character == "{":
                stack.append((line_index, column))
            elif character == "}" and stack:
                open_line, open_column = stack.pop()
                blocks.append((open_line, open_column, line_index))

    target = line_number - 1
    candidates = [block for block in blocks if block[2] >= target]
    candidates.sort(key=lambda block: (block[2] - block[0], -block[1]))

    for open_line, open_column, close_line in candidates:
        signature_start = _signature_start(sanitized, open_line)
        if signature_start > target or target > close_line:
            continue
        prefix = _prefix_text(sanitized, signature_start, open_line, open_column)
        if _looks_like_function(prefix):
            return signature_start + 1, close_line + 1
    return None


def extract_context(
    repo_root: str | Path,
    diffs: list[FileDiff],
    context_lines: int = 8,
) -> list[SourceSnippet]:
    """Extract hunk and enclosing-function snippets for changed lines."""
    try:
        context_lines = int(context_lines)
    except (TypeError, ValueError):
        context_lines = 0
    context_lines = max(0, context_lines)

    root = Path(repo_root)
    records: list[tuple[str, str, int, int]] = []
    line_cache: dict[str, list[str] | None] = {}

    for file_diff in diffs:
        if file_diff.is_binary:
            continue

        new_path = _normalize_path(file_diff.new_path)
        old_path = _normalize_path(file_diff.old_path)
        if new_path and new_path != "/dev/null":
            path = new_path
            side = "new"
        elif old_path and old_path != "/dev/null":
            path = old_path
            side = "old"
        else:
            continue

        ranges = changed_ranges([file_diff], side)
        if not ranges:
            continue

        if path not in line_cache:
            line_cache[path] = _read_lines(root, path)
        file_lines = line_cache[path]
        if not file_lines:
            continue

        for changed in ranges:
            if changed.start > len(file_lines):
                continue
            start = max(1, changed.start - context_lines)
            end = min(len(file_lines), changed.end + context_lines)
            if start > end:
                continue
            records.append((path, "hunk", start, end))

            function_span = enclosing_function(file_lines, changed.start)
            if function_span is not None:
                function_start, function_end = function_span
                if 1 <= function_start <= function_end <= len(file_lines):
                    records.append(
                        (path, "function", function_start, function_end)
                    )

    merged: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for path, kind, start, end in records:
        merged.setdefault((path, kind), []).append((start, end))

    snippets: list[SourceSnippet] = []
    for (path, kind), intervals in merged.items():
        file_lines = line_cache.get(path)
        if not file_lines:
            continue
        intervals.sort()
        combined: list[tuple[int, int]] = []
        for start, end in intervals:
            if combined and start <= combined[-1][1]:
                previous_start, previous_end = combined[-1]
                combined[-1] = (previous_start, max(previous_end, end))
            else:
                combined.append((start, end))

        for start, end in combined:
            start = max(1, start)
            end = min(len(file_lines), end)
            if start > end:
                continue
            snippets.append(
                SourceSnippet(
                    file=path,
                    start_line=start,
                    end_line=end,
                    text="\n".join(file_lines[start - 1 : end]),
                    kind=kind,
                )
            )

    snippets.sort(
        key=lambda snippet: (
            snippet.file,
            snippet.start_line,
            snippet.end_line,
            snippet.kind,
        )
    )
    return snippets


def _sanitize_lines(lines: list[str]) -> list[str]:
    sanitized: list[str] = []
    in_block_comment = False

    for line in lines:
        characters: list[str] = []
        index = 0
        quote: str | None = None
        while index < len(line):
            character = line[index]

            if in_block_comment:
                end = line.find("*/", index)
                if end == -1:
                    index = len(line)
                else:
                    in_block_comment = False
                    index = end + 2
                continue

            if quote is not None:
                if character == "\\":
                    index += 2
                    continue
                if character == quote:
                    quote = None
                index += 1
                continue

            if character == "/" and index + 1 < len(line):
                following = line[index + 1]
                if following == "/":
                    break
                if following == "*":
                    in_block_comment = True
                    index += 2
                    continue

            if character in ('"', "'"):
                quote = character
                index += 1
                continue

            characters.append(character)
            index += 1

        sanitized.append("".join(characters))

    return sanitized


def _signature_start(sanitized: list[str], open_line: int) -> int:
    start = open_line
    for previous in range(open_line - 1, -1, -1):
        if open_line - previous > 40:
            break
        if _is_boundary(sanitized[previous]):
            break
        start = previous
    return start


def _is_boundary(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return True
    if stripped.startswith("#"):
        return True
    if stripped.endswith((";", "{", "}")):
        return True
    if stripped.endswith(":") and not stripped.endswith("::"):
        return True
    return False


def _prefix_text(
    sanitized: list[str], start_line: int, open_line: int, open_column: int
) -> str:
    parts: list[str] = []
    for line_index in range(start_line, open_line + 1):
        text = sanitized[line_index]
        if line_index == open_line:
            text = text[:open_column]
        parts.append(text)
    return "\n".join(parts)


def _looks_like_function(prefix: str) -> bool:
    text = prefix.strip()
    if not text:
        return False

    first_word = _FIRST_WORD.match(text)
    if first_word is not None and first_word.group(1) in _NON_FUNCTION_FIRST_WORDS:
        return False

    call = _IDENTIFIER_CALL.search(text)
    if call is None:
        return False
    if call.group(1) in _CONTROL_KEYWORDS:
        return False

    signature_head = text[: call.end() - 1]
    if _has_top_level_assignment(signature_head):
        return False
    return True


def _has_top_level_assignment(text: str) -> bool:
    depth = 0
    index = 0
    while index < len(text):
        character = text[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth = max(0, depth - 1)
        elif character == "=" and depth == 0:
            previous = text[index - 1] if index > 0 else ""
            following = text[index + 1] if index + 1 < len(text) else ""
            if previous in "=!<>" or following == "=":
                index += 1
            else:
                return True
        index += 1
    return False


def _normalize_path(path: str | None) -> str:
    if not path:
        return ""
    normalized = str(path).strip().replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized == "/dev/null":
        return normalized
    if normalized.startswith("a/") or normalized.startswith("b/"):
        normalized = normalized[2:]
    return normalized


def _read_lines(root: Path, relative: str) -> list[str] | None:
    if not relative:
        return None

    try:
        root_path = root.resolve()
        candidate = Path(relative)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (root_path / candidate).resolve()
        resolved.relative_to(root_path)
    except (OSError, ValueError, RuntimeError):
        return None

    try:
        if not resolved.is_file():
            return None
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return None
    return text.splitlines()
