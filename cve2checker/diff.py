"""Unified diff parsing and changed-line mapping."""

from __future__ import annotations

import re
from dataclasses import dataclass

_HUNK_HEADER = re.compile(
    r"^@@\s*-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?(?:\s*@@.*)?$"
)
_C_ESCAPES = {
    "a": "\a",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "v": "\v",
    "\\": "\\",
    '"': '"',
}


class DiffError(Exception):
    """A diff that cannot be parsed."""


@dataclass(frozen=True)
class ChangedRange:
    file: str
    start: int
    end: int
    side: str


@dataclass
class Hunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str]


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    hunks: list[Hunk]
    is_binary: bool


def parse_unified_diff(text: str) -> list[FileDiff]:
    """Parse a git or plain unified diff into files and hunks."""
    if not isinstance(text, str):
        raise TypeError("diff text must be a string")

    lines = text.splitlines()
    diffs: list[FileDiff] = []
    current: FileDiff | None = None
    index = 0

    while index < len(lines):
        line = lines[index]

        if line.startswith("diff --git "):
            old_path, new_path = _parse_git_header(line)
            current = FileDiff(
                old_path=old_path,
                new_path=new_path,
                hunks=[],
                is_binary=False,
            )
            diffs.append(current)
            index += 1
            continue

        if (
            line.startswith("--- ")
            and index + 1 < len(lines)
            and lines[index + 1].startswith("+++ ")
        ):
            old_path = _parse_header_path(line[4:])
            new_path = _parse_header_path(lines[index + 1][4:])
            if current is None or current.hunks or current.is_binary:
                current = FileDiff(
                    old_path=old_path,
                    new_path=new_path,
                    hunks=[],
                    is_binary=False,
                )
                diffs.append(current)
            else:
                current.old_path = old_path
                current.new_path = new_path
            index += 2
            continue

        if line.startswith("@@"):
            match = _HUNK_HEADER.match(line)
            if match is None:
                raise DiffError(f"malformed hunk header: {line!r}")

            if current is None:
                index += 1
                continue

            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) is not None else 1
            new_start = int(match.group(3))
            new_count = int(match.group(4)) if match.group(4) is not None else 1
            hunk = Hunk(
                old_start=old_start,
                old_count=old_count,
                new_start=new_start,
                new_count=new_count,
                lines=[],
            )
            current.hunks.append(hunk)
            index += 1
            index = _consume_hunk_body(lines, index, hunk)
            continue

        if line.startswith("GIT binary patch"):
            if current is None:
                current = FileDiff("", "", [], True)
                diffs.append(current)
            current.is_binary = True
            index += 1
            while index < len(lines) and not lines[index].startswith("diff --git "):
                index += 1
            continue

        if line.startswith("Binary files ") and line.rstrip().endswith(" differ"):
            old_path, new_path = _parse_binary_header(line)
            if current is None:
                current = FileDiff(old_path, new_path, [], True)
                diffs.append(current)
            else:
                if not current.hunks:
                    current.old_path = old_path
                    current.new_path = new_path
                current.is_binary = True
            index += 1
            continue

        index += 1

    return diffs


def changed_ranges(
    diffs: list[FileDiff], side: str = "new"
) -> list[ChangedRange]:
    """Return contiguous ranges of added (new) or removed (old) lines."""
    if side not in ("old", "new"):
        raise ValueError("side must be 'old' or 'new'")

    changed_lines: dict[str, set[int]] = {}
    for file_diff in diffs:
        if file_diff.is_binary:
            continue

        raw_path = file_diff.new_path if side == "new" else file_diff.old_path
        path = _normalize_path(raw_path)
        if not path or path == "/dev/null":
            continue

        for hunk in file_diff.hunks:
            old_line = hunk.old_start
            new_line = hunk.new_start
            for raw_line in hunk.lines:
                if raw_line.startswith("\\"):
                    continue
                prefix = raw_line[0] if raw_line else " "
                if prefix == "+":
                    if side == "new":
                        changed_lines.setdefault(path, set()).add(new_line)
                    new_line += 1
                elif prefix == "-":
                    if side == "old":
                        changed_lines.setdefault(path, set()).add(old_line)
                    old_line += 1
                elif prefix == " ":
                    old_line += 1
                    new_line += 1

    ranges: list[ChangedRange] = []
    for path, line_numbers in changed_lines.items():
        ordered = sorted(line_numbers)
        start = end = ordered[0]
        for line_number in ordered[1:]:
            if line_number <= end + 1:
                end = line_number
            else:
                ranges.append(ChangedRange(path, start, end, side))
                start = end = line_number
        ranges.append(ChangedRange(path, start, end, side))
    return ranges


def diff_stats(diffs: list[FileDiff]) -> dict:
    """Summarize files, hunks, changed lines, and binary files."""
    added_lines = 0
    removed_lines = 0
    hunks = 0
    binary_files = 0

    for file_diff in diffs:
        binary_files += int(file_diff.is_binary)
        hunks += len(file_diff.hunks)
        for hunk in file_diff.hunks:
            for line in hunk.lines:
                if line.startswith("+"):
                    added_lines += 1
                elif line.startswith("-"):
                    removed_lines += 1

    return {
        "files": len(diffs),
        "hunks": hunks,
        "added_lines": added_lines,
        "removed_lines": removed_lines,
        "binary_files": binary_files,
    }


def _consume_hunk_body(lines: list[str], index: int, hunk: Hunk) -> int:
    expected = hunk.old_count + hunk.new_count
    consumed = 0

    while index < len(lines):
        line = lines[index]
        if line.startswith("\\"):
            hunk.lines.append(line)
            index += 1
            continue
        if consumed >= expected:
            break
        prefix = line[0] if line else " "
        if prefix not in (" ", "+", "-"):
            break
        hunk.lines.append(line)
        consumed += 1
        index += 1

    while index < len(lines) and lines[index].startswith("\\"):
        hunk.lines.append(lines[index])
        index += 1
    return index


def _parse_git_header(line: str) -> tuple[str, str]:
    rest = line[len("diff --git ") :].strip()
    first, second = _split_git_paths(rest)
    return _parse_path_token(first), _parse_path_token(second)


def _split_git_paths(rest: str) -> tuple[str, str]:
    if not rest:
        return "", ""

    if rest.startswith('"'):
        first, end = _read_quoted(rest, 0)
        remainder = rest[end:].lstrip()
        if remainder.startswith('"'):
            second, _ = _read_quoted(remainder, 0)
        else:
            second = remainder
        return first, second

    candidates: list[int] = []
    for position in range(len(rest)):
        if rest.startswith(" b/", position) or rest.startswith(' "b/', position):
            candidates.append(position)

    for position in candidates:
        first = rest[:position]
        second = rest[position + 1 :]
        if _normalize_path(_decode_path_token(first)) == _normalize_path(
            _decode_path_token(second)
        ):
            return first, second

    if candidates:
        position = candidates[len(candidates) // 2]
        return rest[:position], rest[position + 1 :]

    parts = rest.split(" ", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return rest, rest


def _parse_binary_header(line: str) -> tuple[str, str]:
    content = line[len("Binary files ") :].rstrip()
    if content.endswith(" differ"):
        content = content[: -len(" differ")]

    candidates: list[int] = []
    start = 0
    while True:
        position = content.find(" and ", start)
        if position == -1:
            break
        candidates.append(position)
        start = position + 1

    for position in candidates:
        first = content[:position]
        second = content[position + len(" and ") :]
        if _normalize_path(_decode_path_token(first)) == _normalize_path(
            _decode_path_token(second)
        ):
            return _parse_path_token(first), _parse_path_token(second)

    if candidates:
        position = candidates[0]
        return (
            _parse_path_token(content[:position]),
            _parse_path_token(content[position + len(" and ") :]),
        )

    return _parse_path_token(content), _parse_path_token(content)


def _parse_header_path(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith('"'):
        value, _ = _read_quoted(raw, 0)
        return _normalize_path(value)
    path = raw.split("\t", 1)[0]
    return _normalize_path(path)


def _parse_path_token(token: str) -> str:
    return _normalize_path(_decode_path_token(token))


def _decode_path_token(token: str) -> str:
    token = token.strip()
    if not token:
        return ""
    if token.startswith('"'):
        value, _ = _read_quoted(token, 0)
        return value
    return token.split("\t", 1)[0]


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


def _read_quoted(text: str, start: int) -> tuple[str, int]:
    buffer = bytearray()
    index = start + 1
    while index < len(text):
        character = text[index]
        if character == '"':
            raw = bytes(buffer)
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                decoded = raw.decode("latin-1")
            return decoded, index + 1
        if character == "\\" and index + 1 < len(text):
            escaped = text[index + 1]
            if escaped in _C_ESCAPES:
                buffer.extend(_C_ESCAPES[escaped].encode("utf-8"))
                index += 2
                continue
            if escaped in "01234567":
                digits = escaped
                index += 2
                for _ in range(2):
                    if index < len(text) and text[index] in "01234567":
                        digits += text[index]
                        index += 1
                    else:
                        break
                buffer.append(int(digits, 8) & 0xFF)
                continue
            buffer.extend(escaped.encode("utf-8"))
            index += 2
            continue
        buffer.extend(character.encode("utf-8"))
        index += 1

    try:
        decoded = bytes(buffer).decode("utf-8")
    except UnicodeDecodeError:
        decoded = bytes(buffer).decode("latin-1")
    return decoded, len(text)
