"""SARIF 2.1.0 result parsing and changed-line matching."""

from __future__ import annotations

import json
import ntpath
import os
import posixpath
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit
from urllib.request import url2pathname

_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


class SarifError(Exception):
    """An unreadable or structurally invalid SARIF document."""


@dataclass(frozen=True)
class SarifLocation:
    file: str
    start_line: int
    end_line: int
    uri: str


@dataclass
class SarifResult:
    rule_id: str
    message: str
    level: str
    locations: list[SarifLocation] = field(default_factory=list)
    code_flow_locations: list[SarifLocation] = field(default_factory=list)


def parse_sarif(source: str | Path) -> list[SarifResult]:
    """Parse all results from an SARIF document supplied as text or as a path."""
    document = _load_document(source)
    if not isinstance(document, Mapping):
        raise SarifError("SARIF document must be a JSON object")

    version = document.get("version")
    if version is not None and (
        not isinstance(version, str) or not version.startswith("2.1")
    ):
        raise SarifError(f"unsupported SARIF version {version!r}; expected 2.1.0")

    runs = document.get("runs")
    if not isinstance(runs, list):
        raise SarifError("SARIF document is missing its runs array")

    results: list[SarifResult] = []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        base_paths = _run_base_paths(run)
        for raw_result in _mapping_list(run.get("results")):
            results.append(_parse_result(raw_result, run, base_paths))
    return results


def result_locations(result: SarifResult) -> list[SarifLocation]:
    """Return primary and code-flow locations for a result."""
    return [*result.locations, *result.code_flow_locations]


def location_intersects(
    location: SarifLocation, changed: Iterable[object]
) -> bool:
    """Return whether a location overlaps any changed-file line range."""
    location_range = _valid_range(location.start_line, location.end_line)
    if location_range is None:
        return False

    location_file = _normalise_changed_path(location.file)
    if not location_file:
        return False

    if isinstance(changed, Mapping):
        changed = (changed,)
    try:
        iterator = iter(changed)
    except TypeError:
        return False

    for item in iterator:
        file_value, start_value, end_value = _changed_fields(item)
        changed_file = _normalise_changed_path(file_value)
        if not changed_file or changed_file != location_file:
            continue
        changed_range = _valid_range(start_value, end_value)
        if changed_range is None:
            continue
        if (
            location_range[0] <= changed_range[1]
            and changed_range[0] <= location_range[1]
        ):
            return True
    return False


def _load_document(source: object) -> object:
    if isinstance(source, Mapping):
        return source
    if isinstance(source, (bytes, bytearray)):
        try:
            return json.loads(bytes(source))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SarifError(f"SARIF text is not valid JSON: {exc}") from exc
    if isinstance(source, Path):
        return _load_path(source)
    if isinstance(source, os.PathLike):
        return _load_path(Path(source))
    if isinstance(source, str):
        try:
            return json.loads(source.lstrip("\ufeff"))
        except (json.JSONDecodeError, UnicodeDecodeError) as json_error:
            try:
                return _load_path(Path(source))
            except SarifError as path_error:
                raise SarifError(
                    f"could not parse SARIF JSON text or read file {source!r}: "
                    f"{json_error}"
                ) from path_error
    raise SarifError(f"unsupported SARIF source {type(source).__name__}")


def _load_path(path: Path) -> object:
    try:
        text = path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeError) as exc:
        raise SarifError(f"could not read SARIF file {os.fspath(path)!r}: {exc}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise SarifError(
            f"SARIF file {os.fspath(path)!r} is not valid JSON: {exc}"
        ) from exc


def _parse_result(
    raw_result: Mapping[str, Any],
    run: Mapping[str, Any],
    base_paths: Mapping[str, str],
) -> SarifResult:
    rule_id = raw_result.get("ruleId")
    if not isinstance(rule_id, str):
        rule_id = ""

    level = raw_result.get("level")
    if not isinstance(level, str) or not level:
        level = "warning"

    locations = []
    for raw_location in _mapping_list(raw_result.get("locations")):
        location = _extract_location(raw_location, run, base_paths)
        if location is not None:
            locations.append(location)

    code_flow_locations = []
    for code_flow in _mapping_list(raw_result.get("codeFlows")):
        for thread_flow in _mapping_list(code_flow.get("threadFlows")):
            for flow_location in _mapping_list(thread_flow.get("locations")):
                raw_location = flow_location.get("location")
                if not isinstance(raw_location, Mapping):
                    if isinstance(flow_location.get("physicalLocation"), Mapping):
                        raw_location = flow_location
                    else:
                        continue
                location = _extract_location(raw_location, run, base_paths)
                if location is not None:
                    code_flow_locations.append(location)

    return SarifResult(
        rule_id=rule_id,
        message=_message_text(raw_result.get("message")),
        level=level,
        locations=locations,
        code_flow_locations=code_flow_locations,
    )


def _message_text(message: object) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, Mapping):
        for key in ("text", "markdown", "id"):
            value = message.get(key)
            if isinstance(value, str):
                return value
    return ""


def _extract_location(
    raw_location: Mapping[str, Any],
    run: Mapping[str, Any],
    base_paths: Mapping[str, str],
) -> SarifLocation | None:
    physical_location = raw_location.get("physicalLocation")
    if not isinstance(physical_location, Mapping):
        return None

    uri, uri_base_id = _artifact_uri(physical_location, run)
    region = physical_location.get("region")
    if not isinstance(region, Mapping):
        region = {}

    start_line = _line_number(region.get("startLine"))
    end_line = _line_number(region.get("endLine"))
    if start_line is None:
        start_line = 0
    if end_line is None:
        end_line = start_line if start_line > 0 else 0

    return SarifLocation(
        file=_resolve_location_path(uri, uri_base_id, base_paths),
        start_line=start_line,
        end_line=end_line,
        uri=uri,
    )


def _artifact_uri(
    physical_location: Mapping[str, Any], run: Mapping[str, Any]
) -> tuple[str, str | None]:
    artifact = physical_location.get("artifactLocation")
    if not isinstance(artifact, Mapping):
        return "", None

    uri = artifact.get("uri")
    if not isinstance(uri, str):
        uri = ""
    base_id = artifact.get("uriBaseId")
    if not isinstance(base_id, str):
        base_id = None

    if not uri:
        index = artifact.get("index")
        if isinstance(index, int) and not isinstance(index, bool):
            artifacts = run.get("artifacts")
            if (
                isinstance(artifacts, list)
                and 0 <= index < len(artifacts)
                and isinstance(artifacts[index], Mapping)
            ):
                referenced = artifacts[index].get("location")
                if isinstance(referenced, Mapping):
                    referenced_uri = referenced.get("uri")
                    if isinstance(referenced_uri, str):
                        uri = referenced_uri
                    if base_id is None:
                        referenced_base = referenced.get("uriBaseId")
                        if isinstance(referenced_base, str):
                            base_id = referenced_base
    return uri, base_id


def _run_base_paths(run: Mapping[str, Any]) -> dict[str, str]:
    raw_bases = run.get("originalUriBaseIds")
    if not isinstance(raw_bases, Mapping):
        return {}

    resolved: dict[str, str] = {}
    resolving: set[str] = set()

    def resolve(base_id: str) -> str | None:
        if base_id in resolved:
            return resolved[base_id]
        if base_id in resolving:
            return None
        entry = raw_bases.get(base_id)
        if not isinstance(entry, Mapping):
            return None

        resolving.add(base_id)
        try:
            uri = entry.get("uri")
            parent_id = entry.get("uriBaseId")
            path: str | None = None

            if isinstance(uri, str) and uri.strip():
                child, is_absolute = _uri_to_path(uri)
                if child:
                    if is_absolute:
                        path = child
                    elif isinstance(parent_id, str) and parent_id:
                        parent = resolve(parent_id)
                        if parent is not None:
                            path = _normalise_path(posixpath.join(parent, child))
                    else:
                        path = child
            elif isinstance(parent_id, str) and parent_id:
                path = resolve(parent_id)

            if path is not None:
                resolved[base_id] = path
            return path
        finally:
            resolving.discard(base_id)

    for base_id in raw_bases:
        if isinstance(base_id, str):
            resolve(base_id)
    return resolved


def _resolve_location_path(
    uri: str, base_id: str | None, base_paths: Mapping[str, str]
) -> str:
    if not uri.strip():
        return ""

    path, is_absolute = _uri_to_path(uri)
    if path is None:
        return ""
    if not is_absolute:
        return path

    candidates: list[str] = []
    if base_id is not None and base_id in base_paths:
        candidates.append(base_paths[base_id])
    for candidate in base_paths.values():
        if candidate not in candidates:
            candidates.append(candidate)

    for base in sorted(candidates, key=len, reverse=True):
        relative = _relative_path(path, base)
        if relative is not None:
            return relative
    return path


def _uri_to_path(uri: str) -> tuple[str | None, bool]:
    text = uri.strip()
    if not text:
        return None, False

    decoded = unquote(text)
    if _WINDOWS_DRIVE.match(decoded):
        return _normalise_path(decoded), True

    try:
        parsed = urlsplit(text)
    except ValueError:
        return _normalise_path(decoded), False

    scheme = parsed.scheme.lower()
    if scheme == "file":
        raw_path = unquote(parsed.path)
        netloc = unquote(parsed.netloc)
        if netloc and netloc.lower() != "localhost":
            raw_path = f"//{netloc}{raw_path}"
        elif re.match(r"^/[A-Za-z]:[\\/]", raw_path):
            raw_path = raw_path[1:]
        try:
            local_path = url2pathname(raw_path)
        except (OSError, ValueError):
            local_path = raw_path
        return _normalise_path(local_path), True

    if scheme:
        return None, False

    path = unquote(parsed.path)
    if not path:
        return None, False
    return _normalise_path(path), path.startswith("/") or path.startswith("\\")


def _normalise_path(value: str) -> str:
    text = str(value).replace("\\", "/")
    if not text:
        return ""
    if _WINDOWS_DRIVE.match(text) or text.startswith("//"):
        return ntpath.normpath(text).replace("\\", "/")
    return posixpath.normpath(text)


def _path_key(path: str) -> str:
    normalised = _normalise_path(path)
    if os.name == "nt":
        return normalised.lower()
    return normalised


def _relative_path(path: str, root: str) -> str | None:
    normal_path = _normalise_path(path)
    normal_root = _normalise_path(root)
    if not normal_path or not normal_root:
        return None

    path_key = _path_key(normal_path)
    root_key = _path_key(normal_root)
    if path_key == root_key:
        return None

    prefix = root_key if root_key.endswith("/") else f"{root_key}/"
    if path_key.startswith(prefix):
        return normal_path[len(prefix) :]
    return None


def _line_number(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _valid_range(start_value: object, end_value: object) -> tuple[int, int] | None:
    start = _line_number(start_value)
    end = _line_number(end_value)
    if start is None or end is None:
        return None
    if start <= 0 or end <= 0 or end < start:
        return None
    return start, end


def _changed_fields(item: object) -> tuple[object, object, object]:
    if isinstance(item, Mapping):
        file_value = item.get("file")
        start_value = item.get("start")
        end_value = item.get("end")
        if start_value is None:
            start_value = item.get("start_line")
        if end_value is None:
            end_value = item.get("end_line")
        return file_value, start_value, end_value

    file_value = getattr(item, "file", None)
    start_value = getattr(item, "start", None)
    end_value = getattr(item, "end", None)
    if start_value is None:
        start_value = getattr(item, "start_line", None)
    if end_value is None:
        end_value = getattr(item, "end_line", None)
    return file_value, start_value, end_value


def _normalise_changed_path(value: object) -> str:
    try:
        text = os.fspath(value)
    except TypeError:
        return ""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            return ""
    text = str(text).strip()
    if not text:
        return ""

    path, _ = _uri_to_path(text)
    if path is None:
        return ""
    if os.name == "nt":
        return path.lower()
    return path


def _mapping_list(value: object) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]
