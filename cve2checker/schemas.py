"""Validation for the feasibility and vulnerability-IR contracts."""

from __future__ import annotations

import re
from typing import Any

_CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_CWE_ID = re.compile(r"^CWE-[0-9]+$")

FEASIBILITY_DECISIONS = {"proceed", "insufficient_evidence", "unsupported"}
MODELING_KINDS = {"taint", "missing_guard", "unsafe_call", "arithmetic", "lifetime"}
IR_STATUSES = {"complete", "insufficient_evidence"}
LANGUAGES = {"cpp", "c"}


class SchemaError(ValueError):
    """A structured agent response does not satisfy its contract."""


def validate_feasibility(data: Any) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(data, dict):
        raise SchemaError("feasibility response must be a JSON object")

    decision = data.get("decision")
    if decision not in FEASIBILITY_DECISIONS:
        errors.append(
            "decision must be one of: " + ", ".join(sorted(FEASIBILITY_DECISIONS))
        )

    confidence = data.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        errors.append("confidence must be a number between 0 and 1")
    elif not 0.0 <= float(confidence) <= 1.0:
        errors.append("confidence must be between 0 and 1")

    language = data.get("language")
    if language not in LANGUAGES:
        errors.append("language must be 'cpp' or 'c'")

    cwe_ids = data.get("cwe_ids")
    if not isinstance(cwe_ids, list) or any(
        not isinstance(item, str) or not _CWE_ID.match(item) for item in cwe_ids
    ):
        errors.append("cwe_ids must be a list of CWE-<number> strings")

    modeling = data.get("modeling")
    if modeling not in MODELING_KINDS:
        errors.append("modeling must be one of: " + ", ".join(sorted(MODELING_KINDS)))

    for field in (
        "source_candidates",
        "sink_candidates",
        "sanitizer_candidates",
    ):
        value = data.get(field)
        if not isinstance(value, list):
            errors.append(f"{field} must be a list")
            continue
        for index, candidate in enumerate(value):
            if not isinstance(candidate, dict):
                errors.append(f"{field}[{index}] must be an object")
                continue
            if not isinstance(candidate.get("kind"), str) or not candidate["kind"].strip():
                errors.append(f"{field}[{index}].kind must be a non-empty string")
            if not isinstance(candidate.get("evidence"), str) or not candidate["evidence"].strip():
                errors.append(f"{field}[{index}].evidence must be a non-empty string")

    for field in ("missing_evidence", "reasons"):
        value = data.get(field)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            errors.append(f"{field} must be a list of strings")

    if not isinstance(data.get("recommended_next_action"), str):
        errors.append("recommended_next_action must be a string")

    if decision == "proceed":
        sinks = data.get("sink_candidates")
        if not isinstance(sinks, list) or not sinks:
            errors.append("a proceed decision requires at least one sink candidate")
        if modeling == "taint":
            sources = data.get("source_candidates")
            if not isinstance(sources, list) or not sources:
                errors.append("a taint proceed decision requires at least one source candidate")
    elif decision in {"insufficient_evidence", "unsupported"}:
        reasons = data.get("reasons")
        if not isinstance(reasons, list) or not reasons:
            errors.append(f"a {decision} decision requires at least one reason")

    if errors:
        raise SchemaError("; ".join(errors))
    return data


def validate_ir(data: Any) -> dict[str, Any]:
    errors = _ir_errors(data)
    if errors:
        raise SchemaError("; ".join(errors))
    return data


def citation_commit_errors(
    data: Any, allowed_commits: list[str] | set[str] | tuple[str, ...]
) -> list[str]:
    """Return citations whose commit is not one of the evidence commits."""
    allowed = {str(commit).lower() for commit in allowed_commits if commit}
    if not allowed:
        return []
    errors: list[str] = []
    components = data.get("components") if isinstance(data, dict) else None
    if isinstance(components, dict):
        for section in (
            "sources",
            "sinks",
            "sanitizers",
            "additional_taint_steps",
        ):
            for index, item in enumerate(components.get(section, []) or []):
                commit = item.get("commit") if isinstance(item, dict) else None
                if isinstance(commit, str) and commit.lower() not in allowed:
                    errors.append(
                        f"components.{section}[{index}].commit {commit!r} "
                        f"is not one of the evidence commits"
                    )
    diff_locations = data.get("diff_locations") if isinstance(data, dict) else None
    if isinstance(diff_locations, list):
        for index, item in enumerate(diff_locations):
            commit = item.get("commit") if isinstance(item, dict) else None
            if isinstance(commit, str) and commit.lower() not in allowed:
                errors.append(
                    f"diff_locations[{index}].commit {commit!r} "
                    f"is not one of the evidence commits"
                )
    return errors


def citation_errors(data: Any) -> list[str]:
    """Return missing or invalid evidence citations in an IR document."""
    if not isinstance(data, dict):
        return ["IR must be a JSON object"]
    errors: list[str] = []
    components = data.get("components")
    if not isinstance(components, dict):
        return ["components must be an object"]

    for section in (
        "sources",
        "sinks",
        "sanitizers",
        "additional_taint_steps",
    ):
        items = components.get(section)
        if not isinstance(items, list):
            errors.append(f"components.{section} must be a list")
            continue
        for index, item in enumerate(items):
            errors.extend(_citation_errors(item, f"components.{section}[{index}]"))

    diff_locations = data.get("diff_locations")
    if not isinstance(diff_locations, list):
        errors.append("diff_locations must be a list")
    else:
        for index, item in enumerate(diff_locations):
            errors.extend(_citation_errors(item, f"diff_locations[{index}]", diff=True))
    return errors


def _ir_errors(data: Any) -> list[str]:
    if not isinstance(data, dict):
        return ["IR response must be a JSON object"]

    errors: list[str] = []
    if data.get("schema_version") != "1.0":
        errors.append("schema_version must be '1.0'")

    cve_id = data.get("cve_id")
    if not isinstance(cve_id, str) or not _CVE_ID.match(cve_id):
        errors.append("cve_id must be a valid CVE identifier")

    status = data.get("status")
    if status not in IR_STATUSES:
        errors.append("status must be 'complete' or 'insufficient_evidence'")

    language = data.get("language")
    if language not in LANGUAGES:
        errors.append("language must be 'cpp' or 'c'")

    cwe_ids = data.get("cwe_ids")
    if not isinstance(cwe_ids, list) or any(
        not isinstance(item, str) or not _CWE_ID.match(item) for item in cwe_ids
    ):
        errors.append("cwe_ids must be a list of CWE-<number> strings")

    root_cause = data.get("root_cause")
    if not isinstance(root_cause, dict):
        errors.append("root_cause must be an object")
    else:
        if root_cause.get("type") is not None and not isinstance(root_cause.get("type"), str):
            errors.append("root_cause.type must be a string or null")
        if root_cause.get("sink") is not None and not isinstance(root_cause.get("sink"), str):
            errors.append("root_cause.sink must be a string or null")
        if root_cause.get("unsafe_condition") is not None and not isinstance(
            root_cause.get("unsafe_condition"), str
        ):
            errors.append("root_cause.unsafe_condition must be a string or null")
        if not isinstance(root_cause.get("preconditions"), list):
            errors.append("root_cause.preconditions must be a list")

    components = data.get("components")
    if not isinstance(components, dict):
        errors.append("components must be an object")

    errors.extend(citation_errors(data))

    if not isinstance(data.get("unknowns"), list):
        errors.append("unknowns must be a list")

    if status == "complete":
        sinks = components.get("sinks") if isinstance(components, dict) else None
        if not isinstance(sinks, list) or not sinks:
            errors.append("a complete IR requires at least one cited sink")
        diff_locations = data.get("diff_locations")
        if not isinstance(diff_locations, list) or not diff_locations:
            errors.append("a complete IR requires at least one diff location")
    return errors


def _citation_errors(item: Any, prefix: str, *, diff: bool = False) -> list[str]:
    if not isinstance(item, dict):
        return [f"{prefix} must be an object"]
    errors: list[str] = []
    for field in ("file", "commit", "snippet"):
        value = item.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{prefix}.{field} must be a non-empty string")
    start = item.get("start_line")
    end = item.get("end_line")
    if isinstance(start, bool) or not isinstance(start, int) or start <= 0:
        errors.append(f"{prefix}.start_line must be a positive integer")
    if isinstance(end, bool) or not isinstance(end, int) or end <= 0:
        errors.append(f"{prefix}.end_line must be a positive integer")
    if (
        isinstance(start, int)
        and not isinstance(start, bool)
        and isinstance(end, int)
        and not isinstance(end, bool)
        and start > 0
        and end > 0
        and end < start
    ):
        errors.append(f"{prefix}.end_line must be greater than or equal to start_line")
    if diff:
        return errors
    confidence = item.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        errors.append(f"{prefix}.confidence must be a number between 0 and 1")
    elif not 0.0 <= float(confidence) <= 1.0:
        errors.append(f"{prefix}.confidence must be between 0 and 1")
    return errors
