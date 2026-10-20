"""Deterministic validation of a candidate CodeQL query."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable

from .codeql import CodeQLError, analyze_query, compile_query
from .sarif import SarifError, SarifLocation, parse_sarif, result_locations


class ValidationError(RuntimeError):
    """The validator cannot score a query with the supplied inputs."""


def validate_query(
    query_path: str | os.PathLike[str],
    vulnerable_database: str | os.PathLike[str],
    fixed_database: str | os.PathLike[str],
    changed_ranges: Iterable[Any],
    workdir: str | os.PathLike[str],
    *,
    codeql_path: str | os.PathLike[str] = "codeql",
    iteration: int = 1,
    precision_threshold: float = 0.5,
) -> dict[str, Any]:
    """Compile, execute, and score a query against vulnerable/fixed databases."""
    query = Path(query_path)
    if not query.is_file():
        raise ValidationError(f"query file does not exist: {query}")
    changed = list(changed_ranges)
    if not changed:
        raise ValidationError("at least one changed range is required")

    output_dir = Path(workdir)
    output_dir.mkdir(parents=True, exist_ok=True)
    feedback: dict[str, Any] = {
        "iteration": int(iteration),
        "query_path": str(query.resolve()),
        "query_sha256": hashlib.sha256(query.read_bytes()).hexdigest(),
        "compile": {"ok": False, "errors": []},
        "vulnerable": {"ok": False, "match_count": 0, "diff_intersection_count": 0, "traces": []},
        "fixed": {"ok": False, "match_count": 0, "diff_intersection_count": 0, "traces": []},
        "metrics": {"recall": False, "precision": 0.0, "f1": 0.0},
        "verdict": "compile_failed",
        "next_actions": [],
    }

    try:
        compile_query(query, codeql_path=codeql_path)
    except CodeQLError as exc:
        feedback["compile"]["errors"] = [{"message": str(exc)}]
        feedback["verdict"] = "compile_failed"
        feedback["next_actions"] = [
            "Fix the compilation error before changing detection logic.",
            "Use LSP diagnostics and hover to verify predicate names and types.",
        ]
        _write_feedback(output_dir / "feedback.json", feedback)
        return feedback
    except Exception as exc:
        feedback["compile"]["errors"] = [{"message": str(exc)}]
        feedback["verdict"] = "compile_failed"
        feedback["next_actions"] = ["Inspect the CodeQL CLI configuration."]
        _write_feedback(output_dir / "feedback.json", feedback)
        return feedback

    feedback["compile"]["ok"] = True

    vulnerable_sarif = output_dir / "vulnerable.sarif"
    fixed_sarif = output_dir / "fixed.sarif"
    try:
        analyze_query(
            vulnerable_database,
            query,
            vulnerable_sarif,
            codeql_path=codeql_path,
        )
    except (CodeQLError, OSError, ValueError) as exc:
        feedback["vulnerable"]["error"] = str(exc)
        feedback["verdict"] = "analysis_failed"
        feedback["next_actions"] = [
            "Verify that the vulnerable database is valid and built for the same CodeQL version."
        ]
        _write_feedback(output_dir / "feedback.json", feedback)
        return feedback

    try:
        analyze_query(
            fixed_database,
            query,
            fixed_sarif,
            codeql_path=codeql_path,
        )
    except (CodeQLError, OSError, ValueError) as exc:
        feedback["fixed"]["error"] = str(exc)
        feedback["verdict"] = "analysis_failed"
        feedback["next_actions"] = [
            "Verify that the fixed database is valid and built for the same CodeQL version."
        ]
        _write_feedback(output_dir / "feedback.json", feedback)
        return feedback

    try:
        feedback["vulnerable"] = _summarize_sarif(vulnerable_sarif, changed)
        feedback["fixed"] = _summarize_sarif(fixed_sarif, changed)
    except SarifError as exc:
        feedback["verdict"] = "analysis_failed"
        feedback["error"] = f"could not parse CodeQL SARIF output: {exc}"
        feedback["next_actions"] = [
            "Inspect the CodeQL analysis output and ensure the query produced valid SARIF."
        ]
        _write_feedback(output_dir / "feedback.json", feedback)
        return feedback
    feedback["vulnerable"]["ok"] = True
    feedback["fixed"]["ok"] = True
    feedback["metrics"] = _metrics(feedback)

    vulnerable_hits = int(feedback["vulnerable"]["diff_intersection_count"])
    fixed_hits = int(feedback["fixed"]["diff_intersection_count"])
    if vulnerable_hits == 0:
        feedback["verdict"] = "detection_failed"
        feedback["next_actions"] = _detection_actions(feedback)
    elif fixed_hits > 0:
        feedback["verdict"] = "discrimination_failed"
        feedback["next_actions"] = [
            "The fixed database still matches the patched region.",
            "Add or strengthen the sanitizer/barrier for the behavior introduced by the fix.",
            "Narrow sources or sinks so the patched path no longer qualifies.",
        ]
    else:
        feedback["verdict"] = "success"
        feedback["next_actions"] = []
        if feedback["metrics"]["precision"] < precision_threshold:
            feedback["warning"] = (
                "Query succeeded but precision is below the configured threshold; "
                "consider tightening it before reuse."
            )

    _write_feedback(output_dir / "feedback.json", feedback)
    return feedback


def _summarize_sarif(path: Path, changed: list[Any]) -> dict[str, Any]:
    results = parse_sarif(path)
    traces: list[dict[str, Any]] = []
    intersection_count = 0
    for result in results:
        locations = result_locations(result)
        intersects = any(
            location_intersects(location, changed) for location in locations
        )
        if intersects:
            intersection_count += 1
        traces.append(
            {
                "rule_id": result.rule_id,
                "message": result.message,
                "level": result.level,
                "intersects_diff": intersects,
                "locations": [
                    {
                        "file": location.file,
                        "start_line": location.start_line,
                        "end_line": location.end_line,
                    }
                    for location in locations
                ],
            }
        )
    return {
        "ok": True,
        "match_count": len(results),
        "diff_intersection_count": intersection_count,
        "traces": traces,
    }


def location_intersects(location: SarifLocation, changed: Iterable[Any]) -> bool:
    """Intersect a SARIF location with changed ranges, tolerating path prefixes."""
    if location.start_line <= 0 or location.end_line < location.start_line:
        return False
    for item in changed:
        file_value = _field(item, "file")
        start = _field(item, "start")
        end = _field(item, "end")
        if not isinstance(file_value, str) or not file_value:
            continue
        if not _same_file(location.file, file_value):
            continue
        if not isinstance(start, int) or not isinstance(end, int):
            continue
        if start <= 0 or end < start:
            continue
        if location.start_line <= end and start <= location.end_line:
            return True
    return False


def _same_file(left: str, right: str) -> bool:
    if not left or not right:
        return False
    first = _normalize_path(left)
    second = _normalize_path(right)
    if os.name == "nt":
        first = first.lower()
        second = second.lower()
    if first == second:
        return True
    return first.endswith("/" + second) or second.endswith("/" + first)


def _normalize_path(value: str) -> str:
    text = str(value).strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def _field(item: Any, name: str) -> Any:
    if isinstance(item, dict):
        return item.get(name)
    return getattr(item, name, None)


def _metrics(feedback: dict[str, Any]) -> dict[str, Any]:
    vulnerable_count = int(feedback["vulnerable"]["match_count"])
    true_positive_count = int(feedback["vulnerable"]["diff_intersection_count"])
    recall = true_positive_count > 0
    precision = (
        true_positive_count / vulnerable_count if vulnerable_count > 0 else 0.0
    )
    if precision + (1.0 if recall else 0.0) == 0.0:
        f1 = 0.0
    else:
        f1 = 2 * precision * (1.0 if recall else 0.0) / (precision + (1.0 if recall else 0.0))
    return {
        "recall": recall,
        "precision": precision,
        "f1": f1,
    }


def _detection_actions(feedback: dict[str, Any]) -> list[str]:
    actions = [
        "The vulnerable database produced no alert intersecting the changed lines.",
        "Check that the source and sink definitions match the IR and the AST.",
        "Add missing taint steps or broaden the tracked property.",
    ]
    if feedback["vulnerable"]["match_count"] > 0:
        actions.append(
            "Alerts exist but none intersect the patch; move the sink toward the changed behavior."
        )
    return actions


def _write_feedback(path: Path, feedback: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(feedback, output, indent=2, ensure_ascii=False)
        output.write("\n")
