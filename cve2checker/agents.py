"""Structured feasibility and root-cause agents."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from .llm import LLMClient
from .prompts import (
    extract_json,
    feasibility_prompt,
    root_cause_prompt,
)
from .schemas import (
    SchemaError,
    citation_commit_errors,
    validate_feasibility,
    validate_ir,
)

_SYSTEM = (
    "You are a precise C/C++ security analysis assistant. "
    "Follow the user prompt exactly and return only the requested JSON."
)


class AgentError(RuntimeError):
    """An agent did not produce a valid structured result."""


def run_feasibility(
    cve: dict[str, Any],
    source: dict[str, Any],
    diff_summary: dict[str, Any] | str,
    llm: LLMClient,
    *,
    build_log: str = "",
    codeql_version: str = "unknown",
    max_attempts: int = 2,
) -> dict[str, Any]:
    prompt = feasibility_prompt(
        cve,
        source,
        diff_summary,
        build_log=build_log,
        codeql_version=codeql_version,
    )
    return _run_structured(
        llm,
        prompt,
        validate_feasibility,
        label="feasibility",
        max_attempts=max_attempts,
    )


def run_root_cause(
    cve: dict[str, Any],
    diff: str,
    snippets: list[dict[str, Any]],
    llm: LLMClient,
    *,
    ast_snippets: list[dict[str, Any]] | None = None,
    vulnerable_commit: str | None = None,
    fix_commit: str | None = None,
    max_attempts: int = 2,
) -> dict[str, Any]:
    expected_cve = cve.get("cveMetadata", {}).get("cveId") if isinstance(cve, dict) else None
    allowed_commits = [
        commit
        for commit in (vulnerable_commit, fix_commit)
        if isinstance(commit, str) and commit
    ]
    prompt = root_cause_prompt(
        cve,
        diff,
        snippets,
        ast_snippets=ast_snippets,
        vulnerable_commit=vulnerable_commit,
        fix_commit=fix_commit,
    )

    def validator(payload: dict[str, Any]) -> dict[str, Any]:
        validate_ir(payload)
        errors = citation_commit_errors(payload, allowed_commits)
        if errors:
            raise SchemaError("; ".join(errors))
        return payload

    validated = _run_structured(
        llm,
        prompt,
        validator,
        label="root-cause",
        max_attempts=max_attempts,
    )
    actual_cve = validated.get("cve_id")
    if expected_cve and actual_cve != expected_cve:
        raise AgentError(
            f"root-cause response is for {actual_cve!r}, expected {expected_cve!r}"
        )
    return validated


def write_json_artifact(path: str | Path, payload: Any) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(payload, output, indent=2, ensure_ascii=False)
        output.write("\n")
    return destination


def _run_structured(
    llm: LLMClient,
    prompt: str,
    validator: Callable[[Any], dict[str, Any]],
    *,
    label: str,
    max_attempts: int,
) -> dict[str, Any]:
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    current_prompt = prompt
    last_error = "unknown validation failure"
    for attempt in range(1, max_attempts + 1):
        response = llm.complete(_SYSTEM, current_prompt)
        try:
            payload = extract_json(response)
            return validator(payload)
        except (ValueError, SchemaError) as exc:
            last_error = str(exc)
            if attempt < max_attempts:
                current_prompt = (
                    prompt
                    + "\n\nCORRECTION REQUIRED\n"
                    + f"Your previous {label} response was rejected: {last_error}\n"
                    + "Return only valid JSON that matches the required schema. "
                    + "Do not include prose or tool calls.\n"
                )
        except Exception as exc:
            raise AgentError(f"{label} agent failed: {exc}") from exc

    raise AgentError(
        f"{label} agent did not produce a valid response after "
        f"{max_attempts} attempt(s): {last_error}"
    )
