"""Prompt templates and response extraction for the CVE2Checker agents."""

from __future__ import annotations

import html
import json
import re
from typing import Any

QUERY_SENTINEL = "QUERY_FILE_PATH:"
_MAX_JSON_CHARS = 60_000
_MAX_DIFF_CHARS = 40_000

GLOBAL_CONTRACT = """\
You are {role} in CVE2Checker, a C/C++ CVE-to-CodeQL pipeline.

NON-NEGOTIABLE RULES
1. Evidence over plausibility. Do not invent functions, files, APIs, commits, or behavior.
2. Every root-cause claim must cite a repository path, line range, commit, and a short quoted snippet.
3. Distinguish OBSERVED facts from INFERRED hypotheses. Put inferences in unknowns or lower confidence.
4. Use only the tools listed in this prompt. Do not use shell, network, or external web search.
5. Never modify tests, validation oracles, build files, or the target repository.
6. Write only to your designated artifact path, or to the query path specified below.
7. If required evidence is absent, return the explicit status instead of guessing.
8. Your final response must be valid JSON matching the provided schema, or a saved .ql file ending with the required sentinel.

CONTEXT POLICY
- The vulnerable code is the REMOVED (-) side of the diff.
- The fixed code is the ADDED (+) side of the diff.
- Validation methods added by the fix are sanitizer candidates, not proof by themselves.
- Do not assume a validation method is correct or complete.
"""


def global_contract(role: str) -> str:
    if not role or not role.strip():
        raise ValueError("role must be non-empty")
    return GLOBAL_CONTRACT.format(role=role.strip())


def feasibility_prompt(
    cve: dict[str, Any],
    source: dict[str, Any],
    diff_summary: dict[str, Any] | str,
    *,
    build_log: str = "",
    codeql_version: str = "unknown",
) -> str:
    return (
        global_contract("the feasibility gate")
        + f"""

TASK
Determine whether this CVE can be modeled as a CodeQL C/C++ query with the evidence available.

INPUTS
CVE RECORD:
{compact_json(cve)}

SOURCE EVIDENCE:
{compact_json(source)}

DIFF SUMMARY:
{compact_json(diff_summary)}

BUILD EVIDENCE:
{build_log.strip() or "not available"}

CODEQL VERSION:
{codeql_version}

RUBRIC — all six must be justified:
1. Public source and both revisions are available.
2. The project can produce a CodeQL C/C++ database (build evidence or documented fallback).
3. The vulnerability is expressible as a static property: taint flow, missing guard, unsafe call, or bounds/overflow pattern.
4. The fix diff localizes the behavior change sufficiently to define vulnerable/fixed oracles.
5. The CWE is in the supported MVP set: CWE-22, 78, 120, 125, 190, 416, 476, 787.
6. There is enough evidence to identify at least one source, sink, sanitizer, or unsafe operation.

OUTPUT
Return only JSON with this shape:
{{
  "decision": "proceed" | "insufficient_evidence" | "unsupported",
  "confidence": 0.0,
  "language": "cpp",
  "cwe_ids": ["CWE-000"],
  "modeling": "taint" | "missing_guard" | "unsafe_call" | "arithmetic" | "lifetime",
  "source_candidates": [{{"kind": "", "evidence": "path:line"}}],
  "sink_candidates": [{{"kind": "", "evidence": "path:line"}}],
  "sanitizer_candidates": [{{"kind": "", "evidence": "path:line"}}],
  "missing_evidence": [],
  "reasons": [],
  "recommended_next_action": ""
}}

Return "proceed" only if every rubric item is satisfied or is an explicitly validated assumption. Otherwise stop with the precise missing evidence.
"""
    )


def root_cause_prompt(
    cve: dict[str, Any],
    diff: str,
    snippets: list[dict[str, Any]],
    *,
    ast_snippets: list[dict[str, Any]] | None = None,
    vulnerable_commit: str | None = None,
    fix_commit: str | None = None,
) -> str:
    commit_section = ""
    if vulnerable_commit or fix_commit:
        commit_section = f"""
EVIDENCE COMMITS
Vulnerable commit: {vulnerable_commit or "unknown"}
Fix commit: {fix_commit or "unknown"}
The supplied source context is from the checked-out fix revision.
Every component and diff_location commit MUST be one of these two SHAs.
Do not use other commits from the CVE reference list.
"""
    return (
        global_contract("the root-cause analyst")
        + f"""

TASK
Explain the vulnerability using the fix diff and the supplied source context. Produce a structured vulnerability IR.

CVE RECORD:
{compact_json(cve)}
{commit_section}
FIX DIFF:
```diff
{truncate(diff, _MAX_DIFF_CHARS)}
```

SOURCE CONTEXT:
{compact_json(snippets)}

AST CONTEXT (may be empty):
{compact_json(ast_snippets or [])}

ANALYSIS RULES
1. The vulnerable behavior is in the "-" lines; the fix is in the "+" lines.
2. Identify source, sink, sanitizer/barrier, additional taint steps, preconditions, and the unsafe condition.
3. Every component must have file, start_line, end_line, commit, snippet, and confidence.
4. If a component cannot be supported by the supplied evidence, leave the list empty and record it in unknowns.
5. Do not claim library internals or runtime behavior that is not visible in the evidence.
6. A diff location must identify a changed line in the fix.

OUTPUT
Return only JSON with this shape:
{{
  "schema_version": "1.0",
  "cve_id": "CVE-0000-0000",
  "status": "complete" | "insufficient_evidence",
  "language": "cpp",
  "cwe_ids": ["CWE-000"],
  "root_cause": {{
    "type": "",
    "sink": "",
    "unsafe_condition": "",
    "preconditions": []
  }},
  "components": {{
    "sources": [{{"description": "", "file": "", "start_line": 1, "end_line": 1, "commit": "", "snippet": "", "confidence": 0.0}}],
    "sinks": [],
    "sanitizers": [],
    "additional_taint_steps": []
  }},
  "diff_locations": [{{"file": "", "start_line": 1, "end_line": 1, "commit": "", "snippet": ""}}],
  "unknowns": [],
  "analysis_notes": ""
}}
"""
    )


def synthesis_initial_prompt(
    *,
    cve_id: str,
    cve: dict[str, Any],
    cwe_ids: list[str],
    repo_path: str,
    vulnerable_commit: str,
    fix_commit: str,
    diff: str,
    vulnerability_ir: dict[str, Any],
    ast_snippets: list[dict[str, Any]],
    workdir: str,
    codeql_version: str,
    max_tool_calls: int = 50,
) -> str:
    return f"""# CodeQL Query Synthesis — {cve_id}, iteration 1

You are the Query Synthesis Agent. Write a complete CodeQL C/C++ query for {cve_id}.

## Success predicate
The query is successful only if all are true:
1. It compiles under CodeQL {codeql_version}.
2. On the vulnerable database it reports at least one alert/path whose location intersects a changed line in the fix diff.
3. On the fixed database it reports no alert/path whose location intersects a changed line in the fix diff.

A compiling query that detects nothing is not successful.

## Inputs
CVE:
{compact_json(cve)}

CWE: {", ".join(cwe_ids) or "unknown"}
Repository: {repo_path}
Vulnerable commit: {vulnerable_commit}
Fixed commit: {fix_commit}
Diff:
```diff
{truncate(diff, _MAX_DIFF_CHARS)}
```
Vulnerability IR:
{compact_json(vulnerability_ir)}
AST/source context:
{compact_json(ast_snippets)}

## Tools
You may call exactly these tools:
- rag_search(collection, query, k): semantic retrieval over CodeQL docs/examples and CVE notes.
- rag_get(collection, where, limit): fetch indexed documents by metadata.
- read_file(path, start_line, end_line): read a file in the repository (read-only).
- list_dir(path): list a repository directory.
- search_text(path, pattern): search repository text.
- lsp_update(path, content): write a draft query and open it in the code server.
- lsp_diagnostics(path): compile/lint diagnostics for the query file.
- lsp_hover(path, line, character): type/signature documentation (0-based positions).
- lsp_definition(path, line, character): definition lookup (0-based positions).
- lsp_completion(path, line, character): completion (0-based positions).
- lsp_format(path): format edits for the query.

You do NOT have a build or analyze tool. The validator runs those after you stop.
Use LSP diagnostics only for syntax feedback.

## Response protocol
Reply with JSON only.
To call a tool:
{{"tool": "tool_name", "arguments": {{...}}}}
To finish:
{{"final": "<complete CodeQL query text>"}}

You may use at most {max_tool_calls} tool calls in this iteration. Use lsp_update to create a draft and lsp_diagnostics to check it. The harness will save your final "final" query to:
{workdir}/{cve_id}-query-iter-1.ql

## Required query shape
- Use @kind path-problem unless the root cause is not a taint/path property; then justify @kind problem.
- Import library predicates only. Importing or copying a complete existing query is forbidden.
- Prefer the C/C++ dataflow/taint APIs present in CodeQL {codeql_version}. Verify names with hover/definition/RAG; do not guess.
- Add an ID: cve2checker/{cve_id}.
- Keep predicates readable and the alert message specific to this CVE.

## Starting skeleton — adapt, do not assume imports are correct
```ql
/**
 * @name ...
 * @description ...
 * @kind path-problem
 * @problem.severity error
 * @id cve2checker/{cve_id}
 * @precision high
 * @tags security
 */
import cpp
// Verify the exact dataflow/taint imports for {codeql_version} with RAG/LSP.
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

class Source extends DataFlow::Node {{ /* ... */ }}
class Sink extends DataFlow::Node {{ /* ... */ }}
class Sanitizer extends DataFlow::Node {{ /* ... */ }}

module Config implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{ n instanceof Source }}
  predicate isSink(DataFlow::Node n) {{ n instanceof Sink }}
  predicate isBarrier(DataFlow::Node n) {{ n instanceof Sanitizer }}
  predicate isAdditionalFlowStep(DataFlow::Node a, DataFlow::Node b) {{ /* ... */ }}
}}

module Flow = TaintTracking::Global<Config>;
import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "...", source.getNode(), "source"
```

## Workflow
1. Read the IR and diff. Identify the exact changed behavior.
2. Retrieve similar C/C++ queries and same-version docs with rag_search.
3. Compare vulnerable vs fixed source context to find the distinguishing node.
4. Write source, sink, sanitizer, and additional steps.
5. Use LSP diagnostics and hover to fix names/types.
6. Finish with the complete query in the "final" JSON field.

Stop immediately after the final response. Do not try to run the query.
"""


def synthesis_repair_prompt(
    *,
    cve_id: str,
    iteration: int,
    previous_query: str,
    feedback: dict[str, Any],
    vulnerability_ir: dict[str, Any],
    workdir: str,
    max_tool_calls: int = 50,
) -> str:
    return (
        global_contract("the Query Synthesis Agent in repair mode")
        + f"""

# CodeQL Query Repair — {cve_id}, iteration {iteration}

## Previous query
```ql
{truncate(previous_query, _MAX_DIFF_CHARS)}
```

## Validator feedback
{compact_json(feedback)}

## Vulnerability IR
{compact_json(vulnerability_ir)}

## Success predicate
Unchanged: compile + vulnerable alert intersecting the diff + no fixed alert intersecting the diff.

## Repair priority
1. Fix compilation errors first.
2. If the vulnerable database has no matching alert: repair sources, sinks, taint steps, or the tracked property.
3. If the fixed database still matches: add or strengthen sanitizers/guards, or narrow sources/sinks.
4. If the vulnerable match does not intersect the changed lines: move the sink toward the patched behavior.
5. Only then reduce false positives.

## Repair rules
- Make the smallest change that addresses the highest-priority failure.
- Preserve predicates that are already working.
- Do not change the IR, validator, tests, or oracle. If the IR is contradicted by evidence, note it and adjust only the query.
- Do not import complete existing queries.
- Use the same JSON tool protocol as before.
- Finish with the complete query in the "final" JSON field.
- Use lsp_update for draft edits and diagnostics. The harness saves the final query to:
  {workdir}/{cve_id}-query-iter-{iteration}.ql

You may use at most {max_tool_calls} tool calls in this iteration. Do not build or execute the query.
"""
    )


def extract_json(text: str) -> Any:
    """Extract the first JSON object from a model response."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("model response is empty")
    cleaned = text.strip().lstrip("\ufeff")
    candidates = [cleaned]
    fenced = re.findall(r"```(?:json)?\s*(.*?)```", cleaned, re.DOTALL | re.IGNORECASE)
    candidates.extend(item.strip() for item in fenced)
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        extracted = _first_balanced_object(candidate)
        if extracted is not None:
            try:
                return json.loads(extracted)
            except json.JSONDecodeError:
                continue
    raise ValueError("model response does not contain valid JSON")


def extract_json_objects(text: str) -> list[Any]:
    """Extract all top-level balanced JSON objects from a response."""
    if not isinstance(text, str) or not text.strip():
        return []
    cleaned = text.strip().lstrip("\ufeff")
    objects: list[Any] = []
    cursor = 0
    while cursor < len(cleaned):
        start = cleaned.find("{", cursor)
        if start == -1:
            break
        candidate = _first_balanced_object(cleaned[start:])
        if candidate is None:
            break
        try:
            objects.append(json.loads(candidate))
        except json.JSONDecodeError:
            pass
        cursor = start + len(candidate)
    return objects


_XML_TOOL_CALL = re.compile(
    r"<tool_call>\s*<function=([A-Za-z_][A-Za-z0-9_]*)>(.*?)"
    r"</function>\s*</tool_call>",
    re.DOTALL | re.IGNORECASE,
)
_XML_PARAMETER = re.compile(
    r"<parameter=([A-Za-z_][A-Za-z0-9_]*)>(.*?)</parameter>",
    re.DOTALL | re.IGNORECASE,
)

_DSML_INVOKE = re.compile(
    r"<\|+\s*DSML\s*\|+\s*invoke\s+name=\"([^\"]+)\"\s*>(.*?)"
    r"</\|+\s*DSML\s*\|+\s*invoke>",
    re.DOTALL | re.IGNORECASE,
)
_DSML_PARAMETER = re.compile(
    r"<\|+\s*DSML\s*\|+\s*parameter\s+name=\"([^\"]+)\"(?:\s+[^>]*)?>(.*?)"
    r"</\|+\s*DSML\s*\|+\s*parameter>",
    re.DOTALL | re.IGNORECASE,
)


def extract_dsml_tool_calls(text: str) -> list[Any]:
    """Extract tool calls emitted in the DSML format used by some models."""
    if not isinstance(text, str) or "DSML" not in text:
        return []
    calls: list[Any] = []
    for match in _DSML_INVOKE.finditer(text):
        name = html.unescape(match.group(1).strip())
        arguments: dict[str, Any] = {}
        for parameter in _DSML_PARAMETER.finditer(match.group(2)):
            key = html.unescape(parameter.group(1).strip())
            raw_value = html.unescape(parameter.group(2).strip())
            try:
                value: Any = json.loads(raw_value)
            except (json.JSONDecodeError, TypeError):
                value = raw_value
            arguments[key] = value
        if name.lower() in {"final", "finish", "answer", "submit"}:
            query = (
                arguments.get("query")
                or arguments.get("final")
                or arguments.get("content")
            )
            if isinstance(query, str) and query.strip():
                calls.append({"final": query})
            continue
        calls.append({"tool": name, "arguments": arguments})
    return calls


def extract_xml_tool_calls(text: str) -> list[Any]:
    """Extract the XML-ish ``<tool_call>`` format used by some models."""
    if not isinstance(text, str) or "<tool_call>" not in text:
        return []
    calls: list[Any] = []
    for match in _XML_TOOL_CALL.finditer(text):
        name = html.unescape(match.group(1).strip())
        arguments: dict[str, Any] = {}
        for parameter in _XML_PARAMETER.finditer(match.group(2)):
            key = html.unescape(parameter.group(1).strip())
            raw_value = html.unescape(parameter.group(2).strip())
            try:
                value: Any = json.loads(raw_value)
            except (json.JSONDecodeError, TypeError):
                value = raw_value
            arguments[key] = value
        if name.lower() in {"final", "finish", "answer", "submit"}:
            query = (
                arguments.get("query")
                or arguments.get("final")
                or arguments.get("content")
            )
            if query is None:
                query = match.group(2).strip()
            if isinstance(query, str) and query.strip():
                calls.append({"final": query})
            continue
        calls.append({"tool": name, "arguments": arguments})
    return calls


def extract_query(text: str) -> str:
    """Extract a final CodeQL query from a JSON or fenced-text response."""
    try:
        payload = extract_json(text)
    except ValueError:
        payload = None
    if isinstance(payload, dict):
        for key in ("final", "query", "ql"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return _strip_query_fences(value)
        if "tool" in payload:
            raise ValueError("model requested a tool call instead of a final query")
    fenced = re.findall(
        r"```(?:ql|codeql)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE
    )
    for block in fenced:
        if "select" in block and ("from " in block or "class " in block):
            return block.strip()
    if "select" in text and ("from " in text or "class " in text):
        return _strip_query_fences(text)
    raise ValueError("model response does not contain a CodeQL query")


def extract_query_path(text: str) -> str | None:
    match = re.search(rf"{re.escape(QUERY_SENTINEL)}\s*(\S+)", text)
    if match is None:
        return None
    return match.group(1).strip().strip("`'\"")


def compact_json(value: Any, max_chars: int = _MAX_JSON_CHARS) -> str:
    try:
        rendered = json.dumps(value, indent=2, ensure_ascii=False)
    except (TypeError, ValueError):
        rendered = str(value)
    return truncate(rendered, max_chars)


def truncate(text: str, max_chars: int) -> str:
    if not isinstance(text, str):
        text = str(text)
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... [truncated]"


def _strip_query_fences(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(
            r"^```(?:ql|codeql)?\s*", "", stripped, flags=re.IGNORECASE
        )
        stripped = re.sub(r"\s*```$", "", stripped)
    sentinel = stripped.find(QUERY_SENTINEL)
    if sentinel != -1:
        stripped = stripped[:sentinel].rstrip()
    return stripped


def _first_balanced_object(text: str) -> str | None:
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        character = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None
