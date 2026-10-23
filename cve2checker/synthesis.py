"""Tool-using CodeQL synthesis loop."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from .llm import LLMClient
from .prompts import (
    extract_dsml_tool_calls,
    extract_json_objects,
    extract_query,
    extract_xml_tool_calls,
    synthesis_initial_prompt,
    synthesis_repair_prompt,
)
from .rag import RagIndex

_SYSTEM = (
    "You are a precise CodeQL C/C++ query synthesis agent. "
    "Use the provided tools when needed. Reply with JSON only."
)


class SynthesisError(RuntimeError):
    """The synthesis protocol failed."""


class SynthesisProtocolError(SynthesisError):
    """The agent response could not be interpreted; keep the raw text."""

    def __init__(self, message: str, response: str = ""):
        super().__init__(message)
        self.response = response


class ToolError(RuntimeError):
    """A synthesis tool was called incorrectly or failed."""


@dataclass
class SynthesisResult:
    status: str
    iterations: int
    query_path: Path | None
    feedback: dict[str, Any] | None
    history: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ToolBox:
    """Read-only tools exposed to the synthesis agent."""

    repo_root: Path
    workdir: Path
    rag: RagIndex | None = None
    lsp: Any | None = None
    max_output_chars: int = 12_000

    def execute(self, name: str, arguments: dict[str, Any] | None = None) -> str:
        if not isinstance(name, str) or not name:
            raise ToolError("tool name must be a non-empty string")
        args = arguments or {}
        if not isinstance(args, dict):
            raise ToolError("tool arguments must be an object")

        handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "list_tools": self._list_tools,
            "harness_tools_list": self._list_tools,
            "rag_search": self._rag_search,
            "rag_get": self._rag_get,
            "read_file": self._read_file,
            "list_dir": self._list_dir,
            "search_text": self._search_text,
            "lsp_update": self._lsp_update,
            "lsp_diagnostics": self._lsp_diagnostics,
            "lsp_hover": self._lsp_hover,
            "lsp_definition": self._lsp_definition,
            "lsp_completion": self._lsp_completion,
            "lsp_format": self._lsp_format,
        }
        handler = handlers.get(name)
        if handler is None:
            raise ToolError(
                f"unknown tool {name!r}; available tools: {', '.join(sorted(handlers))}"
            )
        return _render(handler(args), self.max_output_chars)

    def _list_tools(self, args: dict[str, Any]) -> Any:
        return {
            "tools": [
                "rag_search(collection, query, k)",
                "rag_get(collection, ids, where, limit)",
                "read_file(path, start_line, end_line)",
                "list_dir(path)",
                "search_text(path, pattern, max_results)",
                "lsp_update(path, content)",
                "lsp_diagnostics(path)",
                "lsp_hover(path, line, character)",
                "lsp_definition(path, line, character)",
                "lsp_completion(path, line, character)",
                "lsp_format(path)",
            ]
        }

    def _rag_search(self, args: dict[str, Any]) -> Any:
        self._require_rag()
        collection = self._resolve_collection(_string_arg(args, "collection"))
        query = _string_arg(args, "query")
        limit = _int_arg(args, "k", 5)
        return self.rag.search(collection, query, limit=limit)

    def _rag_get(self, args: dict[str, Any]) -> Any:
        self._require_rag()
        collection = self._resolve_collection(_string_arg(args, "collection"))
        ids = args.get("ids")
        where = args.get("where")
        limit = _int_arg(args, "limit", 10)
        if ids is not None and not isinstance(ids, list):
            raise ToolError("ids must be a list of strings")
        if where is not None and not isinstance(where, dict):
            raise ToolError("where must be an object")
        return self.rag.get(collection, ids=ids, where=where, limit=limit)

    def _resolve_collection(self, collection: str) -> str:
        available = self.rag.collections()
        if collection in available:
            return collection
        aliases = {
            "codeql_docs": "codeql_cpp",
            "codeql-docs": "codeql_cpp",
            "codeql_examples": "codeql_cpp",
            "codeql-examples": "codeql_cpp",
            "codeql_examples_cpp": "codeql_cpp",
            "codeql_docs_2_27_2": "codeql_cpp",
            "codeql_docs_2.27.2": "codeql_cpp",
        }
        resolved = aliases.get(collection.lower())
        if resolved in available:
            return resolved
        raise ToolError(
            f"unknown collection {collection!r}; available: {', '.join(available)}"
        )

    def _read_file(self, args: dict[str, Any]) -> Any:
        path = self._repo_path(_string_arg(args, "path"))
        start_line = _int_arg(args, "start_line", 1)
        end_line = _int_arg(args, "end_line", start_line + 199)
        if start_line < 1 or end_line < start_line:
            raise ToolError("line range must be positive and ordered")
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            raise ToolError(f"could not read {path}: {exc}") from exc
        end_line = min(end_line, start_line + 199, len(lines))
        segment = lines[start_line - 1 : end_line]
        return {
            "file": self._relative(path),
            "start_line": start_line,
            "end_line": end_line,
            "text": "\n".join(segment),
        }

    def _list_dir(self, args: dict[str, Any]) -> Any:
        path = self._repo_path(_string_arg(args, "path", "."))
        if not path.is_dir():
            raise ToolError(f"not a directory: {path}")
        entries = []
        for entry in sorted(path.iterdir(), key=lambda item: item.name)[:200]:
            entries.append(
                {
                    "name": entry.name,
                    "type": "dir" if entry.is_dir() else "file",
                }
            )
        return {"path": self._relative(path), "entries": entries}

    def _search_text(self, args: dict[str, Any]) -> Any:
        path = self._repo_path(_string_arg(args, "path", "."))
        pattern = _string_arg(args, "pattern")
        max_results = min(_int_arg(args, "max_results", 50), 200)
        try:
            expression = re.compile(pattern)
        except re.error as exc:
            raise ToolError(f"invalid regular expression: {exc}") from exc

        files = [path] if path.is_file() else _walk_files(path)
        results: list[dict[str, Any]] = []
        for file_path in files:
            if len(results) >= max_results:
                break
            try:
                lines = file_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                continue
            for line_number, line in enumerate(lines, start=1):
                if expression.search(line):
                    results.append(
                        {
                            "file": self._relative(file_path),
                            "line": line_number,
                            "text": line[:500],
                        }
                    )
                    if len(results) >= max_results:
                        break
        return results

    def _lsp_update(self, args: dict[str, Any]) -> Any:
        self._require_lsp()
        path = self._query_path(_string_arg(args, "path"))
        content = args.get("content")
        if not isinstance(content, str) or not content.strip():
            raise ToolError("content must be a non-empty string")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.rstrip() + "\n", encoding="utf-8", newline="\n")
        self.lsp.update_file(path, content)
        return {"path": self._relative_query(path)}

    def _lsp_diagnostics(self, args: dict[str, Any]) -> Any:
        self._require_lsp()
        path = self._query_path(_string_arg(args, "path"))
        return self.lsp.diagnostics(path)

    def _lsp_hover(self, args: dict[str, Any]) -> Any:
        self._require_lsp()
        path = self._query_path(_string_arg(args, "path"))
        return self.lsp.hover(
            path, _int_arg(args, "line", 0), _int_arg(args, "character", 0)
        )

    def _lsp_definition(self, args: dict[str, Any]) -> Any:
        self._require_lsp()
        path = self._query_path(_string_arg(args, "path"))
        return self.lsp.definition(
            path, _int_arg(args, "line", 0), _int_arg(args, "character", 0)
        )

    def _lsp_completion(self, args: dict[str, Any]) -> Any:
        self._require_lsp()
        path = self._query_path(_string_arg(args, "path"))
        return self.lsp.complete(
            path, _int_arg(args, "line", 0), _int_arg(args, "character", 0)
        )

    def _lsp_format(self, args: dict[str, Any]) -> Any:
        self._require_lsp()
        path = self._query_path(_string_arg(args, "path"))
        return self.lsp.format(path)

    def _require_rag(self) -> None:
        if self.rag is None:
            raise ToolError("RAG tools are not configured")

    def _require_lsp(self) -> None:
        if self.lsp is None:
            raise ToolError("LSP tools are not configured")

    def _repo_path(self, value: str) -> Path:
        root = self.repo_root.expanduser().resolve()
        candidate = Path(value)
        resolved = (
            candidate.expanduser().resolve()
            if candidate.is_absolute()
            else (root / candidate).resolve()
        )
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ToolError(f"path escapes the repository: {value}") from exc
        if not resolved.exists() and not Path(value).is_absolute():
            parts = Path(value).parts
            for start in range(1, len(parts)):
                candidate = root.joinpath(*parts[start:]).resolve()
                try:
                    candidate.relative_to(root)
                except ValueError:
                    continue
                if candidate.exists():
                    return candidate
        return resolved

    def _query_path(self, value: str) -> Path:
        workdir = self.workdir.expanduser().resolve()
        candidate = Path(value)
        resolved = (
            candidate.expanduser().resolve()
            if candidate.is_absolute()
            else (workdir / candidate).resolve()
        )
        try:
            resolved.relative_to(workdir)
        except ValueError as exc:
            raise ToolError(f"query path escapes the work directory: {value}") from exc
        return resolved

    def _relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(
                self.repo_root.expanduser().resolve()
            ).as_posix()
        except ValueError:
            return str(path)

    def _relative_query(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(
                self.workdir.expanduser().resolve()
            ).as_posix()
        except ValueError:
            return str(path)


def run_synthesis(
    *,
    cve_id: str,
    cve: dict[str, Any],
    cwe_ids: list[str],
    repo_path: str | os.PathLike[str],
    vulnerable_commit: str,
    fix_commit: str,
    diff: str,
    vulnerability_ir: dict[str, Any],
    ast_snippets: list[dict[str, Any]],
    workdir: str | os.PathLike[str],
    llm: LLMClient,
    tools: ToolBox,
    validate: Callable[[Path, Path, int], dict[str, Any]],
    codeql_version: str = "unknown",
    max_iterations: int = 10,
    max_tool_calls: int = 50,
) -> SynthesisResult:
    """Run the QLCoder-style outer loop with a deterministic validator."""
    if max_iterations < 1:
        raise ValueError("max_iterations must be at least 1")
    if max_tool_calls < 1:
        raise ValueError("max_tool_calls must be at least 1")

    root = Path(workdir)
    root.mkdir(parents=True, exist_ok=True)
    history: list[dict[str, Any]] = []
    previous_query = ""
    previous_feedback: dict[str, Any] | None = None

    for iteration in range(1, max_iterations + 1):
        iteration_dir = root / "iterations" / f"{iteration:03d}"
        iteration_dir.mkdir(parents=True, exist_ok=True)
        query_path = iteration_dir / f"{cve_id}-query-iter-{iteration}.ql"

        if iteration == 1:
            prompt = synthesis_initial_prompt(
                cve_id=cve_id,
                cve=cve,
                cwe_ids=cwe_ids,
                repo_path=str(repo_path),
                vulnerable_commit=vulnerable_commit,
                fix_commit=fix_commit,
                diff=diff,
                vulnerability_ir=vulnerability_ir,
                ast_snippets=ast_snippets,
                workdir=str(iteration_dir),
                codeql_version=codeql_version,
                max_tool_calls=max_tool_calls,
            )
        else:
            prompt = synthesis_repair_prompt(
                cve_id=cve_id,
                iteration=iteration,
                previous_query=previous_query,
                feedback=previous_feedback or {},
                vulnerability_ir=vulnerability_ir,
                workdir=str(iteration_dir),
                max_tool_calls=max_tool_calls,
            )

        try:
            query_text, tool_calls = _agent_query(
                llm, prompt, tools, max_tool_calls=max_tool_calls
            )
        except SynthesisProtocolError as exc:
            raw_path = iteration_dir / "agent-response.txt"
            if exc.response:
                raw_path.write_text(exc.response, encoding="utf-8", newline="\n")
            raise SynthesisError(
                f"synthesis protocol failed in iteration {iteration}: {exc}; "
                f"raw response saved to {raw_path}"
            ) from exc
        except Exception as exc:
            raise SynthesisError(
                f"synthesis protocol failed in iteration {iteration}: {exc}"
            ) from exc

        query_path.write_text(
            query_text.rstrip() + "\n", encoding="utf-8", newline="\n"
        )
        feedback = validate(query_path, iteration_dir, iteration)
        if not isinstance(feedback, dict):
            raise SynthesisError("validator must return a dictionary")
        _write_json(iteration_dir / "feedback.json", feedback)
        history.append(
            {
                "iteration": iteration,
                "query_path": str(query_path),
                "tool_calls": tool_calls,
                "verdict": feedback.get("verdict"),
            }
        )
        previous_query = query_text
        previous_feedback = feedback

        if feedback.get("verdict") == "success":
            return SynthesisResult(
                status="success",
                iterations=iteration,
                query_path=query_path,
                feedback=feedback,
                history=history,
            )

    return SynthesisResult(
        status="failed",
        iterations=max_iterations,
        query_path=query_path if 'query_path' in locals() else None,
        feedback=previous_feedback,
        history=history,
    )


def _agent_query(
    llm: LLMClient,
    prompt: str,
    tools: ToolBox,
    *,
    max_tool_calls: int,
) -> tuple[str, int]:
    conversation = prompt
    tool_calls = 0
    while True:
        response = llm.complete(_SYSTEM, conversation)
        try:
            return extract_query(response), tool_calls
        except ValueError:
            pass

        payloads = [
            payload
            for payload in extract_json_objects(response)
            if isinstance(payload, dict)
        ]
        if not payloads:
            payloads = [
                payload
                for payload in extract_dsml_tool_calls(response)
                if isinstance(payload, dict)
            ]
        if not payloads:
            payloads = [
                payload
                for payload in extract_xml_tool_calls(response)
                if isinstance(payload, dict)
            ]
        if not payloads:
            raise SynthesisProtocolError(
                "agent response contains neither a tool call nor a query", response
            )

        executed = False
        for payload in payloads:
            for key in ("final", "query", "ql"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip().strip("`"), tool_calls
            if (
                "tool" not in payload
                and isinstance(payload.get("name"), str)
                and "arguments" in payload
            ):
                payload = {
                    "tool": payload["name"],
                    "arguments": payload.get("arguments") or {},
                }
            if "tool" not in payload:
                continue
            if tool_calls >= max_tool_calls:
                raise SynthesisProtocolError(
                    f"agent exceeded the tool-call budget of {max_tool_calls}",
                    response,
                )
            tool_name = payload.get("tool")
            arguments = payload.get("arguments") or {}
            try:
                result = tools.execute(tool_name, arguments)
            except ToolError as exc:
                result = json.dumps({"error": str(exc)})
            tool_calls += 1
            executed = True
            conversation += (
                f"\n\nTOOL RESULT for {tool_name}:\n{result}\n\n"
                "Continue. Reply with another tool call or a final query "
                'as {"final": "<complete CodeQL query>"}.'
            )

        if not executed:
            raise SynthesisProtocolError(
                "agent response contains no executable tool call or final query",
                response,
            )


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(payload, output, indent=2, ensure_ascii=False)
        output.write("\n")


def _render(value: Any, max_chars: int) -> str:
    if isinstance(value, str):
        rendered = value
    else:
        try:
            rendered = json.dumps(value, indent=2, ensure_ascii=False)
        except (TypeError, ValueError):
            rendered = str(value)
    if len(rendered) > max_chars:
        rendered = rendered[:max_chars] + "\n... [truncated]"
    return rendered


def _string_arg(args: dict[str, Any], name: str, default: str | None = None) -> str:
    value = args.get(name, default)
    if not isinstance(value, str) or not value.strip():
        raise ToolError(f"{name} must be a non-empty string")
    return value


def _int_arg(args: dict[str, Any], name: str, default: int) -> int:
    value = args.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolError(f"{name} must be an integer")
    return value


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    if not root.is_dir():
        return files
    for directory, subdirectories, names in os.walk(root):
        subdirectories[:] = [
            name
            for name in subdirectories
            if name not in {".git", ".cache", "__pycache__", ".tools"}
        ]
        for name in names:
            file_path = Path(directory) / name
            try:
                if file_path.stat().st_size > 1_000_000:
                    continue
            except OSError:
                continue
            files.append(file_path)
            if len(files) >= 2000:
                return files
    return files
