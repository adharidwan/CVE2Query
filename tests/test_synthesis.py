import json
import tempfile
import unittest
from pathlib import Path

from cve2checker.llm import ScriptedLLM
from cve2checker.rag import RagIndex
from cve2checker.synthesis import (
    SynthesisError,
    ToolBox,
    ToolError,
    run_synthesis,
)

CVE = {
    "dataType": "CVE_RECORD",
    "cveMetadata": {"cveId": "CVE-2024-1234"},
    "containers": {"cna": {"descriptions": [{"lang": "en", "value": "test"}]}},
}
IR = {
    "schema_version": "1.0",
    "cve_id": "CVE-2024-1234",
    "status": "complete",
    "language": "cpp",
    "cwe_ids": ["CWE-120"],
    "root_cause": {"type": "buffer_overflow", "sink": "strcpy"},
    "components": {},
    "diff_locations": [],
    "unknowns": [],
}
QUERY = "from FunctionCall c\nwhere c.getTarget().hasName(\"strcpy\")\nselect c"


class FakeLSP:
    def __init__(self) -> None:
        self.updated = []
        self.diagnostic_paths = []

    def update_file(self, path, content):
        self.updated.append((str(path), content))
        return Path(path).as_uri()

    def diagnostics(self, path):
        self.diagnostic_paths.append(str(path))
        return [{"message": "ok"}]

    def hover(self, path, line, character):
        return {"contents": "hover"}

    def definition(self, path, line, character):
        return {"uri": "file:///definition"}

    def complete(self, path, line, character):
        return {"items": []}

    def format(self, path):
        return []


class ToolBoxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.repo = self.root / "repo"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "copy.c").write_text(
            "void copy() {\n    strcpy(dst, src);\n}\n", encoding="utf-8"
        )
        (self.repo / "README.md").write_text("test repo\n", encoding="utf-8")
        self.workdir = self.root / "work"
        self.workdir.mkdir()
        self.rag = RagIndex(self.root / "rag.sqlite")
        self.rag.add_documents(
            "examples",
            [
                {
                    "id": "q1",
                    "title": "strcpy query",
                    "text": "from FunctionCall c where c.getTarget().hasName(\"strcpy\") select c",
                    "metadata": {"cwe": "CWE-120"},
                }
            ],
        )
        self.lsp = FakeLSP()
        self.tools = ToolBox(
            repo_root=self.repo,
            workdir=self.workdir,
            rag=self.rag,
            lsp=self.lsp,
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_read_list_and_search(self) -> None:
        content = json.loads(
            self.tools.execute(
                "read_file", {"path": "src/copy.c", "start_line": 2, "end_line": 2}
            )
        )
        self.assertEqual(content["text"], "    strcpy(dst, src);")
        listing = json.loads(self.tools.execute("list_dir", {"path": "src"}))
        self.assertEqual(listing["entries"][0]["name"], "copy.c")
        matches = json.loads(
            self.tools.execute(
                "search_text", {"path": ".", "pattern": "strcpy"}
            )
        )
        self.assertEqual(matches[0]["file"], "src/copy.c")

    def test_read_file_falls_back_to_basename_for_model_paths(self) -> None:
        content = json.loads(
            self.tools.execute(
                "read_file",
                {
                    "path": "artifacts-demo/CVE/repo/src/copy.c",
                    "start_line": 2,
                    "end_line": 2,
                },
            )
        )
        self.assertEqual(content["text"], "    strcpy(dst, src);")

    def test_path_escape_is_rejected(self) -> None:
        with self.assertRaisesRegex(ToolError, "escapes"):
            self.tools.execute("read_file", {"path": "../outside.c"})

    def test_rag_and_lsp_tools(self) -> None:
        results = json.loads(
            self.tools.execute(
                "rag_search",
                {"collection": "examples", "query": "strcpy", "k": 1},
            )
        )
        self.assertEqual(results[0]["id"], "q1")
        document = json.loads(
            self.tools.execute(
                "rag_get", {"collection": "examples", "ids": ["q1"]}
            )
        )
        self.assertEqual(document[0]["metadata"]["cwe"], "CWE-120")

        updated = json.loads(
            self.tools.execute(
                "lsp_update",
                {"path": "draft.ql", "content": "from FunctionCall c select c"},
            )
        )
        self.assertEqual(updated["path"], "draft.ql")
        self.assertEqual(len(self.lsp.updated), 1)
        diagnostics = json.loads(
            self.tools.execute("lsp_diagnostics", {"path": "draft.ql"})
        )
        self.assertEqual(diagnostics[0]["message"], "ok")

    def test_list_tools(self) -> None:
        result = json.loads(self.tools.execute("harness_tools_list", {}))
        self.assertTrue(any("rag_search" in item for item in result["tools"]))

    def test_unknown_tool_is_rejected(self) -> None:
        with self.assertRaisesRegex(ToolError, "unknown tool"):
            self.tools.execute("shell", {"command": "whoami"})


class SynthesisLoopTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "copy.c").write_text("strcpy(dst, src);\n", encoding="utf-8")
        self.workdir = self.root / "artifacts"
        self.rag = RagIndex(self.root / "rag.sqlite")
        self.rag.add_documents(
            "examples",
            [{"id": "q1", "title": "strcpy", "text": QUERY}],
        )
        self.tools = ToolBox(
            repo_root=self.repo,
            workdir=self.workdir,
            rag=self.rag,
            lsp=FakeLSP(),
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _run(self, llm, validate, max_iterations=10, max_tool_calls=50):
        return run_synthesis(
            cve_id="CVE-2024-1234",
            cve=CVE,
            cwe_ids=["CWE-120"],
            repo_path=self.repo,
            vulnerable_commit="1" * 40,
            fix_commit="2" * 40,
            diff="- strcpy(dst, src);\n+ strncpy(dst, src, n);",
            vulnerability_ir=IR,
            ast_snippets=[],
            workdir=self.workdir,
            llm=llm,
            tools=self.tools,
            validate=validate,
            codeql_version="2.27.2",
            max_iterations=max_iterations,
            max_tool_calls=max_tool_calls,
        )

    def test_success_on_first_iteration(self) -> None:
        llm = ScriptedLLM([json.dumps({"final": QUERY})])
        result = self._run(llm, lambda query, directory, iteration: {"verdict": "success"})
        self.assertEqual(result.status, "success")
        self.assertEqual(result.iterations, 1)
        self.assertTrue(result.query_path.is_file())
        self.assertTrue((result.query_path.parent / "feedback.json").is_file())

    def test_tool_call_then_final_query(self) -> None:
        tool_call = json.dumps(
            {
                "tool": "rag_search",
                "arguments": {
                    "collection": "examples",
                    "query": "strcpy",
                    "k": 1,
                },
            }
        )
        llm = ScriptedLLM([tool_call, json.dumps({"final": QUERY})])
        result = self._run(llm, lambda query, directory, iteration: {"verdict": "success"})
        self.assertEqual(result.status, "success")
        self.assertEqual(result.history[0]["tool_calls"], 1)
        self.assertIn("TOOL RESULT for rag_search", llm.calls[1]["user"])

    def test_xml_tool_call_then_final_query(self) -> None:
        xml = (
            "<tool_call><function=rag_search><parameter=collection>examples"
            "</parameter><parameter=query>strcpy</parameter>"
            "<parameter=k>1</parameter></function></tool_call>"
        )
        llm = ScriptedLLM([xml, json.dumps({"final": QUERY})])
        result = self._run(
            llm, lambda query, directory, iteration: {"verdict": "success"}
        )
        self.assertEqual(result.status, "success")
        self.assertEqual(result.history[0]["tool_calls"], 1)
        self.assertIn("TOOL RESULT for rag_search", llm.calls[1]["user"])

    def test_named_tool_call_format(self) -> None:
        response = (
            "<tool_call>\n"
            '{"name": "rag_search", "arguments": {"collection": "examples", '
            '"query": "strcpy"}}\n'
            "</tool_call>"
        )
        llm = ScriptedLLM([response, json.dumps({"final": QUERY})])
        result = self._run(
            llm, lambda query, directory, iteration: {"verdict": "success"}
        )
        self.assertEqual(result.status, "success")
        self.assertEqual(result.history[0]["tool_calls"], 1)

    def test_dsml_tool_call_then_final_query(self) -> None:
        dsml = (
            "<||DSML|| calls>\n"
            '<||DSML|| invoke name="rag_search">\n'
            '<||DSML|| parameter name="collection" string="true">examples</||DSML|| parameter>\n'
            '<||DSML|| parameter name="query" string="true">strcpy</||DSML|| parameter>\n'
            '<||DSML|| parameter name="k" string="false">1</||DSML|| parameter>\n'
            "</||DSML|| invoke>\n"
            "</||DSML|| calls>"
        )
        llm = ScriptedLLM([dsml, json.dumps({"final": QUERY})])
        result = self._run(
            llm, lambda query, directory, iteration: {"verdict": "success"}
        )
        self.assertEqual(result.status, "success")
        self.assertEqual(result.history[0]["tool_calls"], 1)
        self.assertIn("TOOL RESULT for rag_search", llm.calls[1]["user"])

    def test_batched_tool_calls_are_executed(self) -> None:
        batched = (
            json.dumps(
                {
                    "tool": "rag_search",
                    "arguments": {"collection": "examples", "query": "strcpy"},
                }
            )
            + "\n"
            + json.dumps(
                {
                    "tool": "read_file",
                    "arguments": {"path": "copy.c"},
                }
            )
        )
        llm = ScriptedLLM([batched, json.dumps({"final": QUERY})])
        result = self._run(
            llm, lambda query, directory, iteration: {"verdict": "success"}
        )
        self.assertEqual(result.status, "success")
        self.assertEqual(result.history[0]["tool_calls"], 2)
        self.assertEqual(llm.calls[1]["user"].count("TOOL RESULT"), 2)

    def test_repair_after_detection_failure(self) -> None:
        llm = ScriptedLLM(
            [json.dumps({"final": QUERY}), json.dumps({"final": QUERY + "\n// v2"})]
        )
        verdicts = iter([{"verdict": "detection_failed"}, {"verdict": "success"}])
        result = self._run(
            llm, lambda query, directory, iteration: next(verdicts)
        )
        self.assertEqual(result.status, "success")
        self.assertEqual(result.iterations, 2)
        self.assertIn("detection_failed", llm.calls[1]["user"])

    def test_budget_exhaustion_returns_failed(self) -> None:
        llm = ScriptedLLM(
            [json.dumps({"final": QUERY}), json.dumps({"final": QUERY})]
        )
        result = self._run(
            llm,
            lambda query, directory, iteration: {"verdict": "detection_failed"},
            max_iterations=2,
        )
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.iterations, 2)
        self.assertEqual(len(result.history), 2)

    def test_invalid_agent_response_raises_and_saves_raw_response(self) -> None:
        llm = ScriptedLLM(["no query here"])
        with self.assertRaises(SynthesisError):
            self._run(llm, lambda query, directory, iteration: {"verdict": "success"})
        raw = self.workdir / "iterations" / "001" / "agent-response.txt"
        self.assertTrue(raw.is_file())
        self.assertEqual(raw.read_text(encoding="utf-8"), "no query here")

    def test_tool_error_is_fed_back_to_the_agent(self) -> None:
        tool_call = json.dumps(
            {"tool": "shell", "arguments": {"command": "whoami"}}
        )
        llm = ScriptedLLM([tool_call, json.dumps({"final": QUERY})])
        result = self._run(
            llm, lambda query, directory, iteration: {"verdict": "success"}
        )
        self.assertEqual(result.status, "success")
        self.assertIn("unknown tool", llm.calls[1]["user"])

    def test_tool_budget_is_enforced(self) -> None:
        tool_call = json.dumps(
            {
                "tool": "rag_search",
                "arguments": {"collection": "examples", "query": "strcpy"},
            }
        )
        llm = ScriptedLLM([tool_call, tool_call])
        with self.assertRaisesRegex(SynthesisError, "tool-call budget"):
            self._run(
                llm,
                lambda query, directory, iteration: {"verdict": "success"},
                max_tool_calls=1,
            )


if __name__ == "__main__":
    unittest.main()
