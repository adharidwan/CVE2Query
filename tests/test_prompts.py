import unittest

from cve2checker.prompts import (
    compact_json,
    extract_dsml_tool_calls,
    extract_json,
    extract_json_objects,
    extract_query,
    extract_xml_tool_calls,
    extract_query_path,
    feasibility_prompt,
    global_contract,
    root_cause_prompt,
    synthesis_initial_prompt,
    synthesis_repair_prompt,
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
    "root_cause": {},
    "components": {},
    "diff_locations": [],
    "unknowns": [],
}


class PromptContentTests(unittest.TestCase):
    def test_global_contract_contains_evidence_rules(self) -> None:
        contract = global_contract("the analyst")
        self.assertIn("Evidence over plausibility", contract)
        self.assertIn("Do not use shell, network", contract)
        self.assertIn("the analyst", contract)

    def test_feasibility_prompt_contains_rubric_and_json(self) -> None:
        prompt = feasibility_prompt(CVE, {"fix_commit": "a" * 40}, {"files": 1})
        self.assertIn("RUBRIC", prompt)
        self.assertIn("Return only JSON", prompt)
        self.assertIn("CWE-22", prompt)

    def test_root_cause_prompt_contains_diff_rules(self) -> None:
        prompt = root_cause_prompt(CVE, "- strcpy(dst, src);\n+ strncpy(dst, src, n);", [])
        self.assertIn("REMOVED (-)", prompt)
        self.assertIn("start_line", prompt)
        self.assertIn("```diff", prompt)

    def test_synthesis_initial_prompt_contains_success_and_tools(self) -> None:
        prompt = synthesis_initial_prompt(
            cve_id="CVE-2024-1234",
            cve=CVE,
            cwe_ids=["CWE-120"],
            repo_path="/repo",
            vulnerable_commit="1" * 40,
            fix_commit="2" * 40,
            diff="- strcpy(dst, src);\n+ strncpy(dst, src, n);",
            vulnerability_ir=IR,
            ast_snippets=[],
            workdir="/artifacts/CVE-2024-1234",
            codeql_version="2.27.2",
        )
        self.assertIn("Success predicate", prompt)
        self.assertIn("rag_search", prompt)
        self.assertIn("lsp_diagnostics", prompt)
        self.assertIn('"final"', prompt)
        self.assertIn("cve2checker/CVE-2024-1234", prompt)

    def test_repair_prompt_contains_feedback_and_priority(self) -> None:
        prompt = synthesis_repair_prompt(
            cve_id="CVE-2024-1234",
            iteration=2,
            previous_query="from FunctionCall c select c",
            feedback={"verdict": "detection_failed"},
            vulnerability_ir=IR,
            workdir="/artifacts/CVE-2024-1234",
        )
        self.assertIn("Validator feedback", prompt)
        self.assertIn("detection_failed", prompt)
        self.assertIn("Fix compilation errors first", prompt)


class ResponseExtractionTests(unittest.TestCase):
    def test_extract_json_direct_fenced_and_prose(self) -> None:
        self.assertEqual(extract_json('{"a": 1}'), {"a": 1})
        self.assertEqual(extract_json('```json\n{"a": 1}\n```'), {"a": 1})
        self.assertEqual(
            extract_json('Here is the answer:\n{"a": {"b": "}"}}\nDone'),
            {"a": {"b": "}"}},
        )

    def test_extract_json_rejects_no_json(self) -> None:
        with self.assertRaises(ValueError):
            extract_json("no object here")

    def test_extract_dsml_tool_calls(self) -> None:
        text = (
            "<||DSML|| calls>\n"
            '<||DSML|| invoke name="read_file">\n'
            '<||DSML|| parameter name="path" string="true">inflate.c</||DSML|| parameter>\n'
            '<||DSML|| parameter name="start_line" string="false">700</||DSML|| parameter>\n'
            "</||DSML|| invoke>\n"
            "</||DSML|| calls>"
        )
        calls = extract_dsml_tool_calls(text)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["tool"], "read_file")
        self.assertEqual(calls[0]["arguments"]["path"], "inflate.c")
        self.assertEqual(calls[0]["arguments"]["start_line"], 700)

    def test_extract_dsml_with_fullwidth_bars(self) -> None:
        text = (
            "<\uff5c\uff5cDSML\uff5c\uff5c calls>\n"
            '<\uff5c\uff5cDSML\uff5c\uff5c invoke name="rag_search">\n'
            '<\uff5c\uff5cDSML\uff5c\uff5c parameter name="collection" string="true">examples</\uff5c\uff5cDSML\uff5c\uff5c parameter>\n'
            "</\uff5c\uff5cDSML\uff5c\uff5c invoke>\n"
            "</\uff5c\uff5cDSML\uff5c\uff5c calls>"
        )
        calls = extract_dsml_tool_calls(text)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["tool"], "rag_search")

    def test_extract_xml_tool_calls(self) -> None:
        text = (
            "<tool_call><function=list_dir><parameter=path>.</parameter>"
            "</function></tool_call>\n"
            "<tool_call><function=rag_search><parameter=collection>cve_notes"
            "</parameter><parameter=query>zlib inflate</parameter>"
            "<parameter=k>5</parameter></function></tool_call>"
        )
        calls = extract_xml_tool_calls(text)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]["tool"], "list_dir")
        self.assertEqual(calls[1]["arguments"]["k"], 5)

    def test_extract_json_objects_handles_batched_tool_calls(self) -> None:
        text = (
            '{"tool": "read_file", "arguments": {"path": "a.c"}}\n'
            '{"tool": "rag_search", "arguments": {"collection": "x"}}\n'
        )
        objects = extract_json_objects(text)
        self.assertEqual(len(objects), 2)
        self.assertEqual(objects[0]["tool"], "read_file")
        self.assertEqual(objects[1]["tool"], "rag_search")

    def test_extract_query_from_json_fenced_and_raw(self) -> None:
        self.assertEqual(
            extract_query('{"final": "from FunctionCall c select c"}'),
            "from FunctionCall c select c",
        )
        self.assertEqual(
            extract_query(
                "```ql\n/** @kind problem */\nfrom FunctionCall c\nselect c\n```"
            ),
            "/** @kind problem */\nfrom FunctionCall c\nselect c",
        )
        self.assertEqual(
            extract_query("from FunctionCall c\nselect c\n"),
            "from FunctionCall c\nselect c",
        )

    def test_extract_query_rejects_tool_call(self) -> None:
        with self.assertRaisesRegex(ValueError, "tool call"):
            extract_query('{"tool": "rag_search", "arguments": {}}')

    def test_extract_query_path_and_compact_json(self) -> None:
        self.assertEqual(
            extract_query_path("QUERY_FILE_PATH: artifacts/CVE.ql"),
            "artifacts/CVE.ql",
        )
        self.assertIsNone(extract_query_path("no path"))
        self.assertIn("truncated", compact_json("x" * 100, max_chars=10))


if __name__ == "__main__":
    unittest.main()
