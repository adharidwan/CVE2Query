import copy
import json
import tempfile
import unittest
from pathlib import Path

from cve2checker.agents import (
    AgentError,
    run_feasibility,
    run_root_cause,
    write_json_artifact,
)
from cve2checker.llm import ScriptedLLM

CVE = {
    "dataType": "CVE_RECORD",
    "cveMetadata": {"cveId": "CVE-2024-1234"},
    "containers": {"cna": {"descriptions": [{"lang": "en", "value": "test"}]}},
}

SOURCE = {"fix_commit": "a" * 40, "diff_stats": {"files": 1}}

FEASIBILITY = {
    "decision": "proceed",
    "confidence": 0.8,
    "language": "cpp",
    "cwe_ids": ["CWE-120"],
    "modeling": "unsafe_call",
    "source_candidates": [{"kind": "argv", "evidence": "src/main.c:10"}],
    "sink_candidates": [{"kind": "strcpy", "evidence": "src/copy.c:3"}],
    "sanitizer_candidates": [],
    "missing_evidence": [],
    "reasons": ["source is available"],
    "recommended_next_action": "synthesize",
}

CITATION = {
    "description": "copy",
    "file": "src/copy.c",
    "start_line": 2,
    "end_line": 2,
    "commit": "a" * 40,
    "snippet": "strcpy(dst, src);",
    "confidence": 0.8,
}

IR = {
    "schema_version": "1.0",
    "cve_id": "CVE-2024-1234",
    "status": "complete",
    "language": "cpp",
    "cwe_ids": ["CWE-120"],
    "root_cause": {
        "type": "buffer_overflow",
        "sink": "strcpy",
        "unsafe_condition": "unbounded copy",
        "preconditions": [],
    },
    "components": {
        "sources": [copy.deepcopy(CITATION)],
        "sinks": [copy.deepcopy(CITATION)],
        "sanitizers": [],
        "additional_taint_steps": [],
    },
    "diff_locations": [
        {
            "file": "src/copy.c",
            "start_line": 1,
            "end_line": 3,
            "commit": "a" * 40,
            "snippet": "strncpy(dst, src, n);",
        }
    ],
    "unknowns": [],
    "analysis_notes": "",
}


class FeasibilityAgentTests(unittest.TestCase):
    def test_returns_valid_json(self) -> None:
        llm = ScriptedLLM([json.dumps(FEASIBILITY)])
        result = run_feasibility(CVE, SOURCE, {"files": 1}, llm)
        self.assertEqual(result["decision"], "proceed")
        self.assertEqual(len(llm.calls), 1)

    def test_accepts_fenced_json(self) -> None:
        llm = ScriptedLLM(["```json\n" + json.dumps(FEASIBILITY) + "\n```"])
        result = run_feasibility(CVE, SOURCE, {"files": 1}, llm)
        self.assertEqual(result["sink_candidates"][0]["kind"], "strcpy")

    def test_retries_after_schema_failure(self) -> None:
        invalid = json.dumps({"decision": "maybe"})
        llm = ScriptedLLM([invalid, json.dumps(FEASIBILITY)])
        result = run_feasibility(CVE, SOURCE, {"files": 1}, llm, max_attempts=2)
        self.assertEqual(result["decision"], "proceed")
        self.assertEqual(len(llm.calls), 2)
        self.assertIn("CORRECTION REQUIRED", llm.calls[1]["user"])
        self.assertIn("rejected", llm.calls[1]["user"])

    def test_exhausts_attempts_and_raises(self) -> None:
        llm = ScriptedLLM(["not json", "still not json"])
        with self.assertRaises(AgentError):
            run_feasibility(CVE, SOURCE, {"files": 1}, llm, max_attempts=2)
        self.assertEqual(len(llm.calls), 2)


class RootCauseAgentTests(unittest.TestCase):
    def test_returns_cited_ir(self) -> None:
        llm = ScriptedLLM([json.dumps(IR)])
        result = run_root_cause(CVE, "- strcpy\n+ strncpy", [CITATION], llm)
        self.assertEqual(result["components"]["sinks"][0]["file"], "src/copy.c")

    def test_missing_citation_triggers_retry(self) -> None:
        invalid = copy.deepcopy(IR)
        invalid["components"]["sinks"][0]["snippet"] = ""
        llm = ScriptedLLM([json.dumps(invalid), json.dumps(IR)])
        result = run_root_cause(CVE, "- strcpy\n+ strncpy", [CITATION], llm)
        self.assertEqual(result["cve_id"], "CVE-2024-1234")
        self.assertEqual(len(llm.calls), 2)
        self.assertIn("snippet", llm.calls[1]["user"])

    def test_citation_commit_must_match_evidence(self) -> None:
        wrong = copy.deepcopy(IR)
        for item in wrong["components"]["sources"]:
            item["commit"] = "b" * 40
        for item in wrong["components"]["sinks"]:
            item["commit"] = "b" * 40
        for item in wrong["diff_locations"]:
            item["commit"] = "b" * 40
        llm = ScriptedLLM([json.dumps(wrong), json.dumps(IR)])
        result = run_root_cause(
            CVE,
            "- strcpy\n+ strncpy",
            [CITATION],
            llm,
            vulnerable_commit="c" * 40,
            fix_commit="a" * 40,
        )
        self.assertEqual(result["cve_id"], "CVE-2024-1234")
        self.assertEqual(len(llm.calls), 2)
        self.assertIn("evidence commits", llm.calls[1]["user"])

    def test_cve_mismatch_is_rejected(self) -> None:
        wrong = copy.deepcopy(IR)
        wrong["cve_id"] = "CVE-2024-9999"
        llm = ScriptedLLM([json.dumps(wrong)])
        with self.assertRaisesRegex(AgentError, "expected 'CVE-2024-1234'"):
            run_root_cause(CVE, "- a\n+ b", [], llm)

    def test_write_json_artifact_creates_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "result.json"
            written = write_json_artifact(path, {"ok": True})
            self.assertEqual(written, path)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"ok": True})


if __name__ == "__main__":
    unittest.main()
