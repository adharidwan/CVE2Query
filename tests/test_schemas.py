import copy
import unittest

from cve2checker.schemas import (
    SchemaError,
    citation_errors,
    validate_feasibility,
    validate_ir,
)

FEASIBILITY = {
    "decision": "proceed",
    "confidence": 0.9,
    "language": "cpp",
    "cwe_ids": ["CWE-120"],
    "modeling": "unsafe_call",
    "source_candidates": [{"kind": "request body", "evidence": "src/main.c:10"}],
    "sink_candidates": [{"kind": "strcpy", "evidence": "src/copy.c:3"}],
    "sanitizer_candidates": [],
    "missing_evidence": [],
    "reasons": ["source and fix commit are available"],
    "recommended_next_action": "generate a query",
}

CITATION = {
    "description": "copy destination",
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
        "unsafe_condition": "copy size is unbounded",
        "preconditions": ["src is attacker controlled"],
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
            "start_line": 2,
            "end_line": 4,
            "commit": "a" * 40,
            "snippet": "strncpy(dst, src, size - 1);",
        }
    ],
    "unknowns": [],
    "analysis_notes": "",
}


class FeasibilitySchemaTests(unittest.TestCase):
    def test_accepts_valid_proceed_response(self) -> None:
        payload = copy.deepcopy(FEASIBILITY)
        self.assertIs(validate_feasibility(payload), payload)

    def test_rejects_invalid_decision_and_confidence(self) -> None:
        payload = copy.deepcopy(FEASIBILITY)
        payload["decision"] = "maybe"
        payload["confidence"] = 1.5
        with self.assertRaisesRegex(SchemaError, "decision"):
            validate_feasibility(payload)

    def test_proceed_requires_sink_and_taint_source(self) -> None:
        payload = copy.deepcopy(FEASIBILITY)
        payload["sink_candidates"] = []
        payload["modeling"] = "taint"
        payload["source_candidates"] = []
        with self.assertRaises(SchemaError) as raised:
            validate_feasibility(payload)
        self.assertIn("sink candidate", str(raised.exception))
        self.assertIn("source candidate", str(raised.exception))

    def test_blocked_decision_requires_reason(self) -> None:
        payload = copy.deepcopy(FEASIBILITY)
        payload["decision"] = "insufficient_evidence"
        payload["reasons"] = []
        with self.assertRaisesRegex(SchemaError, "requires at least one reason"):
            validate_feasibility(payload)

    def test_rejects_non_object(self) -> None:
        with self.assertRaises(SchemaError):
            validate_feasibility([])


class IRSchemaTests(unittest.TestCase):
    def test_accepts_valid_complete_ir(self) -> None:
        payload = copy.deepcopy(IR)
        self.assertIs(validate_ir(payload), payload)

    def test_citation_errors_are_reported(self) -> None:
        payload = copy.deepcopy(IR)
        payload["components"]["sinks"][0]["snippet"] = ""
        errors = citation_errors(payload)
        self.assertTrue(any("snippet" in error for error in errors))
        with self.assertRaisesRegex(SchemaError, "snippet"):
            validate_ir(payload)

    def test_complete_ir_needs_sink_and_diff_location(self) -> None:
        payload = copy.deepcopy(IR)
        payload["components"]["sinks"] = []
        payload["diff_locations"] = []
        with self.assertRaises(SchemaError) as raised:
            validate_ir(payload)
        message = str(raised.exception)
        self.assertIn("at least one cited sink", message)
        self.assertIn("at least one diff location", message)

    def test_insufficient_ir_can_have_empty_components(self) -> None:
        payload = copy.deepcopy(IR)
        payload["status"] = "insufficient_evidence"
        payload["components"] = {
            "sources": [],
            "sinks": [],
            "sanitizers": [],
            "additional_taint_steps": [],
        }
        payload["diff_locations"] = []
        self.assertIs(validate_ir(payload), payload)

    def test_rejects_invalid_cve_and_lines(self) -> None:
        payload = copy.deepcopy(IR)
        payload["cve_id"] = "not-a-cve"
        payload["components"]["sinks"][0]["start_line"] = 0
        payload["components"]["sinks"][0]["end_line"] = -1
        with self.assertRaises(SchemaError) as raised:
            validate_ir(payload)
        message = str(raised.exception)
        self.assertIn("cve_id", message)
        self.assertIn("start_line", message)


if __name__ == "__main__":
    unittest.main()
