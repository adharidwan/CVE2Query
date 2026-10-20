import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cve2checker.codeql import CodeQLError
from cve2checker.diff import ChangedRange
from cve2checker.validator import ValidationError, validate_query


def sarif_document(path: str, line: int) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "cve2checker/test",
                        "message": {"text": "test alert"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": path},
                                    "region": {
                                        "startLine": line,
                                        "endLine": line,
                                    },
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }


class ValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.query = self.root / "query.ql"
        self.query.write_text("select 1\n", encoding="utf-8")
        self.workdir = self.root / "iteration"
        self.changed = [ChangedRange("src/copy.c", 2, 4, "new")]
        self.vulnerable = sarif_document("src/copy.c", 3)
        self.fixed = {"version": "2.1.0", "runs": [{"results": []}]}

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _run(self, vulnerable=None, fixed=None):
        vulnerable = self.vulnerable if vulnerable is None else vulnerable
        fixed = self.fixed if fixed is None else fixed

        def fake_analyze(database, query, output, *, codeql_path="codeql"):
            target = Path(output)
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = vulnerable if "vulnerable" in str(database) else fixed
            target.write_text(json.dumps(payload), encoding="utf-8")

        with patch("cve2checker.validator.compile_query"), patch(
            "cve2checker.validator.analyze_query", side_effect=fake_analyze
        ):
            return validate_query(
                self.query,
                "db-vulnerable",
                "db-fixed",
                self.changed,
                self.workdir,
            )

    def test_success_requires_vulnerable_hit_and_no_fixed_hit(self) -> None:
        feedback = self._run()
        self.assertEqual(feedback["verdict"], "success")
        self.assertEqual(feedback["vulnerable"]["diff_intersection_count"], 1)
        self.assertEqual(feedback["fixed"]["diff_intersection_count"], 0)
        self.assertEqual(feedback["metrics"]["recall"], True)
        self.assertTrue((self.workdir / "feedback.json").is_file())

    def test_no_vulnerable_intersection_is_detection_failure(self) -> None:
        feedback = self._run(vulnerable=sarif_document("src/copy.c", 10))
        self.assertEqual(feedback["verdict"], "detection_failed")
        self.assertTrue(feedback["next_actions"])

    def test_fixed_intersection_is_discrimination_failure(self) -> None:
        feedback = self._run(fixed=sarif_document("src/copy.c", 3))
        self.assertEqual(feedback["verdict"], "discrimination_failed")

    def test_compile_failure(self) -> None:
        with patch(
            "cve2checker.validator.compile_query",
            side_effect=CodeQLError("bad predicate"),
        ):
            feedback = validate_query(
                self.query, "v", "f", self.changed, self.workdir
            )
        self.assertEqual(feedback["verdict"], "compile_failed")
        self.assertIn("bad predicate", feedback["compile"]["errors"][0]["message"])

    def test_analysis_failure(self) -> None:
        with patch("cve2checker.validator.compile_query"), patch(
            "cve2checker.validator.analyze_query",
            side_effect=CodeQLError("database missing"),
        ):
            feedback = validate_query(
                self.query, "v", "f", self.changed, self.workdir
            )
        self.assertEqual(feedback["verdict"], "analysis_failed")

    def test_invalid_sarif_is_analysis_failure(self) -> None:
        def fake_analyze(database, query, output, *, codeql_path="codeql"):
            Path(output).write_text("not json", encoding="utf-8")

        with patch("cve2checker.validator.compile_query"), patch(
            "cve2checker.validator.analyze_query", side_effect=fake_analyze
        ):
            feedback = validate_query(
                self.query, "v", "f", self.changed, self.workdir
            )
        self.assertEqual(feedback["verdict"], "analysis_failed")
        self.assertIn("SARIF", feedback["error"])

    def test_suffix_path_matching(self) -> None:
        feedback = self._run(
            vulnerable=sarif_document("D:/repo/src/copy.c", 3)
        )
        self.assertEqual(feedback["verdict"], "success")

    def test_requires_query_and_changed_ranges(self) -> None:
        with self.assertRaises(ValidationError):
            validate_query(
                self.root / "missing.ql", "v", "f", self.changed, self.workdir
            )
        with self.assertRaises(ValidationError):
            validate_query(self.query, "v", "f", [], self.workdir)


if __name__ == "__main__":
    unittest.main()
