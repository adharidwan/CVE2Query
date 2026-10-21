import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cve2checker.report import sha256_file, write_run_report


class ReportTests(unittest.TestCase):
    def test_writes_manifest_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            query = root / "query.ql"
            query.write_text("from FunctionCall c select c\n", encoding="utf-8")
            manifest_path, report_path = write_run_report(
                root,
                cve_id="CVE-2024-1234",
                status="success",
                stages={"evidence": {"status": "completed"}},
                artifacts={"query": query, "missing": root / "missing.json"},
                metadata={
                    "repo": "https://github.com/acme/widget",
                    "fix_commit": "a" * 40,
                    "model": "test-model",
                },
                summary={"verdict": "success", "precision": 1.0},
            )

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["cve_id"], "CVE-2024-1234")
            self.assertEqual(manifest["artifacts"]["query"]["sha256"], sha256_file(query))
            self.assertFalse(manifest["artifacts"]["missing"]["exists"])
            report = report_path.read_text(encoding="utf-8")
            self.assertIn("CVE2Query report: CVE-2024-1234", report)
            self.assertIn("evidence", report)
            self.assertIn("precision", report)

    def test_sha256_file_matches_hashlib(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.bin"
            path.write_bytes(b"abc")
            self.assertEqual(
                sha256_file(path), hashlib.sha256(b"abc").hexdigest()
            )


if __name__ == "__main__":
    unittest.main()
