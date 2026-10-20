import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cve2checker.cli import main
from cve2checker.cve import (
    CVEError,
    build_vulnerability_spec,
    parse_record,
    validate_cve_id,
)


CVE_ID = "CVE-2024-1234"
SAMPLE_RECORD = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {"cveId": CVE_ID, "state": "PUBLISHED"},
    "containers": {
        "cna": {
            "descriptions": [
                {"lang": "fr", "value": "Description francaise."},
                {"lang": "en", "value": "A test vulnerability description."},
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {"lang": "en", "cweId": "CWE-79", "description": "XSS"}
                    ]
                }
            ],
            "affected": [
                {
                    "vendor": "Example Vendor",
                    "product": "Example Product",
                    "versions": [
                        {
                            "version": "1.0",
                            "status": "affected",
                            "lessThan": "2.0",
                            "versionType": "semver",
                        }
                    ],
                }
            ],
            "references": [
                {"url": "https://example.test/advisory", "tags": ["vendor-advisory"]}
            ],
        },
        "adp": [
            {
                "problemTypes": [
                    {
                        "descriptions": [
                            {"lang": "en", "cweId": "CWE-79", "description": "XSS"},
                            {"lang": "en", "cweId": "CWE-116", "description": "Encoding"},
                        ]
                    }
                ],
                "affected": [
                    {
                        "vendor": "Another Vendor",
                        "product": "Another Product",
                        "versions": [{"version": "3.x", "status": "affected"}],
                    }
                ],
                "references": [{"url": "https://example.test/patch"}],
            }
        ],
    },
}


class CVERecordTests(unittest.TestCase):
    def test_parses_record_and_builds_evidence_gated_ir(self) -> None:
        raw_json = json.dumps(SAMPLE_RECORD).encode("utf-8")
        record = parse_record(raw_json, CVE_ID)
        spec = build_vulnerability_spec(CVE_ID, record)

        self.assertEqual(spec["schema_version"], "1.0")
        self.assertEqual(spec["cve_id"], CVE_ID)
        self.assertEqual(spec["status"], "insufficient_evidence")
        self.assertEqual(spec["weakness"]["cwe_ids"], ["CWE-79", "CWE-116"])
        self.assertEqual(
            spec["evidence"]["affected"][0],
            {
                "vendor": "Example Vendor",
                "product": "Example Product",
                "versions": SAMPLE_RECORD["containers"]["cna"]["affected"][0]["versions"],
            },
        )
        self.assertEqual(len(spec["evidence"]["affected"]), 2)
        self.assertEqual(len(spec["evidence"]["references"]), 2)
        self.assertEqual(
            spec["evidence"]["description"], "A test vulnerability description."
        )
        self.assertEqual(spec["root_cause"]["evidence"], [])
        self.assertEqual(spec["detection"]["query_language"], "CodeQL")
        self.assertEqual(spec["generation_gate"]["decision"], "blocked")
        self.assertIn("CVE metadata alone", spec["generation_gate"]["reasons"][0])

    def test_parse_rejects_mismatched_record_id(self) -> None:
        with self.assertRaisesRegex(CVEError, "does not match requested ID"):
            parse_record(json.dumps(SAMPLE_RECORD), "CVE-2024-5678")

    def test_parse_rejects_invalid_json(self) -> None:
        with self.assertRaisesRegex(CVEError, "not valid JSON"):
            parse_record(b"not json")

    def test_rejects_invalid_cve_ids(self) -> None:
        invalid_ids = (
            "CVE-2024-123",
            "CVE-24-1234",
            "cve-2024-1234",
            "CVE-2024-12A4",
            "CVE-２０２４-１２３４",
        )
        for cve_id in invalid_ids:
            with self.subTest(cve_id=cve_id), self.assertRaises(CVEError):
                validate_cve_id(cve_id)

    def test_cli_rejects_invalid_id_without_fetching(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            stderr = StringIO()
            with patch("cve2checker.cli.fetch_record") as fetch_record:
                with redirect_stderr(stderr):
                    result = main(
                        [
                            "add",
                            "bad-id",
                            "--output-dir",
                            str(root / "patterns"),
                            "--cache-dir",
                            str(root / "cache"),
                        ]
                    )

            self.assertEqual(result, 2)
            self.assertIn("invalid CVE ID", stderr.getvalue())
            fetch_record.assert_not_called()
            self.assertFalse((root / "patterns").exists())
            self.assertFalse((root / "cache").exists())

    def test_cli_uses_local_cache_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            output_directory = root / "patterns"
            cache_directory = root / "cache"
            cache_directory.mkdir()
            raw_json = json.dumps(SAMPLE_RECORD).encode("utf-8")
            (cache_directory / f"{CVE_ID}.json").write_bytes(raw_json)

            stdout = StringIO()
            with patch("cve2checker.cli.fetch_record") as fetch_record:
                with redirect_stdout(stdout):
                    result = main(
                        [
                            "add",
                            CVE_ID,
                            "--output-dir",
                            str(output_directory),
                            "--cache-dir",
                            str(cache_directory),
                        ]
                    )

            self.assertEqual(result, 0, stdout.getvalue())
            fetch_record.assert_not_called()
            self.assertEqual(
                (cache_directory / f"{CVE_ID}.json").read_bytes(), raw_json
            )
            artifact_dir = output_directory / CVE_ID
            spec = json.loads(
                (artifact_dir / "vulnerability_spec.json").read_text(encoding="utf-8")
            )
            self.assertEqual(spec["status"], "insufficient_evidence")
            self.assertEqual(
                (artifact_dir / "cve_record.json").read_bytes(), raw_json
            )


if __name__ == "__main__":
    unittest.main()
