import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from cve2checker.cli import main
from cve2checker.llm import ScriptedLLM
from cve2checker.synthesis import SynthesisResult

CVE_ID = "CVE-2024-1234"


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def make_repo(root: Path) -> tuple[Path, str]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init")
    (repo / "copy.c").write_text("void f(void) { strcpy(dst, src); }\n", encoding="utf-8")
    git(repo, "add", ".")
    git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "vulnerable",
    )
    (repo / "copy.c").write_text("void f(void) { strncpy(dst, src, n); }\n", encoding="utf-8")
    git(repo, "add", ".")
    git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        "fix",
    )
    return repo, git(repo, "rev-parse", "HEAD")


def cve_record(fix_commit: str) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {"cveId": CVE_ID, "state": "PUBLISHED"},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "test"}],
                "references": [
                    {
                        "url": f"https://github.com/acme/widget/commit/{fix_commit}"
                    }
                ],
            }
        },
    }


class CliPhaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_config_set_key_and_show_without_leaking_secret(self) -> None:
        env_path = self.root / ".env"
        stdout = StringIO()
        with patch(
            "cve2checker.cli.project_env_paths", return_value=[env_path]
        ), patch(
            "cve2checker.cli.getpass.getpass", return_value="test-secret-key"
        ):
            with redirect_stdout(stdout):
                result = main(["config", "set-key"])
        self.assertEqual(result, 0, stdout.getvalue())
        self.assertNotIn("test-secret-key", stdout.getvalue())
        self.assertIn("OPENCODE_API_KEY=test-secret-key", env_path.read_text(encoding="utf-8"))

        environment = {
            "CVE2CHECKER_LLM_BASE_URL": "https://example.test/v1",
            "CVE2CHECKER_LLM_MODEL": "test-model",
            "OPENCODE_API_KEY": "test-secret-key",
        }
        stdout = StringIO()
        with patch.dict(os.environ, environment, clear=False):
            with redirect_stdout(stdout):
                result = main(["config", "show"])
        self.assertEqual(result, 0)
        self.assertIn("key_present: True", stdout.getvalue())
        self.assertIn("test-model", stdout.getvalue())
        self.assertNotIn("test-secret-key", stdout.getvalue())

    def test_rag_index_and_search_commands(self) -> None:
        source = self.root / "source"
        source.mkdir()
        (source / "example.qll").write_text(
            "class Source extends DataFlow::Node {}\n", encoding="utf-8"
        )
        database = self.root / "rag.sqlite"

        stdout = StringIO()
        with redirect_stdout(stdout):
            result = main(
                [
                    "rag",
                    "index",
                    "--db",
                    str(database),
                    "--collection",
                    "examples",
                    "--source",
                    str(source),
                ]
            )
        self.assertEqual(result, 0, stdout.getvalue())
        self.assertIn("Indexed 1 document chunk", stdout.getvalue())

        stdout = StringIO()
        with redirect_stdout(stdout):
            result = main(
                [
                    "rag",
                    "search",
                    "DataFlow",
                    "--db",
                    str(database),
                    "--collection",
                    "examples",
                ]
            )
        self.assertEqual(result, 0)
        documents = json.loads(stdout.getvalue())
        self.assertEqual(documents[0]["id"], "example.qll#chunk-1")

    def test_evidence_command_with_local_repository(self) -> None:
        repo, fix_commit = make_repo(self.root)
        cve_file = self.root / "cve.json"
        cve_file.write_text(json.dumps(cve_record(fix_commit)), encoding="utf-8")
        output = self.root / "artifacts"

        stdout = StringIO()
        with redirect_stdout(stdout):
            result = main(
                [
                    "evidence",
                    "--cve-id",
                    CVE_ID,
                    "--cve-file",
                    str(cve_file),
                    "--repo-path",
                    str(repo),
                    "--fix-commit",
                    fix_commit,
                    "--output-dir",
                    str(output),
                ]
            )
        self.assertEqual(result, 0, stdout.getvalue())
        self.assertTrue((output / CVE_ID / "source.json").is_file())
        self.assertTrue((output / CVE_ID / "diff.patch").is_file())

    def test_validate_command_uses_diff_and_exit_code(self) -> None:
        diff = self.root / "fix.diff"
        diff.write_text(
            "diff --git a/copy.c b/copy.c\n"
            "--- a/copy.c\n"
            "+++ b/copy.c\n"
            "@@ -1 +1 @@\n"
            "-void f(void) { strcpy(dst, src); }\n"
            "+void f(void) { strncpy(dst, src, n); }\n",
            encoding="utf-8",
        )
        query = self.root / "query.ql"
        query.write_text("select 1\n", encoding="utf-8")
        feedback = {
            "verdict": "success",
            "vulnerable": {"match_count": 1, "diff_intersection_count": 1},
            "fixed": {"match_count": 0, "diff_intersection_count": 0},
        }

        stdout = StringIO()
        with patch("cve2checker.cli.validate_query", return_value=feedback):
            with redirect_stdout(stdout):
                result = main(
                    [
                        "validate",
                        "--query",
                        str(query),
                        "--vuln-db",
                        "vuln-db",
                        "--fixed-db",
                        "fixed-db",
                        "--diff",
                        str(diff),
                        "--output-dir",
                        str(self.root / "validation"),
                    ]
                )
        self.assertEqual(result, 0, stdout.getvalue())
        self.assertIn("Verdict: success", stdout.getvalue())

        failed = {**feedback, "verdict": "detection_failed"}
        with patch("cve2checker.cli.validate_query", return_value=failed):
            with redirect_stdout(StringIO()):
                result = main(
                    [
                        "validate",
                        "--query",
                        str(query),
                        "--vuln-db",
                        "vuln-db",
                        "--fixed-db",
                        "fixed-db",
                        "--diff",
                        str(diff),
                        "--output-dir",
                        str(self.root / "validation"),
                    ]
                )
        self.assertEqual(result, 1)

    def test_database_create_passes_build_mode(self) -> None:
        with patch("cve2checker.cli.create_cpp_database") as create:
            result = main(
                [
                    "database",
                    "create",
                    "--source-root",
                    "src",
                    "--database",
                    "db",
                    "--build-mode",
                    "none",
                ]
            )
        self.assertEqual(result, 0)
        self.assertEqual(create.call_args.kwargs["build_mode"], "none")

    def test_analyze_command_writes_feasibility_and_ir(self) -> None:
        repo, fix_commit = make_repo(self.root)
        cve_file = self.root / "cve.json"
        cve_file.write_text(json.dumps(cve_record(fix_commit)), encoding="utf-8")
        diff = self.root / "fix.diff"
        diff.write_text(
            "diff --git a/copy.c b/copy.c\n"
            "--- a/copy.c\n"
            "+++ b/copy.c\n"
            "@@ -1 +1 @@\n"
            "-strcpy(dst, src);\n"
            "+strncpy(dst, src, n);\n",
            encoding="utf-8",
        )
        context = self.root / "context.json"
        context.write_text(
            json.dumps(
                {
                    "snippets": [
                        {
                            "file": "copy.c",
                            "start_line": 1,
                            "end_line": 1,
                            "text": "strcpy(dst, src);",
                            "kind": "hunk",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        source_json = self.root / "source.json"
        source_json.write_text(
            json.dumps(
                {
                    "artifact_dir": str(self.root / "analysis"),
                    "diff_stats": {"files": 1},
                    "diff_path": str(diff),
                    "context_path": str(context),
                }
            ),
            encoding="utf-8",
        )
        feasibility = {
            "decision": "proceed",
            "confidence": 0.8,
            "language": "cpp",
            "cwe_ids": ["CWE-120"],
            "modeling": "unsafe_call",
            "source_candidates": [{"kind": "argv", "evidence": "copy.c:1"}],
            "sink_candidates": [{"kind": "strcpy", "evidence": "copy.c:1"}],
            "sanitizer_candidates": [],
            "missing_evidence": [],
            "reasons": ["source available"],
            "recommended_next_action": "synthesize",
        }
        citation = {
            "description": "copy",
            "file": "copy.c",
            "start_line": 1,
            "end_line": 1,
            "commit": fix_commit,
            "snippet": "strcpy(dst, src);",
            "confidence": 0.8,
        }
        vulnerability_ir = {
            "schema_version": "1.0",
            "cve_id": CVE_ID,
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
                "sources": [citation],
                "sinks": [citation],
                "sanitizers": [],
                "additional_taint_steps": [],
            },
            "diff_locations": [
                {
                    "file": "copy.c",
                    "start_line": 1,
                    "end_line": 1,
                    "commit": fix_commit,
                    "snippet": "strncpy(dst, src, n);",
                }
            ],
            "unknowns": [],
            "analysis_notes": "",
        }
        llm = ScriptedLLM([json.dumps(feasibility), json.dumps(vulnerability_ir)])
        output = self.root / "analysis"

        stdout = StringIO()
        with patch(
            "cve2checker.cli.llm_from_env", return_value=llm
        ):
            with redirect_stdout(stdout):
                result = main(
                    [
                        "analyze",
                        "--cve-file",
                        str(cve_file),
                        "--source-json",
                        str(source_json),
                        "--output-dir",
                        str(output),
                    ]
                )

        self.assertEqual(result, 0, stdout.getvalue())
        self.assertTrue((output / "feasibility.json").is_file())
        self.assertTrue((output / "vulnerability_ir.json").is_file())
        self.assertIn("-strcpy(dst, src);", llm.calls[0]["user"])
        self.assertIn("+strncpy(dst, src, n);", llm.calls[0]["user"])

    def test_synthesize_command_wires_loop(self) -> None:
        repo, fix_commit = make_repo(self.root)
        cve_file = self.root / "cve.json"
        cve_file.write_text(json.dumps(cve_record(fix_commit)), encoding="utf-8")
        ir_file = self.root / "ir.json"
        ir_file.write_text(json.dumps({"cwe_ids": ["CWE-120"]}), encoding="utf-8")
        diff = self.root / "fix.diff"
        diff.write_text(
            "diff --git a/copy.c b/copy.c\n"
            "--- a/copy.c\n"
            "+++ b/copy.c\n"
            "@@ -1 +1 @@\n"
            "-strcpy(dst, src);\n"
            "+strncpy(dst, src, n);\n",
            encoding="utf-8",
        )
        result_value = SynthesisResult(
            status="success",
            iterations=1,
            query_path=self.root / "query.ql",
            feedback={"verdict": "success"},
        )

        stdout = StringIO()
        with patch(
            "cve2checker.cli.llm_from_env",
            return_value=object(),
        ), patch(
            "cve2checker.cli.run_synthesis", return_value=result_value
        ) as run:
            with redirect_stdout(stdout):
                result = main(
                    [
                        "synthesize",
                        "--cve-file",
                        str(cve_file),
                        "--ir",
                        str(ir_file),
                        "--repo",
                        str(repo),
                        "--vuln-commit",
                        "1" * 40,
                        "--fix-commit",
                        fix_commit,
                        "--diff",
                        str(diff),
                        "--vuln-db",
                        "vuln-db",
                        "--fixed-db",
                        "fixed-db",
                        "--output-dir",
                        str(self.root / "synthesis"),
                        "--no-lsp",
                    ]
                )

        self.assertEqual(result, 0, stdout.getvalue())
        self.assertIn("Status: success", stdout.getvalue())
        self.assertEqual(run.call_args.kwargs["cve_id"], CVE_ID)


if __name__ == "__main__":
    unittest.main()
