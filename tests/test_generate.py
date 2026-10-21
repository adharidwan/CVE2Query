import json
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


def make_repo(root: Path) -> tuple[Path, str, str]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init")
    source = repo / "copy.c"
    source.write_text("void f(void) { strcpy(dst, src); }\n", encoding="utf-8")
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
    vulnerable = git(repo, "rev-parse", "HEAD")
    source.write_text("void f(void) { strncpy(dst, src, n); }\n", encoding="utf-8")
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
    return repo, vulnerable, git(repo, "rev-parse", "HEAD")


class GenerateTests(unittest.TestCase):
    def test_generate_orchestrates_and_writes_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, vulnerable, fix = make_repo(root)
            cve_file = root / "cve.json"
            cve_file.write_text(
                json.dumps(
                    {
                        "dataType": "CVE_RECORD",
                        "cveMetadata": {"cveId": CVE_ID},
                        "containers": {
                            "cna": {
                                "references": [
                                    {
                                        "url": "https://github.com/acme/widget/commit/"
                                        + fix
                                    }
                                ]
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            feasibility = {
                "decision": "proceed",
                "confidence": 0.9,
                "language": "cpp",
                "cwe_ids": ["CWE-120"],
                "modeling": "missing_guard",
                "source_candidates": [],
                "sink_candidates": [
                    {"kind": "strcpy", "evidence": "copy.c:1"}
                ],
                "sanitizer_candidates": [],
                "missing_evidence": [],
                "reasons": ["source and diff are available"],
                "recommended_next_action": "synthesize",
            }
            citation = {
                "description": "copy",
                "file": "copy.c",
                "start_line": 1,
                "end_line": 1,
                "commit": fix,
                "snippet": "strcpy(dst, src);",
                "confidence": 0.9,
            }
            ir = {
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
                    "sources": [],
                    "sinks": [citation],
                    "sanitizers": [],
                    "additional_taint_steps": [],
                },
                "diff_locations": [
                    {
                        "file": "copy.c",
                        "start_line": 1,
                        "end_line": 1,
                        "commit": fix,
                        "snippet": "strncpy(dst, src, n);",
                    }
                ],
                "unknowns": [],
                "analysis_notes": "",
            }
            llm = ScriptedLLM([json.dumps(feasibility), json.dumps(ir)])

            def fake_db(source, database, **kwargs):
                target = Path(database)
                target.mkdir(parents=True, exist_ok=True)
                (target / "codeql-database.yml").write_text("db\n", encoding="utf-8")

            def fake_synthesis(**kwargs):
                query = Path(kwargs["workdir"]) / "iteration" / "query.ql"
                query.parent.mkdir(parents=True, exist_ok=True)
                query.write_text("from FunctionCall c select c\n", encoding="utf-8")
                return SynthesisResult(
                    status="success",
                    iterations=1,
                    query_path=query,
                    feedback={
                        "verdict": "success",
                        "metrics": {"precision": 1.0, "f1": 1.0},
                    },
                    history=[],
                )

            output = root / "artifacts"
            arguments = [
                "generate",
                "--cve-id",
                CVE_ID,
                "--cve-file",
                str(cve_file),
                "--repo-path",
                str(repo),
                "--fix-commit",
                fix,
                "--output-dir",
                str(output),
                "--no-lsp",
            ]
            stdout = StringIO()
            with patch("cve2checker.cli._build_llm", return_value=llm), patch(
                "cve2checker.cli.create_cpp_database", side_effect=fake_db
            ), patch(
                "cve2checker.cli.ensure_query_pack",
                side_effect=lambda path, **kwargs: Path(path),
            ), patch(
                "cve2checker.cli.run_synthesis", side_effect=fake_synthesis
            ):
                with redirect_stdout(stdout):
                    result = main(arguments)

            self.assertEqual(result, 0, stdout.getvalue())
            run_dir = output / CVE_ID
            self.assertTrue((run_dir / "state.json").is_file())
            self.assertTrue((run_dir / "generated-analysis" / "feasibility.json").is_file())
            self.assertTrue((run_dir / "generated-analysis" / "vulnerability_ir.json").is_file())
            self.assertTrue((run_dir / "final" / f"{CVE_ID}.ql").is_file())
            self.assertTrue((run_dir / "final" / "manifest.json").is_file())
            self.assertTrue((run_dir / "final" / "report.md").is_file())
            state = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
            self.assertEqual(state["stages"]["evidence"]["status"], "completed")
            self.assertEqual(state["stages"]["synthesis"]["status"], "completed")

            with patch(
                "cve2checker.cli.build_evidence",
                side_effect=AssertionError("evidence should be reused"),
            ), patch(
                "cve2checker.cli.create_cpp_database",
                side_effect=AssertionError("databases should be reused"),
            ), patch(
                "cve2checker.cli._build_llm",
                side_effect=AssertionError("LLM should not be called"),
            ), patch(
                "cve2checker.cli.run_synthesis",
                side_effect=AssertionError("synthesis should be reused"),
            ):
                with redirect_stdout(StringIO()):
                    resumed = main(arguments + ["--resume"])
            self.assertEqual(resumed, 0)


if __name__ == "__main__":
    unittest.main()
