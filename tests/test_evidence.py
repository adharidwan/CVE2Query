import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from cve2checker.evidence import EvidenceError, build_evidence


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
    source = repo / "src"
    source.mkdir()
    vulnerable = source / "copy.c"
    vulnerable.write_text(
        "void copy(char *dst, char *src) {\n"
        "    strcpy(dst, src);\n"
        "}\n",
        encoding="utf-8",
    )
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
    vulnerable_commit = git(repo, "rev-parse", "HEAD")
    vulnerable.write_text(
        "void copy(char *dst, char *src, unsigned size) {\n"
        "    strncpy(dst, src, size - 1);\n"
        "    dst[size - 1] = 0;\n"
        "}\n",
        encoding="utf-8",
    )
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
    fix_commit = git(repo, "rev-parse", "HEAD")
    return repo, vulnerable_commit, fix_commit


def record(fix_commit: str) -> dict:
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {"cveId": "CVE-2024-1234"},
        "containers": {
            "cna": {
                "references": [
                    {
                        "url": f"https://github.com/acme/widget/commit/{fix_commit}"
                    }
                ]
            }
        },
    }


class EvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.repo, self.vulnerable_commit, self.fix_commit = make_repo(self.root)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_builds_artifacts_from_local_repository(self) -> None:
        workspace = self.root / "artifacts"
        result = build_evidence(
            "CVE-2024-1234",
            record(self.fix_commit),
            workspace,
            repo_path=self.repo,
        )

        self.assertEqual(result["vulnerable_commit"], self.vulnerable_commit)
        self.assertEqual(result["fix_commit"], self.fix_commit)
        self.assertEqual(result["source"]["diff_stats"]["files"], 1)
        self.assertGreater(result["source"]["diff_stats"]["added_lines"], 0)
        self.assertIn("strcpy(dst, src)", result["diff"])

        artifact_dir = workspace / "CVE-2024-1234"
        source = json.loads((artifact_dir / "source.json").read_text(encoding="utf-8"))
        self.assertEqual(source["repo_path"], str(self.repo.resolve()))
        self.assertTrue((artifact_dir / "diff.patch").is_file())
        context = json.loads((artifact_dir / "context.json").read_text(encoding="utf-8"))
        self.assertTrue(context["snippets"])
        self.assertEqual(context["snippets"][0]["file"], "src/copy.c")

    def test_requires_a_fix_commit(self) -> None:
        empty_record = {
            "dataType": "CVE_RECORD",
            "cveMetadata": {"cveId": "CVE-2024-1234"},
            "containers": {"cna": {"references": []}},
        }
        with self.assertRaisesRegex(EvidenceError, "no fix commit"):
            build_evidence(
                "CVE-2024-1234",
                empty_record,
                self.root / "artifacts",
                repo_path=self.repo,
            )

    def test_rejects_non_git_repository(self) -> None:
        not_a_repo = self.root / "plain"
        not_a_repo.mkdir()
        with self.assertRaisesRegex(EvidenceError, "not a git repository"):
            build_evidence(
                "CVE-2024-1234",
                record(self.fix_commit),
                self.root / "artifacts",
                repo_path=not_a_repo,
            )


if __name__ == "__main__":
    unittest.main()
