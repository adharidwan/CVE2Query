import subprocess
import tempfile
import unittest
from pathlib import Path

from cve2checker.git_tools import (
    GitError,
    add_worktree,
    checkout_commit,
    clone_repository,
    current_commit,
    diff_commits,
    is_git_repository,
    resolve_parent,
    show_file,
)


def git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def commit_file(repository: Path, content: str, message: str) -> str:
    (repository / "sample.c").write_text(content, encoding="utf-8")
    git(repository, "add", "sample.c")
    git(
        repository,
        "-c",
        "user.name=Test User",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-m",
        message,
    )
    return git(repository, "rev-parse", "HEAD")


class GitToolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary_directory.name)
        git(self.repo, "init")
        self.first = commit_file(self.repo, "int main(void) { return 0; }\n", "first")
        self.second = commit_file(
            self.repo,
            "int main(void) { char *p = 0; return p[0]; }\n",
            "second",
        )

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_parent_diff_show_and_checkout(self) -> None:
        self.assertEqual(resolve_parent(self.repo, self.second), self.first)
        diff = diff_commits(self.repo, self.first, self.second)
        self.assertIn("-int main(void)", diff)
        self.assertIn("+int main(void) { char *p = 0; return p[0]; }", diff)
        self.assertIn("int main(void) { return 0; }", show_file(self.repo, self.first, "sample.c"))

        checkout_commit(self.repo, self.first)
        self.assertEqual(current_commit(self.repo), self.first)

    def test_repository_detection(self) -> None:
        self.assertTrue(is_git_repository(self.repo))
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(is_git_repository(directory))

    def test_unsafe_commit_and_path_are_rejected(self) -> None:
        with self.assertRaises(GitError):
            resolve_parent(self.repo, "--upload-pack=evil")
        with self.assertRaises(GitError):
            show_file(self.repo, self.second, "../outside.c")

    def test_add_worktree_and_reuse_it(self) -> None:
        destination = Path(self.temporary_directory.name) / "worktree"
        created = add_worktree(self.repo, destination, self.first)
        self.assertEqual(created, destination.resolve())
        self.assertIn(
            "int main(void) { return 0; }",
            (created / "sample.c").read_text(encoding="utf-8"),
        )
        self.assertEqual(add_worktree(self.repo, destination, self.first), created)

    def test_clone_local_repository(self) -> None:
        destination = Path(self.temporary_directory.name) / "clone"
        cloned = clone_repository(str(self.repo), destination)
        self.assertTrue((cloned / ".git").is_dir())
        checkout_commit(cloned, self.second)
        self.assertEqual(current_commit(cloned), self.second)

    def test_clone_to_relative_destination(self) -> None:
        import os

        previous = Path.cwd()
        try:
            os.chdir(self.temporary_directory.name)
            cloned = clone_repository(str(self.repo), Path("relative-clone"))
        finally:
            os.chdir(previous)
        self.assertEqual(
            cloned,
            (Path(self.temporary_directory.name) / "relative-clone").resolve(),
        )
        self.assertTrue((cloned / ".git").is_dir())


if __name__ == "__main__":
    unittest.main()
