import tempfile
import unittest
from pathlib import Path

from cve2checker.context import (
    SourceSnippet,
    enclosing_function,
    extract_context,
)
from cve2checker.diff import FileDiff, Hunk, parse_unified_diff


SOURCE = [
    "#include <string.h>",
    "",
    "static int helper(int value)",
    "{",
    "    if (value > 0) {",
    "        return value + 1;",
    "    }",
    "    return 0;",
    "}",
    "",
    "void vulnerable(char *input)",
    "{",
    "    char buffer[8];",
    "    /* injected */",
    "    strcpy(buffer, input);",
    "    helper(1);",
    "}",
    "",
    "int other(void)",
    "{",
    "    return 42;",
    "}",
]

MAIN_DIFF = """diff --git a/src/main.c b/src/main.c
--- a/src/main.c
+++ b/src/main.c
@@ -12,5 +12,6 @@
 {
     char buffer[8];
+    /* injected */
     strcpy(buffer, input);
     helper(1);
 }
"""


def _write(root: Path, relative: str, content: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class EnclosingFunctionTests(unittest.TestCase):
    def test_finds_function_around_nested_control_blocks(self) -> None:
        self.assertEqual(enclosing_function(SOURCE, 6), (3, 9))
        self.assertEqual(enclosing_function(SOURCE, 5), (3, 9))
        self.assertEqual(enclosing_function(SOURCE, 14), (11, 17))
        self.assertEqual(enclosing_function(SOURCE, 17), (11, 17))
        self.assertEqual(enclosing_function(SOURCE, 20), (19, 22))

    def test_returns_none_outside_functions_or_for_control_statements(self) -> None:
        self.assertIsNone(enclosing_function(SOURCE, 2))
        self.assertIsNone(enclosing_function(SOURCE, 0))
        self.assertIsNone(enclosing_function(SOURCE, len(SOURCE) + 1))
        control_only = ["if (x) {", "    y();", "}"]
        self.assertIsNone(enclosing_function(control_only, 2))

    def test_handles_multiline_signatures(self) -> None:
        lines = [
            "static int",
            "compute(int a,",
            "        int b)",
            "{",
            "    return a + b;",
            "}",
        ]
        self.assertEqual(enclosing_function(lines, 5), (1, 6))

    def test_ignores_braces_in_comments_and_strings(self) -> None:
        lines = [
            "void f(void)",
            "{",
            "    if (x) { /* } */",
            '        char *s = "}";',
            "    }",
            "}",
        ]
        self.assertEqual(enclosing_function(lines, 4), (1, 6))


class ExtractContextTests(unittest.TestCase):
    def test_extracts_hunk_and_function_snippets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write(root, "src/main.c", "\n".join(SOURCE) + "\n")

            snippets = extract_context(
                root, parse_unified_diff(MAIN_DIFF), context_lines=2
            )

            self.assertEqual(len(snippets), 2)
            by_kind = {snippet.kind: snippet for snippet in snippets}
            self.assertEqual(set(by_kind), {"hunk", "function"})

            hunk = by_kind["hunk"]
            self.assertIsInstance(hunk, SourceSnippet)
            self.assertEqual(hunk.file, "src/main.c")
            self.assertEqual((hunk.start_line, hunk.end_line), (12, 16))
            self.assertEqual(hunk.text, "\n".join(SOURCE[11:16]))

            function = by_kind["function"]
            self.assertEqual(function.file, "src/main.c")
            self.assertEqual((function.start_line, function.end_line), (11, 17))
            self.assertEqual(function.text, "\n".join(SOURCE[10:17]))
            self.assertIn("void vulnerable", function.text)
            self.assertNotIn("int other", function.text)

    def test_deduplicates_overlapping_snippets(self) -> None:
        lines = (
            ["int f(void)", "{"] + [f"    int x{i};" for i in range(30)] + ["}"]
        )
        diff_text = """diff --git a/dup.c b/dup.c
--- a/dup.c
+++ b/dup.c
@@ -4,1 +4,2 @@
 context
+first
@@ -9,1 +10,2 @@
 context
+second
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write(root, "dup.c", "\n".join(lines) + "\n")

            snippets = extract_context(
                root, parse_unified_diff(diff_text), context_lines=5
            )

            self.assertEqual(len(snippets), 2)
            by_kind = {snippet.kind: snippet for snippet in snippets}
            self.assertEqual((by_kind["hunk"].start_line, by_kind["hunk"].end_line), (1, 16))
            self.assertEqual(
                (by_kind["function"].start_line, by_kind["function"].end_line),
                (1, len(lines)),
            )
            self.assertEqual(by_kind["function"].text, "\n".join(lines))

    def test_context_is_clamped_to_file_bounds(self) -> None:
        lines = [f"line{number}" for number in range(1, 11)]
        diff_text = """diff --git a/bounds.txt b/bounds.txt
--- a/bounds.txt
+++ b/bounds.txt
@@ -1 +1 @@
-old
+new
@@ -10 +10 @@
-old
+new
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write(root, "bounds.txt", "\n".join(lines) + "\n")

            snippets = extract_context(
                root, parse_unified_diff(diff_text), context_lines=8
            )

            self.assertEqual(len(snippets), 1)
            snippet = snippets[0]
            self.assertEqual(snippet.kind, "hunk")
            self.assertEqual((snippet.start_line, snippet.end_line), (1, 10))
            self.assertEqual(snippet.text, "\n".join(lines))

    def test_deleted_file_uses_old_path(self) -> None:
        diff_text = """diff --git a/gone.txt b/gone.txt
deleted file mode 100644
--- a/gone.txt
+++ /dev/null
@@ -2,2 +0,0 @@
-beta
-gamma
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write(root, "gone.txt", "alpha\nbeta\ngamma\ndelta\n")

            snippets = extract_context(
                root, parse_unified_diff(diff_text), context_lines=1
            )

            self.assertEqual(len(snippets), 1)
            snippet = snippets[0]
            self.assertEqual(snippet.kind, "hunk")
            self.assertEqual(snippet.file, "gone.txt")
            self.assertEqual((snippet.start_line, snippet.end_line), (1, 4))
            self.assertEqual(snippet.text, "alpha\nbeta\ngamma\ndelta")

    def test_new_file_uses_new_path(self) -> None:
        diff_text = """diff --git a/new.c b/new.c
new file mode 100644
--- /dev/null
+++ b/new.c
@@ -0,0 +1,4 @@
+int main(void)
+{
+    return 0;
+}
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write(root, "new.c", "int main(void)\n{\n    return 0;\n}\n")

            snippets = extract_context(
                root, parse_unified_diff(diff_text), context_lines=0
            )

            self.assertEqual(len(snippets), 2)
            by_kind = {snippet.kind: snippet for snippet in snippets}
            self.assertEqual(set(by_kind), {"hunk", "function"})
            for snippet in snippets:
                self.assertEqual(snippet.file, "new.c")
                self.assertEqual((snippet.start_line, snippet.end_line), (1, 4))
                self.assertEqual(
                    snippet.text, "int main(void)\n{\n    return 0;\n}"
                )

    def test_prefers_new_path_for_modified_files(self) -> None:
        diff = FileDiff(
            old_path="old.c",
            new_path="new.c",
            hunks=[Hunk(1, 1, 1, 1, ["-old only", "+new only"])],
            is_binary=False,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write(root, "old.c", "old only\n")
            _write(root, "new.c", "new only\n")

            snippets = extract_context(root, [diff], context_lines=0)

            self.assertEqual(len(snippets), 1)
            self.assertEqual(snippets[0].file, "new.c")
            self.assertEqual(snippets[0].text, "new only")

    def test_strips_prefixes_from_manually_built_file_diff(self) -> None:
        diff = FileDiff(
            old_path="a/src/name.c",
            new_path="b/src/name.c",
            hunks=[Hunk(1, 1, 1, 1, ["-old", "+new"])],
            is_binary=False,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write(root, "src/name.c", "new\n")

            snippets = extract_context(root, [diff], context_lines=0)

            self.assertEqual(len(snippets), 1)
            self.assertEqual(snippets[0].file, "src/name.c")
            self.assertEqual(snippets[0].text, "new")

    def test_missing_and_binary_files_are_ignored(self) -> None:
        missing = FileDiff(
            old_path="missing.c",
            new_path="missing.c",
            hunks=[Hunk(1, 0, 1, 1, ["+added"])],
            is_binary=False,
        )
        binary = FileDiff(
            old_path="image.png",
            new_path="image.png",
            hunks=[],
            is_binary=True,
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            self.assertEqual(extract_context(root, [missing, binary]), [])

    def test_does_not_escape_repo_root(self) -> None:
        diff_text = """diff --git a/../secret.txt b/../secret.txt
--- a/../secret.txt
+++ b/../secret.txt
@@ -1 +1 @@
-old
+new
"""
        with tempfile.TemporaryDirectory() as temporary_directory:
            base = Path(temporary_directory)
            root = base / "repo"
            root.mkdir()
            (base / "secret.txt").write_text("TOPSECRET\n", encoding="utf-8")

            snippets = extract_context(
                root, parse_unified_diff(diff_text), context_lines=0
            )

            self.assertEqual(snippets, [])


if __name__ == "__main__":
    unittest.main()
