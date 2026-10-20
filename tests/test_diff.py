import unittest

from cve2checker.diff import (
    ChangedRange,
    DiffError,
    FileDiff,
    Hunk,
    changed_ranges,
    diff_stats,
    parse_unified_diff,
)


MULTI_FILE_DIFF = """diff --git a/src/alpha.c b/src/alpha.c
index 1111111..2222222 100644
--- a/src/alpha.c
+++ b/src/alpha.c
@@ -1,5 +1,6 @@
 #include <stdio.h>
 
-int old(void) {
+int new(void) {
+    int added = 1;
     return 0;
 }
diff --git a/src/beta.c b/src/beta.c
--- a/src/beta.c
+++ b/src/beta.c
@@ -10,3 +10,3 @@
 a
-b
+B
 c
"""


class ParseUnifiedDiffTests(unittest.TestCase):
    def test_parses_multiple_files_and_stats(self) -> None:
        diffs = parse_unified_diff(MULTI_FILE_DIFF)

        self.assertEqual(len(diffs), 2)
        self.assertEqual(diffs[0].old_path, "src/alpha.c")
        self.assertEqual(diffs[0].new_path, "src/alpha.c")
        self.assertFalse(diffs[0].is_binary)
        self.assertEqual(diffs[1].old_path, "src/beta.c")
        self.assertEqual(diffs[1].new_path, "src/beta.c")
        self.assertEqual(diffs[0].hunks[0].old_start, 1)
        self.assertEqual(diffs[0].hunks[0].old_count, 5)
        self.assertEqual(diffs[0].hunks[0].new_start, 1)
        self.assertEqual(diffs[0].hunks[0].new_count, 6)
        self.assertEqual(
            diffs[0].hunks[0].lines,
            [
                " #include <stdio.h>",
                " ",
                "-int old(void) {",
                "+int new(void) {",
                "+    int added = 1;",
                "     return 0;",
                " }",
            ],
        )
        self.assertEqual(
            diff_stats(diffs),
            {
                "files": 2,
                "hunks": 2,
                "added_lines": 3,
                "removed_lines": 2,
                "binary_files": 0,
            },
        )

    def test_maps_added_and_removed_lines(self) -> None:
        diffs = parse_unified_diff(MULTI_FILE_DIFF)

        self.assertEqual(
            changed_ranges(diffs, "new"),
            [
                ChangedRange("src/alpha.c", 3, 4, "new"),
                ChangedRange("src/beta.c", 11, 11, "new"),
            ],
        )
        self.assertEqual(
            changed_ranges(diffs, "old"),
            [
                ChangedRange("src/alpha.c", 3, 3, "old"),
                ChangedRange("src/beta.c", 11, 11, "old"),
            ],
        )
        with self.assertRaises(ValueError):
            changed_ranges(diffs, "both")

    def test_merges_adjacent_ranges_across_hunks(self) -> None:
        diffs = parse_unified_diff(
            """diff --git a/a.c b/a.c
--- a/a.c
+++ b/a.c
@@ -1,0 +2,2 @@
+one
+two
@@ -3,0 +4,1 @@
+three
"""
        )

        self.assertEqual(
            changed_ranges(diffs, "new"),
            [ChangedRange("a.c", 2, 4, "new")],
        )

    def test_new_and_deleted_files_use_dev_null(self) -> None:
        diffs = parse_unified_diff(
            """diff --git a/new.txt b/new.txt
new file mode 100644
--- /dev/null
+++ b/new.txt
@@ -0,0 +1,2 @@
+hello
+world
diff --git a/old.txt b/old.txt
deleted file mode 100644
--- a/old.txt
+++ /dev/null
@@ -1,2 +0,0 @@
-bye
-now
"""
        )

        self.assertEqual(len(diffs), 2)
        self.assertEqual(diffs[0].old_path, "/dev/null")
        self.assertEqual(diffs[0].new_path, "new.txt")
        self.assertEqual(diffs[1].old_path, "old.txt")
        self.assertEqual(diffs[1].new_path, "/dev/null")
        self.assertEqual(
            changed_ranges(diffs, "new"),
            [ChangedRange("new.txt", 1, 2, "new")],
        )
        self.assertEqual(
            changed_ranges(diffs, "old"),
            [ChangedRange("old.txt", 1, 2, "old")],
        )

    def test_binary_diffs_are_marked_and_skipped(self) -> None:
        diffs = parse_unified_diff(
            """diff --git a/logo.png b/logo.png
new file mode 100644
index 0000000..1111111
Binary files /dev/null and b/logo.png differ
diff --git a/data.bin b/data.bin
index 2222222..3333333 100644
GIT binary patch
literal 4
Lc$@N00000
diff --git a/src/after.c b/src/after.c
--- a/src/after.c
+++ b/src/after.c
@@ -1 +1 @@
-old
+new
"""
        )

        self.assertEqual(len(diffs), 3)
        self.assertTrue(diffs[0].is_binary)
        self.assertEqual(diffs[0].old_path, "/dev/null")
        self.assertEqual(diffs[0].new_path, "logo.png")
        self.assertTrue(diffs[1].is_binary)
        self.assertEqual(diffs[1].hunks, [])
        self.assertFalse(diffs[2].is_binary)
        self.assertEqual(len(diffs[2].hunks), 1)
        self.assertEqual(
            diff_stats(diffs),
            {
                "files": 3,
                "hunks": 1,
                "added_lines": 1,
                "removed_lines": 1,
                "binary_files": 2,
            },
        )
        self.assertEqual(
            changed_ranges(diffs),
            [ChangedRange("src/after.c", 1, 1, "new")],
        )

    def test_quoted_and_unquoted_paths_with_spaces(self) -> None:
        diffs = parse_unified_diff(
            """diff --git "a/dir with space/name.c" "b/dir with space/name.c"
--- "a/dir with space/name.c"
+++ "b/dir with space/name.c"
@@ -1 +1 @@
-old
+new
diff --git a/plain dir/file.c b/plain dir/file.c
--- a/plain dir/file.c
+++ b/plain dir/file.c
@@ -2 +2 @@
-before
+after
"""
        )

        self.assertEqual(diffs[0].old_path, "dir with space/name.c")
        self.assertEqual(diffs[0].new_path, "dir with space/name.c")
        self.assertEqual(diffs[1].old_path, "plain dir/file.c")
        self.assertEqual(diffs[1].new_path, "plain dir/file.c")
        self.assertEqual(
            changed_ranges(diffs),
            [
                ChangedRange("dir with space/name.c", 1, 1, "new"),
                ChangedRange("plain dir/file.c", 2, 2, "new"),
            ],
        )

    def test_decodes_escaped_quoted_paths(self) -> None:
        diffs = parse_unified_diff(
            r'''diff --git "a/caf\303\251.c" "b/caf\303\251.c"
--- "a/caf\303\251.c"
+++ "b/caf\303\251.c"
@@ -1 +1 @@
-a
+b
'''
        )

        self.assertEqual(diffs[0].new_path, "café.c")
        self.assertEqual(changed_ranges(diffs)[0].file, "café.c")

    def test_normalizes_backslash_paths(self) -> None:
        diffs = parse_unified_diff(
            r"""diff --git a\src\win.c b\src\win.c
--- a\src\win.c
+++ b\src\win.c
@@ -1 +1 @@
-old
+new
"""
        )

        self.assertEqual(diffs[0].old_path, "src/win.c")
        self.assertEqual(diffs[0].new_path, "src/win.c")
        self.assertEqual(changed_ranges(diffs)[0].file, "src/win.c")

    def test_tolerates_missing_counts_and_no_newline_markers(self) -> None:
        diffs = parse_unified_diff(
            """diff --git a/eof.c b/eof.c
--- a/eof.c
+++ b/eof.c
@@ -3 +3 @@
-old
\\ No newline at end of file
+new
\\ No newline at end of file
"""
        )

        self.assertEqual(len(diffs), 1)
        hunk = diffs[0].hunks[0]
        self.assertEqual((hunk.old_count, hunk.new_count), (1, 1))
        self.assertEqual(len(hunk.lines), 4)
        self.assertEqual(
            changed_ranges(diffs, "old"),
            [ChangedRange("eof.c", 3, 3, "old")],
        )
        self.assertEqual(
            changed_ranges(diffs, "new"),
            [ChangedRange("eof.c", 3, 3, "new")],
        )
        self.assertEqual(
            diff_stats(diffs),
            {
                "files": 1,
                "hunks": 1,
                "added_lines": 1,
                "removed_lines": 1,
                "binary_files": 0,
            },
        )

    def test_hunk_body_lines_that_look_like_file_headers(self) -> None:
        diffs = parse_unified_diff(
            """diff --git a/comments.c b/comments.c
--- a/comments.c
+++ b/comments.c
@@ -1 +1 @@
--- old comment
+++ new comment
"""
        )

        self.assertEqual(len(diffs), 1)
        self.assertEqual(
            diffs[0].hunks[0].lines,
            ["--- old comment", "+++ new comment"],
        )
        self.assertEqual(
            changed_ranges(diffs, "old"),
            [ChangedRange("comments.c", 1, 1, "old")],
        )
        self.assertEqual(
            changed_ranges(diffs, "new"),
            [ChangedRange("comments.c", 1, 1, "new")],
        )

    def test_tolerates_hunk_header_without_closing_marker(self) -> None:
        diffs = parse_unified_diff(
            """diff --git a/a.c b/a.c
--- a/a.c
+++ b/a.c
@@ -1 +1
-old
+new
"""
        )

        self.assertEqual(len(diffs), 1)
        self.assertEqual(len(diffs[0].hunks), 1)
        self.assertEqual(
            changed_ranges(diffs),
            [ChangedRange("a.c", 1, 1, "new")],
        )

    def test_malformed_hunk_header_raises(self) -> None:
        text = """diff --git a/a.c b/a.c
--- a/a.c
+++ b/a.c
@@ not a hunk header @@
"""
        with self.assertRaises(DiffError):
            parse_unified_diff(text)

    def test_ignores_unrelated_metadata(self) -> None:
        diffs = parse_unified_diff(
            """Mail header
diff --git a/a.c b/a.c
old mode 100644
new mode 100755
similarity index 100%
rename from a.c
rename to a.c
--- a/a.c
+++ b/a.c
@@ -1 +1 @@
-old
+new
trailing text
"""
        )

        self.assertEqual(len(diffs), 1)
        self.assertEqual(len(diffs[0].hunks), 1)
        self.assertEqual(
            changed_ranges(diffs),
            [ChangedRange("a.c", 1, 1, "new")],
        )

    def test_accepts_directly_constructed_hunks(self) -> None:
        diffs = [
            FileDiff(
                old_path="x.c",
                new_path="x.c",
                hunks=[
                    Hunk(1, 2, 1, 2, [" context", "-old", "+new"]),
                ],
                is_binary=False,
            )
        ]

        self.assertEqual(
            changed_ranges(diffs, "old"),
            [ChangedRange("x.c", 2, 2, "old")],
        )
        self.assertEqual(
            changed_ranges(diffs, "new"),
            [ChangedRange("x.c", 2, 2, "new")],
        )


if __name__ == "__main__":
    unittest.main()
