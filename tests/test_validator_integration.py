import os
import tempfile
import unittest
from pathlib import Path

from cve2checker.codeql import create_cpp_database
from cve2checker.diff import ChangedRange
from cve2checker.validator import validate_query

VULNERABLE = """\
#include <string.h>

void copy(char *dst, const char *src) {
    strcpy(dst, src);
}
"""

FIXED = """\
#include <string.h>

void copy(char *dst, const char *src, unsigned size) {
    strncpy(dst, src, size - 1);
    dst[size - 1] = 0;
}
"""


@unittest.skipUnless(
    os.environ.get("CVE2CHECKER_CODEQL_INTEGRATION") == "1",
    "set CVE2CHECKER_CODEQL_INTEGRATION=1 to run the real CodeQL validator test",
)
class RealCodeQLValidatorTests(unittest.TestCase):
    def test_baseline_query_succeeds_on_vulnerable_and_not_fixed(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        codeql = project_root / ".tools" / "codeql" / "codeql.cmd"
        if not codeql.is_file():
            self.skipTest("pinned CodeQL bundle is not installed")
        query = (
            project_root
            / "codeql-pack"
            / "queries"
            / "BaselineDirectStrcpyCall.ql"
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vulnerable = root / "vulnerable"
            fixed = root / "fixed"
            (vulnerable / "src").mkdir(parents=True)
            (fixed / "src").mkdir(parents=True)
            (vulnerable / "src" / "copy.c").write_text(
                VULNERABLE, encoding="utf-8"
            )
            (fixed / "src" / "copy.c").write_text(FIXED, encoding="utf-8")

            create_cpp_database(
                vulnerable,
                root / "db-vulnerable",
                build_mode="none",
                codeql_path=codeql,
            )
            create_cpp_database(
                fixed,
                root / "db-fixed",
                build_mode="none",
                codeql_path=codeql,
            )

            changed = [
                ChangedRange("src/copy.c", 3, 5, "old"),
                ChangedRange("src/copy.c", 3, 6, "new"),
            ]
            feedback = validate_query(
                query,
                root / "db-vulnerable",
                root / "db-fixed",
                changed,
                root / "iteration",
                codeql_path=codeql,
            )

        self.assertEqual(feedback["verdict"], "success", feedback)
        self.assertGreaterEqual(
            feedback["vulnerable"]["diff_intersection_count"], 1
        )
        self.assertEqual(feedback["fixed"]["diff_intersection_count"], 0)


if __name__ == "__main__":
    unittest.main()
