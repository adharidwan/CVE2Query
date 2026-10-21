import json
import os
import tempfile
import unittest
from pathlib import Path

from cve2checker.codeql import create_cpp_database, ensure_query_pack
from cve2checker.diff import ChangedRange
from cve2checker.llm import ScriptedLLM
from cve2checker.synthesis import ToolBox, run_synthesis
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
    "set CVE2CHECKER_CODEQL_INTEGRATION=1 to run the real end-to-end loop",
)
class RealEndToEndTests(unittest.TestCase):
    def test_scripted_agent_query_runs_through_loop_and_validates(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        codeql = project_root / ".tools" / "codeql" / "codeql.cmd"
        if not codeql.is_file():
            self.skipTest("pinned CodeQL bundle is not installed")
        baseline = (
            project_root
            / "codeql-pack"
            / "queries"
            / "BaselineDirectStrcpyCall.ql"
        )
        query_text = baseline.read_text(encoding="utf-8")

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

            workdir = root / "synthesis"
            ensure_query_pack(workdir, codeql_path=codeql)
            changed = [
                ChangedRange("src/copy.c", 3, 5, "old"),
                ChangedRange("src/copy.c", 3, 6, "new"),
            ]
            llm = ScriptedLLM([json.dumps({"final": query_text})])
            tools = ToolBox(repo_root=fixed, workdir=workdir)

            def validate(query, iteration_dir, iteration):
                return validate_query(
                    query,
                    root / "db-vulnerable",
                    root / "db-fixed",
                    changed,
                    iteration_dir,
                    codeql_path=codeql,
                    iteration=iteration,
                )

            result = run_synthesis(
                cve_id="CVE-2024-1234",
                cve={"cveMetadata": {"cveId": "CVE-2024-1234"}},
                cwe_ids=["CWE-120"],
                repo_path=fixed,
                vulnerable_commit="1" * 40,
                fix_commit="2" * 40,
                diff="-strcpy(dst, src);\n+strncpy(dst, src, size - 1);",
                vulnerability_ir={"cwe_ids": ["CWE-120"]},
                ast_snippets=[],
                workdir=workdir,
                llm=llm,
                tools=tools,
                validate=validate,
                codeql_version="2.27.2",
                max_iterations=2,
                max_tool_calls=5,
            )
            self.assertTrue(result.query_path.is_file())

        self.assertEqual(result.status, "success", result.feedback)
        self.assertEqual(result.iterations, 1)
        self.assertGreaterEqual(
            result.feedback["vulnerable"]["diff_intersection_count"], 1
        )
        self.assertEqual(result.feedback["fixed"]["diff_intersection_count"], 0)


if __name__ == "__main__":
    unittest.main()
