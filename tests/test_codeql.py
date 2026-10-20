import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from cve2checker.codeql import (
    CodeQLError,
    analyze_query,
    compile_query,
    create_cpp_database,
    ensure_query_pack,
    install_pack,
    verify_pack,
)


class CodeQLWrapperTests(unittest.TestCase):
    def test_create_cpp_database_passes_optional_build_command_as_one_argument(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="created", stderr="")
        source_root = r"C:\work\source tree"
        database_path = r"C:\work\analysis database"
        codeql_path = r"C:\Program Files\CodeQL\codeql.exe"

        with patch(
            "cve2checker.codeql.subprocess.run", return_value=completed
        ) as run:
            result = create_cpp_database(
                source_root,
                database_path,
                build_command="cmake --build build dir",
                codeql_path=codeql_path,
            )

        self.assertIs(result, completed)
        run.assert_called_once_with(
            [
                codeql_path,
                "database",
                "create",
                "--language=cpp",
                f"--source-root={source_root}",
                "--command=cmake --build build dir",
                "--",
                database_path,
            ],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            cwd=None,
        )

    def test_create_cpp_database_omits_build_command_by_default(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch(
            "cve2checker.codeql.subprocess.run", return_value=completed
        ) as run:
            create_cpp_database("src", "db")

        self.assertEqual(
            run.call_args.args[0],
            [
                "codeql",
                "database",
                "create",
                "--language=cpp",
                "--source-root=src",
                "--build-mode=autobuild",
                "--",
                "db",
            ],
        )

    def test_create_cpp_database_rejects_an_empty_build_command(self) -> None:
        with patch("cve2checker.codeql.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "build_command must be non-empty"):
                create_cpp_database("src", "db", build_command=" ")

        run.assert_not_called()

    def test_compile_query_uses_query_compile(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch(
            "cve2checker.codeql.subprocess.run", return_value=completed
        ) as run:
            result = compile_query("queries/check.ql", codeql_path="/tools/codeql")

        self.assertIs(result, completed)
        run.assert_called_once_with(
            ["/tools/codeql", "query", "compile", "--", "queries/check.ql"],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            cwd=None,
        )

    def test_analyze_query_writes_sarif_2_1_0(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch(
            "cve2checker.codeql.subprocess.run", return_value=completed
        ) as run:
            result = analyze_query(
                "db",
                "queries/check.ql",
                "results/check.sarif",
                codeql_path="custom-codeql",
            )

        self.assertIs(result, completed)
        run.assert_called_once_with(
            [
                "custom-codeql",
                "database",
                "analyze",
                "--format=sarifv2.1.0",
                "--output=results/check.sarif",
                "--",
                "db",
                "queries/check.ql",
            ],
            shell=False,
            check=False,
            capture_output=True,
            text=True,
            cwd=None,
        )

    def test_missing_cli_executable_has_actionable_error(self) -> None:
        with patch(
            "cve2checker.codeql.subprocess.run",
            side_effect=FileNotFoundError("not found"),
        ):
            with self.assertRaises(CodeQLError) as raised:
                compile_query("query.ql", codeql_path="missing-codeql")

        self.assertIn("missing-codeql", str(raised.exception))
        self.assertIn("Install the CodeQL CLI", str(raised.exception))
        self.assertIn("codeql_path", str(raised.exception))

    def test_nonzero_cli_exit_includes_status_and_diagnostic(self) -> None:
        failed = subprocess.CompletedProcess(
            [], 17, stdout="", stderr="compiler could not find the database"
        )
        with patch("cve2checker.codeql.subprocess.run", return_value=failed):
            with self.assertRaises(CodeQLError) as raised:
                analyze_query("db", "query.ql", "result.sarif")

        self.assertIn("CodeQL database analyze", str(raised.exception))
        self.assertIn("exit code 17", str(raised.exception))
        self.assertIn("compiler could not find the database", str(raised.exception))

    def test_pack_install_and_ci_use_pack_root(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch(
            "cve2checker.codeql.subprocess.run", return_value=completed
        ) as run:
            install_pack("codeql-pack", codeql_path="custom-codeql")
            verify_pack("codeql-pack", codeql_path="custom-codeql")

        expected_root = str(Path("codeql-pack").resolve())
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["custom-codeql", "pack", "install", "--", expected_root],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["custom-codeql", "pack", "ci", "--", expected_root],
        )
        self.assertEqual(run.call_args_list[0].kwargs["cwd"], expected_root)
        self.assertEqual(run.call_args_list[1].kwargs["cwd"], expected_root)

    def test_create_cpp_database_supports_none_build_mode(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with patch(
            "cve2checker.codeql.subprocess.run", return_value=completed
        ) as run:
            create_cpp_database("src", "db", build_mode="none")

        self.assertIn("--build-mode=none", run.call_args.args[0])

    def test_create_cpp_database_rejects_conflicting_build_options(self) -> None:
        with patch("cve2checker.codeql.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "mutually exclusive"):
                create_cpp_database(
                    "src", "db", build_command="make", build_mode="autobuild"
                )
            with self.assertRaisesRegex(ValueError, "build_mode must be"):
                create_cpp_database("src", "db", build_mode="magic")

        run.assert_not_called()

    def test_analyze_query_creates_output_parent(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with TemporaryDirectory() as temporary_directory:
            sarif = Path(temporary_directory) / "nested" / "result.sarif"
            with patch(
                "cve2checker.codeql.subprocess.run", return_value=completed
            ):
                analyze_query("db", "query.ql", sarif)
            self.assertTrue(sarif.parent.is_dir())

    def test_ensure_query_pack_creates_and_installs_pack(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "synthesis"
            with patch("cve2checker.codeql.install_pack") as install:
                result = ensure_query_pack(root)
            self.assertEqual(result, root.resolve())
            qlpack = (root / "qlpack.yml").read_text(encoding="utf-8")
            self.assertIn("codeql/cpp-all: 12.2.0", qlpack)
            install.assert_called_once_with(root.resolve(), codeql_path="codeql")

    def test_ensure_query_pack_reuses_ancestor_pack(self) -> None:
        with TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "qlpack.yml").write_text("name: test/pack\n", encoding="utf-8")
            child = root / "synthesis"
            with patch("cve2checker.codeql.install_pack") as install:
                result = ensure_query_pack(child)
            self.assertFalse((child / "qlpack.yml").exists())
            self.assertEqual(result, child.resolve())
            install.assert_not_called()

    def test_query_in_pack_runs_from_pack_root_with_absolute_paths(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with TemporaryDirectory() as temporary_directory:
            pack_root = Path(temporary_directory)
            query = pack_root / "queries" / "check.ql"
            query.parent.mkdir()
            query.write_text("import cpp\n", encoding="utf-8")
            (pack_root / "qlpack.yml").write_text("name: test/pack\n", encoding="utf-8")
            output = pack_root / "results.sarif"

            with patch(
                "cve2checker.codeql.subprocess.run", return_value=completed
            ) as run:
                compile_query(query)
                compile_call = run.call_args
                analyze_query("db", query, output)
                analyze_call = run.call_args

        self.assertEqual(compile_call.kwargs["cwd"], str(pack_root))
        self.assertEqual(compile_call.args[0][-1], str(query))
        self.assertEqual(analyze_call.kwargs["cwd"], str(pack_root))
        self.assertEqual(analyze_call.args[0][-2], str(Path("db").resolve()))
        self.assertEqual(analyze_call.args[0][-1], str(query))
        self.assertIn(f"--output={output}", analyze_call.args[0])


if __name__ == "__main__":
    unittest.main()
