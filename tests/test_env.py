import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cve2checker.env import load_dotenv, project_env_paths, set_env_value


class DotEnvTests(unittest.TestCase):
    def test_loads_values_comments_quotes_and_exports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "# comment\n"
                "PLAIN=value\n"
                "export EXPORTED=two\n"
                "QUOTED='three four'\n"
                "DOUBLE=\"five\"\n"
                "WITH_COMMENT=six # trailing\n"
                "MALFORMED LINE\n"
                "=nokey\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {}, clear=True):
                loaded = load_dotenv([path])
                self.assertEqual(loaded, [path])
                self.assertEqual(os.environ["PLAIN"], "value")
                self.assertEqual(os.environ["EXPORTED"], "two")
                self.assertEqual(os.environ["QUOTED"], "three four")
                self.assertEqual(os.environ["DOUBLE"], "five")
                self.assertEqual(os.environ["WITH_COMMENT"], "six")
                self.assertNotIn("MALFORMED LINE", os.environ)

    def test_existing_environment_wins_unless_override(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("CVE2CHECKER_LLM_API_KEY=file-key\n", encoding="utf-8")
            with patch.dict(
                os.environ, {"CVE2CHECKER_LLM_API_KEY": "process-key"}, clear=True
            ):
                load_dotenv([path])
                self.assertEqual(os.environ["CVE2CHECKER_LLM_API_KEY"], "process-key")
                load_dotenv([path], override=True)
                self.assertEqual(os.environ["CVE2CHECKER_LLM_API_KEY"], "file-key")

    def test_set_env_value_replaces_and_appends_without_touching_other_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text(
                "# keep me\nBASE=value\nOPENCODE_API_KEY=old\n",
                encoding="utf-8",
            )
            set_env_value(path, "OPENCODE_API_KEY", "new-key")
            set_env_value(path, "EXTRA", "added")
            text = path.read_text(encoding="utf-8")
            self.assertIn("# keep me", text)
            self.assertIn("BASE=value", text)
            self.assertIn("OPENCODE_API_KEY=new-key", text)
            self.assertIn("EXTRA=added", text)
            self.assertNotIn("OPENCODE_API_KEY=old", text)
            self.assertEqual(text.count("OPENCODE_API_KEY="), 1)

    def test_set_env_value_rejects_invalid_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            with self.assertRaises(ValueError):
                set_env_value(path, "BAD KEY", "value")
            with self.assertRaises(ValueError):
                set_env_value(path, "KEY", "")

    def test_missing_file_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(load_dotenv([Path(directory) / "missing.env"]), [])

    def test_project_paths_include_project_root(self) -> None:
        paths = project_env_paths()
        self.assertTrue(paths)
        self.assertEqual(paths[0].name, ".env")


if __name__ == "__main__":
    unittest.main()
