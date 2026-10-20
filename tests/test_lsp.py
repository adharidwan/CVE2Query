import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from cve2checker.lsp import CodeQLLanguageServer, LSPError

FAKE_SERVER = r'''
import json
import sys


def read_message():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line in (b"\r\n", b"\n"):
            break
        key, value = line.decode("ascii").split(":", 1)
        headers[key.strip().lower()] = value.strip()
    length = int(headers.get("content-length", "0"))
    if length <= 0:
        return None
    return json.loads(sys.stdin.buffer.read(length))


def send(message):
    body = json.dumps(message).encode("utf-8")
    sys.stdout.buffer.write(
        f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
    )
    sys.stdout.buffer.flush()


while True:
    message = read_message()
    if message is None:
        break
    method = message.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"capabilities": {}}})
    elif method == "initialized":
        send(
            {
                "jsonrpc": "2.0",
                "id": 900,
                "method": "workspace/configuration",
                "params": {"items": [{"section": "codeql"}]},
            }
        )
    elif method in ("textDocument/didOpen", "textDocument/didChange"):
        uri = message["params"]["textDocument"]["uri"]
        text = message["params"]["textDocument"].get("text")
        if text is None:
            changes = message["params"].get("contentChanges") or []
            text = changes[0]["text"] if changes else ""
        diagnostics = []
        if "BROKEN" in text:
            diagnostics = [
                {
                    "range": {
                        "start": {"line": 0, "character": 0},
                        "end": {"line": 0, "character": 1},
                    },
                    "severity": 1,
                    "message": "fake error",
                }
            ]
        send(
            {
                "jsonrpc": "2.0",
                "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": diagnostics},
            }
        )
    elif method == "textDocument/hover":
        send(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"contents": "hover text"},
            }
        )
    elif method == "textDocument/completion":
        send(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"items": [{"label": "Source"}]},
            }
        )
    elif method == "textDocument/formatting":
        send(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": [
                    {
                        "range": {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": 0},
                        },
                        "newText": "formatted",
                    }
                ],
            }
        )
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": message["id"], "result": None})
    elif method == "exit":
        break
'''


class LSPClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.pack = self.root / "pack"
        self.pack.mkdir()
        (self.pack / "qlpack.yml").write_text(
            "name: test/pack\nversion: 0.0.1\n", encoding="utf-8"
        )
        self.server = self.root / "fake_lsp.py"
        self.server.write_text(FAKE_SERVER, encoding="utf-8")
        self.query = self.pack / "query.ql"
        self.query.write_text("import cpp\n", encoding="utf-8")
        self.client = CodeQLLanguageServer(
            pack_root=self.pack,
            request_timeout=10.0,
            server_command=[sys.executable, str(self.server)],
        )

    def tearDown(self) -> None:
        try:
            self.client.stop()
        finally:
            self.temporary_directory.cleanup()

    def test_start_update_and_empty_diagnostics(self) -> None:
        self.client.start()
        self.client.update_file(self.query, "import cpp\n")
        diagnostics = self.client.diagnostics(self.query)
        self.assertEqual(diagnostics, [])

    def test_broken_content_returns_diagnostics(self) -> None:
        self.client.start()
        self.query.write_text("BROKEN\n", encoding="utf-8")
        diagnostics = self.client.diagnostics(self.query)
        self.assertEqual(len(diagnostics), 1)
        self.assertEqual(diagnostics[0]["message"], "fake error")

    def test_hover_completion_and_format(self) -> None:
        self.client.start()
        self.client.update_file(self.query, "import cpp\n")
        hover = self.client.hover(self.query, 0, 2)
        self.assertEqual(hover["contents"], "hover text")
        completion = self.client.complete(self.query, 0, 2)
        self.assertEqual(completion["items"][0]["label"], "Source")
        edits = self.client.format(self.query)
        self.assertEqual(edits[0]["newText"], "formatted")

    def test_close_and_stop_are_idempotent(self) -> None:
        self.client.start()
        self.client.close_file(self.query)
        self.client.stop()
        self.client.stop()

    def test_missing_executable_has_actionable_error(self) -> None:
        missing = self.root / "missing-codeql.exe"
        client = CodeQLLanguageServer(
            codeql_path=str(missing), pack_root=self.pack, request_timeout=5.0
        )
        with self.assertRaisesRegex(LSPError, "was not found"):
            client.start()


@unittest.skipUnless(
    os.environ.get("CVE2CHECKER_LSP_INTEGRATION") == "1",
    "set CVE2CHECKER_LSP_INTEGRATION=1 to run the real CodeQL LSP test",
)
class RealCodeQLLSPTests(unittest.TestCase):
    def test_baseline_query_has_no_diagnostics_and_broken_query_does(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        codeql = project_root / ".tools" / "codeql" / "codeql.cmd"
        if not codeql.is_file():
            self.skipTest("pinned CodeQL bundle is not installed")
        client = CodeQLLanguageServer(
            codeql_path=codeql,
            pack_root=project_root / "codeql-pack",
            request_timeout=120.0,
        )
        client.start()
        temporary = None
        try:
            baseline = (
                project_root
                / "codeql-pack"
                / "queries"
                / "BaselineDirectStrcpyCall.ql"
            )
            self.assertEqual(client.diagnostics(baseline), [])

            temporary = tempfile.TemporaryDirectory(
                dir=project_root / "codeql-pack"
            )
            broken = Path(temporary.name) / "broken.ql"
            broken.write_text(
                "import cpp\n\nfrom NoSuchType n\nselect n\n", encoding="utf-8"
            )
            diagnostics = client.diagnostics(broken)
            self.assertTrue(diagnostics)
        finally:
            client.stop()
            if temporary is not None:
                temporary.cleanup()


if __name__ == "__main__":
    unittest.main()
