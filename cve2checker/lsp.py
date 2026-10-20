"""Minimal JSON-RPC client for the CodeQL language server."""

from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from collections import deque
from collections.abc import Sequence
from pathlib import Path
from typing import Any


class LSPError(RuntimeError):
    """The CodeQL language server could not be started or did not answer."""


class CodeQLLanguageServer:
    """A synchronous client for ``codeql execute language-server``.

    Positions accepted by the public methods are zero-based, matching LSP.
    The server is started with the query pack as its workspace root so QL
    imports resolve from the pack's ``qlpack.yml`` dependencies.
    """

    def __init__(
        self,
        codeql_path: str | os.PathLike[str] = "codeql",
        pack_root: str | os.PathLike[str] = "codeql-pack",
        *,
        request_timeout: float = 90.0,
        server_command: Sequence[str] | None = None,
    ):
        self._server_command = (
            [os.fspath(part) for part in server_command]
            if server_command is not None
            else None
        )
        self._codeql_path = (
            "" if server_command is not None else _resolve_executable(codeql_path)
        )
        self._pack_root = Path(pack_root).expanduser().resolve()
        self._request_timeout = float(request_timeout)
        self._process: subprocess.Popen[bytes] | None = None
        self._reader_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._write_lock = threading.Lock()
        self._pending: dict[int, queue.Queue[dict]] = {}
        self._next_id = 0
        self._document_versions: dict[str, int] = {}
        self._diagnostic_queues: dict[str, list[queue.Queue[dict]]] = {}
        self._stderr_tail: deque[str] = deque(maxlen=40)
        self._closed = False

    @property
    def pack_root(self) -> Path:
        return self._pack_root

    def start(self) -> "CodeQLLanguageServer":
        if self._process is not None:
            return self
        if not self._pack_root.is_dir():
            raise LSPError(f"CodeQL pack root does not exist: {self._pack_root}")

        command = (
            list(self._server_command)
            if self._server_command is not None
            else [
                self._codeql_path,
                "execute",
                "language-server",
                "--check-errors",
                "ON_CHANGE",
            ]
        )
        try:
            self._process = subprocess.Popen(
                command,
                cwd=str(self._pack_root),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as exc:
            raise LSPError(
                f"CodeQL executable {self._codeql_path!r} was not found; "
                "pass codeql_path or install the pinned bundle."
            ) from exc
        except OSError as exc:
            raise LSPError(f"could not start CodeQL language server: {exc}") from exc

        self._closed = False
        self._reader_thread = threading.Thread(
            target=self._read_messages, name="codeql-lsp-reader", daemon=True
        )
        self._reader_thread.start()
        self._stderr_thread = threading.Thread(
            target=self._read_stderr, name="codeql-lsp-stderr", daemon=True
        )
        self._stderr_thread.start()

        pack_uri = self._pack_root.as_uri()
        try:
            self._request(
                "initialize",
                {
                    "processId": os.getpid(),
                    "rootUri": pack_uri,
                    "workspaceFolders": [
                        {"uri": pack_uri, "name": self._pack_root.name}
                    ],
                    "capabilities": {
                        "workspace": {
                            "configuration": True,
                            "workspaceFolders": True,
                        },
                        "textDocument": {
                            "publishDiagnostics": {"relatedInformation": True},
                            "hover": {"contentFormat": ["markdown", "plaintext"]},
                            "completion": {
                                "completionItem": {"snippetSupport": True}
                            },
                            "definition": {"linkSupport": True},
                            "references": {"dynamicRegistration": False},
                        },
                    },
                },
                timeout=self._request_timeout,
            )
        except Exception:
            self.stop()
            raise
        self._notify("initialized", {})
        return self

    def stop(self) -> None:
        process = self._process
        if process is None:
            return
        self._closed = True
        try:
            if process.poll() is None:
                try:
                    self._request("shutdown", None, timeout=5.0)
                except LSPError:
                    pass
                self._notify("exit", None)
        finally:
            self._process = None
            self._document_versions.clear()
            self._diagnostic_queues.clear()
            self._fail_pending("language server stopped")
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    process.kill()
            for stream in (process.stdin, process.stdout, process.stderr):
                try:
                    if stream is not None:
                        stream.close()
                except OSError:
                    pass

    def __enter__(self) -> "CodeQLLanguageServer":
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.stop()

    def update_file(self, path: str | os.PathLike[str], content: str) -> str:
        """Open or update a QL file and return its ``file://`` URI."""
        self._ensure_started()
        if not isinstance(content, str):
            raise LSPError("query content must be a string")
        uri = Path(path).expanduser().resolve().as_uri()
        version = self._document_versions.get(uri)
        if version is None:
            version = 1
            self._notify(
                "textDocument/didOpen",
                {
                    "textDocument": {
                        "uri": uri,
                        "languageId": "ql",
                        "version": version,
                        "text": content,
                    }
                },
            )
        else:
            version += 1
            self._notify(
                "textDocument/didChange",
                {
                    "textDocument": {"uri": uri, "version": version},
                    "contentChanges": [{"text": content}],
                },
            )
        self._document_versions[uri] = version
        self._notify(
            "textDocument/codeQLDidChangeVisibleFiles", {"visibleFiles": [uri]}
        )
        return uri

    def diagnostics(
        self, path: str | os.PathLike[str], *, timeout: float | None = None
    ) -> list[dict[str, Any]]:
        """Return the diagnostics published for a QL file.

        A ``didChange`` is sent first so the server re-checks the current
        content. The newest publication after that change is returned.
        """
        self._ensure_started()
        uri = Path(path).expanduser().resolve().as_uri()
        notifications: queue.Queue[dict] = queue.Queue()
        self._diagnostic_queues.setdefault(uri, []).append(notifications)
        try:
            content = Path(path).expanduser().read_text(encoding="utf-8")
            self.update_file(path, content)
            deadline = time.monotonic() + (
                self._request_timeout if timeout is None else float(timeout)
            )
            result: dict[str, Any] | None = None
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    if result is None:
                        raise LSPError(
                            f"timed out waiting for CodeQL diagnostics for {path}"
                        )
                    return list(result.get("diagnostics") or [])
                try:
                    message = notifications.get(timeout=min(remaining, 1.0))
                except queue.Empty:
                    continue
                result = message
                # Let a second publication from the same change replace the
                # first one if it arrives shortly after.
                try:
                    newer = notifications.get(timeout=0.25)
                except queue.Empty:
                    newer = None
                if newer is not None:
                    result = newer
                return list(result.get("diagnostics") or [])
        finally:
            listeners = self._diagnostic_queues.get(uri, [])
            if notifications in listeners:
                listeners.remove(notifications)
            if not listeners:
                self._diagnostic_queues.pop(uri, None)

    def complete(
        self,
        path: str | os.PathLike[str],
        line: int,
        character: int,
        *,
        trigger_character: str | None = None,
    ) -> Any:
        uri = self._file_uri(path)
        context: dict[str, Any] = {"triggerKind": 2 if trigger_character else 1}
        if trigger_character:
            context["triggerCharacter"] = trigger_character
        return self._request(
            "textDocument/completion",
            {
                "textDocument": {"uri": uri},
                "position": {"line": int(line), "character": int(character)},
                "context": context,
            },
        )

    def hover(
        self, path: str | os.PathLike[str], line: int, character: int
    ) -> Any:
        return self._request(
            "textDocument/hover",
            {
                "textDocument": {"uri": self._file_uri(path)},
                "position": {"line": int(line), "character": int(character)},
            },
        )

    def definition(
        self, path: str | os.PathLike[str], line: int, character: int
    ) -> Any:
        return self._request(
            "textDocument/definition",
            {
                "textDocument": {"uri": self._file_uri(path)},
                "position": {"line": int(line), "character": int(character)},
            },
        )

    def references(
        self,
        path: str | os.PathLike[str],
        line: int,
        character: int,
        *,
        include_declaration: bool = True,
    ) -> Any:
        return self._request(
            "textDocument/references",
            {
                "textDocument": {"uri": self._file_uri(path)},
                "position": {"line": int(line), "character": int(character)},
                "context": {"includeDeclaration": bool(include_declaration)},
            },
        )

    def format(self, path: str | os.PathLike[str], *, tab_size: int = 2) -> Any:
        return self._request(
            "textDocument/formatting",
            {
                "textDocument": {"uri": self._file_uri(path)},
                "options": {"tabSize": int(tab_size), "insertSpaces": True},
            },
        )

    def close_file(self, path: str | os.PathLike[str]) -> None:
        uri = Path(path).expanduser().resolve().as_uri()
        if uri not in self._document_versions:
            return
        self._notify("textDocument/didClose", {"textDocument": {"uri": uri}})
        self._document_versions.pop(uri, None)

    def _file_uri(self, path: str | os.PathLike[str]) -> str:
        self._ensure_started()
        return Path(path).expanduser().resolve().as_uri()

    def _ensure_started(self) -> None:
        if self._process is None:
            self.start()
        if self._process is None or self._process.poll() is not None:
            raise LSPError(self._exit_message())

    def _exit_message(self) -> str:
        detail = "\n".join(self._stderr_tail).strip()
        message = "CodeQL language server is not running"
        if detail:
            message += f": {detail[-2000:]}"
        return message

    def _request(
        self, method: str, params: Any, *, timeout: float | None = None
    ) -> Any:
        self._ensure_started()
        request_id = self._next_id
        self._next_id += 1
        response_queue: queue.Queue[dict] = queue.Queue(maxsize=1)
        self._pending[request_id] = response_queue
        try:
            self._send(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": method,
                    "params": params,
                }
            )
            wait = self._request_timeout if timeout is None else float(timeout)
            try:
                message = response_queue.get(timeout=wait)
            except queue.Empty as exc:
                raise LSPError(
                    f"timed out waiting for CodeQL language server method {method}"
                ) from exc
        finally:
            self._pending.pop(request_id, None)

        if "error" in message:
            error = message["error"]
            raise LSPError(f"CodeQL language server rejected {method}: {error}")
        return message.get("result")

    def _notify(self, method: str, params: Any) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _send(self, message: dict[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise LSPError(self._exit_message())
        body = json.dumps(message, ensure_ascii=False).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        with self._write_lock:
            try:
                process.stdin.write(header + body)
                process.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                raise LSPError(self._exit_message()) from exc

    def _read_messages(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        stream = process.stdout
        try:
            while True:
                headers: dict[str, str] = {}
                while True:
                    line = stream.readline()
                    if not line:
                        return
                    if line in (b"\r\n", b"\n"):
                        break
                    try:
                        key, value = line.decode("ascii").split(":", 1)
                    except ValueError:
                        continue
                    headers[key.strip().lower()] = value.strip()
                length = int(headers.get("content-length", "0"))
                if length <= 0:
                    continue
                body = stream.read(length)
                try:
                    message = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                self._dispatch(message)
        finally:
            self._fail_pending("CodeQL language server exited")

    def _dispatch(self, message: dict[str, Any]) -> None:
        if not isinstance(message, dict):
            return
        method = message.get("method")
        if "id" in message and method is None:
            response_queue = self._pending.get(message["id"])
            if response_queue is not None:
                try:
                    response_queue.put_nowait(message)
                except queue.Full:
                    pass
            return
        if method is None:
            return
        if "id" in message:
            self._respond_to_server(message)
            return
        if method == "textDocument/publishDiagnostics":
            params = message.get("params")
            if not isinstance(params, dict):
                return
            uri = params.get("uri")
            if not isinstance(uri, str):
                return
            for listener in list(self._diagnostic_queues.get(uri, [])):
                try:
                    listener.put_nowait(params)
                except queue.Full:
                    pass

    def _respond_to_server(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        result: Any = None
        if method == "workspace/configuration":
            params = message.get("params")
            items = params.get("items") if isinstance(params, dict) else None
            count = len(items) if isinstance(items, list) else 1
            result = [{} for _ in range(count)]
        elif method == "workspace/applyEdit":
            result = {"applied": False}
        with self._write_lock:
            process = self._process
            if process is None or process.stdin is None:
                return
            body = json.dumps(
                {"jsonrpc": "2.0", "id": message["id"], "result": result}
            ).encode("utf-8")
            try:
                process.stdin.write(
                    f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
                )
                process.stdin.flush()
            except (BrokenPipeError, OSError):
                pass

    def _read_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        for raw_line in iter(process.stderr.readline, b""):
            line = raw_line.decode("utf-8", errors="replace").rstrip()
            if line:
                self._stderr_tail.append(line)

    def _fail_pending(self, reason: str) -> None:
        for response_queue in list(self._pending.values()):
            try:
                response_queue.put_nowait(
                    {"error": {"code": -32000, "message": reason}}
                )
            except queue.Full:
                pass
        self._pending.clear()


def _resolve_executable(codeql_path: str | os.PathLike[str]) -> str:
    value = os.fspath(codeql_path)
    if not value:
        raise LSPError("CodeQL executable path must not be empty")
    if os.sep in value or (os.altsep and os.altsep in value):
        return str(Path(value).expanduser().resolve())
    return value
