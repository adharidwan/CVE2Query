import io
import json
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from cve2checker.llm import (
    FallbackLLM,
    LLMError,
    OpenAICompatibleClient,
    RetryingLLM,
    ScriptedLLM,
    _content_from_response,
    llm_from_env,
)


class FakeResponse:
    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class ScriptedLLMTests(unittest.TestCase):
    def test_returns_responses_and_records_calls(self) -> None:
        llm = ScriptedLLM(["one", "two"])
        self.assertEqual(llm.complete("system", "first"), "one")
        self.assertEqual(llm.complete("system", "second"), "two")
        self.assertEqual(len(llm.calls), 2)
        self.assertEqual(llm.calls[0]["user"], "first")

    def test_exhaustion_raises(self) -> None:
        llm = ScriptedLLM([])
        with self.assertRaises(LLMError):
            llm.complete("system", "user")


class OpenAICompatibleTests(unittest.TestCase):
    def test_builds_request_and_parses_content(self) -> None:
        payload = {
            "choices": [{"message": {"content": '{"ok": true}'}}],
        }
        with patch(
            "cve2checker.llm.urlopen", return_value=FakeResponse(payload)
        ) as urlopen:
            client = OpenAICompatibleClient(
                base_url="http://localhost:11434/v1",
                model="test-model",
                api_key="secret",
            )
            result = client.complete("system", "user", temperature=0.2, max_tokens=100)

        self.assertEqual(result, '{"ok": true}')
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://localhost:11434/v1/chat/completions")
        self.assertEqual(request.get_header("Authorization"), "Bearer secret")
        body = json.loads(request.data)
        self.assertEqual(body["model"], "test-model")
        self.assertEqual(body["messages"][0]["role"], "system")
        self.assertEqual(body["temperature"], 0.2)
        self.assertEqual(body["max_tokens"], 100)

    def test_accepts_full_endpoint_and_content_parts(self) -> None:
        payload = {
            "choices": [
                {"message": {"content": [{"type": "text", "text": "hello"}]}}
            ]
        }
        with patch("cve2checker.llm.urlopen", return_value=FakeResponse(payload)):
            client = OpenAICompatibleClient(
                base_url="http://localhost/v1/chat/completions", model="m"
            )
            self.assertEqual(client.complete("s", "u"), "hello")
        self.assertEqual(client.endpoint, "http://localhost/v1/chat/completions")

    def test_http_error_includes_status_and_body(self) -> None:
        error = HTTPError(
            "http://localhost", 500, "Server Error", None, io.BytesIO(b"boom")
        )
        with patch("cve2checker.llm.urlopen", side_effect=error):
            client = OpenAICompatibleClient(base_url="http://localhost", model="m")
            with self.assertRaisesRegex(LLMError, "HTTP 500.*boom"):
                client.complete("s", "u")

    def test_invalid_response_shapes_raise(self) -> None:
        with self.assertRaisesRegex(LLMError, "choices"):
            _content_from_response({})
        with self.assertRaisesRegex(LLMError, "message"):
            _content_from_response({"choices": [{}]})
        with self.assertRaisesRegex(LLMError, "text content"):
            _content_from_response({"choices": [{"message": {"content": 1}}]})

    def test_empty_content_with_reasoning_has_actionable_error(self) -> None:
        payload = {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": "", "reasoning_content": "thinking"},
                }
            ]
        }
        with self.assertRaisesRegex(LLMError, "reasoning_content"):
            _content_from_response(payload)

    def test_length_finish_has_max_tokens_hint(self) -> None:
        payload = {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": ""},
                }
            ]
        }
        with self.assertRaisesRegex(LLMError, "MAX_TOKENS"):
            _content_from_response(payload)

    def test_from_env(self) -> None:
        environment = {
            "TESTLLM_BASE_URL": "http://example.test/v1",
            "TESTLLM_MODEL": "model-x",
            "TESTLLM_API_KEY": "key",
        }
        with patch.dict(os.environ, environment, clear=False):
            client = OpenAICompatibleClient.from_env(prefix="TESTLLM")
        self.assertEqual(client.base_url, "http://example.test/v1")
        self.assertEqual(client.model, "model-x")
        self.assertEqual(client.api_key, "key")

    def test_from_env_uses_opencode_key_fallback(self) -> None:
        environment = {
            "TESTLLM_BASE_URL": "http://example.test/v1",
            "TESTLLM_MODEL": "model-x",
            "OPENCODE_API_KEY": "opencode-key",
        }
        with patch.dict(os.environ, environment, clear=True):
            client = OpenAICompatibleClient.from_env(prefix="TESTLLM")
        self.assertEqual(client.api_key, "opencode-key")

    def test_from_env_requires_configuration(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(LLMError, "BASE_URL"):
                OpenAICompatibleClient.from_env(prefix="MISSING")


class RetryAndFallbackTests(unittest.TestCase):
    def test_retries_transient_errors(self) -> None:
        class Flaky:
            def __init__(self):
                self.calls = 0

            def complete(self, system, user, *, temperature=0.0, max_tokens=None):
                self.calls += 1
                if self.calls == 1:
                    raise LLMError("HTTP 503: upstream unavailable")
                return "ok"

        client = Flaky()
        sleeps = []
        retrying = RetryingLLM(client, attempts=3, backoff=1.0, sleep=sleeps.append)
        self.assertEqual(retrying.complete("s", "u"), "ok")
        self.assertEqual(client.calls, 2)
        self.assertEqual(sleeps, [1.0])

    def test_does_not_retry_auth_errors(self) -> None:
        class Unauthorized:
            def __init__(self):
                self.calls = 0

            def complete(self, system, user, *, temperature=0.0, max_tokens=None):
                self.calls += 1
                raise LLMError("HTTP 401: invalid key")

        client = Unauthorized()
        retrying = RetryingLLM(client, attempts=3, sleep=lambda _: None)
        with self.assertRaises(LLMError):
            retrying.complete("s", "u")
        self.assertEqual(client.calls, 1)

    def test_fallback_uses_next_model(self) -> None:
        class Failing:
            def complete(self, system, user, *, temperature=0.0, max_tokens=None):
                raise LLMError("HTTP 503")

        class Working:
            def complete(self, system, user, *, temperature=0.0, max_tokens=None):
                return "from fallback"

        fallback = FallbackLLM([Failing(), Working()])
        self.assertEqual(fallback.complete("s", "u"), "from fallback")

    def test_llm_from_env_builds_fallbacks(self) -> None:
        environment = {
            "TESTLLM_BASE_URL": "https://example.test/v1",
            "TESTLLM_MODEL": "primary",
            "TESTLLM_FALLBACK_MODELS": "backup-a,backup-b",
            "TESTLLM_API_KEY": "key",
            "TESTLLM_MAX_TOKENS": "1024",
            "TESTLLM_RETRIES": "2",
        }
        with patch.dict(os.environ, environment, clear=True):
            client = llm_from_env(prefix="TESTLLM")
        self.assertIsInstance(client, RetryingLLM)
        self.assertIsInstance(client.client, FallbackLLM)
        self.assertEqual(
            [item.model for item in client.client.clients],
            ["primary", "backup-a", "backup-b"],
        )


if __name__ == "__main__":
    unittest.main()
