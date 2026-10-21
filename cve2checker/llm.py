"""Pluggable LLM clients used by the analysis and synthesis agents."""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class LLMError(RuntimeError):
    """An LLM endpoint could not be reached or returned an invalid response."""


class LLMClient(Protocol):
    def complete(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str: ...


@dataclass
class ScriptedLLM:
    """Deterministic test backend that returns pre-recorded responses."""

    responses: Sequence[str]
    calls: list[dict[str, Any]] = field(default_factory=list)
    _index: int = 0

    def complete(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> str:
        self.calls.append(
            {
                "system": system,
                "user": user,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
        )
        if self._index >= len(self.responses):
            raise LLMError("scripted LLM has no response left")
        response = self.responses[self._index]
        self._index += 1
        if isinstance(response, Exception):
            raise response
        return str(response)


class OpenAICompatibleClient:
    """Minimal standards-compatible chat-completions client.

    Works with OpenAI, Ollama, LM Studio, vLLM, and similar endpoints. The
    base URL may end in ``/v1`` or already include ``/chat/completions``.
    """

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout: float = 180.0,
        extra_headers: dict[str, str] | None = None,
        session_id: str | None = None,
        max_tokens: int = 16_384,
    ):
        if not base_url or not base_url.strip():
            raise LLMError("base_url must not be empty")
        if not model or not model.strip():
            raise LLMError("model must not be empty")
        if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
            raise LLMError("max_tokens must be a positive integer")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = float(timeout)
        self.extra_headers = dict(extra_headers or {})
        self.session_id = session_id or uuid.uuid4().hex
        self.default_max_tokens = max_tokens

    @classmethod
    def from_env(cls, prefix: str = "CVE2CHECKER_LLM") -> "OpenAICompatibleClient":
        base_url = os.environ.get(f"{prefix}_BASE_URL", "")
        model = os.environ.get(f"{prefix}_MODEL", "")
        if not base_url or not model:
            raise LLMError(
                f"set {prefix}_BASE_URL and {prefix}_MODEL to use the LLM backend"
            )
        return cls(
            base_url=base_url,
            model=model,
            api_key=(
                os.environ.get(f"{prefix}_API_KEY")
                or os.environ.get("OPENCODE_API_KEY")
                or None
            ),
            timeout=float(os.environ.get(f"{prefix}_TIMEOUT", "180")),
            max_tokens=int(os.environ.get(f"{prefix}_MAX_TOKENS", "16384")),
        )

    @property
    def endpoint(self) -> str:
        if self.base_url.endswith("/chat/completions"):
            return self.base_url
        return f"{self.base_url}/chat/completions"

    def complete(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> str:
        effective_max_tokens = (
            self.default_max_tokens if max_tokens is None else int(max_tokens)
        )
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": float(temperature),
            "max_tokens": effective_max_tokens,
        }
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "cve2checker/0.1",
            **self.extra_headers,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if "opencode.ai" in self.base_url:
            headers.setdefault("x-opencode-session", self.session_id)
        request = Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read()
        except HTTPError as exc:
            detail = _read_error_body(exc)
            raise LLMError(
                f"LLM endpoint returned HTTP {exc.code}: {detail}"
            ) from exc
        except URLError as exc:
            raise LLMError(f"could not reach LLM endpoint: {exc.reason}") from exc
        except TimeoutError as exc:
            raise LLMError("LLM request timed out") from exc
        except OSError as exc:
            raise LLMError(f"could not read LLM response: {exc}") from exc

        try:
            decoded = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise LLMError("LLM endpoint returned invalid JSON") from exc
        return _content_from_response(decoded)


class RetryingLLM:
    """Retry transient endpoint failures with exponential backoff."""

    def __init__(
        self,
        client: LLMClient,
        *,
        attempts: int = 3,
        backoff: float = 2.0,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if attempts < 1:
            raise LLMError("attempts must be at least 1")
        self.client = client
        self.attempts = attempts
        self.backoff = float(backoff)
        self.sleep = sleep

    def complete(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> str:
        last_error: LLMError | None = None
        for attempt in range(1, self.attempts + 1):
            try:
                return self.client.complete(
                    system,
                    user,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except LLMError as exc:
                last_error = exc
                if attempt >= self.attempts or not _retryable(exc):
                    raise
                self.sleep(self.backoff * (2 ** (attempt - 1)))
        raise last_error or LLMError("LLM request failed")


class FallbackLLM:
    """Try multiple models in order, moving on only after an LLM failure."""

    def __init__(self, clients: Sequence[LLMClient]):
        self.clients = list(clients)
        if not self.clients:
            raise LLMError("at least one LLM client is required")

    def complete(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> str:
        last_error: LLMError | None = None
        for client in self.clients:
            try:
                return client.complete(
                    system,
                    user,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except LLMError as exc:
                last_error = exc
        raise last_error or LLMError("all LLM clients failed")


def build_llm_client(
    *,
    base_url: str,
    model: str,
    api_key: str | None = None,
    timeout: float = 180.0,
    max_tokens: int = 32_768,
    fallback_models: Sequence[str] | None = None,
    attempts: int = 3,
    backoff: float = 2.0,
) -> LLMClient:
    models = [model]
    for fallback in fallback_models or []:
        if fallback and fallback not in models:
            models.append(fallback)
    clients = [
        OpenAICompatibleClient(
            base_url=base_url,
            model=candidate,
            api_key=api_key,
            timeout=timeout,
            max_tokens=max_tokens,
        )
        for candidate in models
    ]
    inner: LLMClient = clients[0] if len(clients) == 1 else FallbackLLM(clients)
    return RetryingLLM(inner, attempts=attempts, backoff=backoff)


def llm_from_env(prefix: str = "CVE2CHECKER_LLM") -> LLMClient:
    base_url = os.environ.get(f"{prefix}_BASE_URL", "")
    model = os.environ.get(f"{prefix}_MODEL", "")
    if not base_url or not model:
        raise LLMError(
            f"set {prefix}_BASE_URL and {prefix}_MODEL to use the LLM backend"
        )
    fallback_models = [
        item.strip()
        for item in os.environ.get(f"{prefix}_FALLBACK_MODELS", "").replace(
            ";", ","
        ).split(",")
        if item.strip()
    ]
    return build_llm_client(
        base_url=base_url,
        model=model,
        api_key=(
            os.environ.get(f"{prefix}_API_KEY")
            or os.environ.get("OPENCODE_API_KEY")
            or None
        ),
        timeout=float(os.environ.get(f"{prefix}_TIMEOUT", "180")),
        max_tokens=int(os.environ.get(f"{prefix}_MAX_TOKENS", "32768")),
        fallback_models=fallback_models,
        attempts=int(os.environ.get(f"{prefix}_RETRIES", "3")),
        backoff=float(os.environ.get(f"{prefix}_BACKOFF", "2")),
    )


def _retryable(error: LLMError) -> bool:
    message = str(error).lower()
    non_retryable = ("http 400", "http 401", "http 403", "http 404")
    if any(marker in message for marker in non_retryable):
        return False
    retryable = (
        "http 429",
        "http 500",
        "http 502",
        "http 503",
        "http 504",
        "timed out",
        "timeout",
        "could not reach",
        "connection",
        "temporarily",
        "overloaded",
    )
    return any(marker in message for marker in retryable)


def _content_from_response(payload: Any) -> str:
    if not isinstance(payload, dict):
        raise LLMError("LLM response must be a JSON object")
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise LLMError("LLM response is missing choices")
    choice = choices[0]
    if not isinstance(choice, dict):
        raise LLMError("LLM choice must be an object")
    message = choice.get("message")
    if not isinstance(message, dict):
        raise LLMError("LLM response is missing message")
    content = message.get("content")
    text = ""
    if isinstance(content, str):
        text = content
    elif isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        text = "\n".join(parts)
    if text.strip():
        return text

    finish_reason = choice.get("finish_reason")
    reasoning = message.get("reasoning_content")
    if finish_reason == "length":
        raise LLMError(
            "model exhausted max_tokens before producing final content; "
            "increase CVE2CHECKER_LLM_MAX_TOKENS and retry"
        )
    if isinstance(reasoning, str) and reasoning.strip():
        raise LLMError(
            "model returned reasoning_content but empty final content; "
            "retry with a larger CVE2CHECKER_LLM_MAX_TOKENS"
        )
    raise LLMError("LLM response is missing text content")


def _read_error_body(error: HTTPError) -> str:
    try:
        body = error.read().decode("utf-8", errors="replace").strip()
    except OSError:
        return str(error.reason)
    return body[:2000] or str(error.reason)
