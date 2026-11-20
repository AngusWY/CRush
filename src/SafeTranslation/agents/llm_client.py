from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Protocol, Sequence
from urllib.parse import urlparse

from SafeTranslation.agents.prompts import Message
from SafeTranslation.models import JsonDict, LLMResponse, TokenUsage, ToolCall


class TranslationLLMError(RuntimeError):
    pass


class TranslationLLMClient(Protocol):
    @property
    def model(self) -> str:
        pass

    async def chat(
        self,
        *,
        messages: Sequence[Message],
        tools: Sequence[JsonDict] = (),
    ) -> LLMResponse:
        pass


class OpenAICompatibleTranslationLLMClient:


    def __init__(
        self,
        *,
        role: str = "translator",
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        dotenv_path: Path | str | None = None,
        timeout_seconds: float | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
        client: Any | None = None,
    ) -> None:
        dotenv = _default_dotenv_path() if dotenv_path is None else Path(dotenv_path)
        _load_dotenv(dotenv)
        prefix = _role_prefix(role)
        self.role = role
        self._model = model or _env_str(f"{prefix}_MODEL", "")
        self.api_key = api_key or _env_str(f"{prefix}_API_KEY", "")
        self.base_url = base_url or _env_optional_str(f"{prefix}_BASE_URL")
        self.token_parameter = _env_optional_str(f"{prefix}_TOKEN_PARAMETER")
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else _env_float(f"{prefix}_TIMEOUT", 300.0 if role == "correctness" else 120.0)
        )
        self.max_tokens = (
            max_tokens
            if max_tokens is not None
            else _env_optional_int(f"{prefix}_MAX_TOKENS")
        )
        self.temperature = (
            temperature
            if temperature is not None
            else _env_optional_float(f"{prefix}_TEMPERATURE")
        )
        self._validate_config(client=client)
        self._client = client if client is not None else self._build_client()

    @property
    def model(self) -> str:
        return self._model

    async def chat(
        self,
        *,
        messages: Sequence[Message],
        tools: Sequence[JsonDict] = (),
    ) -> LLMResponse:
        _validate_messages(messages)
        request: dict[str, Any] = {
            "model": self._model,
            "messages": list(messages),
        }
        if self.temperature is not None:
            request["temperature"] = self.temperature
        if self.max_tokens is not None:
            request[self._token_parameter_name()] = self.max_tokens
        if tools:
            request["tools"] = list(tools)
            request["tool_choice"] = "auto"
        extra_body = self._extra_body()
        if extra_body:
            request["extra_body"] = extra_body

        last_error: str | None = None
        attempts = 1 if self.role == "correctness" else 3
        for attempt in range(attempts):
            try:
                response = await self._client.chat.completions.create(**request)
                content = self._response_content(response)
                response_model = str(getattr(response, "model", None) or self._model)
                return LLMResponse(
                    content=content,
                    model=response_model,
                    token_usage=self._token_usage(getattr(response, "usage", None)),
                    tool_calls=self._tool_calls(response),
                )
            except TranslationLLMError as exc:
                last_error = str(exc)
                if attempt < attempts - 1:
                    continue
            except Exception as exc:
                last_error = f"model request failed for {self._model}: {exc}"
                if attempt < attempts - 1:
                    continue
        raise TranslationLLMError(last_error or "unknown error")

    def _validate_config(self, *, client: Any | None) -> None:
        if not self._model.strip():
            raise TranslationLLMError(f"{_role_prefix(self.role)}_MODEL must not be empty")
        if client is None and not self.api_key.strip():
            raise TranslationLLMError(f"{_role_prefix(self.role)}_API_KEY must not be empty")
        if self.timeout_seconds <= 0:
            raise TranslationLLMError(f"{_role_prefix(self.role)}_TIMEOUT must be positive")
        if self.max_tokens is not None and self.max_tokens <= 0:
            raise TranslationLLMError(f"{_role_prefix(self.role)}_MAX_TOKENS must be positive")
        if self.temperature is not None and self.temperature < 0:
            raise TranslationLLMError(f"{_role_prefix(self.role)}_TEMPERATURE must be >= 0")

    def _build_client(self) -> Any:
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise TranslationLLMError(
                "the openai package is required for Translation Agent model calls"
            ) from exc

        kwargs: dict[str, Any] = {
            "api_key": self.api_key,
            "timeout": self.timeout_seconds,
        }
        if self.role == "correctness":
            kwargs["max_retries"] = 0
        if self.base_url:
            kwargs["base_url"] = _normalize_openai_base_url(self.base_url)
        return AsyncOpenAI(**kwargs)

    def _token_parameter_name(self) -> str:
        configured = (self.token_parameter or "").strip()
        if configured:
            if configured not in {"max_tokens", "max_completion_tokens"}:
                raise TranslationLLMError(
                    "TRANSLATOR_TOKEN_PARAMETER must be max_tokens or "
                    "max_completion_tokens"
                )
            return configured
        return (
            "max_completion_tokens"
            if _uses_max_completion_tokens(self._model)
            else "max_tokens"
        )

    def _extra_body(self) -> dict[str, Any]:



        if _is_gpt_family_model(self._model):
            return {}
        return {"thinking": {"type": "disabled"}}

    def _response_content(self, response: Any) -> str:
        choices = _field(response, "choices")
        if not choices:
            raise TranslationLLMError(
                "model response contains no choices; raw response: "
                f"{_response_debug_excerpt(response)}"
            )
        message = _field(choices[0], "message")
        content = _field(message, "content")
        tool_calls = _field(message, "tool_calls")
        if not isinstance(content, str) or not content.strip():
            if tool_calls:
                return ""


            reasoning = _field(message, "reasoning_content")
            finish = _field(choices[0], "finish_reason") or "?"
            if isinstance(reasoning, str) and reasoning.strip():
                raise TranslationLLMError(
                    f"model returned only reasoning content "
                    f"({len(reasoning)} chars, finish_reason={finish}); "
                    f"the output token budget may be too small — consider "
                    f"increasing *_MAX_TOKENS"
                )
            raise TranslationLLMError(
                f"model response has no text content (finish_reason={finish})"
            )
        return content.strip()

    @staticmethod
    def _tool_calls(response: Any) -> tuple[ToolCall, ...]:
        choices = _field(response, "choices")
        if not choices:
            return ()
        message = _field(choices[0], "message")
        raw_tool_calls = _field(message, "tool_calls")
        if not raw_tool_calls:
            return ()

        tool_calls: list[ToolCall] = []
        for index, raw_call in enumerate(raw_tool_calls):
            call_id = str(_field(raw_call, "id") or "")
            function = _field(raw_call, "function")
            name = str(_field(function, "name") or "")
            arguments = str(_field(function, "arguments") or "")
            if not call_id or not name:
                raise TranslationLLMError(
                    f"model returned invalid tool call at index {index}"
                )
            tool_calls.append(
                ToolCall(
                    call_id=call_id,
                    name=name,
                    arguments=arguments,
                )
            )
        return tuple(tool_calls)

    @staticmethod
    def _token_usage(usage: Any) -> TokenUsage:
        if usage is None:
            return TokenUsage()
        return TokenUsage(
            prompt_tokens=_usage_int(usage, "prompt_tokens"),
            completion_tokens=_usage_int(usage, "completion_tokens"),
            total_tokens=_usage_int(usage, "total_tokens"),
        )


def _validate_messages(messages: Sequence[Message]) -> None:
    if not messages:
        raise TranslationLLMError("model request must contain messages")
    for index, message in enumerate(messages):
        role = message.get("role")
        content = message.get("content")
        if role not in {"system", "user", "assistant", "tool"}:
            raise TranslationLLMError(
                f"message {index} has unsupported role: {role!r}"
            )
        has_tool_calls = bool(message.get("tool_calls"))
        if role == "assistant" and has_tool_calls and content in {None, ""}:
            continue
        if role == "tool":
            if not isinstance(message.get("tool_call_id"), str):
                raise TranslationLLMError(
                    f"message {index} tool_call_id must be a string"
                )
        if not isinstance(content, str) or (not content.strip() and not has_tool_calls):
            raise TranslationLLMError(f"message {index} content must not be empty")


def _usage_int(usage: Any, field: str) -> int:
    try:
        value = int(_field(usage, field) or 0)
    except (TypeError, ValueError, OverflowError):
        return 0
    return max(value, 0)


def _field(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default).strip()


def _env_optional_str(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    text = value.strip()
    return text or None


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None or not value.strip():
        return default
    try:
        return float(value)
    except ValueError as exc:
        raise TranslationLLMError(f"{name} must be a float") from exc


def _env_optional_float(name: str) -> float | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    try:
        return float(value)
    except ValueError as exc:
        raise TranslationLLMError(f"{name} must be a float") from exc


def _env_optional_int(name: str) -> int | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise TranslationLLMError(f"{name} must be an integer") from exc


def _normalize_openai_base_url(base_url: str) -> str:
    text = base_url.strip().rstrip("/")
    parsed = urlparse(text)
    if not parsed.scheme or not parsed.netloc:
        return text
    path = parsed.path.rstrip("/")
    if path and path != "/":
        return text
    return f"{text}/v1"


def _is_gpt_family_model(model: str) -> bool:
    return model.strip().lower().startswith("gpt-")


def _uses_max_completion_tokens(model: str) -> bool:
    return model.strip().lower().startswith(("gpt-5", "o1", "o3", "o4"))


def _response_debug_excerpt(response: Any) -> str:
    try:
        if hasattr(response, "model_dump_json"):
            text = response.model_dump_json(exclude_none=True)
        elif hasattr(response, "model_dump"):
            text = json.dumps(response.model_dump(), ensure_ascii=False)
        elif isinstance(response, (dict, list)):
            text = json.dumps(response, ensure_ascii=False)
        else:
            text = repr(response)
    except Exception:
        text = repr(response)
    return _redact_secrets(text)[:2000]


def _redact_secrets(text: str) -> str:
    result = text
    for key in (
        os.getenv("TRANSLATOR_API_KEY"),
        os.getenv("CORRECTNESS_AGENT_API_KEY"),
        os.getenv("CORRECTNESS_AGPENT_API_KEY"),
        os.getenv("OPENAI_API_KEY"),
    ):
        if key:
            result = result.replace(key, "<redacted>")
    return result


def _role_prefix(role: str) -> str:
    normalized = role.strip().lower()
    if normalized in {"translator", "translate"}:
        return "TRANSLATOR"
    if normalized in {"checker", "compile_checker"}:
        return "CHECKER"
    if normalized in {"correctness", "correctness_agent"}:
        return "CORRECTNESS_AGENT"
    raise TranslationLLMError(f"unsupported Translation LLM role: {role!r}")


def _default_dotenv_path() -> Path:
    return Path(__file__).resolve().parents[3] / ".env"


def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ.setdefault(key, value)
