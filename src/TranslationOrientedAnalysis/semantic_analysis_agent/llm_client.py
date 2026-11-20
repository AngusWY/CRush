from __future__ import annotations

import os
from typing import Any, Protocol, Sequence

from .config import SemanticAgentConfig
from .models import ChatMessage, LLMResponse, TokenUsage


class SemanticLLMError(RuntimeError):
    pass


class SemanticLLMClient(Protocol):


    @property
    def model(self) -> str:
        pass

    async def chat(
        self,
        *,
        messages: Sequence[ChatMessage],
    ) -> LLMResponse:
        pass


class OpenAICompatibleSemanticLLMClient:


    def __init__(
        self,
        *,
        config: SemanticAgentConfig,
        client: Any | None = None,
    ) -> None:
        config.validate()
        self.config = config
        self._client = (
            client if client is not None else self._build_client(config)
        )

    @property
    def model(self) -> str:
        return self.config.model

    async def chat(
        self,
        *,
        messages: Sequence[ChatMessage],
    ) -> LLMResponse:
        if not messages:
            raise SemanticLLMError("model request must contain messages")
        for message in messages:
            if message.role not in {"system", "user", "assistant"}:
                raise SemanticLLMError(
                    f"unsupported chat message role: {message.role!r}"
                )
            if not message.content.strip():
                raise SemanticLLMError(
                    f"{message.role} chat message must not be empty"
                )

        request: dict[str, Any] = {
            "model": self.config.model,
            "messages": [
                {"role": message.role, "content": message.content}
                for message in messages
            ],
            "temperature": self.config.temperature,
        }
        if self.config.max_tokens is not None:
            request["max_tokens"] = self.config.max_tokens
        if not self._omit_enable_thinking():
            request["extra_body"] = {"enable_thinking": False}

        try:
            response = await self._client.chat.completions.create(**request)
        except Exception as exc:
            raise SemanticLLMError(
                f"model request failed for {self.config.model}: {exc}"
            ) from exc

        content = self._response_content(response)
        response_model = str(
            getattr(response, "model", None) or self.config.model
        )
        return LLMResponse(
            content=content,
            model=response_model,
            token_usage=self._token_usage(getattr(response, "usage", None)),
        )

    @staticmethod
    def _build_client(config: SemanticAgentConfig) -> Any:
        try:
            from openai import AsyncOpenAI
        except ImportError as exc:
            raise SemanticLLMError(
                "the openai package is required for Semantic Agent model calls"
            ) from exc

        return AsyncOpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            timeout=config.timeout_seconds,
        )

    @staticmethod
    def _response_content(response: Any) -> str:
        choices = getattr(response, "choices", None)
        if not choices:
            raise SemanticLLMError("model response contains no choices")
        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None)
        if not isinstance(content, str) or not content.strip():
            raise SemanticLLMError("model response contains no text content")
        return content.strip()

    @staticmethod
    def _token_usage(usage: Any) -> TokenUsage:
        if usage is None:
            return TokenUsage()
        return TokenUsage(
            prompt_tokens=OpenAICompatibleSemanticLLMClient._usage_int(
                usage, "prompt_tokens"
            ),
            completion_tokens=OpenAICompatibleSemanticLLMClient._usage_int(
                usage, "completion_tokens"
            ),
            total_tokens=OpenAICompatibleSemanticLLMClient._usage_int(
                usage, "total_tokens"
            ),
        )

    @staticmethod
    def _usage_int(usage: Any, field: str) -> int:
        try:
            value = int(getattr(usage, field, 0) or 0)
        except (TypeError, ValueError, OverflowError):
            return 0
        return max(value, 0)

    @staticmethod
    def _omit_enable_thinking() -> bool:
        return os.getenv(
            "LLM_OMIT_ENABLE_THINKING", ""
        ).strip().lower() in {"1", "true", "yes"}
