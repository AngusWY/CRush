from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, MutableMapping


DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT_SECONDS = 180.0
DEFAULT_MAX_TURNS = 6
DEFAULT_MAX_TOOL_CALLS_PER_TURN = 4
DEFAULT_MAX_CONCURRENCY = 5
DEFAULT_MAX_RETRIES = 2
DEFAULT_TEMPERATURE = 0.1


class SemanticAgentConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class SemanticAgentConfig:


    api_key: str
    base_url: str
    model: str
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    max_turns: int = DEFAULT_MAX_TURNS
    max_tool_calls_per_turn: int = DEFAULT_MAX_TOOL_CALLS_PER_TURN
    max_concurrency: int = DEFAULT_MAX_CONCURRENCY
    max_retries: int = DEFAULT_MAX_RETRIES
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int | None = None

    @classmethod
    def from_env(
        cls,
        *,
        dotenv_path: Path | None = None,
        environ: MutableMapping[str, str] | None = None,
    ) -> "SemanticAgentConfig":


        target_environ = os.environ if environ is None else environ
        resolved_dotenv = (
            cls.default_dotenv_path()
            if dotenv_path is None
            else dotenv_path.resolve()
        )
        cls._load_dotenv(resolved_dotenv, target_environ)

        api_key = cls._first_value(
            target_environ,
            "SEMANTIC_AGENT_API_KEY",
            "WORKER_API_KEY",
            "OPENAI_API_KEY",
        )
        if api_key is None:
            raise SemanticAgentConfigurationError(
                "missing Semantic Agent API key; set "
                "SEMANTIC_AGENT_API_KEY, WORKER_API_KEY, or OPENAI_API_KEY"
            )

        base_url = cls._first_value(
            target_environ,
            "SEMANTIC_AGENT_BASE_URL",
            "WORKER_BASE_URL",
            "OPENAI_BASE_URL",
        ) or DEFAULT_BASE_URL
        model = cls._first_value(
            target_environ,
            "SEMANTIC_AGENT_MODEL",
            "WORKER_MODEL",
            "OPENAI_MODEL",
        ) or DEFAULT_MODEL

        config = cls(
            api_key=api_key,
            base_url=base_url,
            model=model,
            timeout_seconds=cls._float_value(
                target_environ,
                "SEMANTIC_AGENT_TIMEOUT",
                DEFAULT_TIMEOUT_SECONDS,
            ),
            max_turns=cls._int_value(
                target_environ,
                "SEMANTIC_AGENT_MAX_TURNS",
                DEFAULT_MAX_TURNS,
            ),
            max_tool_calls_per_turn=cls._int_value(
                target_environ,
                "SEMANTIC_AGENT_MAX_TOOL_CALLS_PER_TURN",
                DEFAULT_MAX_TOOL_CALLS_PER_TURN,
            ),
            max_concurrency=cls._int_value(
                target_environ,
                "SEMANTIC_AGENT_MAX_CONCURRENCY",
                DEFAULT_MAX_CONCURRENCY,
            ),
            max_retries=cls._int_value(
                target_environ,
                "SEMANTIC_AGENT_MAX_RETRIES",
                DEFAULT_MAX_RETRIES,
            ),
            temperature=cls._float_value(
                target_environ,
                "SEMANTIC_AGENT_TEMPERATURE",
                DEFAULT_TEMPERATURE,
            ),
            max_tokens=cls._optional_int_value(
                target_environ,
                "SEMANTIC_AGENT_MAX_TOKENS",
            ),
        )
        config.validate()
        return config

    @staticmethod
    def default_dotenv_path() -> Path:


        return Path(__file__).resolve().parents[3] / ".env"

    def validate(self) -> None:
        if not self.api_key.strip():
            raise SemanticAgentConfigurationError(
                "Semantic Agent API key must not be empty"
            )
        if not self.base_url.strip():
            raise SemanticAgentConfigurationError(
                "Semantic Agent base URL must not be empty"
            )
        if not self.model.strip():
            raise SemanticAgentConfigurationError(
                "Semantic Agent model must not be empty"
            )
        if self.timeout_seconds <= 0:
            raise SemanticAgentConfigurationError(
                "SEMANTIC_AGENT_TIMEOUT must be greater than zero"
            )
        if self.max_turns <= 0:
            raise SemanticAgentConfigurationError(
                "SEMANTIC_AGENT_MAX_TURNS must be greater than zero"
            )
        if self.max_tool_calls_per_turn < 0:
            raise SemanticAgentConfigurationError(
                "SEMANTIC_AGENT_MAX_TOOL_CALLS_PER_TURN must be nonnegative"
            )
        if self.max_concurrency <= 0:
            raise SemanticAgentConfigurationError(
                "SEMANTIC_AGENT_MAX_CONCURRENCY must be greater than zero"
            )
        if self.max_retries < 0:
            raise SemanticAgentConfigurationError(
                "SEMANTIC_AGENT_MAX_RETRIES must be nonnegative"
            )
        if not 0.0 <= self.temperature <= 2.0:
            raise SemanticAgentConfigurationError(
                "SEMANTIC_AGENT_TEMPERATURE must be between 0 and 2"
            )
        if self.max_tokens is not None and self.max_tokens <= 0:
            raise SemanticAgentConfigurationError(
                "SEMANTIC_AGENT_MAX_TOKENS must be greater than zero"
            )

    @staticmethod
    def _load_dotenv(
        path: Path,
        environ: MutableMapping[str, str],
    ) -> None:
        if not path.is_file():
            return
        try:
            lines = path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError as exc:
            raise SemanticAgentConfigurationError(
                f"failed to read dotenv file {path}: {exc}"
            ) from exc

        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, raw_value = line.split("=", 1)
            key = key.strip()
            value = raw_value.strip()
            if not key:
                continue
            if (
                len(value) >= 2
                and value[0] == value[-1]
                and value[0] in {"'", '"'}
            ):
                value = value[1:-1]
            environ.setdefault(key, value)

    @staticmethod
    def _first_value(
        environ: Mapping[str, str],
        *keys: str,
    ) -> str | None:
        for key in keys:
            value = environ.get(key)
            if value is not None and value.strip():
                return value.strip()
        return None

    @classmethod
    def _int_value(
        cls,
        environ: Mapping[str, str],
        key: str,
        default: int,
    ) -> int:
        value = cls._first_value(environ, key)
        if value is None:
            return default
        try:
            return int(value)
        except ValueError as exc:
            raise SemanticAgentConfigurationError(
                f"{key} must be an integer; got {value!r}"
            ) from exc

    @classmethod
    def _optional_int_value(
        cls,
        environ: Mapping[str, str],
        key: str,
    ) -> int | None:
        value = cls._first_value(environ, key)
        if value is None:
            return None
        try:
            return int(value)
        except ValueError as exc:
            raise SemanticAgentConfigurationError(
                f"{key} must be an integer; got {value!r}"
            ) from exc

    @classmethod
    def _float_value(
        cls,
        environ: Mapping[str, str],
        key: str,
        default: float,
    ) -> float:
        value = cls._first_value(environ, key)
        if value is None:
            return default
        try:
            return float(value)
        except ValueError as exc:
            raise SemanticAgentConfigurationError(
                f"{key} must be a number; got {value!r}"
            ) from exc
