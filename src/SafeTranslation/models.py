from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any


JsonDict = dict[str, Any]


@dataclass(frozen=True)
class HumanComment:
    comment_id: str
    kind: str
    path: str
    rel_path: str
    start_line: int
    end_line: int
    text: str


@dataclass(frozen=True)
class EntityPackage:


    entity_id: int
    kind: str
    name: str
    original_c_source: str
    annotated_c_source: str
    hint_anchor_ids: tuple[str, ...]
    package_file: Path
    human_comments: tuple[HumanComment, ...] = ()
    is_static: bool = False
    is_extern: bool = False
    export_names: tuple[str, ...] = ()
    macro_context: tuple[JsonDict, ...] = ()


@dataclass(frozen=True)
class EntityPlacement:


    entity_id: int
    rust_file: Path
    module_path: tuple[str, ...]


@dataclass(frozen=True)
class TranslationTask:


    entity_id: int
    kind: str
    package: EntityPackage
    placement: EntityPlacement
    dependency_ids: tuple[int, ...]
    expected_exports: tuple[str, ...]


@dataclass(frozen=True)
class TranslationBatch:


    batch_id: int
    tasks: tuple[TranslationTask, ...]


@dataclass(frozen=True)
class CompileResult:


    passed: bool
    exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class CheckerSummary:


    summary: str
    root_causes: tuple[str, ...]
    repair_priority: tuple[str, ...]
    raw_model_output: str = ""


@dataclass(frozen=True)
class ResourceDecision:


    protocol_id: str
    strategy: str
    discharged_requirements: tuple[str, ...]


@dataclass(frozen=True)
class CargoDependencySpec:


    name: str
    version: str
    features: tuple[str, ...] = ()


@dataclass(frozen=True)
class TranslatedEntity:


    entity_id: int
    rust_code: str
    exports: tuple[str, ...]
    summary: str
    raw_model_output: str = ""
    resource_decisions: tuple[ResourceDecision, ...] = ()
    support_exports: tuple[str, ...] = ()
    cargo_dependencies: tuple[CargoDependencySpec, ...] = ()


@dataclass(frozen=True)
class TranslatedSignature:


    entity_id: int
    rust_signature: str
    exports: tuple[str, ...]
    summary: str
    raw_model_output: str = ""
    resource_decisions: tuple[ResourceDecision, ...] = ()
    support_exports: tuple[str, ...] = ()
    cargo_dependencies: tuple[CargoDependencySpec, ...] = ()


@dataclass(frozen=True)
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass(frozen=True)
class ToolCall:


    call_id: str
    name: str
    arguments: str


@dataclass(frozen=True)
class LLMResponse:
    content: str
    model: str
    token_usage: TokenUsage = TokenUsage()
    tool_calls: tuple[ToolCall, ...] = ()


@dataclass(frozen=True)
class RepairAttempt:


    attempt: int
    rust_before: str
    rust_after: str
    diagnostic_summary: str
    repair_summary: str
    result: str


@dataclass
class EntityTranslationState:


    entity_id: int
    status: str
    attempt: int
    max_attempts: int
    current_rust: str = ""
    tool_call: int = 0
    last_checker_summary: CheckerSummary | None = None
    repair_history: list[RepairAttempt] | None = None

    def __post_init__(self) -> None:
        if self.repair_history is None:
            self.repair_history = []
