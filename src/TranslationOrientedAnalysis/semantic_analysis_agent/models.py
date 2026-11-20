from __future__ import annotations

import dataclasses
from enum import Enum
from typing import TypeAlias

from ..semantic_hint_schemas import (
    Lifetime,
    Mutability,
    Nullability,
    Ownership,
    PointeeShape,
    PointerDeclarationSemantics,
    UnsafeStmtSemantics,
    VariableDeclarationSemantics,
    VariableMutability,
)


DECLARATION_TASK_KIND = "declaration"
UNSAFE_STMT_TASK_KIND = "unsafe_stmt"
TASK_KINDS = (DECLARATION_TASK_KIND, UNSAFE_STMT_TASK_KIND)

JsonValue: TypeAlias = (
    str
    | int
    | float
    | bool
    | None
    | list["JsonValue"]
    | dict[str, "JsonValue"]
)
PointerSemanticValue: TypeAlias = (
    Nullability
    | Ownership
    | Mutability
    | PointeeShape
    | Lifetime
    | bool
)
VariableSemanticValue: TypeAlias = VariableMutability


@dataclasses.dataclass(frozen=True)
class EntitySource:


    path: str
    rel_path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int


@dataclasses.dataclass(frozen=True)
class PointerSemanticGap:


    stmt_id: int
    current_semantics: PointerDeclarationSemantics
    missing_fields: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class VariableSemanticGap:


    stmt_id: int
    current_semantics: VariableDeclarationSemantics
    missing_fields: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class UnsafeStmtSemanticGap:


    stmt_id: int
    operation: str
    semantic_kind: str
    current_semantics: UnsafeStmtSemantics
    missing_fields: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class SemanticAgentTask:


    task_kind: str
    entity_id: int
    entity_name: str
    entity_kind: str
    unit_id: int
    member_entity_ids: tuple[int, ...]
    source: EntitySource
    pointer_gaps: tuple[PointerSemanticGap, ...]
    variable_gaps: tuple[VariableSemanticGap, ...] = ()
    unsafe_stmt_gaps: tuple[UnsafeStmtSemanticGap, ...] = ()


@dataclasses.dataclass(frozen=True)
class SourceCodeContext:


    path: str
    rel_path: str | None
    start_line: int | None
    end_line: int | None
    source: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "path": self.path,
            "rel_path": self.rel_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "source": self.source,
        }


@dataclasses.dataclass(frozen=True)
class PointerTaskContext:


    stmt_id: int
    name: str
    c_type: str
    location: str
    declaration_source: str
    missing_fields: tuple[str, ...]
    current_semantics: PointerDeclarationSemantics

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "stmt_id": self.stmt_id,
            "name": self.name,
            "c_type": self.c_type,
            "location": self.location,
            "declaration_source": self.declaration_source,
            "missing_fields": list(self.missing_fields),
            "current_semantics": self.current_semantics.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class VariableTaskContext:


    stmt_id: int
    name: str
    c_type: str
    location: str
    declaration_source: str
    missing_fields: tuple[str, ...]
    current_semantics: VariableDeclarationSemantics

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "stmt_id": self.stmt_id,
            "name": self.name,
            "c_type": self.c_type,
            "location": self.location,
            "declaration_source": self.declaration_source,
            "missing_fields": list(self.missing_fields),
            "current_semantics": self.current_semantics.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class UnsafeStmtTaskContext:


    stmt_id: int
    operation: str
    semantic_kind: str
    stmt_source: SourceCodeContext
    missing_fields: tuple[str, ...]
    current_semantics: UnsafeStmtSemantics

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "stmt_id": self.stmt_id,
            "operation": self.operation,
            "semantic_kind": self.semantic_kind,
            "stmt_source": self.stmt_source.to_dict(),
            "missing_fields": list(self.missing_fields),
            "current_semantics": self.current_semantics.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class CallerCallSiteContext:


    pointer_stmt_id: int
    caller_entity_id: int | None
    caller_name: str
    call_stmt_id: int
    argument_index: int
    argument_value: str
    source: SourceCodeContext

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "pointer_stmt_id": self.pointer_stmt_id,
            "caller_entity_id": self.caller_entity_id,
            "caller_name": self.caller_name,
            "call_stmt_id": self.call_stmt_id,
            "argument_index": self.argument_index,
            "argument_value": self.argument_value,
            "source": self.source.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class CalleeParameterContext:


    pointer_stmt_id: int
    call_stmt_id: int
    callee_entity_id: int | None
    callee_name: str
    argument_index: int
    parameter_stmt_id: int | None
    parameter_name: str | None
    discovered_effects: tuple[str, ...]
    call_source: SourceCodeContext
    relevant_callee_source: tuple[SourceCodeContext, ...]
    analysis_complete: bool = False

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "pointer_stmt_id": self.pointer_stmt_id,
            "call_stmt_id": self.call_stmt_id,
            "callee_entity_id": self.callee_entity_id,
            "callee_name": self.callee_name,
            "argument_index": self.argument_index,
            "parameter_stmt_id": self.parameter_stmt_id,
            "parameter_name": self.parameter_name,
            "discovered_effects": list(self.discovered_effects),
            "call_source": self.call_source.to_dict(),
            "relevant_callee_source": [
                source.to_dict() for source in self.relevant_callee_source
            ],
            "analysis_complete": self.analysis_complete,
        }


@dataclasses.dataclass(frozen=True)
class RelatedTypeContext:


    type_name: str
    entity_id: int | None
    declaration_stmt_ids: tuple[int, ...]
    source: SourceCodeContext

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "type_name": self.type_name,
            "entity_id": self.entity_id,
            "declaration_stmt_ids": list(self.declaration_stmt_ids),
            "source": self.source.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class CrossEntityPointerUsageContext:


    pointer_stmt_id: int
    entity_id: int | None
    entity_name: str | None
    stmt_id: int
    kind: str
    source: SourceCodeContext

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "pointer_stmt_id": self.pointer_stmt_id,
            "entity_id": self.entity_id,
            "entity_name": self.entity_name,
            "stmt_id": self.stmt_id,
            "kind": self.kind,
            "source": self.source.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class SemanticAgentContext:


    entity_source: SourceCodeContext
    pointer_tasks: tuple[PointerTaskContext, ...]
    caller_call_sites: tuple[CallerCallSiteContext, ...]
    callee_parameter_contexts: tuple[CalleeParameterContext, ...]
    related_types: tuple[RelatedTypeContext, ...]
    cross_entity_pointer_usages: tuple[
        CrossEntityPointerUsageContext, ...
    ]
    variable_tasks: tuple[VariableTaskContext, ...] = ()
    unsafe_stmt_tasks: tuple[UnsafeStmtTaskContext, ...] = ()
    cross_entity_search_complete: bool = False

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "entity_source": self.entity_source.to_dict(),
            "pointer_tasks": [
                pointer.to_dict() for pointer in self.pointer_tasks
            ],
            "variable_tasks": [
                variable.to_dict() for variable in self.variable_tasks
            ],
            "unsafe_stmt_tasks": [
                stmt.to_dict() for stmt in self.unsafe_stmt_tasks
            ],
            "caller_call_sites": [
                caller.to_dict() for caller in self.caller_call_sites
            ],
            "callee_parameter_contexts": [
                callee.to_dict()
                for callee in self.callee_parameter_contexts
            ],
            "related_types": [
                related_type.to_dict()
                for related_type in self.related_types
            ],
            "cross_entity_pointer_usages": [
                usage.to_dict()
                for usage in self.cross_entity_pointer_usages
            ],
            "cross_entity_search_complete": (
                self.cross_entity_search_complete
            ),
        }


@dataclasses.dataclass(frozen=True)
class UnresolvedField:


    field: str
    reason: str


@dataclasses.dataclass(frozen=True)
class SemanticConflict:


    field: str
    programmatic_value: JsonValue
    suggested_value: JsonValue
    reason: str
    evidence_refs: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class PointerSemanticPatch:


    stmt_id: int
    updates: dict[str, PointerSemanticValue]
    unresolved_fields: tuple[UnresolvedField, ...] = ()
    conflicts: tuple[SemanticConflict, ...] = ()


@dataclasses.dataclass(frozen=True)
class VariableSemanticPatch:


    stmt_id: int
    updates: dict[str, VariableSemanticValue]
    unresolved_fields: tuple[UnresolvedField, ...] = ()
    conflicts: tuple[SemanticConflict, ...] = ()


@dataclasses.dataclass(frozen=True)
class UnsafeStmtSemanticPatch:


    stmt_id: int
    updates: dict[str, JsonValue]
    unresolved_fields: tuple[UnresolvedField, ...] = ()
    conflicts: tuple[SemanticConflict, ...] = ()


@dataclasses.dataclass(frozen=True)
class EntitySemanticPatch:


    entity_id: int
    pointer_patches: tuple[PointerSemanticPatch, ...]
    variable_patches: tuple[VariableSemanticPatch, ...] = ()
    unsafe_stmt_patches: tuple[UnsafeStmtSemanticPatch, ...] = ()


@dataclasses.dataclass(frozen=True)
class SemanticMergeIssue:


    kind: str
    entity_id: int
    stmt_id: int | None
    field: str | None
    reason: str
    existing_value: JsonValue = None
    suggested_value: JsonValue = None
    evidence_refs: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class PointerSemanticMergeResult:


    entity_id: int
    stmt_id: int
    applied_fields: tuple[str, ...]
    confirmed_fields: tuple[str, ...]
    remaining_fields: tuple[str, ...]
    issues: tuple[SemanticMergeIssue, ...] = ()


@dataclasses.dataclass(frozen=True)
class VariableSemanticMergeResult:


    entity_id: int
    stmt_id: int
    applied_fields: tuple[str, ...]
    confirmed_fields: tuple[str, ...]
    remaining_fields: tuple[str, ...]
    issues: tuple[SemanticMergeIssue, ...] = ()


@dataclasses.dataclass(frozen=True)
class UnsafeStmtSemanticMergeResult:


    entity_id: int
    stmt_id: int
    applied_fields: tuple[str, ...]
    confirmed_fields: tuple[str, ...]
    remaining_fields: tuple[str, ...]
    issues: tuple[SemanticMergeIssue, ...] = ()


@dataclasses.dataclass(frozen=True)
class SemanticMergeResult:


    pointer_semantics: dict[str, JsonValue]
    variable_semantics: dict[str, JsonValue] | None
    unsafe_stmt_semantics: dict[str, JsonValue] | None
    pointer_results: tuple[PointerSemanticMergeResult, ...]
    issues: tuple[SemanticMergeIssue, ...]
    remaining_entity_ids: tuple[int, ...]
    variable_results: tuple[VariableSemanticMergeResult, ...] = ()
    unsafe_stmt_results: tuple[UnsafeStmtSemanticMergeResult, ...] = ()


@dataclasses.dataclass(frozen=True)
class ToolCallRecord:


    tool_name: str
    arguments: dict[str, JsonValue]
    result: JsonValue | None = None
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class TokenUsage:


    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclasses.dataclass(frozen=True)
class ChatMessage:


    role: str
    content: str


@dataclasses.dataclass(frozen=True)
class LLMResponse:


    content: str
    model: str
    token_usage: TokenUsage = dataclasses.field(default_factory=TokenUsage)


@dataclasses.dataclass(frozen=True)
class SemanticAgentResult:


    patch: EntitySemanticPatch
    model: str
    raw_model_outputs: tuple[str, ...]
    tool_calls: tuple[ToolCallRecord, ...] = ()
    token_usage: TokenUsage = dataclasses.field(default_factory=TokenUsage)
    turn_count: int = 0

    @property
    def has_patch(self) -> bool:

        return bool(
            self.patch.pointer_patches
            or self.patch.variable_patches
            or self.patch.unsafe_stmt_patches
        )


class TaskStatus(str, Enum):


    COMPLETED = "completed"
    FAILED = "failed"


@dataclasses.dataclass(frozen=True)
class TaskExecutionResult:


    entity_id: int
    task_kind: str
    status: TaskStatus
    attempts: int
    output: object | None = None
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class SchedulerResult:


    task_results: tuple[TaskExecutionResult, ...]

    @property
    def completed_entity_ids(self) -> tuple[int, ...]:
        return tuple(
            result.entity_id
            for result in self.task_results
            if result.status is TaskStatus.COMPLETED
        )

    @property
    def failed_entity_ids(self) -> tuple[int, ...]:
        return tuple(
            result.entity_id
            for result in self.task_results
            if result.status is TaskStatus.FAILED
        )
