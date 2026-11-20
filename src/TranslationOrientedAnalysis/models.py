from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any

from .semantic_hint_schemas import (
    PointerDeclarationOperation,
    PointerDeclarationSemantics,
    UnsafeStmtSemantics,
    UnsafeSemanticKind,
    UnsafeStmtOperation,
    VariableDeclarationOperation,
    VariableDeclarationSemantics,
)


class PointerLocation(str, Enum):


    PARAMETER = "parameter"
    LOCAL = "local"
    GLOBAL = "global"
    STRUCT_MEMBER = "struct_member"
    UNION_MEMBER = "union_member"
    TYPE_ALIAS = "type_alias"


@dataclasses.dataclass(frozen=True)
class PointerSourceSpan:


    path: str
    rel_path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "rel_path": self.rel_path,
            "start_line": self.start_line,
            "start_col": self.start_col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }


@dataclasses.dataclass(frozen=True)
class PointerTarget:


    stmt_id: int
    entity_id: int
    unit_id: int
    method_id: int | None
    name: str
    c_type: str
    operation: PointerDeclarationOperation
    location: PointerLocation
    aggregate_id: int | None = None
    aggregate_name: str | None = None
    source: PointerSourceSpan | None = None

    @property
    def is_aggregate_member(self) -> bool:
        return self.location in {
            PointerLocation.STRUCT_MEMBER,
            PointerLocation.UNION_MEMBER,
        }

    def to_dict(self) -> dict[str, Any]:


        return {
            "stmt_id": self.stmt_id,
            "entity_id": self.entity_id,
            "unit_id": self.unit_id,
            "method_id": self.method_id,
            "name": self.name,
            "c_type": self.c_type,
            "operation": self.operation.value,
            "location": self.location.value,
            "aggregate_id": self.aggregate_id,
            "aggregate_name": self.aggregate_name,
            "source": None if self.source is None else self.source.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class PointerAnalysisResult:


    target: PointerTarget
    semantics: PointerDeclarationSemantics


class VariableLocation(str, Enum):


    PARAMETER = "parameter"
    LOCAL = "local"
    GLOBAL = "global"
    STRUCT_MEMBER = "struct_member"
    UNION_MEMBER = "union_member"


@dataclasses.dataclass(frozen=True)
class VariableTarget:


    stmt_id: int
    entity_id: int
    unit_id: int
    method_id: int | None
    name: str
    c_type: str
    operation: VariableDeclarationOperation
    location: VariableLocation
    aggregate_id: int | None = None
    aggregate_name: str | None = None
    source: PointerSourceSpan | None = None

    @property
    def is_aggregate_member(self) -> bool:
        return self.location in {
            VariableLocation.STRUCT_MEMBER,
            VariableLocation.UNION_MEMBER,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "stmt_id": self.stmt_id,
            "entity_id": self.entity_id,
            "unit_id": self.unit_id,
            "method_id": self.method_id,
            "name": self.name,
            "c_type": self.c_type,
            "operation": self.operation.value,
            "location": self.location.value,
            "aggregate_id": self.aggregate_id,
            "aggregate_name": self.aggregate_name,
            "source": None if self.source is None else self.source.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class VariableAnalysisResult:


    target: VariableTarget
    semantics: VariableDeclarationSemantics


@dataclasses.dataclass(frozen=True)
class UnsafeStmtTarget:


    stmt_id: int
    entity_id: int
    unit_id: int
    method_id: int | None
    operation: UnsafeStmtOperation
    semantic_kind: UnsafeSemanticKind
    raw_gir: dict[str, Any]
    source: PointerSourceSpan | None = None
    related_symbols: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "stmt_id": self.stmt_id,
            "entity_id": self.entity_id,
            "unit_id": self.unit_id,
            "method_id": self.method_id,
            "operation": self.operation.value,
            "semantic_kind": self.semantic_kind.value,
            "source": None if self.source is None else self.source.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class UnsafeStmtAnalysisResult:


    target: UnsafeStmtTarget
    semantics: UnsafeStmtSemantics
