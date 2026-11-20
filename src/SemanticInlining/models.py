from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any, TypeAlias

JsonValue: TypeAlias = (
    str
    | int
    | float
    | bool
    | None
    | list["JsonValue"]
    | dict[str, "JsonValue"]
)


class AnchorPlacementKind(str, Enum):


    LINE_END = "line_end"
    ENTITY_LEVEL_FALLBACK = "entity_level_fallback"


@dataclasses.dataclass(frozen=True)
class SourceSpan:


    path: str
    rel_path: str
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def __post_init__(self) -> None:
        if self.start_line < 1 or self.end_line < 1:
            raise ValueError("source line numbers must be positive")
        if self.start_col < 0 or self.end_col < 0:
            raise ValueError("source columns must be non-negative")
        if (self.end_line, self.end_col) < (
            self.start_line,
            self.start_col,
        ):
            raise ValueError("source span ends before it starts")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "path": self.path,
            "rel_path": self.rel_path,
            "start_line": self.start_line,
            "start_col": self.start_col,
            "end_line": self.end_line,
            "end_col": self.end_col,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SourceSpan":
        return cls(
            path=str(value["path"]),
            rel_path=str(value["rel_path"]),
            start_line=int(value["start_line"]),
            start_col=int(value["start_col"]),
            end_line=int(value["end_line"]),
            end_col=int(value["end_col"]),
        )


@dataclasses.dataclass(frozen=True)
class EntityMetadata:


    entity_id: int
    kind: str
    name: str
    unit_id: int
    member_entity_ids: tuple[int, ...]
    source: SourceSpan
    origin: SourceSpan | None = None
    is_static: bool = False
    is_extern: bool = False
    export_names: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.entity_id <= 0:
            raise ValueError("entity_id must be positive")
        if not self.member_entity_ids:
            raise ValueError("member_entity_ids must not be empty")

    def to_dict(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "id": self.entity_id,
            "kind": self.kind,
            "name": self.name,
            "unit_id": self.unit_id,
            "member_entity_ids": list(self.member_entity_ids),
            "source": self.source.to_dict(),
            "declaration_facts": {
                "is_static": self.is_static,
                "is_extern": self.is_extern,
            },
        }
        if self.origin is not None:
            result["origin"] = self.origin.to_dict()
        if self.export_names:
            result["export_names"] = list(self.export_names)
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EntityMetadata":
        source = value.get("source")
        if not isinstance(source, dict):
            raise ValueError("translation entity source must be an object")
        raw_origin = value.get("origin")
        origin = SourceSpan.from_dict(raw_origin) if isinstance(raw_origin, dict) else None
        raw_member_ids = value.get("member_entity_ids")
        if not isinstance(raw_member_ids, list):
            raise ValueError("member_entity_ids must be a list")
        declaration_facts = value.get("declaration_facts", {})
        if not isinstance(declaration_facts, dict):
            raise ValueError("declaration_facts must be an object")
        is_static = declaration_facts.get("is_static", False)
        is_extern = declaration_facts.get("is_extern", False)
        if not isinstance(is_static, bool) or not isinstance(is_extern, bool):
            raise ValueError("declaration facts must be booleans")
        raw_export_names = value.get("export_names", [])
        if not isinstance(raw_export_names, list) or any(
            not isinstance(item, str) or not item.strip()
            for item in raw_export_names
        ):
            raise ValueError("export_names must be a list of non-empty strings")
        return cls(
            entity_id=int(value["id"]),
            kind=str(value["kind"]),
            name=str(value["name"]),
            unit_id=int(value["unit_id"]),
            member_entity_ids=tuple(int(item) for item in raw_member_ids),
            source=SourceSpan.from_dict(source),
            origin=origin,
            is_static=is_static,
            is_extern=is_extern,
            export_names=tuple(dict.fromkeys(raw_export_names)),
        )


@dataclasses.dataclass(frozen=True)
class HumanComment:


    comment_id: str
    kind: str
    source: SourceSpan
    text: str

    def __post_init__(self) -> None:
        if not self.comment_id:
            raise ValueError("human comment ID must not be empty")
        if self.kind not in {"leading", "file_header"}:
            raise ValueError(f"unsupported human comment kind: {self.kind!r}")
        if not self.text.strip():
            raise ValueError("human comment text must not be empty")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "id": self.comment_id,
            "kind": self.kind,
            "source": self.source.to_dict(),
            "text": self.text,
        }


@dataclasses.dataclass(frozen=True)
class SemanticTarget:


    entity_id: int
    stmt_id: int
    unit_id: int
    method_id: int | None
    source: SourceSpan
    operation: str
    name: str | None = None
    c_type: str | None = None
    location: str | None = None
    semantic_kind: str | None = None
    aggregate_id: int | None = None
    aggregate_name: str | None = None

    def __post_init__(self) -> None:
        if self.entity_id <= 0 or self.stmt_id <= 0 or self.unit_id <= 0:
            raise ValueError("semantic target IDs must be positive")
        if self.method_id is not None and self.method_id <= 0:
            raise ValueError("method_id must be positive when present")
        if self.aggregate_id is not None and self.aggregate_id <= 0:
            raise ValueError("aggregate_id must be positive when present")
        if not self.operation:
            raise ValueError("semantic target operation must not be empty")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "entity_id": self.entity_id,
            "stmt_id": self.stmt_id,
            "unit_id": self.unit_id,
            "method_id": self.method_id,
            "name": self.name,
            "c_type": self.c_type,
            "operation": self.operation,
            "location": self.location,
            "semantic_kind": self.semantic_kind,
            "aggregate_id": self.aggregate_id,
            "aggregate_name": self.aggregate_name,
            "source": self.source.to_dict(),
        }


@dataclasses.dataclass(frozen=True)
class AnchorPlacement:


    anchor_id: str
    target: SemanticTarget
    line_index: int
    kind: AnchorPlacementKind
    fallback_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.anchor_id:
            raise ValueError("anchor_id must not be empty")
        if self.line_index < 0:
            raise ValueError("line_index must be non-negative")
        if (
            self.kind is AnchorPlacementKind.ENTITY_LEVEL_FALLBACK
            and not self.fallback_reason
        ):
            raise ValueError("entity-level fallback requires a reason")
        if (
            self.kind is not AnchorPlacementKind.ENTITY_LEVEL_FALLBACK
            and self.fallback_reason is not None
        ):
            raise ValueError(
                "fallback_reason is only valid for entity-level fallback"
            )


@dataclasses.dataclass(frozen=True)
class SemanticHint:


    anchor_id: str
    target: SemanticTarget
    facts: dict[str, JsonValue]
    placement_kind: AnchorPlacementKind
    line_index: int
    unresolved_fields: tuple[str, ...] = ()
    fallback_reason: str | None = None

    def __post_init__(self) -> None:
        if self.line_index < 0:
            raise ValueError("line_index must be non-negative")
        if (
            self.placement_kind
            is AnchorPlacementKind.ENTITY_LEVEL_FALLBACK
            and not self.fallback_reason
        ):
            raise ValueError("entity-level fallback requires a reason")
        if (
            self.placement_kind
            is not AnchorPlacementKind.ENTITY_LEVEL_FALLBACK
            and self.fallback_reason is not None
        ):
            raise ValueError(
                "fallback_reason is only valid for entity-level fallback"
            )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "anchor_id": self.anchor_id,
            "target": self.target.to_dict(),
            "facts": dict(self.facts),
            "unresolved_fields": list(self.unresolved_fields),
            "placement": {
                "kind": self.placement_kind.value,
                "line_index": self.line_index,
                "fallback_reason": self.fallback_reason,
            },
        }


@dataclasses.dataclass(frozen=True)
class EntityHintPackage:


    version: int
    entity: EntityMetadata
    original_c_source: str
    annotated_c_source: str
    hint_anchor_ids: tuple[str, ...]
    human_comment_ids: tuple[str, ...] = ()
    macro_context: tuple[dict[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValueError("package version must be positive")
        if len(self.hint_anchor_ids) != len(set(self.hint_anchor_ids)):
            raise ValueError("package contains duplicate hint anchor IDs")
        for anchor_id in self.hint_anchor_ids:
            if not anchor_id:
                raise ValueError("hint anchor IDs must not be empty")
        if len(self.human_comment_ids) != len(set(self.human_comment_ids)):
            raise ValueError("package contains duplicate human comment IDs")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "version": self.version,
            "entity": self.entity.to_dict(),
            "original_c_source": self.original_c_source,
            "annotated_c_source": self.annotated_c_source,
            "hint_anchor_ids": list(self.hint_anchor_ids),
            "human_comment_ids": list(self.human_comment_ids),
            "macro_context": [dict(item) for item in self.macro_context],
        }


@dataclasses.dataclass(frozen=True)
class SemanticHintStore:


    version: int
    hints: dict[str, SemanticHint]

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValueError("hint store version must be positive")
        for anchor_id, hint in self.hints.items():
            if not anchor_id:
                raise ValueError("hint store keys must not be empty")
            if anchor_id != hint.anchor_id:
                raise ValueError(
                    f"hint store key {anchor_id!r} does not match hint "
                    f"anchor_id {hint.anchor_id!r}"
                )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "version": self.version,
            "hints": {
                anchor_id: hint.to_dict()
                for anchor_id, hint in sorted(self.hints.items())
            },
        }


@dataclasses.dataclass(frozen=True)
class SemanticHintManifestEntry:


    entity_id: int
    kind: str
    package_file: str
    hint_count: int
    human_comment_count: int = 0

    def __post_init__(self) -> None:
        if self.entity_id <= 0:
            raise ValueError("entity_id must be positive")
        if self.hint_count < 0:
            raise ValueError("hint_count must be non-negative")
        if self.human_comment_count < 0:
            raise ValueError("human_comment_count must be non-negative")

    def to_dict(self) -> dict[str, JsonValue]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class SemanticHintManifest:


    version: int
    hint_store_file: str
    human_comment_store_file: str
    entities: tuple[SemanticHintManifestEntry, ...]

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValueError("manifest version must be positive")
        if not self.hint_store_file:
            raise ValueError("manifest hint_store_file must not be empty")
        if not self.human_comment_store_file:
            raise ValueError("manifest human_comment_store_file must not be empty")
        entity_ids = [entry.entity_id for entry in self.entities]
        if len(entity_ids) != len(set(entity_ids)):
            raise ValueError("manifest contains duplicate entity IDs")

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "version": self.version,
            "hint_store_file": self.hint_store_file,
            "human_comment_store_file": self.human_comment_store_file,
            "entities": [entry.to_dict() for entry in self.entities],
        }
