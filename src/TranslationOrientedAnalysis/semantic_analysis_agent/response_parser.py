from __future__ import annotations

import dataclasses
import json
import re
from enum import Enum
from typing import Any, Mapping

from ..semantic_hint_schemas import (
    CStringRead,
    CStringSemantics,
    CStringTermination,
    ResourceSemantics,
)
from .models import (
    DECLARATION_TASK_KIND,
    EntitySemanticPatch,
    PointerSemanticPatch,
    SemanticAgentTask,
    SemanticConflict,
    UNSAFE_STMT_TASK_KIND,
    UnsafeStmtSemanticPatch,
    UnresolvedField,
    VariableSemanticPatch,
)
from .prompts import allowed_pointer_semantic_values


_SEMANTIC_FIELDS = (
    "nullability",
    "ownership",
    "mutability",
    "pointee_shape",
    "lifetime",
    "resource_semantics",
    "string_semantics",
)
_VARIABLE_FIELDS = ("mutability",)
_VARIABLE_MUTABILITY_VALUES = ("const", "mutable")
_IDENTITY_FIELDS = frozenset(
    {
        "stmt_id",
        "name",
        "operation",
        "entity_id",
        "is_struct_member",
        "usage_path",
        "semantic_kind",
        "resource_required",
    }
)
_MARKDOWN_FENCE_PATTERN = re.compile(r"^```(?:json)?\s*$", re.MULTILINE)
_UNSAFE_STRING_FIELDS = frozenset(
    {
        "array_role",
        "resolves_to_element",
        "address_origin_expr",
        "call_kind",
        "target_symbol",
        "ownership",
        "origin_kind",
        "storage_kind",
        "transfer_kind",
        "allocation_shape",
        "allocation_size_bytes",
        "initialized_by",
        "escape_kind",
        "byte_count",
        "source_storage_kind",
        "borrow_kind",
        "cast_kind",
        "offset_base",
        "offset",
        "arith_base_pointee_shape",
        "arith_base_object_kind",
        "base",
        "base_path",
        "offset_expr",
        "derived_from",
        "ownership_kind",
        "ownership_source",
        "arith_kind",
        "base_left",
        "base_right",
        "result_semantics",
    }
)
_UNSAFE_BOOL_FIELDS = frozenset(
    {"is_pointer_field", "establishes_alias"}
)
_UNSAFE_LIST_STRING_FIELDS = frozenset(
    {
        "write_source_deps",
        "arg_effects",
        "arg_borrows",
        "arg_escapes",
        "constraints",
        "escape",
    }
)
_UNSAFE_LIST_INT_FIELDS = frozenset({"mutating_access_sites"})
_UNSAFE_LIST_OBJECT_FIELDS = frozenset({"escape_sites"})
_UNSAFE_OBJECT_FIELDS = {
    "c_string_read": CStringRead,
    "c_string_termination": CStringTermination,
}
_UNSAFE_INT_FIELDS = frozenset({"valid_until_stmt_id"})


class ParseKind(str, Enum):
    FINAL = "final"
    TOOL_CALL = "tool_call"


@dataclasses.dataclass(frozen=True)
class ToolCallRequest:


    tool_name: str
    arguments: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class ParsedResponse:


    kind: ParseKind
    entity_patch: EntitySemanticPatch | None = None
    tool_call_requests: tuple[ToolCallRequest, ...] = ()


class ResponseParseError(RuntimeError):
    pass


class AgentResponseParser:


    def parse(
        self,
        raw_text: str,
        task: SemanticAgentTask,
    ) -> ParsedResponse:
        payload = self._extract_json(raw_text)
        kind = self._parse_kind(payload)

        if kind is ParseKind.TOOL_CALL:
            return self._parse_tool_calls(payload)
        return self._parse_final(payload, task)



    @staticmethod
    def _extract_json(raw_text: str) -> dict[str, Any]:
        text = raw_text.strip()
        if not text:
            raise ResponseParseError("model response is empty")


        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            pass
        else:
            if isinstance(parsed, dict):
                return parsed


        stripped = _MARKDOWN_FENCE_PATTERN.sub("", text).strip()
        if stripped and stripped != text:
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ResponseParseError(
                    "model response is not valid JSON after stripping "
                    f"markdown fences: {exc}"
                ) from exc
            if isinstance(parsed, dict):
                return parsed

        extracted = AgentResponseParser._extract_first_json_object(text)
        if extracted is not None:
            return extracted

        raise ResponseParseError(
            "model response is not a valid JSON object"
        )

    @staticmethod
    def _extract_first_json_object(text: str) -> dict[str, Any] | None:


        start = text.find("{")
        while start != -1:
            depth = 0
            in_string = False
            escaped = False
            for index in range(start, len(text)):
                char = text[index]
                if in_string:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == '"':
                        in_string = False
                    continue

                if char == '"':
                    in_string = True
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = text[start : index + 1]
                        try:
                            parsed = json.loads(candidate)
                        except json.JSONDecodeError:
                            break
                        if isinstance(parsed, dict):
                            return parsed
                        break
            start = text.find("{", start + 1)
        return None

    @staticmethod
    def _parse_kind(payload: Mapping[str, Any]) -> ParseKind:
        raw_type = payload.get("type")
        if not isinstance(raw_type, str):
            raise ResponseParseError(
                "response JSON must contain a string 'type' field "
                "('final' or 'tool_calls')"
            )
        normalized = raw_type.strip().lower()
        if normalized in {"final"}:
            return ParseKind.FINAL
        if normalized in {"tool_call", "tool_calls"}:
            return ParseKind.TOOL_CALL
        raise ResponseParseError(
            f"unknown response type {raw_type!r}; "
            "expected 'final' or 'tool_calls'"
        )



    @staticmethod
    def _parse_tool_calls(payload: Mapping[str, Any]) -> ParsedResponse:


        raw_calls = payload.get("tool_calls")
        if isinstance(raw_calls, list) and raw_calls:
            requests: list[ToolCallRequest] = []
            for index, raw_call in enumerate(raw_calls):
                if not isinstance(raw_call, dict):
                    raise ResponseParseError(
                        f"tool_calls[{index}] must be an object"
                    )
                requests.append(
                    AgentResponseParser._parse_one_tool_call(
                        raw_call, prefix=f"tool_calls[{index}]"
                    )
                )
            return ParsedResponse(
                kind=ParseKind.TOOL_CALL,
                tool_call_requests=tuple(requests),
            )


        tool = payload.get("tool")
        if isinstance(tool, str) and tool.strip():
            request = AgentResponseParser._parse_one_tool_call(
                payload, prefix="root"
            )
            return ParsedResponse(
                kind=ParseKind.TOOL_CALL,
                tool_call_requests=(request,),
            )

        raise ResponseParseError(
            "tool_calls response must contain a non-empty 'tool_calls' array, "
            "or a 'tool' string for backward compatibility"
        )

    @staticmethod
    def _parse_one_tool_call(
        raw: Mapping[str, Any],
        *,
        prefix: str,
    ) -> ToolCallRequest:
        tool = raw.get("tool")
        if not isinstance(tool, str) or not tool.strip():
            raise ResponseParseError(
                f"{prefix} must include a non-empty 'tool' string"
            )
        arguments = raw.get("arguments")
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, Mapping):
            raise ResponseParseError(
                f"{prefix} 'arguments' must be an object"
            )
        return ToolCallRequest(
            tool_name=tool.strip(),
            arguments=dict(arguments),
        )



    @staticmethod
    def _parse_final(
        payload: Mapping[str, Any],
        task: SemanticAgentTask,
    ) -> ParsedResponse:
        AgentResponseParser._validate_task_kind_shape(task)
        entity_id = task.entity_id
        raw_entity_id = payload.get("entity_id")
        if raw_entity_id is not None:
            parsed_entity_id = AgentResponseParser._required_positive_int(
                raw_entity_id, "entity_id"
            )
            if parsed_entity_id != task.entity_id:
                raise ResponseParseError(
                    f"response entity_id {parsed_entity_id} does not match "
                    f"task entity_id {task.entity_id}"
                )

        allowed_values = allowed_pointer_semantic_values()
        pointer_gaps_by_stmt = {
            gap.stmt_id: gap for gap in task.pointer_gaps
        }
        pointer_patches: list[PointerSemanticPatch] = []
        seen_stmt_ids: set[int] = set()
        raw_patches = payload.get("pointer_patches", [])
        if raw_patches is None:
            raw_patches = []
        if not isinstance(raw_patches, list):
            raise ResponseParseError("pointer_patches must be an array")

        for index, raw_patch in enumerate(raw_patches):
            if not isinstance(raw_patch, dict):
                raise ResponseParseError(
                    f"pointer_patches[{index}] must be an object"
                )
            stmt_id = AgentResponseParser._required_positive_int(
                raw_patch.get("stmt_id"),
                f"pointer_patches[{index}].stmt_id",
            )
            gap = pointer_gaps_by_stmt.get(stmt_id)
            if gap is None:
                raise ResponseParseError(
                    f"pointer_patches contain unknown stmt_id {stmt_id}"
                )
            pointer_patches.append(
                AgentResponseParser._parse_pointer_patch(
                    raw_patch,
                    index=index,
                    allowed_values=allowed_values,
                    allowed_fields=set(gap.missing_fields),
                )
            )
            if stmt_id in seen_stmt_ids:
                raise ResponseParseError(
                    f"duplicate stmt_id {stmt_id} in pointer_patches"
                )
            seen_stmt_ids.add(stmt_id)


        gap_stmt_ids = {gap.stmt_id for gap in task.pointer_gaps}
        patch_stmt_ids = {patch.stmt_id for patch in pointer_patches}
        missing_from_patches = gap_stmt_ids - patch_stmt_ids
        if missing_from_patches:
            raise ResponseParseError(
                f"pointer_patches missing required stmt_ids: "
                f"{sorted(missing_from_patches)}"
            )
        extra_patches = patch_stmt_ids - gap_stmt_ids
        if extra_patches:
            raise ResponseParseError(
                f"pointer_patches contain unknown stmt_ids: "
                f"{sorted(extra_patches)}"
            )

        raw_variable_patches = payload.get("variable_patches", [])
        if raw_variable_patches is None:
            raw_variable_patches = []
        if not isinstance(raw_variable_patches, list):
            raise ResponseParseError("variable_patches must be an array")

        variable_gaps_by_stmt = {
            gap.stmt_id: gap for gap in task.variable_gaps
        }
        variable_patches: list[VariableSemanticPatch] = []
        seen_variable_stmt_ids: set[int] = set()
        for index, raw_patch in enumerate(raw_variable_patches):
            if not isinstance(raw_patch, dict):
                raise ResponseParseError(
                    f"variable_patches[{index}] must be an object"
                )
            stmt_id = AgentResponseParser._required_positive_int(
                raw_patch.get("stmt_id"),
                f"variable_patches[{index}].stmt_id",
            )
            gap = variable_gaps_by_stmt.get(stmt_id)
            if gap is None:
                raise ResponseParseError(
                    f"variable_patches contain unknown stmt_id {stmt_id}"
                )
            patch = AgentResponseParser._parse_variable_patch(
                raw_patch,
                index=index,
                stmt_id=stmt_id,
                allowed_fields=set(gap.missing_fields),
            )
            if patch.stmt_id in seen_variable_stmt_ids:
                raise ResponseParseError(
                    f"duplicate stmt_id {patch.stmt_id} in variable_patches"
                )
            seen_variable_stmt_ids.add(patch.stmt_id)
            variable_patches.append(patch)

        variable_gap_stmt_ids = set(variable_gaps_by_stmt)
        variable_patch_stmt_ids = {
            patch.stmt_id for patch in variable_patches
        }
        missing_variables = variable_gap_stmt_ids - variable_patch_stmt_ids
        if missing_variables:
            raise ResponseParseError(
                f"variable_patches missing required stmt_ids: "
                f"{sorted(missing_variables)}"
            )
        extra_variables = variable_patch_stmt_ids - variable_gap_stmt_ids
        if extra_variables:
            raise ResponseParseError(
                f"variable_patches contain unknown stmt_ids: "
                f"{sorted(extra_variables)}"
            )

        raw_unsafe_patches = payload.get("unsafe_stmt_patches", [])
        if raw_unsafe_patches is None:
            raw_unsafe_patches = []
        if not isinstance(raw_unsafe_patches, list):
            raise ResponseParseError("unsafe_stmt_patches must be an array")

        unsafe_gaps_by_stmt = {
            gap.stmt_id: gap for gap in task.unsafe_stmt_gaps
        }
        unsafe_stmt_patches: list[UnsafeStmtSemanticPatch] = []
        seen_unsafe_stmt_ids: set[int] = set()
        for index, raw_patch in enumerate(raw_unsafe_patches):
            if not isinstance(raw_patch, dict):
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}] must be an object"
                )
            stmt_id = AgentResponseParser._required_positive_int(
                raw_patch.get("stmt_id"),
                f"unsafe_stmt_patches[{index}].stmt_id",
            )
            gap = unsafe_gaps_by_stmt.get(stmt_id)
            if gap is None:
                raise ResponseParseError(
                    f"unsafe_stmt_patches contain unknown stmt_id {stmt_id}"
                )
            patch = AgentResponseParser._parse_unsafe_stmt_patch(
                raw_patch,
                index=index,
                stmt_id=stmt_id,
                allowed_fields=set(gap.missing_fields),
            )
            if patch.stmt_id in seen_unsafe_stmt_ids:
                raise ResponseParseError(
                    f"duplicate stmt_id {patch.stmt_id} in unsafe_stmt_patches"
                )
            seen_unsafe_stmt_ids.add(patch.stmt_id)
            unsafe_stmt_patches.append(patch)

        unsafe_gap_stmt_ids = set(unsafe_gaps_by_stmt)
        unsafe_patch_stmt_ids = {patch.stmt_id for patch in unsafe_stmt_patches}
        missing_unsafe = unsafe_gap_stmt_ids - unsafe_patch_stmt_ids
        if missing_unsafe:
            raise ResponseParseError(
                f"unsafe_stmt_patches missing required stmt_ids: "
                f"{sorted(missing_unsafe)}"
            )
        extra_unsafe = unsafe_patch_stmt_ids - unsafe_gap_stmt_ids
        if extra_unsafe:
            raise ResponseParseError(
                f"unsafe_stmt_patches contain unknown stmt_ids: "
                f"{sorted(extra_unsafe)}"
            )

        return ParsedResponse(
            kind=ParseKind.FINAL,
            entity_patch=EntitySemanticPatch(
                entity_id=entity_id,
                pointer_patches=tuple(pointer_patches),
                variable_patches=tuple(variable_patches),
                unsafe_stmt_patches=tuple(unsafe_stmt_patches),
            ),
        )

    @staticmethod
    def _validate_task_kind_shape(task: SemanticAgentTask) -> None:


        if task.task_kind == DECLARATION_TASK_KIND:
            if task.unsafe_stmt_gaps:
                raise ResponseParseError(
                    f"declaration task {task.entity_id} contains unsafe gaps"
                )
            if not task.pointer_gaps and not task.variable_gaps:
                raise ResponseParseError(
                    f"declaration task {task.entity_id} has no declaration gaps"
                )
            return
        if task.task_kind == UNSAFE_STMT_TASK_KIND:
            if task.pointer_gaps or task.variable_gaps:
                raise ResponseParseError(
                    f"unsafe stmt task {task.entity_id} contains declaration gaps"
                )
            if not task.unsafe_stmt_gaps:
                raise ResponseParseError(
                    f"unsafe stmt task {task.entity_id} has no unsafe gaps"
                )
            return
        raise ResponseParseError(
            f"task {task.entity_id} has invalid task_kind: {task.task_kind!r}"
        )

    @staticmethod
    def _parse_pointer_patch(
        raw: Mapping[str, Any],
        *,
        index: int,
        allowed_values: dict[str, tuple[str, ...]],
        allowed_fields: set[str],
    ) -> PointerSemanticPatch:
        stmt_id = AgentResponseParser._required_positive_int(
            raw.get("stmt_id"), f"pointer_patches[{index}].stmt_id"
        )

        updates: dict[str, Any] = {}
        raw_updates = raw.get("updates")
        if raw_updates is not None:
            if not isinstance(raw_updates, Mapping):
                raise ResponseParseError(
                    f"pointer_patches[{index}].updates must be an object"
                )
            for field, value in raw_updates.items():
                AgentResponseParser._reject_identity_field(
                    field, index=index
                )
                if field not in allowed_fields:
                    raise ResponseParseError(
                        f"pointer_patches[{index}].updates contains field "
                        f"{field!r}; allowed missing fields: "
                        f"{sorted(allowed_fields)}"
                    )
                AgentResponseParser._validate_field(
                    field, value, index=index, allowed_values=allowed_values
                )
                updates[str(field)] = value

        unresolved_fields: list[UnresolvedField] = []
        raw_unresolved = raw.get("unresolved_fields")
        if raw_unresolved is not None:
            if not isinstance(raw_unresolved, list):
                raise ResponseParseError(
                    f"pointer_patches[{index}].unresolved_fields must be an array"
                )
            for uf_index, raw_uf in enumerate(raw_unresolved):
                if not isinstance(raw_uf, dict):
                    raise ResponseParseError(
                        f"pointer_patches[{index}].unresolved_fields[{uf_index}] "
                        "must be an object"
                    )
                unresolved_fields.append(
                    UnresolvedField(
                        field=str(
                            AgentResponseParser._required_string(
                                raw_uf.get("field"),
                                f"pointer_patches[{index}].unresolved_fields[{uf_index}].field",
                            )
                        ),
                        reason=AgentResponseParser._optional_string(
                            raw_uf.get("reason")
                        ),
                    )
                )

        conflicts: list[SemanticConflict] = []
        raw_conflicts = raw.get("conflicts")
        if raw_conflicts is not None:
            if not isinstance(raw_conflicts, list):
                raise ResponseParseError(
                    f"pointer_patches[{index}].conflicts must be an array"
                )
            for c_index, raw_conflict in enumerate(raw_conflicts):
                if not isinstance(raw_conflict, dict):
                    raise ResponseParseError(
                        f"pointer_patches[{index}].conflicts[{c_index}] "
                        "must be an object"
                    )
                conflict_field = str(
                    AgentResponseParser._required_string(
                        raw_conflict.get("field"),
                        f"pointer_patches[{index}].conflicts[{c_index}].field",
                    )
                )
                raw_evidence = raw_conflict.get("evidence_refs")
                evidence_refs: tuple[str, ...] = ()
                if isinstance(raw_evidence, list):
                    evidence_refs = tuple(
                        str(ref) for ref in raw_evidence
                    )
                conflicts.append(
                    SemanticConflict(
                        field=conflict_field,
                        programmatic_value=raw_conflict.get(
                            "programmatic_value"
                        ),
                        suggested_value=raw_conflict.get(
                            "suggested_value"
                        ),
                        reason=str(
                            AgentResponseParser._required_string(
                                raw_conflict.get("reason"),
                                f"pointer_patches[{index}].conflicts[{c_index}].reason",
                            )
                        ),
                        evidence_refs=evidence_refs,
                    )
                )

        return PointerSemanticPatch(
            stmt_id=stmt_id,
            updates=updates,
            unresolved_fields=tuple(unresolved_fields),
            conflicts=tuple(conflicts),
        )

    @staticmethod
    def _parse_variable_patch(
        raw: Mapping[str, Any],
        *,
        index: int,
        stmt_id: int,
        allowed_fields: set[str],
    ) -> VariableSemanticPatch:
        parsed_stmt_id = AgentResponseParser._required_positive_int(
            raw.get("stmt_id"), f"variable_patches[{index}].stmt_id"
        )
        if parsed_stmt_id != stmt_id:
            raise ResponseParseError(
                f"variable_patches[{index}].stmt_id changed while parsing"
            )

        updates: dict[str, Any] = {}
        raw_updates = raw.get("updates")
        if raw_updates is not None:
            if not isinstance(raw_updates, Mapping):
                raise ResponseParseError(
                    f"variable_patches[{index}].updates must be an object"
                )
            for field, value in raw_updates.items():
                field_name = str(field)
                AgentResponseParser._reject_variable_identity_field(
                    field_name, index=index
                )
                if field_name not in allowed_fields:
                    raise ResponseParseError(
                        f"variable_patches[{index}].updates contains "
                        f"field {field_name!r}; allowed missing fields: "
                        f"{sorted(allowed_fields)}"
                    )
                AgentResponseParser._validate_variable_field_value(
                    field_name, value, index=index
                )
                updates[field_name] = value

        return VariableSemanticPatch(
            stmt_id=stmt_id,
            updates=updates,
            unresolved_fields=AgentResponseParser._parse_unresolved_fields(
                raw.get("unresolved_fields"),
                prefix=f"variable_patches[{index}]",
            ),
            conflicts=AgentResponseParser._parse_conflicts(
                raw.get("conflicts"),
                prefix=f"variable_patches[{index}]",
            ),
        )

    @staticmethod
    def _parse_unsafe_stmt_patch(
        raw: Mapping[str, Any],
        *,
        index: int,
        stmt_id: int,
        allowed_fields: set[str],
    ) -> UnsafeStmtSemanticPatch:
        parsed_stmt_id = AgentResponseParser._required_positive_int(
            raw.get("stmt_id"), f"unsafe_stmt_patches[{index}].stmt_id"
        )
        if parsed_stmt_id != stmt_id:
            raise ResponseParseError(
                f"unsafe_stmt_patches[{index}].stmt_id changed while parsing"
            )

        updates: dict[str, Any] = {}
        raw_updates = raw.get("updates")
        if raw_updates is not None:
            if not isinstance(raw_updates, Mapping):
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates must be an object"
                )
            for field, value in raw_updates.items():
                field_name = str(field)
                AgentResponseParser._reject_unsafe_identity_field(
                    field_name, index=index
                )
                if field_name not in allowed_fields:
                    raise ResponseParseError(
                        f"unsafe_stmt_patches[{index}].updates contains "
                        f"field {field_name!r}; allowed missing fields: "
                        f"{sorted(allowed_fields)}"
                    )
                AgentResponseParser._validate_unsafe_field_value(
                    field_name, value, index=index
                )
                updates[field_name] = value

        return UnsafeStmtSemanticPatch(
            stmt_id=stmt_id,
            updates=updates,
            unresolved_fields=AgentResponseParser._parse_unresolved_fields(
                raw.get("unresolved_fields"),
                prefix=f"unsafe_stmt_patches[{index}]",
            ),
            conflicts=AgentResponseParser._parse_conflicts(
                raw.get("conflicts"),
                prefix=f"unsafe_stmt_patches[{index}]",
            ),
        )



    @staticmethod
    def _validate_field(
        field: str,
        value: Any,
        *,
        index: int,
        allowed_values: dict[str, tuple[str, ...]],
    ) -> None:
        if field not in _SEMANTIC_FIELDS:
            raise ResponseParseError(
                f"pointer_patches[{index}].updates contains unknown field "
                f"{field!r}; allowed: {_SEMANTIC_FIELDS}"
            )
        if field == "resource_semantics":
            if not isinstance(value, dict):
                raise ResponseParseError(
                    f"pointer_patches[{index}].updates.resource_semantics "
                    "must be an object"
                )
            try:
                ResourceSemantics.from_dict(value)
            except (KeyError, TypeError, ValueError) as exc:
                raise ResponseParseError(
                    f"pointer_patches[{index}].updates.resource_semantics "
                    f"is invalid: {exc}"
                ) from exc
            return
        if field == "string_semantics":
            if not isinstance(value, dict):
                raise ResponseParseError(
                    f"pointer_patches[{index}].updates.string_semantics "
                    "must be an object"
                )
            try:
                CStringSemantics.from_dict(value)
            except (KeyError, TypeError, ValueError) as exc:
                raise ResponseParseError(
                    f"pointer_patches[{index}].updates.string_semantics "
                    f"is invalid: {exc}"
                ) from exc
            return
        allowed = allowed_values.get(field, ())
        if not isinstance(value, str):
            raise ResponseParseError(
                f"pointer_patches[{index}].updates.{field} must be a string "
                f"from {allowed}"
            )
        if value not in allowed:
            raise ResponseParseError(
                f"pointer_patches[{index}].updates.{field} has invalid value "
                f"{value!r}; allowed: {allowed}"
            )

    @staticmethod
    def _reject_identity_field(field: str, *, index: int) -> None:
        if field in _IDENTITY_FIELDS:
            raise ResponseParseError(
                f"pointer_patches[{index}].updates contains identity field "
                f"{field!r} which the Agent must not modify"
            )

    @staticmethod
    def _reject_variable_identity_field(field: str, *, index: int) -> None:
        if field in _IDENTITY_FIELDS:
            raise ResponseParseError(
                f"variable_patches[{index}].updates contains identity field "
                f"{field!r} which the Agent must not modify"
            )

    @staticmethod
    def _reject_unsafe_identity_field(field: str, *, index: int) -> None:
        if field in _IDENTITY_FIELDS:
            raise ResponseParseError(
                f"unsafe_stmt_patches[{index}].updates contains identity "
                f"field {field!r} which the Agent must not modify"
            )

    @staticmethod
    def _validate_variable_field_value(
        field: str,
        value: Any,
        *,
        index: int,
    ) -> None:
        if field not in _VARIABLE_FIELDS:
            raise ResponseParseError(
                f"variable_patches[{index}].updates contains unknown field "
                f"{field!r}; allowed: {_VARIABLE_FIELDS}"
            )
        if not isinstance(value, str):
            raise ResponseParseError(
                f"variable_patches[{index}].updates.{field} must be a string "
                f"from {_VARIABLE_MUTABILITY_VALUES}"
            )
        if value not in _VARIABLE_MUTABILITY_VALUES:
            raise ResponseParseError(
                f"variable_patches[{index}].updates.{field} has invalid value "
                f"{value!r}; allowed: {_VARIABLE_MUTABILITY_VALUES}"
            )

    @staticmethod
    def _validate_unsafe_field_value(
        field: str,
        value: Any,
        *,
        index: int,
    ) -> None:
        if field in _UNSAFE_STRING_FIELDS:
            if not isinstance(value, str) or not value.strip():
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates.{field} must "
                    "be a non-empty string"
                )
            return
        if field in _UNSAFE_BOOL_FIELDS:
            if not isinstance(value, bool):
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates.{field} must "
                    "be a boolean"
                )
            return
        if field in _UNSAFE_LIST_STRING_FIELDS:
            if not isinstance(value, list) or not all(
                isinstance(item, str) and item.strip() for item in value
            ):
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates.{field} must "
                    "be an array of non-empty strings"
                )
            return
        if field in _UNSAFE_LIST_INT_FIELDS:
            if not isinstance(value, list) or not all(
                isinstance(item, int) and not isinstance(item, bool)
                for item in value
            ):
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates.{field} must "
                    "be an array of integers"
                )
            return
        if field in _UNSAFE_LIST_OBJECT_FIELDS:
            if not isinstance(value, list) or not all(
                isinstance(item, Mapping) for item in value
            ):
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates.{field} must "
                    "be an array of objects"
                )
            return
        if field in _UNSAFE_OBJECT_FIELDS:
            if not isinstance(value, Mapping):
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates.{field} must "
                    "be an object"
                )
            try:
                _UNSAFE_OBJECT_FIELDS[field].from_dict(dict(value))
            except (TypeError, ValueError) as exc:
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates.{field} is "
                    f"invalid: {exc}"
                ) from exc
            return
        if field in _UNSAFE_INT_FIELDS:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ResponseParseError(
                    f"unsafe_stmt_patches[{index}].updates.{field} must "
                    "be an integer"
                )
            return
        raise ResponseParseError(
            f"unsafe_stmt_patches[{index}].updates contains unsupported "
            f"field {field!r}"
        )

    @staticmethod
    def _parse_unresolved_fields(
        raw_unresolved: Any,
        *,
        prefix: str,
    ) -> tuple[UnresolvedField, ...]:
        unresolved_fields: list[UnresolvedField] = []
        if raw_unresolved is None:
            return ()
        if not isinstance(raw_unresolved, list):
            raise ResponseParseError(
                f"{prefix}.unresolved_fields must be an array"
            )
        for uf_index, raw_uf in enumerate(raw_unresolved):
            if not isinstance(raw_uf, dict):
                raise ResponseParseError(
                    f"{prefix}.unresolved_fields[{uf_index}] must be an object"
                )
            unresolved_fields.append(
                UnresolvedField(
                    field=AgentResponseParser._required_string(
                        raw_uf.get("field"),
                        f"{prefix}.unresolved_fields[{uf_index}].field",
                    ),
                    reason=AgentResponseParser._optional_string(
                        raw_uf.get("reason")
                    ),
                )
            )
        return tuple(unresolved_fields)

    @staticmethod
    def _parse_conflicts(
        raw_conflicts: Any,
        *,
        prefix: str,
    ) -> tuple[SemanticConflict, ...]:
        conflicts: list[SemanticConflict] = []
        if raw_conflicts is None:
            return ()
        if not isinstance(raw_conflicts, list):
            raise ResponseParseError(f"{prefix}.conflicts must be an array")
        for c_index, raw_conflict in enumerate(raw_conflicts):
            if not isinstance(raw_conflict, dict):
                raise ResponseParseError(
                    f"{prefix}.conflicts[{c_index}] must be an object"
                )
            raw_evidence = raw_conflict.get("evidence_refs")
            evidence_refs: tuple[str, ...] = ()
            if isinstance(raw_evidence, list):
                evidence_refs = tuple(str(ref) for ref in raw_evidence)
            conflicts.append(
                SemanticConflict(
                    field=AgentResponseParser._required_string(
                        raw_conflict.get("field"),
                        f"{prefix}.conflicts[{c_index}].field",
                    ),
                    programmatic_value=raw_conflict.get("programmatic_value"),
                    suggested_value=raw_conflict.get("suggested_value"),
                    reason=AgentResponseParser._required_string(
                        raw_conflict.get("reason"),
                        f"{prefix}.conflicts[{c_index}].reason",
                    ),
                    evidence_refs=evidence_refs,
                )
            )
        return tuple(conflicts)



    @staticmethod
    def _required_positive_int(value: Any, description: str) -> int:
        if isinstance(value, bool):
            raise ResponseParseError(f"{description} must be a positive integer")
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ResponseParseError(
                f"{description} must be a positive integer"
            ) from exc
        if result <= 0:
            raise ResponseParseError(f"{description} must be a positive integer")
        return result

    @staticmethod
    def _required_string(value: Any, description: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ResponseParseError(f"{description} must be non-empty text")
        return value.strip()

    @staticmethod
    def _optional_string(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        return value.strip()
