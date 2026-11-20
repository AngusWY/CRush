from __future__ import annotations

import copy
import math
from collections.abc import Iterable, Mapping
from enum import Enum
from typing import Any

from ..semantic_hint_schemas import (
    CStringSemantics,
    Lifetime,
    Mutability,
    Nullability,
    Ownership,
    PointeeShape,
    PointerDeclarationSemantics,
    ResourceSemantics,
    UnsafeStmtSemantics,
    VariableDeclarationSemantics,
    VariableMutability,
)
from .models import (
    EntitySemanticPatch,
    JsonValue,
    PointerSemanticMergeResult,
    SemanticMergeIssue,
    SemanticMergeResult,
    UnsafeStmtSemanticMergeResult,
    VariableSemanticMergeResult,
)


_SEMANTIC_FIELDS = (
    "nullability",
    "ownership",
    "mutability",
    "pointee_shape",
    "lifetime",
    "resource_semantics",
    "string_semantics",
)
_ENUM_FIELDS: dict[str, type[Enum]] = {
    "nullability": Nullability,
    "ownership": Ownership,
    "mutability": Mutability,
    "pointee_shape": PointeeShape,
    "lifetime": Lifetime,
}
_VARIABLE_FIELDS = ("mutability",)
_VARIABLE_ENUM_FIELDS: dict[str, type[Enum]] = {
    "mutability": VariableMutability,
}


class SemanticMergeError(RuntimeError):
    pass


class SemanticMerger:


    def merge(
        self,
        pointer_semantics: Mapping[str, Any],
        entity_patches: Iterable[EntitySemanticPatch],
        unsafe_stmt_semantics: Mapping[str, Any] | None = None,
        variable_semantics: Mapping[str, Any] | None = None,
    ) -> SemanticMergeResult:
        payload, pointers_by_key, entity_by_stmt = self._prepare_payload(
            pointer_semantics
        )
        variable_payload, variables_by_key, variable_entity_by_stmt = (
            self._prepare_variable_payload(variable_semantics)
        )
        unsafe_payload, unsafe_by_key, unsafe_entity_by_stmt = (
            self._prepare_unsafe_payload(unsafe_stmt_semantics)
        )
        pointer_results: list[PointerSemanticMergeResult] = []
        variable_results: list[VariableSemanticMergeResult] = []
        unsafe_results: list[UnsafeStmtSemanticMergeResult] = []
        issues: list[SemanticMergeIssue] = []
        seen_pointer_keys: set[tuple[int, int]] = set()
        seen_variable_keys: set[tuple[int, int]] = set()
        seen_unsafe_keys: set[tuple[int, int]] = set()

        for entity_patch in entity_patches:
            entity_id = self._positive_int(
                entity_patch.entity_id,
                "patch entity_id",
            )

            for pointer_patch in entity_patch.pointer_patches:
                stmt_id = self._positive_int(
                    pointer_patch.stmt_id,
                    "patch stmt_id",
                )
                key = (entity_id, stmt_id)
                if key in seen_pointer_keys:
                    issue = self._issue(
                        kind="duplicate_pointer_patch",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        reason=(
                            "more than one pointer patch was supplied for "
                            "this declaration"
                        ),
                    )
                    issues.append(issue)
                    pointer_results.append(
                        PointerSemanticMergeResult(
                            entity_id=entity_id,
                            stmt_id=stmt_id,
                            applied_fields=(),
                            confirmed_fields=(),
                            remaining_fields=self._remaining_fields(
                                pointers_by_key.get(key)
                            ),
                            issues=(issue,),
                        )
                    )
                    continue
                seen_pointer_keys.add(key)

                pointer_result = self._merge_pointer_patch(
                    entity_id=entity_id,
                    pointer_patch=pointer_patch,
                    pointer=pointers_by_key.get(key),
                    actual_entity_id=entity_by_stmt.get(stmt_id),
                )
                pointer_results.append(pointer_result)
                issues.extend(pointer_result.issues)

            for variable_patch in entity_patch.variable_patches:
                stmt_id = self._positive_int(
                    variable_patch.stmt_id,
                    "variable patch stmt_id",
                )
                key = (entity_id, stmt_id)
                if key in seen_variable_keys:
                    issue = self._issue(
                        kind="duplicate_variable_patch",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        reason=(
                            "more than one variable patch was supplied for "
                            "this declaration"
                        ),
                    )
                    issues.append(issue)
                    variable_results.append(
                        VariableSemanticMergeResult(
                            entity_id=entity_id,
                            stmt_id=stmt_id,
                            applied_fields=(),
                            confirmed_fields=(),
                            remaining_fields=self._remaining_variable_fields(
                                variables_by_key.get(key)
                            ),
                            issues=(issue,),
                        )
                    )
                    continue
                seen_variable_keys.add(key)

                variable_result = self._merge_variable_patch(
                    entity_id=entity_id,
                    variable_patch=variable_patch,
                    variable=variables_by_key.get(key),
                    actual_entity_id=variable_entity_by_stmt.get(stmt_id),
                )
                variable_results.append(variable_result)
                issues.extend(variable_result.issues)

            for unsafe_patch in entity_patch.unsafe_stmt_patches:
                stmt_id = self._positive_int(
                    unsafe_patch.stmt_id,
                    "unsafe patch stmt_id",
                )
                key = (entity_id, stmt_id)
                if key in seen_unsafe_keys:
                    issue = self._issue(
                        kind="duplicate_unsafe_stmt_patch",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        reason=(
                            "more than one unsafe stmt patch was supplied "
                            "for this statement"
                        ),
                    )
                    issues.append(issue)
                    unsafe_results.append(
                        UnsafeStmtSemanticMergeResult(
                            entity_id=entity_id,
                            stmt_id=stmt_id,
                            applied_fields=(),
                            confirmed_fields=(),
                            remaining_fields=self._remaining_unsafe_fields(
                                unsafe_by_key.get(key)
                            ),
                            issues=(issue,),
                        )
                    )
                    continue
                seen_unsafe_keys.add(key)

                unsafe_result = self._merge_unsafe_stmt_patch(
                    entity_id=entity_id,
                    unsafe_patch=unsafe_patch,
                    record=unsafe_by_key.get(key),
                    actual_entity_id=unsafe_entity_by_stmt.get(stmt_id),
                )
                unsafe_results.append(unsafe_result)
                issues.extend(unsafe_result.issues)

        remaining_entity_ids = {
            self._positive_int(pointer["entity_id"], "pointer entity_id")
            for pointer in pointers_by_key.values()
            if self._remaining_fields(pointer)
        }
        remaining_entity_ids.update(
            self._positive_int(variable["entity_id"], "variable entity_id")
            for variable in variables_by_key.values()
            if self._remaining_variable_fields(variable)
        )
        remaining_entity_ids.update(
            self._positive_int(record["entity_id"], "unsafe stmt entity_id")
            for record in unsafe_by_key.values()
            if self._remaining_unsafe_fields(record)
        )
        return SemanticMergeResult(
            pointer_semantics=self._json_payload(payload),
            variable_semantics=(
                self._json_payload(variable_payload)
                if variable_payload is not None
                else None
            ),
            unsafe_stmt_semantics=(
                self._json_payload(self._clean_unsafe_payload(unsafe_payload))
                if unsafe_payload is not None
                else None
            ),
            pointer_results=tuple(pointer_results),
            variable_results=tuple(variable_results),
            unsafe_stmt_results=tuple(unsafe_results),
            issues=tuple(issues),
            remaining_entity_ids=tuple(sorted(remaining_entity_ids)),
        )

    def _merge_pointer_patch(
        self,
        *,
        entity_id: int,
        pointer_patch: Any,
        pointer: dict[str, Any] | None,
        actual_entity_id: int | None,
    ) -> PointerSemanticMergeResult:
        stmt_id = pointer_patch.stmt_id
        applied_fields: list[str] = []
        confirmed_fields: list[str] = []
        issues: list[SemanticMergeIssue] = []

        if pointer is None:
            if actual_entity_id is None:
                reason = "pointer declaration does not exist"
                kind = "unknown_pointer"
            else:
                reason = (
                    f"pointer belongs to entity {actual_entity_id}, not "
                    f"entity {entity_id}"
                )
                kind = "entity_mismatch"
            issue = self._issue(
                kind=kind,
                entity_id=entity_id,
                stmt_id=stmt_id,
                reason=reason,
            )
            return PointerSemanticMergeResult(
                entity_id=entity_id,
                stmt_id=stmt_id,
                applied_fields=(),
                confirmed_fields=(),
                remaining_fields=(),
                issues=(issue,),
            )

        if not isinstance(pointer_patch.updates, Mapping):
            issue = self._issue(
                kind="invalid_updates",
                entity_id=entity_id,
                stmt_id=stmt_id,
                reason="pointer patch updates must be a mapping",
            )
            return PointerSemanticMergeResult(
                entity_id=entity_id,
                stmt_id=stmt_id,
                applied_fields=(),
                confirmed_fields=(),
                remaining_fields=self._remaining_fields(pointer),
                issues=(issue,),
            )

        for field, raw_value in pointer_patch.updates.items():
            if field not in _SEMANTIC_FIELDS:
                issues.append(
                    self._issue(
                        kind="invalid_field",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        field=str(field),
                        reason="field is not Agent-repairable",
                        suggested_value=self._json_value(raw_value),
                    )
                )
                continue
            try:
                value = self._normalize_value(field, raw_value)
            except (TypeError, ValueError) as exc:
                issues.append(
                    self._issue(
                        kind="invalid_value",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        field=field,
                        reason=str(exc),
                        suggested_value=self._json_value(raw_value),
                    )
                )
                continue

            existing_value = pointer.get(field)
            if existing_value is None:
                pointer[field] = value
                applied_fields.append(field)
            elif existing_value == value:
                confirmed_fields.append(field)
            else:
                issues.append(
                    self._issue(
                        kind="programmatic_conflict",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        field=field,
                        reason=(
                            "Agent suggestion differs from the existing "
                            "programmatic value; deferred to conflict "
                            "resolution"
                        ),
                        existing_value=existing_value,
                        suggested_value=value,
                    )
                )

        for conflict in pointer_patch.conflicts:
            field = str(conflict.field)
            issues.append(
                self._issue(
                    kind="agent_reported_conflict",
                    entity_id=entity_id,
                    stmt_id=stmt_id,
                    field=field,
                    reason=conflict.reason,
                    existing_value=self._json_value(
                        conflict.programmatic_value
                    ),
                    suggested_value=self._json_value(
                        conflict.suggested_value
                    ),
                    evidence_refs=tuple(str(ref) for ref in conflict.evidence_refs),
                )
            )

        return PointerSemanticMergeResult(
            entity_id=entity_id,
            stmt_id=stmt_id,
            applied_fields=tuple(applied_fields),
            confirmed_fields=tuple(confirmed_fields),
            remaining_fields=self._remaining_fields(pointer),
            issues=tuple(issues),
        )

    def _merge_variable_patch(
        self,
        *,
        entity_id: int,
        variable_patch: Any,
        variable: dict[str, Any] | None,
        actual_entity_id: int | None,
    ) -> VariableSemanticMergeResult:
        stmt_id = variable_patch.stmt_id
        applied_fields: list[str] = []
        confirmed_fields: list[str] = []
        issues: list[SemanticMergeIssue] = []

        if variable is None:
            if actual_entity_id is None:
                reason = "variable declaration does not exist"
                kind = "unknown_variable"
            else:
                reason = (
                    f"variable belongs to entity {actual_entity_id}, not "
                    f"entity {entity_id}"
                )
                kind = "entity_mismatch"
            issue = self._issue(
                kind=kind,
                entity_id=entity_id,
                stmt_id=stmt_id,
                reason=reason,
            )
            return VariableSemanticMergeResult(
                entity_id=entity_id,
                stmt_id=stmt_id,
                applied_fields=(),
                confirmed_fields=(),
                remaining_fields=(),
                issues=(issue,),
            )

        if not isinstance(variable_patch.updates, Mapping):
            issue = self._issue(
                kind="invalid_updates",
                entity_id=entity_id,
                stmt_id=stmt_id,
                reason="variable patch updates must be a mapping",
            )
            return VariableSemanticMergeResult(
                entity_id=entity_id,
                stmt_id=stmt_id,
                applied_fields=(),
                confirmed_fields=(),
                remaining_fields=self._remaining_variable_fields(variable),
                issues=(issue,),
            )

        for field, raw_value in variable_patch.updates.items():
            field = str(field)
            if field not in _VARIABLE_FIELDS:
                issues.append(
                    self._issue(
                        kind="invalid_field",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        field=field,
                        reason="field is not Agent-repairable for this variable",
                        suggested_value=self._json_value(raw_value),
                    )
                )
                continue
            try:
                value = self._normalize_variable_value(field, raw_value)
            except (TypeError, ValueError) as exc:
                issues.append(
                    self._issue(
                        kind="invalid_value",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        field=field,
                        reason=str(exc),
                        suggested_value=self._json_value(raw_value),
                    )
                )
                continue

            existing_value = variable.get(field)
            if existing_value is None:
                variable[field] = value
                applied_fields.append(field)
            elif existing_value == value:
                confirmed_fields.append(field)
            else:
                issues.append(
                    self._issue(
                        kind="programmatic_conflict",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        field=field,
                        reason=(
                            "Agent suggestion differs from the existing "
                            "programmatic variable value; deferred to "
                            "conflict resolution"
                        ),
                        existing_value=existing_value,
                        suggested_value=value,
                    )
                )

        for conflict in variable_patch.conflicts:
            issues.append(
                self._issue(
                    kind="agent_reported_conflict",
                    entity_id=entity_id,
                    stmt_id=stmt_id,
                    field=str(conflict.field),
                    reason=conflict.reason,
                    existing_value=self._json_value(conflict.programmatic_value),
                    suggested_value=self._json_value(conflict.suggested_value),
                    evidence_refs=tuple(str(ref) for ref in conflict.evidence_refs),
                )
            )

        return VariableSemanticMergeResult(
            entity_id=entity_id,
            stmt_id=stmt_id,
            applied_fields=tuple(applied_fields),
            confirmed_fields=tuple(confirmed_fields),
            remaining_fields=self._remaining_variable_fields(variable),
            issues=tuple(issues),
        )

    def _merge_unsafe_stmt_patch(
        self,
        *,
        entity_id: int,
        unsafe_patch: Any,
        record: dict[str, Any] | None,
        actual_entity_id: int | None,
    ) -> UnsafeStmtSemanticMergeResult:
        stmt_id = unsafe_patch.stmt_id
        applied_fields: list[str] = []
        confirmed_fields: list[str] = []
        issues: list[SemanticMergeIssue] = []

        if record is None:
            reason = (
                "unsafe stmt does not exist"
                if actual_entity_id is None
                else f"unsafe stmt belongs to entity {actual_entity_id}, not entity {entity_id}"
            )
            issue = self._issue(
                kind="unknown_unsafe_stmt"
                if actual_entity_id is None
                else "entity_mismatch",
                entity_id=entity_id,
                stmt_id=stmt_id,
                reason=reason,
            )
            return UnsafeStmtSemanticMergeResult(
                entity_id=entity_id,
                stmt_id=stmt_id,
                applied_fields=(),
                confirmed_fields=(),
                remaining_fields=(),
                issues=(issue,),
            )

        if not isinstance(unsafe_patch.updates, Mapping):
            issue = self._issue(
                kind="invalid_updates",
                entity_id=entity_id,
                stmt_id=stmt_id,
                reason="unsafe stmt patch updates must be a mapping",
            )
            return UnsafeStmtSemanticMergeResult(
                entity_id=entity_id,
                stmt_id=stmt_id,
                applied_fields=(),
                confirmed_fields=(),
                remaining_fields=self._remaining_unsafe_fields(record),
                issues=(issue,),
            )

        hints = record.setdefault("semantic_hints", {})
        if not isinstance(hints, dict):
            issue = self._issue(
                kind="invalid_record",
                entity_id=entity_id,
                stmt_id=stmt_id,
                reason="unsafe stmt semantic_hints must be an object",
            )
            return UnsafeStmtSemanticMergeResult(
                entity_id=entity_id,
                stmt_id=stmt_id,
                applied_fields=(),
                confirmed_fields=(),
                remaining_fields=self._remaining_unsafe_fields(record),
                issues=(issue,),
            )

        missing_fields = set(self._remaining_unsafe_fields(record))
        for field, raw_value in unsafe_patch.updates.items():
            field = str(field)
            if field not in missing_fields and field not in hints:
                issues.append(
                    self._issue(
                        kind="invalid_field",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        field=field,
                        reason="field is not Agent-repairable for this unsafe stmt",
                        suggested_value=self._json_value(raw_value),
                    )
                )
                continue
            value = self._json_value(raw_value)
            existing_value = hints.get(field)
            if existing_value is None:
                hints[field] = value
                applied_fields.append(field)
            elif existing_value == value:
                confirmed_fields.append(field)
            else:
                issues.append(
                    self._issue(
                        kind="programmatic_conflict",
                        entity_id=entity_id,
                        stmt_id=stmt_id,
                        field=field,
                        reason=(
                            "Agent suggestion differs from the existing "
                            "programmatic unsafe hint; deferred to conflict "
                            "resolution"
                        ),
                        existing_value=existing_value,
                        suggested_value=value,
                    )
                )

        remaining = [
            field
            for field in self._remaining_unsafe_fields(record)
            if field not in applied_fields and field not in confirmed_fields
        ]
        record["agent_missing_fields"] = remaining
        record["needs_agent"] = bool(remaining)

        for conflict in unsafe_patch.conflicts:
            issues.append(
                self._issue(
                    kind="agent_reported_conflict",
                    entity_id=entity_id,
                    stmt_id=stmt_id,
                    field=str(conflict.field),
                    reason=conflict.reason,
                    existing_value=self._json_value(conflict.programmatic_value),
                    suggested_value=self._json_value(conflict.suggested_value),
                    evidence_refs=tuple(str(ref) for ref in conflict.evidence_refs),
                )
            )

        return UnsafeStmtSemanticMergeResult(
            entity_id=entity_id,
            stmt_id=stmt_id,
            applied_fields=tuple(applied_fields),
            confirmed_fields=tuple(confirmed_fields),
            remaining_fields=tuple(remaining),
            issues=tuple(issues),
        )

    def _prepare_payload(
        self,
        pointer_semantics: Mapping[str, Any],
    ) -> tuple[
        dict[str, Any],
        dict[tuple[int, int], dict[str, Any]],
        dict[int, int],
    ]:
        if not isinstance(pointer_semantics, Mapping):
            raise SemanticMergeError("pointer semantics must be an object")
        payload = copy.deepcopy(dict(pointer_semantics))
        if payload.get("version") != 4:
            raise SemanticMergeError(
                "unsupported pointer semantics version: "
                f"{payload.get('version')!r}; expected 4"
            )
        if payload.get("kind") != "pointer_declarations":
            raise SemanticMergeError(
                "unsupported pointer semantics kind: "
                f"{payload.get('kind')!r}"
            )
        pointers = payload.get("pointers")
        if not isinstance(pointers, list):
            raise SemanticMergeError(
                "pointer semantics payload has no pointers array"
            )

        pointers_by_key: dict[tuple[int, int], dict[str, Any]] = {}
        entity_by_stmt: dict[int, int] = {}
        for index, pointer in enumerate(pointers):
            if not isinstance(pointer, dict):
                raise SemanticMergeError(
                    f"pointer record {index} is not an object"
                )
            entity_id = self._positive_int(
                pointer.get("entity_id"),
                f"pointer record {index} entity_id",
            )
            try:
                semantics = PointerDeclarationSemantics.from_dict(pointer)
            except (KeyError, TypeError, ValueError) as exc:
                raise SemanticMergeError(
                    f"invalid pointer record {index}: {exc}"
                ) from exc
            key = (entity_id, semantics.stmt_id)
            if key in pointers_by_key or semantics.stmt_id in entity_by_stmt:
                raise SemanticMergeError(
                    f"duplicate pointer stmt_id: {semantics.stmt_id}"
                )
            pointers_by_key[key] = pointer
            entity_by_stmt[semantics.stmt_id] = entity_id
        return payload, pointers_by_key, entity_by_stmt

    def _prepare_variable_payload(
        self,
        variable_semantics: Mapping[str, Any] | None,
    ) -> tuple[
        dict[str, Any] | None,
        dict[tuple[int, int], dict[str, Any]],
        dict[int, int],
    ]:
        if variable_semantics is None:
            return None, {}, {}
        if not isinstance(variable_semantics, Mapping):
            raise SemanticMergeError("variable semantics must be an object")
        payload = copy.deepcopy(dict(variable_semantics))
        if payload.get("version") != 1:
            raise SemanticMergeError(
                "unsupported variable semantics version: "
                f"{payload.get('version')!r}"
            )
        if payload.get("kind") != "variable_declarations":
            raise SemanticMergeError(
                "unsupported variable semantics kind: "
                f"{payload.get('kind')!r}"
            )
        variables = payload.get("variables")
        if not isinstance(variables, list):
            raise SemanticMergeError(
                "variable semantics payload has no variables array"
            )

        variables_by_key: dict[tuple[int, int], dict[str, Any]] = {}
        entity_by_stmt: dict[int, int] = {}
        for index, variable in enumerate(variables):
            if not isinstance(variable, dict):
                raise SemanticMergeError(
                    f"variable record {index} is not an object"
                )
            entity_id = self._positive_int(
                variable.get("entity_id"),
                f"variable record {index} entity_id",
            )
            try:
                semantics = VariableDeclarationSemantics.from_dict(variable)
            except (KeyError, TypeError, ValueError) as exc:
                raise SemanticMergeError(
                    f"invalid variable record {index}: {exc}"
                ) from exc
            key = (entity_id, semantics.stmt_id)
            if key in variables_by_key or semantics.stmt_id in entity_by_stmt:
                raise SemanticMergeError(
                    f"duplicate variable stmt_id: {semantics.stmt_id}"
                )
            variables_by_key[key] = variable
            entity_by_stmt[semantics.stmt_id] = entity_id
        return payload, variables_by_key, entity_by_stmt

    def _prepare_unsafe_payload(
        self,
        unsafe_stmt_semantics: Mapping[str, Any] | None,
    ) -> tuple[
        dict[str, Any] | None,
        dict[tuple[int, int], dict[str, Any]],
        dict[int, int],
    ]:
        if unsafe_stmt_semantics is None:
            return None, {}, {}
        if not isinstance(unsafe_stmt_semantics, Mapping):
            raise SemanticMergeError("unsafe stmt semantics must be an object")
        payload = copy.deepcopy(dict(unsafe_stmt_semantics))
        if payload.get("version") != 3:
            raise SemanticMergeError(
                "unsupported unsafe stmt semantics version: "
                f"{payload.get('version')!r}"
            )
        if payload.get("kind") != "unsafe_stmts":
            raise SemanticMergeError(
                "unsupported unsafe stmt semantics kind: "
                f"{payload.get('kind')!r}"
            )
        records = payload.get("unsafe_stmts")
        if not isinstance(records, list):
            raise SemanticMergeError(
                "unsafe stmt semantics payload has no unsafe_stmts array"
            )

        unsafe_by_key: dict[tuple[int, int], dict[str, Any]] = {}
        entity_by_stmt: dict[int, int] = {}
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise SemanticMergeError(
                    f"unsafe stmt record {index} is not an object"
                )
            entity_id = self._positive_int(
                record.get("entity_id"),
                f"unsafe stmt record {index} entity_id",
            )
            try:
                semantics = UnsafeStmtSemantics.from_dict(record)
            except (KeyError, TypeError, ValueError) as exc:
                raise SemanticMergeError(
                    f"invalid unsafe stmt record {index}: {exc}"
                ) from exc
            key = (entity_id, semantics.stmt_id)
            if key in unsafe_by_key or semantics.stmt_id in entity_by_stmt:
                raise SemanticMergeError(
                    f"duplicate unsafe stmt_id: {semantics.stmt_id}"
                )
            unsafe_by_key[key] = record
            entity_by_stmt[semantics.stmt_id] = entity_id
        return payload, unsafe_by_key, entity_by_stmt

    @classmethod
    def _clean_unsafe_payload(
        cls,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        records = payload.get("unsafe_stmts", [])
        cleaned_records: list[dict[str, Any]] = []
        if isinstance(records, list):
            for record in records:
                if not isinstance(record, Mapping):
                    continue
                cleaned_record = cls._clean_unsafe_record(record)
                if cleaned_record is not None:
                    cleaned_records.append(cleaned_record)
        return {
            "version": 3,
            "kind": "unsafe_stmts",
            "unsafe_stmts": cleaned_records,
        }

    @classmethod
    def _clean_unsafe_record(
        cls,
        record: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        raw_hints = record.get("semantic_hints", {})
        semantic_hints = (
            cls._compact_semantic_hints(raw_hints)
            if isinstance(raw_hints, Mapping)
            else {}
        )

        raw_missing_fields = record.get("agent_missing_fields", [])
        agent_missing_fields = (
            [
                str(field)
                for field in raw_missing_fields
                if isinstance(field, str) and field
            ]
            if isinstance(raw_missing_fields, list)
            else []
        )

        if not semantic_hints and not agent_missing_fields:
            return None

        operation = cls._json_value(record.get("operation"))
        semantic_kind = cls._json_value(record.get("semantic_kind"))
        target = record.get("target")
        target_record = dict(target) if isinstance(target, Mapping) else {}
        if operation is not None:
            target_record["operation"] = operation
        if semantic_kind is not None:
            target_record["semantic_kind"] = semantic_kind

        return {
            "entity_id": cls._json_value(record.get("entity_id")),
            "target": cls._json_value(target_record),
            "stmt_id": cls._json_value(record.get("stmt_id")),
            "operation": operation,
            "semantic_kind": semantic_kind,
            "semantic_hints": semantic_hints,
            "agent_missing_fields": agent_missing_fields,
        }

    @classmethod
    def _compact_semantic_hints(
        cls,
        value: Mapping[str, Any],
    ) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            json_item = cls._json_value(item)
            if json_item is None or json_item == [] or json_item == {}:
                continue
            if json_item == "unknown":
                continue
            result[str(key)] = json_item
        return result

    @staticmethod
    def _normalize_value(field: str, value: Any) -> JsonValue:
        if field == "resource_semantics":
            if not isinstance(value, Mapping):
                raise TypeError("resource_semantics must be an object")
            return ResourceSemantics.from_dict(dict(value)).to_dict()
        if field == "string_semantics":
            if not isinstance(value, Mapping):
                raise TypeError("string_semantics must be an object")
            return CStringSemantics.from_dict(dict(value)).to_dict()
        enum_type = _ENUM_FIELDS[field]
        if isinstance(value, enum_type):
            return str(value.value)
        if isinstance(value, Enum):
            raise TypeError(
                f"{field} must use {enum_type.__name__}, not "
                f"{type(value).__name__}"
            )
        if not isinstance(value, str):
            raise TypeError(f"{field} must be a string enum value")
        try:
            return str(enum_type(value).value)
        except ValueError as exc:
            allowed = ", ".join(str(item.value) for item in enum_type)
            raise ValueError(
                f"invalid {field} value {value!r}; allowed: {allowed}"
            ) from exc

    @staticmethod
    def _normalize_variable_value(field: str, value: Any) -> JsonValue:
        enum_type = _VARIABLE_ENUM_FIELDS[field]
        if isinstance(value, enum_type):
            return str(value.value)
        if isinstance(value, Enum):
            raise TypeError(
                f"{field} must use {enum_type.__name__}, not "
                f"{type(value).__name__}"
            )
        if not isinstance(value, str):
            raise TypeError(f"{field} must be a string enum value")
        try:
            return str(enum_type(value).value)
        except ValueError as exc:
            allowed = ", ".join(str(item.value) for item in enum_type)
            raise ValueError(
                f"invalid {field} value {value!r}; allowed: {allowed}"
            ) from exc

    @staticmethod
    def _remaining_fields(pointer: Mapping[str, Any] | None) -> tuple[str, ...]:
        if pointer is None:
            return ()
        return tuple(PointerDeclarationSemantics.from_dict(dict(pointer)).missing_fields())

    @staticmethod
    def _remaining_variable_fields(
        variable: Mapping[str, Any] | None,
    ) -> tuple[str, ...]:
        if variable is None:
            return ()
        return tuple(
            field for field in _VARIABLE_FIELDS if variable.get(field) is None
        )

    @staticmethod
    def _remaining_unsafe_fields(record: Mapping[str, Any] | None) -> tuple[str, ...]:
        if record is None:
            return ()
        raw_fields = record.get("agent_missing_fields", [])
        if not isinstance(raw_fields, list):
            return ()
        return tuple(str(field) for field in raw_fields)

    @classmethod
    def _issue(
        cls,
        *,
        kind: str,
        entity_id: int,
        reason: str,
        stmt_id: int | None = None,
        field: str | None = None,
        existing_value: Any = None,
        suggested_value: Any = None,
        evidence_refs: Iterable[Any] = (),
    ) -> SemanticMergeIssue:
        return SemanticMergeIssue(
            kind=kind,
            entity_id=entity_id,
            stmt_id=stmt_id,
            field=field,
            reason=reason,
            existing_value=cls._json_value(existing_value),
            suggested_value=cls._json_value(suggested_value),
            evidence_refs=tuple(str(ref) for ref in evidence_refs),
        )

    @staticmethod
    def _positive_int(value: Any, description: str) -> int:
        if isinstance(value, bool):
            raise SemanticMergeError(f"{description} must be a positive integer")
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise SemanticMergeError(
                f"{description} must be a positive integer"
            ) from exc
        if result <= 0:
            raise SemanticMergeError(f"{description} must be a positive integer")
        return result

    @classmethod
    def _json_payload(cls, payload: Mapping[str, Any]) -> dict[str, JsonValue]:
        return {
            str(key): cls._json_value(value)
            for key, value in payload.items()
        }

    @classmethod
    def _json_value(cls, value: Any) -> JsonValue:
        if isinstance(value, float) and math.isnan(value):
            return None
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Enum):
            return cls._json_value(value.value)
        if isinstance(value, Mapping):
            return {
                str(key): cls._json_value(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [cls._json_value(item) for item in value]
        return str(value)
