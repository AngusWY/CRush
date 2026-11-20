from __future__ import annotations

import ast
import dataclasses
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .analysis_context import AnalysisContext


class FunctionReturnAnalysisError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class FunctionReturnAnalysisResult:


    entity_id: int
    method_id: int
    function: str
    target: dict[str, Any]
    return_provenance: dict[str, Any]
    caller_usage: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "method_id": self.method_id,
            "function": self.function,
            "target": dict(self.target),
            "return_provenance": dict(self.return_provenance),
            "caller_usage": dict(self.caller_usage),
        }


class FunctionReturnAnalyzer:


    _NULL_VALUES = {"0", "null", "nullptr", "(void*)0", "((void*)0)"}
    _TEMP_RE = re.compile(r"^%[A-Za-z0-9_]+$")

    def __init__(
        self,
        context: AnalysisContext,
        *,
        translation_entities_path: Path,
    ) -> None:
        self.context = context
        self.translation_entities_path = translation_entities_path

    def analyze_all(self) -> tuple[FunctionReturnAnalysisResult, ...]:
        entities = self._load_function_entities()
        provisional: list[FunctionReturnAnalysisResult] = []
        for entity in entities:
            method_id = int(entity["id"])
            rows = self.context.get_method_rows(method_id)
            method = next(
                (
                    row
                    for row in rows
                    if self._text(getattr(row, "operation", ""))
                    == "method_decl"
                ),
                None,
            )
            if method is None or not self._is_pointer_type(method):
                continue
            provenance = self._analyze_return_provenance(method_id, rows)
            provisional.append(
                FunctionReturnAnalysisResult(
                    entity_id=method_id,
                    method_id=method_id,
                    function=str(entity["name"]),
                    target=self._function_target(entity),
                    return_provenance=provenance,
                    caller_usage={},
                )
            )

        results = [
            dataclasses.replace(
                result,
                caller_usage=self._analyze_caller_usage(result),
            )
            for result in provisional
        ]
        return tuple(sorted(results, key=lambda item: item.entity_id))

    def _analyze_return_provenance(
        self,
        method_id: int,
        rows: tuple[Any, ...],
    ) -> dict[str, Any]:
        parameters = tuple(self.context.get_method_parameters(method_id))
        parameter_indices = {
            self._text(getattr(row, "name", "")): index
            for index, row in enumerate(parameters)
            if self._text(getattr(row, "name", ""))
        }
        definitions: dict[str, list[Any]] = defaultdict(list)
        for row in rows:
            target = self._text(getattr(row, "target", ""))
            if target:
                definitions[target].append(row)

        origins: list[dict[str, Any]] = []
        return_stmt_ids: list[int] = []
        for row in rows:
            if self._text(getattr(row, "operation", "")) != "return_stmt":
                continue
            stmt_id = self._positive_int(getattr(row, "stmt_id", None))
            if stmt_id is not None:
                return_stmt_ids.append(stmt_id)
            value = self._first_text_attr(row, ("name", "value", "operand", "source"))
            origins.extend(
                self._trace_value(
                    value,
                    method_id=method_id,
                    before_stmt_id=stmt_id,
                    definitions=definitions,
                    parameter_indices=parameter_indices,
                    visited=set(),
                    projection_path=(),
                )
            )

        unique = self._deduplicate_origins(origins)
        nullable = any(item.get("kind") == "null" for item in unique)
        non_null = [item for item in unique if item.get("kind") != "null"]
        confidence = (
            "exact"
            if non_null and all(item.get("kind") != "unknown" for item in unique)
            else "unknown"
        )
        return {
            "origins": unique or [{"kind": "unknown", "confidence": "unknown"}],
            "nullable": nullable,
            "returns_alias": any(
                item.get("kind") in {"parameter", "parameter_projection"}
                for item in non_null
            ),
            "return_stmt_ids": sorted(return_stmt_ids),
            "confidence": confidence,
        }

    def _trace_value(
        self,
        value: str,
        *,
        method_id: int,
        before_stmt_id: int | None,
        definitions: dict[str, list[Any]],
        parameter_indices: dict[str, int],
        visited: set[tuple[str, int | None]],
        projection_path: tuple[dict[str, Any], ...],
    ) -> list[dict[str, Any]]:
        value = self._normalize_expr(value)
        if not value:
            return []
        if self._is_null(value):
            return [{"kind": "null", "confidence": "exact"}]
        if value in parameter_indices:
            result: dict[str, Any] = {
                "kind": "parameter_projection" if projection_path else "parameter",
                "parameter": value,
                "parameter_index": parameter_indices[value],
                "alias_kind": "borrowed",
                "confidence": "exact",
            }
            if projection_path:
                result["projection_path"] = list(reversed(projection_path))
                if len(projection_path) == 1:
                    result["projection"] = dict(projection_path[0])
            return [result]

        key = (value, before_stmt_id)
        if key in visited:
            return [{"kind": "unknown", "expression": value, "confidence": "unknown"}]
        next_visited = {*visited, key}
        candidates = [
            row
            for row in definitions.get(value, ())
            if before_stmt_id is None
            or (self._positive_int(getattr(row, "stmt_id", None)) or 0)
            <= before_stmt_id
        ]
        if not candidates:
            storage = self.context.classify_symbol_storage(method_id, value)
            if storage in {"global", "local", "param"}:
                if storage == "param":
                    return [
                        {
                            "kind": "parameter",
                            "parameter": value,
                            "alias_kind": "borrowed",
                            "confidence": "exact",
                        }
                    ]
                return [
                    {
                        "kind": "global" if storage == "global" else "local",
                        "symbol": value,
                        "confidence": "exact",
                    }
                ]
            return [{"kind": "unknown", "expression": value, "confidence": "unknown"}]

        results: list[dict[str, Any]] = []
        for row in candidates:
            operation = self._text(getattr(row, "operation", ""))
            stmt_id = self._positive_int(getattr(row, "stmt_id", None))
            if operation in {"assign_stmt", "type_cast_stmt", "addr_of"}:
                source = self._first_text_attr(row, ("source", "operand", "value", "name"))
                results.extend(
                    self._trace_value(
                        source,
                        method_id=method_id,
                        before_stmt_id=stmt_id,
                        definitions=definitions,
                        parameter_indices=parameter_indices,
                        visited=next_visited,
                        projection_path=projection_path,
                    )
                )
            elif operation == "array_read":
                array = self._text(getattr(row, "array", ""))
                index = self._text(getattr(row, "index", "")) or "unknown"
                results.extend(
                    self._trace_value(
                        array,
                        method_id=method_id,
                        before_stmt_id=stmt_id,
                        definitions=definitions,
                        parameter_indices=parameter_indices,
                        visited=next_visited,
                        projection_path=(
                            *projection_path,
                            {"kind": "array_element", "index_expression": index},
                        ),
                    )
                )
            elif operation == "field_read":
                receiver = self._text(getattr(row, "receiver_object", ""))
                field = self._text(getattr(row, "field", "")) or "unknown"
                results.extend(
                    self._trace_value(
                        receiver,
                        method_id=method_id,
                        before_stmt_id=stmt_id,
                        definitions=definitions,
                        parameter_indices=parameter_indices,
                        visited=next_visited,
                        projection_path=(
                            *projection_path,
                            {"kind": "field", "field": field},
                        ),
                    )
                )
            elif operation == "call_stmt":
                callee = self._text(getattr(row, "name", ""))
                if callee in {"malloc", "calloc", "realloc", "aligned_alloc"}:
                    results.append(
                        {"kind": "heap", "allocator": callee, "confidence": "exact"}
                    )
                else:
                    results.append(
                        {
                            "kind": "external_call",
                            "callee": callee or "unknown",
                            "confidence": "exact" if callee else "unknown",
                        }
                    )
            else:
                results.append(
                    {"kind": "unknown", "expression": value, "confidence": "unknown"}
                )
        return results

    def _analyze_caller_usage(
        self,
        result: FunctionReturnAnalysisResult,
    ) -> dict[str, Any]:
        array_origin = self._single_array_origin(result.return_provenance)
        if array_origin is None:
            return {
                "retained_across_repeated_call": False,
                "repeated_call_uses_same_base": False,
                "simultaneous_element_access": False,
                "evidence_callers": [],
                "evidence_call_stmt_ids": [],
                "confidence": "unknown",
            }

        parameter_index = int(array_origin["parameter_index"])
        evidence_callers: set[int] = set()
        evidence_calls: set[int] = set()
        for caller_id in self.context.get_callers(result.method_id):
            rows = self.context.get_method_rows(caller_id)
            calls = [
                (index, row, self._call_arguments(row))
                for index, row in enumerate(rows)
                if self._text(getattr(row, "operation", "")) == "call_stmt"
                and self._text(getattr(row, "name", "")) == result.function
            ]
            for left_index in range(len(calls)):
                first_pos, first_call, first_args = calls[left_index]
                if parameter_index >= len(first_args):
                    continue
                for second_pos, second_call, second_args in calls[left_index + 1 :]:
                    if parameter_index >= len(second_args):
                        continue
                    if self._normalize_expr(first_args[parameter_index]) != self._normalize_expr(
                        second_args[parameter_index]
                    ):
                        continue
                    aliases = self._result_aliases(
                        rows[first_pos:second_pos],
                        self._text(getattr(first_call, "target", "")),
                    )
                    if not aliases:
                        continue
                    use_row = self._find_retained_use(
                        rows,
                        second_pos,
                        aliases,
                        second_call,
                    )
                    if use_row is None:
                        continue
                    evidence_callers.add(caller_id)
                    for call in (first_call, second_call):
                        stmt_id = self._positive_int(getattr(call, "stmt_id", None))
                        if stmt_id is not None:
                            evidence_calls.add(stmt_id)

        detected = bool(evidence_callers)
        return {
            "retained_across_repeated_call": detected,
            "repeated_call_uses_same_base": detected,
            "simultaneous_element_access": detected,
            "evidence_callers": sorted(evidence_callers),
            "evidence_call_stmt_ids": sorted(evidence_calls),
            "confidence": "exact" if detected else "unknown",
        }

    def _find_retained_use(
        self,
        rows: tuple[Any, ...],
        second_pos: int,
        aliases: set[str],
        second_call: Any,
    ) -> Any | None:
        second_parent = self._positive_int(getattr(second_call, "parent_stmt_id", None))
        for row in rows[second_pos + 1 :]:
            if not self._row_uses_any(row, aliases):
                continue
            if second_parent is None or self._is_in_scope(row, second_parent, rows):
                return row
        return None

    def _is_in_scope(
        self,
        row: Any,
        scope_id: int,
        rows: tuple[Any, ...],
    ) -> bool:
        rows_by_id = {
            stmt_id: item
            for item in rows
            if (stmt_id := self._positive_int(getattr(item, "stmt_id", None)))
            is not None
        }
        parent = self._positive_int(getattr(row, "parent_stmt_id", None))
        seen: set[int] = set()
        while parent is not None and parent not in seen:
            if parent == scope_id:
                return True
            seen.add(parent)
            parent_row = rows_by_id.get(parent)
            if parent_row is None:
                break
            parent = self._positive_int(getattr(parent_row, "parent_stmt_id", None))
        return False

    def _result_aliases(self, rows: tuple[Any, ...], result: str) -> set[str]:
        if not result:
            return set()
        aliases = {result}
        changed = True
        while changed:
            changed = False
            for row in rows:
                if self._text(getattr(row, "operation", "")) != "assign_stmt":
                    continue
                source = self._first_text_attr(row, ("operand", "source"))
                target = self._text(getattr(row, "target", ""))
                if source in aliases and target and target not in aliases:
                    aliases.add(target)
                    changed = True
        return aliases

    def _row_uses_any(self, row: Any, aliases: set[str]) -> bool:
        fields = (
            "source",
            "operand",
            "condition",
            "address",
            "operand2",
            "receiver_object",
            "array",
            "index",
            "positional_args",
            "name",
        )
        values = [self._text(getattr(row, field, "")) for field in fields]
        return any(
            re.search(rf"(?<![A-Za-z0-9_]){re.escape(alias)}(?![A-Za-z0-9_])", value)
            for alias in aliases
            for value in values
            if value
        )

    @staticmethod
    def _single_array_origin(provenance: dict[str, Any]) -> dict[str, Any] | None:
        origins = [
            item
            for item in provenance.get("origins", [])
            if isinstance(item, dict) and item.get("kind") != "null"
        ]
        if not origins or provenance.get("confidence") != "exact":
            return None
        first = origins[0]
        if any(
            item.get("kind") != "parameter_projection"
            or item.get("parameter") != first.get("parameter")
            or item.get("parameter_index") != first.get("parameter_index")
            or item.get("projection", {}).get("kind") != "array_element"
            for item in origins
        ):
            return None
        return first

    @classmethod
    def _call_arguments(cls, row: Any) -> tuple[str, ...]:
        raw = getattr(row, "positional_args", None)
        if isinstance(raw, (list, tuple)):
            return tuple(cls._text(item) for item in raw)
        text = cls._text(raw)
        if not text:
            return ()
        try:
            value = ast.literal_eval(text)
        except (SyntaxError, ValueError):
            return ()
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(cls._text(item) for item in value)

    def _load_function_entities(self) -> tuple[dict[str, Any], ...]:
        try:
            payload = json.loads(self.translation_entities_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FunctionReturnAnalysisError(
                f"failed to read {self.translation_entities_path}: {exc}"
            ) from exc
        entities = payload.get("entities") if isinstance(payload, dict) else None
        if not isinstance(entities, list):
            raise FunctionReturnAnalysisError("translation entities has no entities array")
        return tuple(
            item
            for item in entities
            if isinstance(item, dict)
            and item.get("kind") == "function"
            and isinstance(item.get("id"), int)
            and isinstance(item.get("name"), str)
            and isinstance(item.get("source"), dict)
        )

    @staticmethod
    def _function_target(entity: dict[str, Any]) -> dict[str, Any]:
        entity_id = int(entity["id"])
        return {
            "stmt_id": entity_id,
            "entity_id": entity_id,
            "unit_id": int(entity["unit_id"]),
            "method_id": entity_id,
            "name": str(entity["name"]),
            "c_type": None,
            "operation": "function_contract",
            "location": "function",
            "semantic_kind": "return_provenance",
            "aggregate_id": None,
            "aggregate_name": None,
            "source": dict(entity["source"]),
        }

    @classmethod
    def _is_pointer_type(cls, row: Any) -> bool:
        data_type = cls._text(getattr(row, "data_type", ""))
        attrs = cls._text(getattr(row, "attrs", ""))
        return "*" in data_type or "pointer" in attrs.lower()

    @classmethod
    def _deduplicate_origins(cls, origins: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for origin in origins:
            key = json.dumps(origin, sort_keys=True, ensure_ascii=True)
            unique[key] = origin
        return list(unique.values())

    @classmethod
    def _is_null(cls, value: str) -> bool:
        compact = re.sub(r"\s+", "", value).lower()
        return compact in cls._NULL_VALUES

    @classmethod
    def _normalize_expr(cls, value: Any) -> str:
        text = cls._text(value).strip()
        while text.startswith("(") and text.endswith(")") and len(text) > 2:
            text = text[1:-1].strip()
        return text.lstrip("&").strip()

    @classmethod
    def _first_text_attr(cls, row: Any, names: tuple[str, ...]) -> str:
        for name in names:
            value = cls._text(getattr(row, name, ""))
            if value:
                return value
        return ""

    @staticmethod
    def _positive_int(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result > 0 else None

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, float) and math.isnan(value):
            return ""
        return str(value).strip()
