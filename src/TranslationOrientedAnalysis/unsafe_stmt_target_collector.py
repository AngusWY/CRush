from __future__ import annotations

import dataclasses
import json
import bisect
from enum import Enum
from pathlib import Path
from typing import Any

from .analysis_context import AnalysisContext
from .models import PointerSourceSpan, UnsafeStmtTarget
from .semantic_hint_schemas import UnsafeSemanticKind, UnsafeStmtOperation


_POINTER_ARITHMETIC_OPERATORS = frozenset({"+", "-", "+=", "-="})
_SEMANTICALLY_RELEVANT_CALLEES = frozenset(
    {
        "malloc",
        "calloc",
        "realloc",
        "free",
        "memcpy",
        "memmove",
        "memset",
        "memcmp",
        "memchr",
        "bcopy",
        "bzero",
        "strlen",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strdup",
        "strndup",
    }
)
_TARGET_OPERATION_TO_KIND: dict[str, UnsafeSemanticKind] = {
    UnsafeStmtOperation.MEM_READ.value: UnsafeSemanticKind.MEMORY_READ,
    UnsafeStmtOperation.MEM_WRITE.value: UnsafeSemanticKind.MEMORY_WRITE,
    UnsafeStmtOperation.ARRAY_READ.value: UnsafeSemanticKind.ARRAY_READ,
    UnsafeStmtOperation.ARRAY_WRITE.value: UnsafeSemanticKind.ARRAY_WRITE,
    UnsafeStmtOperation.ADDR_OF.value: UnsafeSemanticKind.ADDRESS_FLOW,




    UnsafeStmtOperation.RETURN_STMT.value: UnsafeSemanticKind.RETURN_VALUE,
    UnsafeStmtOperation.TYPE_CAST_STMT.value: UnsafeSemanticKind.TYPE_CAST,
    UnsafeStmtOperation.ASSIGN_STMT.value: UnsafeSemanticKind.ASSIGNMENT_FLOW,
    UnsafeStmtOperation.FIELD_READ.value: UnsafeSemanticKind.FIELD_READ,
    UnsafeStmtOperation.FIELD_WRITE.value: UnsafeSemanticKind.FIELD_WRITE,
}

_RELATED_SYMBOL_FIELDS = (
    "target",
    "name",
    "address",
    "source",
    "value",
    "operand",
    "operand2",
    "array",
    "index",
    "receiver_object",
    "object",
    "field",
    "field_name",
    "data_type",
    "prototype",
    "cast_action",
)
_ARGUMENT_FIELDS = (
    "positional_args",
    "packed_positional_args",
    "named_args",
    "packed_named_args",
    "args",
)


class UnsafeStmtTargetCollectionError(RuntimeError):
    pass


class UnsafeStmtTargetCollector:


    def __init__(
        self,
        *,
        context: AnalysisContext,
        translation_entities_path: Path,
    ) -> None:
        self.context = context
        self.translation_entities_path = translation_entities_path.resolve()
        self.workspace = self.translation_entities_path.parent
        self._origin_ranges_by_clean_path: (
            dict[Path, tuple[dict[str, Any], ...]] | None
        ) = None
        self._ranges_by_unit_path: dict[
            Path, tuple[dict[str, Any], ...] | None
        ] = {}
        self._range_starts_by_ranges_id: dict[int, tuple[int, ...]] = {}

    def collect(self) -> tuple[UnsafeStmtTarget, ...]:
        entities = self._read_translation_entities()
        targets: list[UnsafeStmtTarget] = []
        seen_stmt_ids: set[int] = set()

        for entity in entities:
            rows = self._entity_rows(entity)
            pointer_names = self._pointer_decl_names(rows)
            array_names = self._array_decl_names(rows)
            for row in rows:
                operation_text = self._text(getattr(row, "operation", ""))
                semantic_kind = _TARGET_OPERATION_TO_KIND.get(operation_text)
                if semantic_kind is None:
                    continue

                stmt_id = self._positive_id(getattr(row, "stmt_id", None))
                if stmt_id is None or stmt_id in seen_stmt_ids:
                    continue
                if not self._should_collect_row(
                    row,
                    pointer_names=pointer_names,
                    array_names=array_names,
                ):
                    continue

                target = self._make_target(
                    row=row,
                    entity=entity,
                    semantic_kind=semantic_kind,
                )
                seen_stmt_ids.add(stmt_id)
                targets.append(target)

        targets.sort(key=lambda target: (target.unit_id, target.stmt_id))
        return tuple(targets)

    def _should_collect_row(
        self,
        row: Any,
        *,
        pointer_names: set[str],
        array_names: set[str],
    ) -> bool:
        operation = self._text(getattr(row, "operation", ""))
        if operation in {
            "mem_read",
            "mem_write",
            "array_read",
            "array_write",
            "addr_of",
            "type_cast_stmt",
            "field_read",
            "field_write",
        }:
            return True
        if operation == "return_stmt":
            return self._enclosing_method_returns_pointer(row)









        if operation == "assign_stmt":
            return self._is_pointer_related_assignment(
                row,
                pointer_names=pointer_names,
                array_names=array_names,
            )
        return False

    def _is_project_callee(self, callee: str) -> bool:
        if not callee:
            return False
        for method_id in self.context.get_all_method_ids():
            if (self.context.get_method_name(method_id) or "").lower() == callee:
                return True
        return False

    def _is_pointer_related_assignment(
        self,
        row: Any,
        *,
        pointer_names: set[str],
        array_names: set[str],
    ) -> bool:
        target = self._text(getattr(row, "target", ""))
        source = self._text(getattr(row, "source", ""))
        operand = self._text(getattr(row, "operand", ""))
        operator = self._text(getattr(row, "operator", ""))
        if target in pointer_names or source in pointer_names or operand in pointer_names:
            return True
        if target in array_names or source in array_names or operand in array_names:
            return True
        if "." in target or "->" in target:
            return True
        return operator in _POINTER_ARITHMETIC_OPERATORS and bool(
            operand in pointer_names or operand in array_names
        )

    def _enclosing_method_returns_pointer(self, row: Any) -> bool:
        stmt_id = self._positive_id(getattr(row, "stmt_id", None))
        if stmt_id is None:
            return False
        method_id = self.context.get_method_id(stmt_id)
        if method_id is None:
            return False
        method_row = self.context.get_stmt(method_id)
        if method_row is None:
            return False
        return "*" in self._text(getattr(method_row, "data_type", ""))

    def _read_translation_entities(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(
                self.translation_entities_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise UnsafeStmtTargetCollectionError(
                "failed to read translation entities "
                f"{self.translation_entities_path}: {exc}"
            ) from exc

        entities = data.get("entities")
        if not isinstance(entities, list):
            raise UnsafeStmtTargetCollectionError(
                "translation entities file has no entities array: "
                f"{self.translation_entities_path}"
            )
        if not all(isinstance(entity, dict) for entity in entities):
            raise UnsafeStmtTargetCollectionError(
                "translation entities array contains a non-object entry: "
                f"{self.translation_entities_path}"
            )
        return entities

    def _entity_rows(self, entity: dict[str, Any]) -> tuple[Any, ...]:
        entity_id = self._required_id(entity, "id")
        kind = self._text(entity.get("kind"))

        if kind == "macro_family":
            return ()

        if kind == "function":
            root = self.context.get_stmt(entity_id)
            if root is None:
                self._missing_root(entity_id)
            return tuple(self.context.get_method_rows(entity_id))

        member_ids = entity.get("member_entity_ids")
        if not isinstance(member_ids, list) or not member_ids:
            member_ids = [entity_id]

        rows: list[Any] = []
        seen_rows: set[int] = set()
        for raw_member_id in member_ids:
            member_id = self._positive_id(raw_member_id)
            if member_id is None:
                raise UnsafeStmtTargetCollectionError(
                    f"translation entity {entity_id} has invalid member ID "
                    f"{raw_member_id!r}"
                )
            root = self.context.get_stmt(member_id)
            if root is None:
                self._missing_root(member_id)
            self._append_row_and_descendants(root, rows, seen_rows)
        return tuple(rows)

    def _append_row_and_descendants(
        self,
        root: Any,
        rows: list[Any],
        seen_rows: set[int],
    ) -> None:
        stack = [root]
        while stack:
            row = stack.pop()
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if stmt_id is None or stmt_id in seen_rows:
                continue
            seen_rows.add(stmt_id)
            rows.append(row)
            children = self.context.get_children(stmt_id)
            stack.extend(reversed(children))

    def _make_target(
        self,
        *,
        row: Any,
        entity: dict[str, Any],
        semantic_kind: UnsafeSemanticKind,
    ) -> UnsafeStmtTarget:
        stmt_id = self._required_row_id(row, "stmt_id")
        entity_id = self._required_id(entity, "id")
        unit_id = self.context.get_unit_id(stmt_id)
        if unit_id is None:
            raise UnsafeStmtTargetCollectionError(
                f"unsafe stmt {stmt_id} has no Lian unit"
            )

        operation_text = self._text(getattr(row, "operation", ""))
        try:
            operation = UnsafeStmtOperation(operation_text)
        except ValueError as exc:
            raise UnsafeStmtTargetCollectionError(
                f"unsafe stmt {stmt_id} has unsupported operation "
                f"{operation_text!r}"
            ) from exc

        return UnsafeStmtTarget(
            stmt_id=stmt_id,
            entity_id=entity_id,
            unit_id=unit_id,
            method_id=self.context.get_method_id(stmt_id),
            operation=operation,
            semantic_kind=semantic_kind,
            raw_gir=self._row_to_dict(row),
            source=self._source_span_or_none(row, unit_id),
            related_symbols=self._related_symbols(row),
        )

    def _source_span_or_none(
        self,
        row: Any,
        unit_id: int,
    ) -> PointerSourceSpan | None:
        unit_path = self.context.get_unit_path(unit_id)
        if unit_path is None:
            return None
        ranges = self._ranges_for_unit_path(unit_path)
        if ranges is None:
            return None

        clean_start = self._optional_nonnegative_int(
            getattr(row, "start_row", None)
        )
        clean_end = self._optional_nonnegative_int(
            getattr(row, "end_row", None)
        )
        start_col = self._optional_nonnegative_int(
            getattr(row, "start_col", None)
        )
        end_col = self._optional_nonnegative_int(
            getattr(row, "end_col", None)
        )
        if (
            clean_start is None
            or clean_end is None
            or start_col is None
            or end_col is None
        ):
            return None

        clean_start += 1
        clean_end += 1
        first = self._range_containing(ranges, clean_start)
        last = self._range_containing(ranges, clean_end)
        if first is None or last is None:
            return None
        if (
            str(first.get("origin_path")) != str(last.get("origin_path"))
            or str(first.get("origin_rel_path"))
            != str(last.get("origin_rel_path"))
        ):
            return None

        origin_start = int(first["origin_start"]) + (
            clean_start - int(first["clean_start"])
        )
        origin_end = int(last["origin_start"]) + (
            clean_end - int(last["clean_start"])
        )
        return PointerSourceSpan(
            path=str(first["origin_path"]),
            rel_path=str(first["origin_rel_path"]),
            start_line=origin_start,
            start_col=start_col,
            end_line=origin_end,
            end_col=end_col,
        )

    def _ranges_for_unit_path(
        self,
        unit_path: Path,
    ) -> tuple[dict[str, Any], ...] | None:
        ranges_by_path = self._origin_ranges()
        resolved_path = unit_path.resolve()
        if resolved_path in self._ranges_by_unit_path:
            return self._ranges_by_unit_path[resolved_path]
        direct = ranges_by_path.get(resolved_path)
        if direct is not None:
            self._ranges_by_unit_path[resolved_path] = direct
            return direct

        unit_parts = resolved_path.parts
        for clean_path, ranges in ranges_by_path.items():
            if self._path_suffix_matches(unit_parts, clean_path):
                self._ranges_by_unit_path[resolved_path] = ranges
                return ranges
        self._ranges_by_unit_path[resolved_path] = None
        return None

    def _path_suffix_matches(self, unit_parts: tuple[str, ...], clean_path: Path) -> bool:
        candidates = [clean_path.parts]
        try:
            relative_parts = clean_path.relative_to(self.workspace).parts
        except ValueError:
            relative_parts = ()
        if relative_parts:
            candidates.append(relative_parts)
            if relative_parts and relative_parts[0] == "preprocessed":
                candidates.append(relative_parts[1:])
        return any(
            bool(parts)
            and len(unit_parts) >= len(parts)
            and unit_parts[-len(parts) :] == parts
            for parts in candidates
        )

    def _origin_ranges(self) -> dict[Path, tuple[dict[str, Any], ...]]:
        if self._origin_ranges_by_clean_path is not None:
            return self._origin_ranges_by_clean_path

        manifest_path = self.workspace / "preprocess-manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self._origin_ranges_by_clean_path = {}
            return self._origin_ranges_by_clean_path

        units = manifest.get("units")
        if not isinstance(units, list):
            self._origin_ranges_by_clean_path = {}
            return self._origin_ranges_by_clean_path

        result: dict[Path, tuple[dict[str, Any], ...]] = {}
        for unit in units:
            if not isinstance(unit, dict):
                continue
            clean_value = unit.get("preprocessed_path")
            origin_value = unit.get("origin_map_path")
            if not isinstance(clean_value, str) or not isinstance(
                origin_value, str
            ):
                continue
            origin_path = (self.workspace / origin_value).resolve()
            try:
                origin_data = json.loads(
                    origin_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError):
                continue
            raw_ranges = origin_data.get("ranges")
            if not isinstance(raw_ranges, list) or not all(
                isinstance(item, dict) for item in raw_ranges
            ):
                continue
            clean_path = (self.workspace / clean_value).resolve()
            result[clean_path] = tuple(raw_ranges)

        self._origin_ranges_by_clean_path = result
        return result

    def _range_containing(
        self,
        ranges: tuple[dict[str, Any], ...],
        clean_line: int,
    ) -> dict[str, Any] | None:
        starts = self._range_starts_by_ranges_id.get(id(ranges))
        if starts is None:
            starts = tuple(int(item["clean_start"]) for item in ranges)
            self._range_starts_by_ranges_id[id(ranges)] = starts
        index = bisect.bisect_right(starts, clean_line) - 1
        if index < 0:
            return None
        item = ranges[index]
        if clean_line <= int(item["clean_end"]):
            return item
        return None

    def _row_to_dict(self, row: Any) -> dict[str, Any]:
        asdict = getattr(row, "_asdict", None)
        if callable(asdict):
            raw = dict(asdict())
        elif callable(getattr(row, "to_dict", None)):
            raw = dict(row.to_dict())
        elif dataclasses.is_dataclass(row):
            raw = dataclasses.asdict(row)
        elif hasattr(row, "__dict__"):
            raw = dict(vars(row))
        else:
            raw = {
                name: getattr(row, name)
                for name in dir(row)
                if not name.startswith("_")
                and not callable(getattr(row, name, None))
            }
        return {
            str(key): self._jsonable(value)
            for key, value in raw.items()
            if not str(key).startswith("_")
        }

    def _related_symbols(self, row: Any) -> tuple[str, ...]:
        values: list[str] = []
        for field_name in _RELATED_SYMBOL_FIELDS:
            values.extend(self._symbol_values(getattr(row, field_name, None)))
        for field_name in _ARGUMENT_FIELDS:
            values.extend(self._symbol_values(getattr(row, field_name, None)))

        seen: set[str] = set()
        result: list[str] = []
        for value in values:
            if not value or value in seen:
                continue
            seen.add(value)
            result.append(value)
        return tuple(result)

    def _symbol_values(self, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, dict):
            result: list[str] = []
            for key, item in value.items():
                result.extend(self._symbol_values(key))
                result.extend(self._symbol_values(item))
            return result
        if isinstance(value, (list, tuple, set, frozenset)):
            result = []
            for item in value:
                result.extend(self._symbol_values(item))
            return result
        text = self._text(value)
        if not text:
            return []
        return [text]

    def _jsonable(self, value: Any) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, Path):
            return str(value)
        if dataclasses.is_dataclass(value):
            return self._jsonable(dataclasses.asdict(value))
        if isinstance(value, dict):
            return {
                str(self._jsonable(key)): self._jsonable(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple, set, frozenset)):
            return [self._jsonable(item) for item in value]
        return str(value)

    @staticmethod
    def _required_id(entity: dict[str, Any], field_name: str) -> int:
        value = UnsafeStmtTargetCollector._positive_id(entity.get(field_name))
        if value is None:
            raise UnsafeStmtTargetCollectionError(
                f"translation entity has invalid {field_name}: "
                f"{entity.get(field_name)!r}"
            )
        return value

    @staticmethod
    def _required_row_id(row: Any, field_name: str) -> int:
        value = UnsafeStmtTargetCollector._positive_id(
            getattr(row, field_name, None)
        )
        if value is None:
            raise UnsafeStmtTargetCollectionError(
                f"GIR row has invalid {field_name}: "
                f"{getattr(row, field_name, None)!r}"
            )
        return value

    @staticmethod
    def _positive_id(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result > 0 else None

    @staticmethod
    def _optional_nonnegative_int(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result >= 0 else None

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        try:
            if value != value:
                return ""
        except (TypeError, ValueError):
            pass
        return str(value).strip()

    @classmethod
    def _pointer_decl_names(cls, rows: tuple[Any, ...]) -> set[str]:
        result: set[str] = set()
        for row in rows:
            if cls._text(getattr(row, "operation", "")) not in {
                "parameter_decl",
                "variable_decl",
            }:
                continue
            name = cls._text(getattr(row, "name", "")) or cls._text(
                getattr(row, "target", "")
            )
            c_type = cls._text(getattr(row, "data_type", ""))
            if name and "*" in c_type:
                result.add(name)
        return result

    @classmethod
    def _array_decl_names(cls, rows: tuple[Any, ...]) -> set[str]:
        result: set[str] = set()
        for row in rows:
            if cls._text(getattr(row, "operation", "")) not in {
                "parameter_decl",
                "variable_decl",
            }:
                continue
            name = cls._text(getattr(row, "name", "")) or cls._text(
                getattr(row, "target", "")
            )
            c_type = cls._text(getattr(row, "data_type", ""))
            if name and "[" in c_type and "]" in c_type:
                result.add(name)
        return result

    def _missing_root(self, stmt_id: int) -> None:
        raise UnsafeStmtTargetCollectionError(
            f"canonical GIR root {stmt_id} does not exist"
        )
