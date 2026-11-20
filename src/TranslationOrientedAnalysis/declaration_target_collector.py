from __future__ import annotations

import json
import re
import bisect
from pathlib import Path
from typing import Any

from .analysis_context import AnalysisContext
from .models import (
    PointerLocation,
    PointerSourceSpan,
    PointerTarget,
    VariableLocation,
    VariableTarget,
)
from .semantic_hint_schemas import (
    PointerDeclarationOperation,
    VariableDeclarationOperation,
)


_POINTER_DECLARATION_OPERATIONS = frozenset(
    {
        PointerDeclarationOperation.PARAMETER_DECL.value,
        PointerDeclarationOperation.TYPE_ALIAS_DECL.value,
        PointerDeclarationOperation.VARIABLE_DECL.value,
    }
)
_VARIABLE_DECLARATION_OPERATIONS = frozenset(
    {
        VariableDeclarationOperation.PARAMETER_DECL.value,
        VariableDeclarationOperation.VARIABLE_DECL.value,
    }
)
_AGGREGATE_OPERATIONS = frozenset({"struct_decl", "union_decl"})
_TYPE_ALIAS_OPERATION = "type_alias_decl"
_TYPE_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_DECLARATION_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_POINTER_ATTRIBUTE_NAMES = frozenset(
    {"pointer", "pointer_type", "ptr", "function_pointer"}
)


class PointerTargetCollectionError(RuntimeError):
    pass


class DeclarationTargetCollectionError(RuntimeError):
    pass


class DeclarationTargetCollector:


    def __init__(
        self,
        *,
        context: AnalysisContext,
        translation_entities_path: Path,
    ) -> None:
        self.pointer_collector = PointerTargetCollector(
            context=context,
            translation_entities_path=translation_entities_path,
        )
        self.variable_collector = VariableTargetCollector(
            context=context,
            translation_entities_path=translation_entities_path,
        )

    def collect_pointer_targets(self) -> tuple[PointerTarget, ...]:
        return self.pointer_collector.collect()

    def collect_variable_targets(self) -> tuple[VariableTarget, ...]:
        return self.variable_collector.collect()


class PointerTargetCollector:


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

    def collect(self) -> tuple[PointerTarget, ...]:
        entities = self._read_translation_entities()
        targets: list[PointerTarget] = []
        seen_stmt_ids: set[int] = set()

        for entity in entities:
            for row in self._entity_rows(entity):
                operation = self._text(getattr(row, "operation", ""))
                if operation not in _POINTER_DECLARATION_OPERATIONS:
                    continue

                stmt_id = self._positive_id(getattr(row, "stmt_id", None))
                if stmt_id is None or stmt_id in seen_stmt_ids:
                    continue

                target = self._make_target(row, entity)
                if target is None:
                    continue
                seen_stmt_ids.add(stmt_id)
                targets.append(target)

        targets.sort(key=lambda target: (target.unit_id, target.stmt_id))
        return tuple(targets)

    def _read_translation_entities(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(
                self.translation_entities_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise PointerTargetCollectionError(
                "failed to read translation entities "
                f"{self.translation_entities_path}: {exc}"
            ) from exc

        entities = data.get("entities")
        if not isinstance(entities, list):
            raise PointerTargetCollectionError(
                "translation entities file has no entities array: "
                f"{self.translation_entities_path}"
            )
        if not all(isinstance(entity, dict) for entity in entities):
            raise PointerTargetCollectionError(
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
                raise PointerTargetCollectionError(
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
        row: Any,
        entity: dict[str, Any],
    ) -> PointerTarget | None:
        stmt_id = self._required_row_id(row, "stmt_id")
        entity_id = self._required_id(entity, "id")
        unit_id = self.context.get_unit_id(stmt_id)
        if unit_id is None:
            raise PointerTargetCollectionError(
                f"declaration {stmt_id} has no Lian unit"
            )

        operation_text = self._text(getattr(row, "operation", ""))
        try:
            operation = PointerDeclarationOperation(operation_text)
        except ValueError as exc:
            raise PointerTargetCollectionError(
                f"declaration {stmt_id} has unsupported operation "
                f"{operation_text!r}"
            ) from exc

        name = self._text(getattr(row, "name", ""))
        c_type = self._declaration_type(row)
        if not name:
            return None
        if not c_type:
            if _DECLARATION_NAME_PATTERN.fullmatch(name) is None:
                return None
            raise PointerTargetCollectionError(
                f"declaration {stmt_id} ({name}) has no data type"
            )
        if not self._is_pointer_declaration(row, unit_id, set()):
            return None

        method_id = self.context.get_method_id(stmt_id)
        aggregate = self._aggregate_ancestor(stmt_id)
        location: PointerLocation
        aggregate_id: int | None = None
        aggregate_name: str | None = None

        if operation is PointerDeclarationOperation.TYPE_ALIAS_DECL:
            location = PointerLocation.TYPE_ALIAS
            method_id = None
        elif operation is PointerDeclarationOperation.PARAMETER_DECL:
            if method_id is None:
                raise PointerTargetCollectionError(
                    f"pointer parameter {stmt_id} ({name}) has no method"
                )
            location = PointerLocation.PARAMETER
        elif aggregate is not None:
            aggregate_operation = self._text(
                getattr(aggregate, "operation", "")
            )
            location = (
                PointerLocation.STRUCT_MEMBER
                if aggregate_operation == "struct_decl"
                else PointerLocation.UNION_MEMBER
            )
            aggregate_id = self._required_row_id(aggregate, "stmt_id")
            aggregate_name = self._aggregate_name(aggregate, entity)
            method_id = None
        elif method_id is not None:
            location = PointerLocation.LOCAL
        else:
            location = PointerLocation.GLOBAL

        return PointerTarget(
            stmt_id=stmt_id,
            entity_id=entity_id,
            unit_id=unit_id,
            method_id=method_id,
            name=name,
            c_type=c_type,
            operation=operation,
            location=location,
            aggregate_id=aggregate_id,
            aggregate_name=aggregate_name,
            source=self._source_span(row, unit_id),
        )

    def _source_span(
        self,
        row: Any,
        unit_id: int,
    ) -> PointerSourceSpan:
        unit_path = self.context.get_unit_path(unit_id)
        if unit_path is None:
            raise PointerTargetCollectionError(
                f"Lian unit {unit_id} has no source path"
            )
        ranges = self._ranges_for_unit_path(unit_path)
        if ranges is None:
            raise PointerTargetCollectionError(
                f"no origin map found for Lian unit {unit_id}: {unit_path}"
            )

        clean_start = self._nonnegative_int(
            getattr(row, "start_row", None),
            f"declaration {getattr(row, 'stmt_id', '?')} start_row",
        ) + 1
        clean_end = self._nonnegative_int(
            getattr(row, "end_row", None),
            f"declaration {getattr(row, 'stmt_id', '?')} end_row",
        ) + 1
        start_col = self._nonnegative_int(
            getattr(row, "start_col", None),
            f"declaration {getattr(row, 'stmt_id', '?')} start_col",
        )
        end_col = self._nonnegative_int(
            getattr(row, "end_col", None),
            f"declaration {getattr(row, 'stmt_id', '?')} end_col",
        )
        first = self._range_containing(ranges, clean_start)
        last = self._range_containing(ranges, clean_end)
        if first is None or last is None:
            raise PointerTargetCollectionError(
                "pointer declaration source is outside the preprocessed "
                f"origin map: unit {unit_id}, rows {clean_start}-{clean_end}"
            )
        if (
            str(first.get("origin_path")) != str(last.get("origin_path"))
            or str(first.get("origin_rel_path"))
            != str(last.get("origin_rel_path"))
        ):
            raise PointerTargetCollectionError(
                "pointer declaration crosses original source files: "
                f"unit {unit_id}, rows {clean_start}-{clean_end}"
            )

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
        resolved_path = unit_path.resolve()
        if resolved_path in self._ranges_by_unit_path:
            return self._ranges_by_unit_path[resolved_path]
        ranges_by_path = self._origin_ranges()
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
        except (OSError, json.JSONDecodeError) as exc:
            raise PointerTargetCollectionError(
                f"failed to read preprocess manifest {manifest_path}: {exc}"
            ) from exc
        units = manifest.get("units")
        if not isinstance(units, list):
            raise PointerTargetCollectionError(
                f"preprocess manifest has no units array: {manifest_path}"
            )

        result: dict[Path, tuple[dict[str, Any], ...]] = {}
        for index, unit in enumerate(units):
            if not isinstance(unit, dict):
                raise PointerTargetCollectionError(
                    f"preprocess manifest unit {index} is not an object"
                )
            clean_value = unit.get("preprocessed_path")
            origin_value = unit.get("origin_map_path")
            if not isinstance(clean_value, str) or not isinstance(
                origin_value, str
            ):
                raise PointerTargetCollectionError(
                    f"preprocess manifest unit {index} has invalid paths"
                )
            origin_path = (self.workspace / origin_value).resolve()
            try:
                origin_data = json.loads(
                    origin_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError) as exc:
                raise PointerTargetCollectionError(
                    f"failed to read origin map {origin_path}: {exc}"
                ) from exc
            raw_ranges = origin_data.get("ranges")
            if not isinstance(raw_ranges, list) or not all(
                isinstance(item, dict) for item in raw_ranges
            ):
                raise PointerTargetCollectionError(
                    f"origin map has invalid ranges array: {origin_path}"
                )
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

    def _is_pointer_declaration(
        self,
        row: Any,
        unit_id: int,
        resolving_aliases: set[int],
    ) -> bool:
        c_type = self._declaration_type(row)
        if "*" in c_type or self._has_pointer_attribute(row):
            return True

        declarations = self.context.get_unit_symbol_declarations(unit_id)
        for type_name in _TYPE_NAME_PATTERN.findall(c_type):
            for declaration_id in declarations.get(type_name, ()):
                if declaration_id in resolving_aliases:
                    continue
                declaration = self.context.get_stmt(declaration_id)
                if (
                    declaration is None
                    or self._text(getattr(declaration, "operation", ""))
                    != _TYPE_ALIAS_OPERATION
                ):
                    continue
                resolving_aliases.add(declaration_id)
                try:
                    if self._is_pointer_declaration(
                        declaration, unit_id, resolving_aliases
                    ):
                        return True
                finally:
                    resolving_aliases.remove(declaration_id)
        return False

    @staticmethod
    def _has_pointer_attribute(row: Any) -> bool:
        for field_name in ("attrs", "attributes", "type_attrs"):
            value = getattr(row, field_name, None)
            if value is None:
                continue
            if isinstance(value, str):
                items = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value)
            else:
                try:
                    items = [str(item) for item in value]
                except TypeError:
                    items = [str(value)]
            if any(item.lower() in _POINTER_ATTRIBUTE_NAMES for item in items):
                return True
        return False

    def _aggregate_ancestor(self, stmt_id: int) -> Any | None:
        for ancestor in self.context.get_ancestors(stmt_id):
            if (
                self._text(getattr(ancestor, "operation", ""))
                in _AGGREGATE_OPERATIONS
            ):
                return ancestor
            if self._text(getattr(ancestor, "operation", "")) == "method_decl":
                return None
        return None

    def _aggregate_name(
        self,
        aggregate: Any,
        entity: dict[str, Any],
    ) -> str | None:
        entity_name = self._text(entity.get("name"))
        raw_name = self._text(getattr(aggregate, "name", ""))
        if entity_name and not entity_name.startswith("%"):
            return entity_name
        if raw_name and not raw_name.startswith("%"):
            return raw_name
        return entity_name or raw_name or None

    @staticmethod
    def _declaration_type(row: Any) -> str:
        for field_name in ("data_type", "default_data_type"):
            value = PointerTargetCollector._text(
                getattr(row, field_name, "")
            )
            if value:
                return value
        return ""

    @staticmethod
    def _required_id(entity: dict[str, Any], field_name: str) -> int:
        value = PointerTargetCollector._positive_id(entity.get(field_name))
        if value is None:
            raise PointerTargetCollectionError(
                f"translation entity has invalid {field_name}: "
                f"{entity.get(field_name)!r}"
            )
        return value

    @staticmethod
    def _required_row_id(row: Any, field_name: str) -> int:
        value = PointerTargetCollector._positive_id(
            getattr(row, field_name, None)
        )
        if value is None:
            raise PointerTargetCollectionError(
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
    def _nonnegative_int(value: Any, description: str) -> int:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise PointerTargetCollectionError(
                f"{description} must be a non-negative integer"
            ) from exc
        if result < 0:
            raise PointerTargetCollectionError(
                f"{description} must be a non-negative integer"
            )
        return result

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _missing_root(self, stmt_id: int) -> None:
        raise PointerTargetCollectionError(
            f"canonical GIR root {stmt_id} does not exist"
        )


class VariableTargetCollectionError(RuntimeError):
    pass


class VariableTargetCollector:


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

    def collect(self) -> tuple[VariableTarget, ...]:
        entities = self._read_translation_entities()
        targets: list[VariableTarget] = []
        seen_stmt_ids: set[int] = set()

        for entity in entities:
            for row in self._entity_rows(entity):
                operation = self._text(getattr(row, "operation", ""))
                if operation not in _VARIABLE_DECLARATION_OPERATIONS:
                    continue

                stmt_id = self._positive_id(getattr(row, "stmt_id", None))
                if stmt_id is None or stmt_id in seen_stmt_ids:
                    continue

                target = self._make_target(row, entity)
                if target is None:
                    continue
                seen_stmt_ids.add(stmt_id)
                targets.append(target)

        targets.sort(key=lambda target: (target.unit_id, target.stmt_id))
        return tuple(targets)

    def _read_translation_entities(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(
                self.translation_entities_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise VariableTargetCollectionError(
                "failed to read translation entities "
                f"{self.translation_entities_path}: {exc}"
            ) from exc

        entities = data.get("entities")
        if not isinstance(entities, list):
            raise VariableTargetCollectionError(
                "translation entities file has no entities array: "
                f"{self.translation_entities_path}"
            )
        if not all(isinstance(entity, dict) for entity in entities):
            raise VariableTargetCollectionError(
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
                raise VariableTargetCollectionError(
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
        row: Any,
        entity: dict[str, Any],
    ) -> VariableTarget | None:
        stmt_id = self._required_row_id(row, "stmt_id")
        entity_id = self._required_id(entity, "id")
        unit_id = self.context.get_unit_id(stmt_id)
        if unit_id is None:
            raise VariableTargetCollectionError(
                f"variable declaration {stmt_id} has no Lian unit"
            )

        operation_text = self._text(getattr(row, "operation", ""))
        try:
            operation = VariableDeclarationOperation(operation_text)
        except ValueError as exc:
            raise VariableTargetCollectionError(
                f"variable declaration {stmt_id} has unsupported operation "
                f"{operation_text!r}"
            ) from exc

        name = self._text(getattr(row, "name", ""))
        c_type = self._declaration_type(row)
        if not name:
            return None
        if not c_type:
            if _DECLARATION_NAME_PATTERN.fullmatch(name) is None:
                return None
            raise VariableTargetCollectionError(
                f"variable declaration {stmt_id} ({name}) has no data type"
            )
        if self._is_pointer_declaration(row, unit_id, set()):
            return None

        method_id = self.context.get_method_id(stmt_id)
        aggregate = self._aggregate_ancestor(stmt_id)
        aggregate_id: int | None = None
        aggregate_name: str | None = None

        if operation is VariableDeclarationOperation.PARAMETER_DECL:
            if method_id is None:
                raise VariableTargetCollectionError(
                    f"variable parameter {stmt_id} ({name}) has no method"
                )
            location = VariableLocation.PARAMETER
        elif aggregate is not None:
            aggregate_operation = self._text(
                getattr(aggregate, "operation", "")
            )
            location = (
                VariableLocation.STRUCT_MEMBER
                if aggregate_operation == "struct_decl"
                else VariableLocation.UNION_MEMBER
            )
            aggregate_id = self._required_row_id(aggregate, "stmt_id")
            aggregate_name = self._aggregate_name(aggregate, entity)
            method_id = None
        elif method_id is not None:
            location = VariableLocation.LOCAL
        else:
            location = VariableLocation.GLOBAL

        return VariableTarget(
            stmt_id=stmt_id,
            entity_id=entity_id,
            unit_id=unit_id,
            method_id=method_id,
            name=name,
            c_type=c_type,
            operation=operation,
            location=location,
            aggregate_id=aggregate_id,
            aggregate_name=aggregate_name,
            source=self._source_span(row, unit_id),
        )

    def _source_span(self, row: Any, unit_id: int) -> PointerSourceSpan:
        unit_path = self.context.get_unit_path(unit_id)
        if unit_path is None:
            raise VariableTargetCollectionError(
                f"Lian unit {unit_id} has no source path"
            )
        ranges = self._ranges_for_unit_path(unit_path)
        if ranges is None:
            raise VariableTargetCollectionError(
                f"no origin map found for Lian unit {unit_id}: {unit_path}"
            )

        clean_start = self._nonnegative_int(
            getattr(row, "start_row", None),
            f"variable declaration {getattr(row, 'stmt_id', '?')} start_row",
        ) + 1
        clean_end = self._nonnegative_int(
            getattr(row, "end_row", None),
            f"variable declaration {getattr(row, 'stmt_id', '?')} end_row",
        ) + 1
        start_col = self._nonnegative_int(
            getattr(row, "start_col", None),
            f"variable declaration {getattr(row, 'stmt_id', '?')} start_col",
        )
        end_col = self._nonnegative_int(
            getattr(row, "end_col", None),
            f"variable declaration {getattr(row, 'stmt_id', '?')} end_col",
        )
        first = self._range_containing(ranges, clean_start)
        last = self._range_containing(ranges, clean_end)
        if first is None or last is None:
            raise VariableTargetCollectionError(
                "variable declaration source is outside the preprocessed "
                f"origin map: unit {unit_id}, rows {clean_start}-{clean_end}"
            )
        if (
            str(first.get("origin_path")) != str(last.get("origin_path"))
            or str(first.get("origin_rel_path"))
            != str(last.get("origin_rel_path"))
        ):
            raise VariableTargetCollectionError(
                "variable declaration crosses original source files: "
                f"stmt {getattr(row, 'stmt_id', '?')}"
            )
        return PointerSourceSpan(
            path=str(first.get("origin_path")),
            rel_path=str(first.get("origin_rel_path")),
            start_line=int(first.get("origin_start", 0))
            + clean_start
            - int(first.get("clean_start", clean_start)),
            start_col=start_col,
            end_line=int(last.get("origin_start", 0))
            + clean_end
            - int(last.get("clean_start", clean_end)),
            end_col=end_col,
        )

    def _ranges_for_unit_path(
        self, unit_path: Path
    ) -> tuple[dict[str, Any], ...] | None:
        resolved = unit_path.resolve()
        if resolved in self._ranges_by_unit_path:
            return self._ranges_by_unit_path[resolved]
        unit_parts = resolved.parts
        for clean_path, ranges in self._origin_ranges().items():
            if clean_path == resolved:
                self._ranges_by_unit_path[resolved] = ranges
                return ranges
            if self._path_suffix_matches(unit_parts, clean_path):
                self._ranges_by_unit_path[resolved] = ranges
                return ranges
        self._ranges_by_unit_path[resolved] = None
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
        except (OSError, json.JSONDecodeError) as exc:
            raise VariableTargetCollectionError(
                f"failed to read preprocess manifest {manifest_path}: {exc}"
            ) from exc
        units = manifest.get("units")
        if not isinstance(units, list):
            raise VariableTargetCollectionError(
                f"preprocess manifest has no units array: {manifest_path}"
            )

        result: dict[Path, tuple[dict[str, Any], ...]] = {}
        for index, unit in enumerate(units):
            if not isinstance(unit, dict):
                raise VariableTargetCollectionError(
                    f"preprocess manifest unit {index} is not an object"
                )
            clean_value = unit.get("preprocessed_path")
            origin_value = unit.get("origin_map_path")
            if not isinstance(clean_value, str) or not isinstance(
                origin_value, str
            ):
                raise VariableTargetCollectionError(
                    f"preprocess manifest unit {index} has invalid paths"
                )
            origin_path = (self.workspace / origin_value).resolve()
            try:
                origin_data = json.loads(
                    origin_path.read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError) as exc:
                raise VariableTargetCollectionError(
                    f"failed to read origin map {origin_path}: {exc}"
                ) from exc
            raw_ranges = origin_data.get("ranges")
            if not isinstance(raw_ranges, list) or not all(
                isinstance(item, dict) for item in raw_ranges
            ):
                raise VariableTargetCollectionError(
                    f"origin map has invalid ranges array: {origin_path}"
                )
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

    def _is_pointer_declaration(
        self,
        row: Any,
        unit_id: int,
        resolving_aliases: set[int],
    ) -> bool:
        c_type = self._declaration_type(row)
        if "*" in c_type or self._has_pointer_attribute(row):
            return True

        declarations = self.context.get_unit_symbol_declarations(unit_id)
        for type_name in _TYPE_NAME_PATTERN.findall(c_type):
            for declaration_id in declarations.get(type_name, ()):
                if declaration_id in resolving_aliases:
                    continue
                declaration = self.context.get_stmt(declaration_id)
                if (
                    declaration is None
                    or self._text(getattr(declaration, "operation", ""))
                    != _TYPE_ALIAS_OPERATION
                ):
                    continue
                resolving_aliases.add(declaration_id)
                try:
                    if self._is_pointer_declaration(
                        declaration, unit_id, resolving_aliases
                    ):
                        return True
                finally:
                    resolving_aliases.remove(declaration_id)
        return False

    @staticmethod
    def _has_pointer_attribute(row: Any) -> bool:
        for field_name in ("attrs", "attributes", "type_attrs"):
            value = getattr(row, field_name, None)
            if value is None:
                continue
            if isinstance(value, str):
                items = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", value)
            else:
                try:
                    items = [str(item) for item in value]
                except TypeError:
                    items = [str(value)]
            if any(item.lower() in _POINTER_ATTRIBUTE_NAMES for item in items):
                return True
        return False

    def _aggregate_ancestor(self, stmt_id: int) -> Any | None:
        for ancestor in self.context.get_ancestors(stmt_id):
            if (
                self._text(getattr(ancestor, "operation", ""))
                in _AGGREGATE_OPERATIONS
            ):
                return ancestor
            if self._text(getattr(ancestor, "operation", "")) == "method_decl":
                return None
        return None

    def _aggregate_name(
        self,
        aggregate: Any,
        entity: dict[str, Any],
    ) -> str | None:
        entity_name = self._text(entity.get("name"))
        raw_name = self._text(getattr(aggregate, "name", ""))
        if entity_name and not entity_name.startswith("%"):
            return entity_name
        if raw_name and not raw_name.startswith("%"):
            return raw_name
        return entity_name or raw_name or None

    @staticmethod
    def _declaration_type(row: Any) -> str:
        for field_name in ("data_type", "default_data_type"):
            value = VariableTargetCollector._text(
                getattr(row, field_name, "")
            )
            if value:
                return value
        return ""

    @staticmethod
    def _required_id(entity: dict[str, Any], field_name: str) -> int:
        value = VariableTargetCollector._positive_id(entity.get(field_name))
        if value is None:
            raise VariableTargetCollectionError(
                f"translation entity has invalid {field_name}: "
                f"{entity.get(field_name)!r}"
            )
        return value

    @staticmethod
    def _required_row_id(row: Any, field_name: str) -> int:
        value = VariableTargetCollector._positive_id(
            getattr(row, field_name, None)
        )
        if value is None:
            raise VariableTargetCollectionError(
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
    def _nonnegative_int(value: Any, description: str) -> int:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise VariableTargetCollectionError(
                f"{description} must be a non-negative integer"
            ) from exc
        if result < 0:
            raise VariableTargetCollectionError(
                f"{description} must be a non-negative integer"
            )
        return result

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()

    def _missing_root(self, stmt_id: int) -> None:
        raise VariableTargetCollectionError(
            f"canonical GIR root {stmt_id} does not exist"
        )
