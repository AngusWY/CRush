from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import ENTITY_INDEX_NAME
from .models import CompileUnit, PreprocessManifest


_ENTITY_OPERATIONS = frozenset(
    {
        "struct_decl",
        "union_decl",
        "enum_decl",
        "type_alias_decl",
        "method_decl",
        "variable_decl",
    }
)
_TYPE_OPERATIONS = frozenset(
    {"struct_decl", "union_decl", "enum_decl"}
)


class EntityMergeError(RuntimeError):
    pass


@dataclass(frozen=True)
class _OriginSpan:
    path: str
    rel_path: str
    start: int
    start_col: int
    end: int
    end_col: int


@dataclass(frozen=True)
class _Occurrence:
    unit_id: int
    stmt_id: int
    translation_unit_rel_path: str
    preprocessed_path: str
    preprocessed_rel_path: str
    expanded_start: int
    expanded_start_col: int
    expanded_end: int
    expanded_end_col: int
    operation: str
    name: str
    origin: _OriginSpan
    expanded_sha256: str
    is_static: bool
    is_extern: bool
    data_type: str = ""
    has_body: bool = False
    enum_constant_names: tuple[str, ...] = ()


class EntityMerger:


    def __init__(self, *, manifest: PreprocessManifest) -> None:
        self.manifest = manifest
        self.output_path = manifest.workspace / ENTITY_INDEX_NAME

    def run(self, loader: Any) -> Path:
        occurrences = self._collect_occurrences(loader)
        entities = self._merge_occurrences(occurrences)
        stmt_to_canonical = {
            str(occurrence["stmt_id"]): entity["canonical_stmt_id"]
            for entity in entities
            for occurrence in entity["occurrences"]
        }
        result = {
            "version": 2,
            "entities": entities,
            "stmt_to_canonical": stmt_to_canonical,
        }

        temporary_path = self.output_path.with_suffix(
            self.output_path.suffix + ".tmp"
        )
        try:
            temporary_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.output_path)
        except OSError as exc:
            raise EntityMergeError(
                f"failed to write entity index {self.output_path}: {exc}"
            ) from exc
        return self.output_path

    def _collect_occurrences(self, loader: Any) -> list[_Occurrence]:
        units_by_source = {
            (self.manifest.workspace / unit.preprocessed_rel_path).resolve(): unit
            for unit in self.manifest.units
        }
        occurrences: list[_Occurrence] = []

        for unit_info in loader.get_all_unit_info():
            unit_id = self._to_int(getattr(unit_info, "module_id", -1))
            compile_unit = self._match_compile_unit(unit_info, units_by_source)
            if unit_id < 0 or compile_unit is None:
                continue

            clean_path = (
                self.manifest.workspace / compile_unit.preprocessed_rel_path
            )
            try:
                clean_lines = clean_path.read_text(
                    encoding="utf-8"
                ).splitlines()
            except OSError as exc:
                raise EntityMergeError(
                    f"failed to read preprocessed source {clean_path}: {exc}"
                ) from exc
            ranges = self._read_origin_ranges(compile_unit)
            unit_gir = tuple(loader.get_unit_gir(unit_id) or ())
            enum_constant_names = self._enum_constant_names_by_enum(unit_gir)
            for stmt in unit_gir:
                occurrence = self._make_occurrence(
                    unit_id=unit_id,
                    translation_unit_rel_path=(
                        compile_unit.source_rel_path.as_posix()
                    ),
                    preprocessed_path=str(clean_path),
                    preprocessed_rel_path=(
                        compile_unit.preprocessed_rel_path.as_posix()
                    ),
                    stmt=stmt,
                    clean_lines=clean_lines,
                    ranges=ranges,
                    enum_constant_names=enum_constant_names.get(
                        self._to_int(getattr(stmt, "stmt_id", -1)),
                        (),
                    ),
                )
                if occurrence is not None:
                    occurrences.append(occurrence)

        return occurrences

    def _make_occurrence(
        self,
        *,
        unit_id: int,
        translation_unit_rel_path: str,
        preprocessed_path: str,
        preprocessed_rel_path: str,
        stmt: Any,
        clean_lines: list[str],
        ranges: list[dict[str, Any]],
        enum_constant_names: tuple[str, ...],
    ) -> _Occurrence | None:
        operation = self._text(getattr(stmt, "operation", ""))
        name = self._text(getattr(stmt, "name", ""))
        stmt_id = self._to_int(getattr(stmt, "stmt_id", -1))
        parent_stmt_id = self._to_int(
            getattr(stmt, "parent_stmt_id", -1)
        )
        if (
            operation not in _ENTITY_OPERATIONS
            or parent_stmt_id != 0
            or stmt_id < 0
            or not name
            or (
                name.startswith("%")
                and operation not in {
                    "struct_decl",
                    "union_decl",
                    "enum_decl",
                }
            )
        ):
            return None

        clean_start = self._to_int(getattr(stmt, "start_row", -1)) + 1
        clean_end = self._to_int(getattr(stmt, "end_row", -1)) + 1
        start_col = self._to_int(getattr(stmt, "start_col", -1))
        end_col = self._to_int(getattr(stmt, "end_col", -1))
        if (
            clean_start < 1
            or clean_end < clean_start
            or clean_end > len(clean_lines)
            or start_col < 0
            or end_col < 0
        ):
            return None

        origin = self._origin_span(
            ranges=ranges,
            clean_start=clean_start,
            clean_end=clean_end,
            start_col=start_col,
            end_col=end_col,
        )
        if origin is None:
            return None

        expanded_text = "\n".join(clean_lines[clean_start - 1 : clean_end])
        expanded_sha256 = hashlib.sha256(
            expanded_text.encode("utf-8")
        ).hexdigest()
        attrs = self._text(getattr(stmt, "attrs", ""))
        data_type = self._text(getattr(stmt, "data_type", ""))
        return _Occurrence(
            unit_id=unit_id,
            stmt_id=stmt_id,
            translation_unit_rel_path=translation_unit_rel_path,
            preprocessed_path=preprocessed_path,
            preprocessed_rel_path=preprocessed_rel_path,
            expanded_start=clean_start,
            expanded_start_col=start_col,
            expanded_end=clean_end,
            expanded_end_col=end_col,
            operation=operation,
            name=name,
            origin=origin,
            expanded_sha256=expanded_sha256,
            is_static=self._has_static_attr(attrs),
            is_extern=self._has_extern_attr(attrs),
            data_type=data_type,
            has_body=(
                operation == "method_decl"
                and self._to_int(getattr(stmt, "body", -1)) > 0
            ),
            enum_constant_names=enum_constant_names,
        )

    def _merge_occurrences(
        self,
        occurrences: list[_Occurrence],
    ) -> list[dict[str, Any]]:
        groups: dict[tuple[Any, ...], list[_Occurrence]] = {}
        for occurrence in occurrences:
            identity_name = occurrence.name
            if (
                identity_name.startswith("%")
                and occurrence.operation in _TYPE_OPERATIONS
            ):
                identity_name = "<anonymous>"
            identity = (
                occurrence.origin.rel_path,
                occurrence.origin.start,
                occurrence.origin.start_col,
                occurrence.origin.end,
                occurrence.origin.end_col,
                occurrence.operation,
                identity_name,
                occurrence.expanded_sha256,
                (
                    occurrence.translation_unit_rel_path
                    if self._requires_translation_unit_owner(occurrence)
                    else ""
                ),
            )
            groups.setdefault(identity, []).append(occurrence)

        entities: list[dict[str, Any]] = []
        for group in groups.values():
            ordered = sorted(
                group,
                key=lambda item: (item.unit_id, item.stmt_id),
            )
            canonical = ordered[0]
            entity = {
                "canonical_stmt_id": canonical.stmt_id,
                "operation": canonical.operation,
                "name": canonical.name,
                "data_type": canonical.data_type,
                "origin": {
                    "path": canonical.origin.path,
                    "rel_path": canonical.origin.rel_path,
                    "start": canonical.origin.start,
                    "start_col": canonical.origin.start_col,
                    "end": canonical.origin.end,
                    "end_col": canonical.origin.end_col,
                },
                "expanded_sha256": canonical.expanded_sha256,
                "is_static": canonical.is_static,
                "is_extern": canonical.is_extern,
                "is_definition": canonical.has_body,
                "occurrences": [
                    {
                        "unit_id": item.unit_id,
                        "stmt_id": item.stmt_id,
                        "translation_unit_rel_path": (
                            item.translation_unit_rel_path
                        ),
                        "expanded_source": {
                            "path": item.preprocessed_path,
                            "rel_path": item.preprocessed_rel_path,
                            "start_line": item.expanded_start,
                            "start_col": item.expanded_start_col,
                            "end_line": item.expanded_end,
                            "end_col": item.expanded_end_col,
                        },
                    }
                    for item in ordered
                ],
            }
            enum_constant_names = tuple(
                dict.fromkeys(
                    name
                    for item in ordered
                    for name in item.enum_constant_names
                )
            )
            if canonical.operation == "enum_decl" and enum_constant_names:
                entity["enum_constant_names"] = list(enum_constant_names)
            entities.append(entity)

        return sorted(
            entities,
            key=lambda item: (
                item["origin"]["rel_path"],
                item["origin"]["start"],
                item["origin"]["start_col"],
                item["operation"],
                item["name"],
                item["canonical_stmt_id"],
            ),
        )

    @staticmethod
    def _enum_constant_names_by_enum(
        rows: tuple[Any, ...],
    ) -> dict[int, tuple[str, ...]]:
        children: dict[int, list[Any]] = {}
        for row in rows:
            parent_stmt_id = EntityMerger._to_int(
                getattr(row, "parent_stmt_id", -1)
            )
            children.setdefault(parent_stmt_id, []).append(row)

        names_by_enum: dict[int, tuple[str, ...]] = {}
        for row in rows:
            if getattr(row, "operation", None) != "enum_decl":
                continue
            enum_stmt_id = EntityMerger._to_int(
                getattr(row, "stmt_id", -1)
            )
            if enum_stmt_id < 0:
                continue
            names: list[str] = []
            worklist = list(reversed(children.get(enum_stmt_id, ())))
            while worklist:
                child = worklist.pop()
                child_stmt_id = EntityMerger._to_int(
                    getattr(child, "stmt_id", -1)
                )
                if getattr(child, "operation", None) == "enum_constant":
                    name = EntityMerger._text(getattr(child, "name", None))
                    if name and name not in names:
                        names.append(name)
                worklist.extend(
                    reversed(children.get(child_stmt_id, ()))
                )
            if names:
                names_by_enum[enum_stmt_id] = tuple(names)
        return names_by_enum

    @staticmethod
    def _requires_translation_unit_owner(occurrence: _Occurrence) -> bool:
        if Path(occurrence.origin.rel_path).suffix.lower() != ".h":
            return False
        return occurrence.is_static or (
            occurrence.operation == "method_decl" and occurrence.has_body
        )

    def _match_compile_unit(
        self,
        unit_info: Any,
        units_by_source: dict[Path, CompileUnit],
    ) -> CompileUnit | None:
        candidates = (
            getattr(unit_info, "original_path", ""),
            getattr(unit_info, "unit_path", ""),
        )
        for candidate in candidates:
            text = self._text(candidate)
            if not text:
                continue
            path = Path(text).resolve()
            unit = units_by_source.get(path)
            if unit is not None:
                return unit
        return None

    def _read_origin_ranges(
        self,
        unit: CompileUnit,
    ) -> list[dict[str, Any]]:
        origin_path = self.manifest.workspace / unit.origin_map_rel_path
        try:
            data = json.loads(origin_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EntityMergeError(
                f"failed to read origin map {origin_path}: {exc}"
            ) from exc
        ranges = data.get("ranges")
        if not isinstance(ranges, list):
            raise EntityMergeError(
                f"origin map has no ranges array: {origin_path}"
            )
        return ranges

    @staticmethod
    def _origin_span(
        *,
        ranges: list[dict[str, Any]],
        clean_start: int,
        clean_end: int,
        start_col: int,
        end_col: int,
    ) -> _OriginSpan | None:
        overlapping = [
            item
            for item in ranges
            if int(item["clean_start"]) <= clean_end
            and int(item["clean_end"]) >= clean_start
        ]
        if not overlapping:
            return None

        first = next(
            (
                item
                for item in overlapping
                if int(item["clean_start"]) <= clean_start
                <= int(item["clean_end"])
            ),
            None,
        )
        last = next(
            (
                item
                for item in reversed(overlapping)
                if int(item["clean_start"]) <= clean_end
                <= int(item["clean_end"])
            ),
            None,
        )
        if first is None or last is None:
            return None






        if (
            str(first["origin_path"]) != str(last["origin_path"])
            or str(first["origin_rel_path"]) != str(last["origin_rel_path"])
        ):
            return None

        origin_start = int(first["origin_start"]) + (
            clean_start - int(first["clean_start"])
        )
        origin_end = int(last["origin_start"]) + (
            clean_end - int(last["clean_start"])
        )
        return _OriginSpan(
            path=str(first["origin_path"]),
            rel_path=str(first["origin_rel_path"]),
            start=origin_start,
            start_col=start_col,
            end=origin_end,
            end_col=end_col,
        )

    @staticmethod
    def _has_static_attr(attrs: str) -> bool:
        return "static" in EntityMerger._attr_tokens(attrs)

    @staticmethod
    def _has_extern_attr(attrs: str) -> bool:
        return "extern" in EntityMerger._attr_tokens(attrs)

    @staticmethod
    def _attr_tokens(attrs: str) -> set[str]:
        return {
            token.strip("'\"[](),")
            for token in attrs.replace(",", " ").split()
        }

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, float) and math.isnan(value):
            return ""
        return str(value)

    @staticmethod
    def _to_int(value: Any, default: int = -1) -> int:
        try:
            if isinstance(value, float) and math.isnan(value):
                return default
            return int(value)
        except (TypeError, ValueError):
            return default
