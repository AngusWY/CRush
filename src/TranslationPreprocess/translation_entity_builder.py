from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .c_macro import load_project_macro_catalog, macro_family_specs
from .c_source_lex import mask_c_non_code
from .config import ENTITY_INDEX_NAME, TRANSLATION_ENTITIES_NAME
from .models import PreprocessManifest


_TYPE_OPERATIONS = frozenset(
    {"struct_decl", "union_decl", "enum_decl"}
)
_TYPE_ALIAS_OPERATION = "type_alias_decl"
_FUNCTION_OPERATION = "method_decl"
_GLOBAL_OPERATION = "variable_decl"
_C_TYPE_TOKEN_PATTERN = re.compile(
    r"\.\.\.|[A-Za-z_][A-Za-z0-9_]*|0[xX][0-9A-Fa-f]+|[0-9]+|[^\s]"
)
_C_TYPE_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_C_TYPE_QUALIFIERS = frozenset(
    {"_Atomic", "const", "restrict", "struct", "union", "enum", "volatile"}
)
_PORTABLE_ALIAS_TYPE_IDENTIFIERS = frozenset(
    {
        "_Atomic",
        "_Bool",
        "_Complex",
        "_Imaginary",
        "bool",
        "char",
        "char16_t",
        "char32_t",
        "const",
        "double",
        "float",
        "int",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "int_fast8_t",
        "int_fast16_t",
        "int_fast32_t",
        "int_fast64_t",
        "int_least8_t",
        "int_least16_t",
        "int_least32_t",
        "int_least64_t",
        "intmax_t",
        "intptr_t",
        "long",
        "ptrdiff_t",
        "restrict",
        "short",
        "signed",
        "size_t",
        "ssize_t",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "uint_fast8_t",
        "uint_fast16_t",
        "uint_fast32_t",
        "uint_fast64_t",
        "uint_least8_t",
        "uint_least16_t",
        "uint_least32_t",
        "uint_least64_t",
        "uintmax_t",
        "uintptr_t",
        "unsigned",
        "void",
        "volatile",
        "wchar_t",
    }
)


def _is_generated_or_build_rel_path(rel_path: str) -> bool:
    parts = tuple(part for part in rel_path.split("/") if part)
    return any(
        part == "build"
        or part == "generated"
        or part.startswith("cmake-build")
        for part in parts
    )


class TranslationEntityBuildError(RuntimeError):
    pass


class TranslationEntityBuilder:


    def __init__(self, *, manifest: PreprocessManifest) -> None:
        self.manifest = manifest
        self.entity_index_path = manifest.workspace / ENTITY_INDEX_NAME
        self.output_path = (
            manifest.workspace / TRANSLATION_ENTITIES_NAME
        )

    def run(self) -> Path:
        source_entities = self._read_entity_index()
        external_declarations = self._external_entity_declarations(
            source_entities
        )
        extern_redirects = self._extern_global_redirects(source_entities)
        duplicate_alias_redirects = (
            self._duplicate_type_alias_redirects(source_entities)
        )
        redirected_entity_ids = (
            set(extern_redirects)
            | set(duplicate_alias_redirects)
            | set(external_declarations)
        )
        buildable_entities = [
            entity
            for entity in source_entities
            if int(entity["canonical_stmt_id"]) not in redirected_entity_ids
        ]
        groups = self._build_groups(buildable_entities)
        translation_entities = [
            self._make_translation_entity(group) for group in groups
        ]
        translation_entities.extend(
            self._macro_family_entities(
                source_entities=source_entities,
                translation_entities=translation_entities,
            )
        )
        translation_entities.sort(key=self._translation_sort_key)

        entity_to_translation_entity = {
            str(member_id): entity["id"]
            for entity in translation_entities
            for member_id in entity["member_entity_ids"]
        }
        for extern_id, definition_id in extern_redirects.items():
            target_translation_id = entity_to_translation_entity.get(
                str(definition_id)
            )
            if target_translation_id is not None:
                entity_to_translation_entity[str(extern_id)] = (
                    target_translation_id
                )
        for duplicate_id, canonical_id in duplicate_alias_redirects.items():
            target_translation_id = entity_to_translation_entity.get(
                str(canonical_id)
            )
            if target_translation_id is not None:
                entity_to_translation_entity[str(duplicate_id)] = (
                    target_translation_id
                )
        pointer_typedef_relations = self._pointer_typedef_relations(
            source_entities,
            entity_to_translation_entity,
            translation_entities,
        )
        self._assign_pointer_typedef_export_names(
            translation_entities,
            pointer_typedef_relations,
        )
        type_alias_name_conflicts = self._type_alias_name_conflicts(
            source_entities,
            entity_to_translation_entity,
        )
        type_name_conflicts = self._type_name_conflicts(
            source_entities,
            entity_to_translation_entity,
        )
        self._mark_resolved_pointer_typedef_conflicts(
            type_name_conflicts,
            pointer_typedef_relations,
        )

        result = {
            "version": 1,
            "entities": translation_entities,
            "entity_to_translation_entity": (
                entity_to_translation_entity
            ),
            "extern_entity_redirects": {
                str(extern_id): definition_id
                for extern_id, definition_id in sorted(
                    extern_redirects.items()
                )
            },
            "duplicate_type_alias_redirects": {
                str(duplicate_id): canonical_id
                for duplicate_id, canonical_id in sorted(
                    duplicate_alias_redirects.items()
                )
            },
            "type_alias_name_conflicts": type_alias_name_conflicts,
            "type_name_conflicts": type_name_conflicts,
            "pointer_typedef_relations": pointer_typedef_relations,
            "external_entity_declarations": {
                str(entity_id): name
                for entity_id, name in sorted(external_declarations.items())
            },
        }
        self._write_result(result)
        return self.output_path

    def _macro_family_entities(
        self,
        *,
        source_entities: list[dict[str, Any]],
        translation_entities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        catalog = load_project_macro_catalog(self.manifest.workspace)
        specs = macro_family_specs(catalog)
        if not specs:
            return []

        used_ids = {
            int(entity["canonical_stmt_id"])
            for entity in source_entities
        }
        used_ids.update(
            int(occurrence["stmt_id"])
            for entity in source_entities
            for occurrence in entity.get("occurrences", ())
        )
        next_id = max(used_ids, default=0) + 1
        existing_names = {
            str(entity.get("name", "")) for entity in translation_entities
        }
        unit_ids = sorted(
            {
                int(entity["unit_id"])
                for entity in translation_entities
                if int(entity.get("unit_id", 0)) > 0
            }
        )
        if not unit_ids:
            return []

        families: list[dict[str, Any]] = []
        for spec in specs:
            name = str(spec["name"])
            if name in existing_names:
                continue
            while next_id in used_ids:
                next_id += 1
            end_line = int(spec["end_line"])
            end_col = self._source_line_length(Path(str(spec["path"])), end_line)
            families.append(
                {
                    "id": next_id,
                    "kind": "macro_family",
                    "name": name,
                    "unit_id": unit_ids[0],
                    "declaration_facts": {
                        "is_static": False,
                        "is_extern": False,
                    },
                    "member_entity_ids": [next_id],
                    "source": {
                        "path": str(spec["path"]),
                        "rel_path": str(spec["rel_path"]),
                        "start_line": int(spec["start_line"]),
                        "start_col": 0,
                        "end_line": end_line,
                        "end_col": end_col,
                    },
                    "export_names": list(spec["export_names"]),
                    "macro_names": list(spec["macro_names"]),
                    "caller_macro_names": list(
                        spec["caller_macro_names"]
                    ),
                    "macro_definition_ids": list(
                        spec["macro_definition_ids"]
                    ),
                }
            )
            existing_names.add(name)
            used_ids.add(next_id)
            next_id += 1
        return families

    @staticmethod
    def _source_line_length(path: Path, line_number: int) -> int:
        try:
            lines = path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            return 0
        if line_number < 1 or line_number > len(lines):
            return 0
        return len(lines[line_number - 1])

    def _read_entity_index(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(
                self.entity_index_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise TranslationEntityBuildError(
                f"failed to read entity index "
                f"{self.entity_index_path}: {exc}"
            ) from exc

        entities = data.get("entities")
        if not isinstance(entities, list):
            raise TranslationEntityBuildError(
                f"entity index has no entities array: "
                f"{self.entity_index_path}"
            )
        return entities

    def _build_groups(
        self,
        entities: list[dict[str, Any]],
    ) -> list[list[dict[str, Any]]]:
        functions = [
            [entity]
            for entity in entities
            if entity.get("operation") == _FUNCTION_OPERATION
        ]
        candidates = [
            entity
            for entity in entities
            if entity.get("operation") != _FUNCTION_OPERATION
        ]

        parent = list(range(len(candidates)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(left: int, right: int) -> None:
            left_root = find(left)
            right_root = find(right)
            if left_root != right_root:
                parent[right_root] = left_root

        for left in range(len(candidates)):
            for right in range(left + 1, len(candidates)):
                if self._should_combine(
                    candidates[left],
                    candidates[right],
                ):
                    union(left, right)

        grouped: dict[int, list[dict[str, Any]]] = {}
        for index, entity in enumerate(candidates):
            grouped.setdefault(find(index), []).append(entity)
        return functions + list(grouped.values())

    def _should_combine(
        self,
        left: dict[str, Any],
        right: dict[str, Any],
    ) -> bool:
        left_origin = left["origin"]
        right_origin = right["origin"]
        same_file = left_origin["rel_path"] == right_origin["rel_path"]

        left_units = self._unit_ids(left)
        right_units = self._unit_ids(right)
        if not left_units & right_units:
            return False

        operations = {left["operation"], right["operation"]}



        if (
            left.get("name") != right.get("name")
            or left.get("expanded_sha256") != right.get("expanded_sha256")
        ):
            return False
        if _GLOBAL_OPERATION in operations and operations != {_GLOBAL_OPERATION}:
            return False

        left_span = self._span(left_origin)
        right_span = self._span(right_origin)
        if same_file and left_span == right_span:
            return True

        has_type_definition = bool(operations & _TYPE_OPERATIONS)
        can_join_type_declaration = operations <= (
            _TYPE_OPERATIONS
            | {_TYPE_ALIAS_OPERATION, _GLOBAL_OPERATION}
        )
        if not has_type_definition or not can_join_type_declaration:
            return False

        if same_file:
            return self._contains(left_span, right_span) or self._contains(
                right_span,
                left_span,
            )








        alias_entity = left if left.get("operation") == _TYPE_ALIAS_OPERATION else right
        type_entity = left if alias_entity is right else right
        alias_type_name = self._normalize_type_name(
            str(alias_entity.get("data_type", ""))
        )
        type_name = str(type_entity.get("name", ""))
        return (
            alias_entity.get("operation") == _TYPE_ALIAS_OPERATION
            and type_entity.get("operation") in _TYPE_OPERATIONS
            and alias_type_name
            and not alias_type_name.startswith("%")
            and not type_name.startswith("%")
            and alias_type_name == type_name
        )

    def _extern_global_redirects(
        self,
        entities: list[dict[str, Any]],
    ) -> dict[int, int]:
        definitions: dict[tuple[str, str], list[dict[str, Any]]] = {}
        externs: list[dict[str, Any]] = []
        for entity in entities:
            if entity.get("operation") != _GLOBAL_OPERATION:
                continue
            name = str(entity.get("name", ""))
            if not name:
                continue
            key = (
                name,
                self._normalize_global_data_type(
                    str(entity.get("data_type", ""))
                ),
            )
            if entity.get("is_extern") is True:
                externs.append(entity)
            else:
                definitions.setdefault(key, []).append(entity)

        redirects: dict[int, int] = {}
        for extern in externs:
            key = (
                str(extern.get("name", "")),
                self._normalize_global_data_type(
                    str(extern.get("data_type", ""))
                ),
            )
            candidates = definitions.get(key, ())
            if not candidates:
                continue
            definition = min(
                candidates,
                key=lambda item: (
                    str(item["origin"]["rel_path"]),
                    int(item["origin"]["start"]),
                    int(item["canonical_stmt_id"]),
                ),
            )
            redirects[int(extern["canonical_stmt_id"])] = int(
                definition["canonical_stmt_id"]
            )
        return redirects

    def _external_entity_declarations(
        self,
        entities: list[dict[str, Any]],
    ) -> dict[int, str]:
        declarations: dict[int, str] = {}
        for entity in entities:
            if not self._is_errno_external_declaration(entity):
                continue
            declarations[int(entity["canonical_stmt_id"])] = "errno"
        return declarations

    def _is_errno_external_declaration(
        self,
        entity: dict[str, Any],
    ) -> bool:
        if (
            entity.get("operation") != _GLOBAL_OPERATION
            or entity.get("is_extern") is not True
            or "".join(str(entity.get("name", "")).split())
            != "(*__errno_location())"
        ):
            return False
        source = self._original_source_span(entity)
        return " ".join(source.split()) == "extern int errno;"

    def _original_source_span(self, entity: dict[str, Any]) -> str:
        origin = entity.get("origin")
        if not isinstance(origin, dict):
            return ""
        rel_path = Path(str(origin.get("rel_path", "")))
        if not rel_path.parts or rel_path.is_absolute() or ".." in rel_path.parts:
            return ""
        try:
            start_line = int(origin["start"])
            end_line = int(origin["end"])
            lines = (
                (self.manifest.project_root / rel_path)
                .read_text(encoding="utf-8")
                .splitlines(keepends=True)
            )
        except (KeyError, TypeError, ValueError, OSError):
            return ""
        if start_line < 1 or end_line < start_line or end_line > len(lines):
            return ""
        return "".join(lines[start_line - 1 : end_line])

    def _duplicate_type_alias_redirects(
        self,
        entities: list[dict[str, Any]],
    ) -> dict[int, int]:
        groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for entity in entities:
            if entity.get("operation") != _TYPE_ALIAS_OPERATION:
                continue
            name = str(entity.get("name", "")).strip()



            signature = self._portable_type_alias_signature(
                str(entity.get("data_type", ""))
            )
            if not name or not signature:
                continue
            groups.setdefault((name, signature), []).append(entity)

        redirects: dict[int, int] = {}
        for group in groups.values():
            if len(group) < 2:
                continue
            canonical = min(
                group,
                key=self._duplicate_type_alias_sort_key,
            )
            canonical_id = int(canonical["canonical_stmt_id"])
            for entity in group:
                entity_id = int(entity["canonical_stmt_id"])
                if entity_id != canonical_id:
                    redirects[entity_id] = canonical_id
        return redirects

    def _type_alias_name_conflicts(
        self,
        entities: list[dict[str, Any]],
        entity_to_translation_entity: dict[str, int],
    ) -> list[dict[str, Any]]:
        return self._type_name_conflicts(
            entities,
            entity_to_translation_entity,
            operations={_TYPE_ALIAS_OPERATION},
            include_operation=False,
        )

    def _type_name_conflicts(
        self,
        entities: list[dict[str, Any]],
        entity_to_translation_entity: dict[str, int],
        *,
        operations: set[str] | None = None,
        include_operation: bool = True,
    ) -> list[dict[str, Any]]:
        allowed_operations = operations or {*_TYPE_OPERATIONS, _TYPE_ALIAS_OPERATION}
        aliases_by_name: dict[str, dict[int, dict[str, Any]]] = {}
        for entity in entities:
            entity_id = int(entity["canonical_stmt_id"])
            name = str(entity.get("name", "")).strip()
            translation_id = entity_to_translation_entity.get(str(entity_id))
            if (
                entity.get("operation") not in allowed_operations
                or not name
                or translation_id is None
            ):
                continue
            candidates = aliases_by_name.setdefault(name, {})
            existing = candidates.get(translation_id)
            if existing is None or self._duplicate_type_alias_sort_key(
                entity
            ) < self._duplicate_type_alias_sort_key(existing):
                candidates[translation_id] = entity

        conflicts: list[dict[str, Any]] = []
        for name, aliases_by_owner in sorted(aliases_by_name.items()):
            if len(aliases_by_owner) < 2:
                continue
            declarations = []
            for entity in sorted(
                aliases_by_owner.values(),
                key=self._duplicate_type_alias_sort_key,
            ):
                entity_id = int(entity["canonical_stmt_id"])
                origin = entity.get("origin", {})
                declaration = {
                    "entity_id": entity_id,
                    "owner_entity_id": entity_to_translation_entity[
                        str(entity_id)
                    ],
                    "normalized_data_type": (
                        self._normalized_type_alias_signature(
                            str(entity.get("data_type", ""))
                        )
                    ),
                    "rel_path": str(origin.get("rel_path", "")),
                    "start_line": int(origin.get("start", 0)),
                }
                if include_operation:
                    declaration["operation"] = str(entity.get("operation", ""))
                declarations.append(declaration)
            conflicts.append(
                {
                    "name": name,
                    "resolution": "kept_separate",
                    "declarations": declarations,
                }
            )
        return conflicts

    def _pointer_typedef_relations(
        self,
        entities: list[dict[str, Any]],
        entity_to_translation_entity: dict[str, int],
        translation_entities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        tags_by_name: dict[str, list[dict[str, Any]]] = {}
        for entity in entities:
            if entity.get("operation") not in _TYPE_OPERATIONS:
                continue
            name = str(entity.get("name", "")).strip()
            if not name or name.startswith("%"):
                continue
            tags_by_name.setdefault(name, []).append(entity)

        relations_by_alias: dict[int, dict[str, Any]] = {}
        for alias in entities:
            if alias.get("operation") != _TYPE_ALIAS_OPERATION:
                continue
            alias_name = str(alias.get("name", "")).strip()
            base_name, pointer_depth = self._type_reference_shape(
                str(alias.get("data_type", ""))
            )
            if (
                not alias_name
                or alias_name != base_name
                or pointer_depth < 1
            ):
                continue

            alias_source_id = int(alias["canonical_stmt_id"])
            alias_owner_id = entity_to_translation_entity.get(
                str(alias_source_id)
            )
            if alias_owner_id is None:
                continue
            candidates = [
                candidate
                for candidate in tags_by_name.get(base_name, ())
                if self._unit_ids(alias) & self._unit_ids(candidate)
                and entity_to_translation_entity.get(
                    str(int(candidate["canonical_stmt_id"]))
                )
                != alias_owner_id
            ]
            embedded_pointee = False
            if candidates:
                pointee = min(
                    candidates,
                    key=lambda candidate: self._pointer_pointee_sort_key(
                        alias,
                        candidate,
                    ),
                )
                pointee_source_id = int(pointee["canonical_stmt_id"])
                pointee_owner_id = entity_to_translation_entity.get(
                    str(pointee_source_id)
                )
                if pointee_owner_id is None:
                    continue
            else:
                embedded_candidates = [
                    candidate
                    for candidate in translation_entities
                    if int(candidate["id"]) != alias_owner_id
                    and int(candidate.get("unit_id", -1)) in self._unit_ids(alias)
                    and self._contains_named_tag_definition(
                        candidate,
                        base_name,
                    )
                ]
                if not embedded_candidates:
                    continue
                pointee_entity = min(
                    embedded_candidates,
                    key=lambda candidate: self._embedded_pointee_sort_key(
                        alias,
                        candidate,
                    ),
                )
                pointee_owner_id = int(pointee_entity["id"])
                embedded_pointee = True
            relations_by_alias[alias_owner_id] = {
                "alias_entity_id": alias_owner_id,
                "pointee_entity_id": pointee_owner_id,
                "alias_name": alias_name,
                "pointer_depth": pointer_depth,
                "embedded_pointee": embedded_pointee,
            }

        return [
            relations_by_alias[alias_id]
            for alias_id in sorted(relations_by_alias)
        ]

    @staticmethod
    def _type_reference_shape(raw: str) -> tuple[str, int]:
        tokens = _C_TYPE_TOKEN_PATTERN.findall(raw)
        pointer_depth = tokens.count("*")
        identifiers = [
            token
            for token in tokens
            if _C_TYPE_IDENTIFIER_PATTERN.fullmatch(token)
            and token not in _C_TYPE_QUALIFIERS
        ]
        base_name = identifiers[-1] if len(identifiers) == 1 else ""
        return base_name, pointer_depth

    @staticmethod
    def _contains_named_tag_definition(
        entity: dict[str, Any],
        name: str,
    ) -> bool:
        source = entity.get("source")
        if not isinstance(source, dict):
            return False
        try:
            path = Path(str(source["path"]))
            start_line = int(source["start_line"])
            end_line = int(source["end_line"])
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        except (KeyError, TypeError, ValueError, OSError):
            return False
        if start_line < 1 or end_line < start_line or end_line > len(lines):
            return False
        text = mask_c_non_code(
            "".join(lines[start_line - 1 : end_line]),
            mask_literals=True,
        )
        return bool(
            re.search(
                rf"\b(?:struct|union|enum)\s+{re.escape(name)}\s*\{{",
                text,
            )
        )

    @staticmethod
    def _embedded_pointee_sort_key(
        alias: dict[str, Any],
        pointee: dict[str, Any],
    ) -> tuple[int, int, str, int]:
        alias_origin = alias.get("origin", {})
        pointee_origin = pointee.get("origin", {})
        alias_path = str(alias_origin.get("rel_path", ""))
        pointee_path = str(pointee_origin.get("rel_path", ""))
        alias_line = int(alias_origin.get("start", 0))
        pointee_line = int(pointee_origin.get("start_line", 0))
        return (
            0 if alias_path == pointee_path else 1,
            abs(alias_line - pointee_line),
            pointee_path,
            int(pointee["id"]),
        )

    @staticmethod
    def _pointer_pointee_sort_key(
        alias: dict[str, Any],
        pointee: dict[str, Any],
    ) -> tuple[int, int, int, str, int]:
        alias_origin = alias.get("origin", {})
        pointee_origin = pointee.get("origin", {})
        alias_path = str(alias_origin.get("rel_path", ""))
        pointee_path = str(pointee_origin.get("rel_path", ""))
        alias_units = TranslationEntityBuilder._unit_ids(alias)
        pointee_units = TranslationEntityBuilder._unit_ids(pointee)
        alias_line = int(alias_origin.get("start", 0))
        pointee_line = int(pointee_origin.get("start", 0))
        return (
            0 if alias_path == pointee_path else 1,
            -len(alias_units & pointee_units),
            abs(alias_line - pointee_line),
            pointee_path,
            int(pointee["canonical_stmt_id"]),
        )

    @staticmethod
    def _assign_pointer_typedef_export_names(
        translation_entities: list[dict[str, Any]],
        relations: list[dict[str, Any]],
    ) -> None:
        entities_by_id = {
            int(entity["id"]): entity for entity in translation_entities
        }
        occupied_names = {
            export_name
            for entity in translation_entities
            for export_name in (
                entity.get("export_names") or [str(entity.get("name", ""))]
            )
            if export_name
        }
        assigned_pointees: dict[int, str] = {}
        for relation in relations:
            alias_id = int(relation["alias_entity_id"])
            pointee_id = int(relation["pointee_entity_id"])
            alias_name = str(relation["alias_name"])
            alias = entities_by_id.get(alias_id)
            pointee = entities_by_id.get(pointee_id)
            if alias is None or pointee is None:
                continue
            alias["export_names"] = [alias_name]
            pointee_name = assigned_pointees.get(pointee_id)
            if pointee_name is None:
                base_name = f"{alias_name}Data"
                pointee_name = base_name
                if pointee_name in occupied_names:
                    pointee_name = f"{base_name}_{pointee_id}"
                occupied_names.add(pointee_name)
                assigned_pointees[pointee_id] = pointee_name
                if relation.get("embedded_pointee") is True:
                    existing_exports = pointee.get("export_names") or [
                        str(pointee.get("name", ""))
                    ]
                    pointee["export_names"] = list(
                        dict.fromkeys(
                            export_name
                            for export_name in (*existing_exports, pointee_name)
                            if export_name
                        )
                    )
                else:
                    pointee["export_names"] = [pointee_name]
            relation["alias_export_name"] = alias_name
            relation["pointee_export_name"] = pointee_name

    @staticmethod
    def _mark_resolved_pointer_typedef_conflicts(
        conflicts: list[dict[str, Any]],
        relations: list[dict[str, Any]],
    ) -> None:
        resolved_pairs = {
            frozenset(
                (
                    int(relation["alias_entity_id"]),
                    int(relation["pointee_entity_id"]),
                )
            )
            for relation in relations
        }
        for conflict in conflicts:
            declarations = conflict.get("declarations", [])
            owners = frozenset(
                int(declaration["owner_entity_id"])
                for declaration in declarations
                if isinstance(declaration, dict)
                and declaration.get("owner_entity_id") is not None
            )
            if owners in resolved_pairs:
                conflict["resolution"] = "pointer_typedef_pair"

    @staticmethod
    def _duplicate_type_alias_sort_key(
        entity: dict[str, Any],
    ) -> tuple[int, str, int]:
        origin = entity.get("origin", {})
        rel_path = str(origin.get("rel_path", "")).replace("\\", "/").lstrip(
            "./"
        )
        return (
            1 if _is_generated_or_build_rel_path(rel_path) else 0,
            rel_path,
            int(entity["canonical_stmt_id"]),
        )

    @staticmethod
    def _normalized_type_alias_signature(raw: str) -> str:
        return " ".join(_C_TYPE_TOKEN_PATTERN.findall(raw))

    @staticmethod
    def _portable_type_alias_signature(raw: str) -> str:
        signature = TranslationEntityBuilder._normalized_type_alias_signature(
            raw
        )
        if not signature:
            return ""
        identifiers = _C_TYPE_IDENTIFIER_PATTERN.findall(signature)
        if any(
            identifier not in _PORTABLE_ALIAS_TYPE_IDENTIFIERS
            for identifier in identifiers
        ):
            return ""
        return signature

    @staticmethod
    def _normalize_type_name(raw: str) -> str:

        text = raw.strip()
        for prefix in ("struct ", "union ", "enum "):
            if text.startswith(prefix):
                text = text[len(prefix):]
        return text.rstrip("*").strip()

    @staticmethod
    def _normalize_global_data_type(raw: str) -> str:
        return raw.replace(" ", "").strip()

    def _make_translation_entity(
        self,
        members: list[dict[str, Any]],
    ) -> dict[str, Any]:
        ordered = sorted(members, key=self._member_sort_key)
        primary = min(ordered, key=self._primary_key)
        primary_rel_path = str(primary["origin"]["rel_path"])
        source_members = [
            item
            for item in ordered
            if str(item["origin"]["rel_path"]) == primary_rel_path
        ]
        starts = [
            (
                int(item["origin"]["start"]),
                int(item["origin"]["start_col"]),
            )
            for item in source_members
        ]
        ends = [
            (
                int(item["origin"]["end"]),
                int(item["origin"]["end_col"]),
            )
            for item in source_members
        ]
        start_line, start_col = min(starts)
        end_line, end_col = max(ends)
        occurrence = self._canonical_occurrence(primary)
        expanded_source = occurrence.get("expanded_source")
        if not isinstance(expanded_source, dict):
            raise TranslationEntityBuildError(
                f"entity {primary['canonical_stmt_id']} has no expanded source"
            )
        source: dict[str, Any] = {
            "path": str(expanded_source["path"]),
            "rel_path": str(expanded_source["rel_path"]),
            "start_line": int(expanded_source["start_line"]),
            "start_col": int(expanded_source["start_col"]),
            "end_line": int(expanded_source["end_line"]),
            "end_col": int(expanded_source["end_col"]),
        }
        if self._requires_module_owner(ordered, str(primary["origin"]["rel_path"])):
            module_rel_path = occurrence.get("translation_unit_rel_path")
            if isinstance(module_rel_path, str) and module_rel_path:
                source["module_rel_path"] = module_rel_path

        translation_entity = {
            "id": int(primary["canonical_stmt_id"]),
            "kind": self._kind(ordered),
            "name": str(primary["name"]),
            "unit_id": int(occurrence["unit_id"]),
            "declaration_facts": {
                "is_static": any(
                    item.get("is_static") is True for item in ordered
                ),
                "is_extern": all(
                    item.get("is_extern") is True for item in ordered
                ),
            },
            "member_entity_ids": [
                int(item["canonical_stmt_id"]) for item in ordered
            ],
            "source": source,
            "origin": {
                "path": str(primary["origin"]["path"]),
                "rel_path": str(primary["origin"]["rel_path"]),
                "start_line": start_line,
                "start_col": start_col,
                "end_line": end_line,
                "end_col": end_col,
            },
        }
        export_names = self._anonymous_enum_export_names(primary)
        if export_names:
            translation_entity["export_names"] = list(export_names)
        return translation_entity

    @staticmethod
    def _anonymous_enum_export_names(
        entity: dict[str, Any],
    ) -> tuple[str, ...]:
        if (
            entity.get("operation") != "enum_decl"
            or not str(entity.get("name", "")).startswith("%")
        ):
            return ()
        raw_names = entity.get("enum_constant_names")
        if not isinstance(raw_names, list):
            return ()
        return tuple(
            dict.fromkeys(
                name
                for item in raw_names
                if (name := str(item).strip())
            )
        )

    @staticmethod
    def _requires_module_owner(
        members: list[dict[str, Any]],
        rel_path: str,
    ) -> bool:
        suffix = Path(rel_path).suffix.lower()
        if suffix == ".inc":
            return True
        if suffix != ".h":
            return False
        return any(
            item.get("is_static") is True
            or (
                item.get("operation") == _FUNCTION_OPERATION
                and item.get("is_definition") is True
            )
            for item in members
        )

    @staticmethod
    def _kind(members: list[dict[str, Any]]) -> str:
        operations = {item["operation"] for item in members}
        if _FUNCTION_OPERATION in operations:
            return "function"
        if operations & (_TYPE_OPERATIONS | {_TYPE_ALIAS_OPERATION}):
            return "type"
        return "global"

    @staticmethod
    def _primary_key(entity: dict[str, Any]) -> tuple[int, int]:
        operation = entity["operation"]
        name = str(entity.get("name", ""))
        data_type = str(entity.get("data_type", ""))
        if (
            operation == _TYPE_ALIAS_OPERATION
            and name
            and not name.startswith("%")
            and data_type.strip().startswith("%")
        ):
            priority = 0
        elif operation in _TYPE_OPERATIONS:
            priority = 1 if name.startswith("%") else 0
        elif operation == _TYPE_ALIAS_OPERATION:
            priority = 2
        elif operation == _FUNCTION_OPERATION:
            priority = 3
        else:
            priority = 4
        return priority, int(entity["canonical_stmt_id"])

    @staticmethod
    def _member_sort_key(
        entity: dict[str, Any],
    ) -> tuple[int, int, int]:
        origin = entity["origin"]
        return (
            int(origin["start"]),
            int(origin["start_col"]),
            int(entity["canonical_stmt_id"]),
        )

    @staticmethod
    def _translation_sort_key(
        entity: dict[str, Any],
    ) -> tuple[str, int, int, int]:
        source = entity["source"]
        return (
            str(source["rel_path"]),
            int(source["start_line"]),
            int(source["start_col"]),
            int(entity["id"]),
        )

    @staticmethod
    def _unit_ids(entity: dict[str, Any]) -> frozenset[int]:
        return frozenset(
            int(item["unit_id"])
            for item in entity.get("occurrences", [])
        )

    @staticmethod
    def _canonical_occurrence(
        entity: dict[str, Any],
    ) -> dict[str, Any]:
        canonical_stmt_id = int(entity["canonical_stmt_id"])
        for occurrence in entity.get("occurrences", []):
            if int(occurrence["stmt_id"]) == canonical_stmt_id:
                return occurrence
        raise TranslationEntityBuildError(
            f"entity {canonical_stmt_id} has no canonical occurrence"
        )

    @staticmethod
    def _span(
        origin: dict[str, Any],
    ) -> tuple[tuple[int, int], tuple[int, int]]:
        return (
            (int(origin["start"]), int(origin["start_col"])),
            (int(origin["end"]), int(origin["end_col"])),
        )

    @staticmethod
    def _contains(
        outer: tuple[tuple[int, int], tuple[int, int]],
        inner: tuple[tuple[int, int], tuple[int, int]],
    ) -> bool:
        return outer[0] <= inner[0] and inner[1] <= outer[1]

    def _write_result(self, result: dict[str, Any]) -> None:
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
            raise TranslationEntityBuildError(
                f"failed to write translation entities "
                f"{self.output_path}: {exc}"
            ) from exc
