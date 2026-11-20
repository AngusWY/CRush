from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .config import (
    ENTITY_DEPENDENCIES_NAME,
    ENTITY_INDEX_NAME,
    TRANSLATION_ENTITIES_NAME,
)
from .models import PreprocessManifest


_TYPE_NAME_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_TAG_TYPE_PATTERN = re.compile(
    r"\b(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)"
)
_INLINE_TAG_DEFINITION_PATTERN = re.compile(
    r"\b(struct|union|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{"
)
_STRING_LITERAL_PATTERN = re.compile(r'"(?:\\.|[^"\\])*"')
_TYPE_FIELDS = ("data_type", "default_data_type")
_TYPE_DECLARATION_OPERATIONS = frozenset(
    {"struct_decl", "union_decl", "enum_decl", "type_alias_decl"}
)
_TAG_TYPE_OPERATIONS = {
    "struct": "struct_decl",
    "union": "union_decl",
    "enum": "enum_decl",
}
_VALUE_REFERENCE_SKIP_FIELDS = frozenset(
    {
        "attrs",
        "body",
        "condition_prebody",
        "data_type",
        "default_data_type",
        "else_body",
        "end_col",
        "end_row",
        "enum_constants",
        "field",
        "fields",
        "init_body",
        "name",
        "operation",
        "original_stmt",
        "parent_stmt_id",
        "parameters",
        "start_col",
        "start_row",
        "stmt_id",
        "then_body",
        "unit_id",
        "update_body",
    }
)
_C_TYPE_WORDS = frozenset(
    {
        "_Bool",
        "_Complex",
        "_Imaginary",
        "auto",
        "bool",
        "char",
        "const",
        "double",
        "enum",
        "extern",
        "float",
        "inline",
        "int",
        "long",
        "register",
        "restrict",
        "short",
        "signed",
        "static",
        "struct",
        "typedef",
        "union",
        "unsigned",
        "void",
        "volatile",
    }
)


class DependencyBuildError(RuntimeError):
    pass


class DependencyBuilder:


    def __init__(self, *, manifest: PreprocessManifest) -> None:
        self.manifest = manifest
        self.entity_index_path = manifest.workspace / ENTITY_INDEX_NAME
        self.translation_entities_path = (
            manifest.workspace / TRANSLATION_ENTITIES_NAME
        )
        self.output_path = (
            manifest.workspace / ENTITY_DEPENDENCIES_NAME
        )

    def run(self, loader: Any) -> Path:
        entity_index = self._read_json(
            self.entity_index_path, "entity index"
        )
        translation_data = self._read_json(
            self.translation_entities_path, "translation entities"
        )
        translation_entities = translation_data.get("entities")
        if not isinstance(translation_entities, list):
            raise DependencyBuildError(
                "translation entities file has no entities array: "
                f"{self.translation_entities_path}"
            )

        occurrence_to_translation = self._occurrence_mapping(
            entity_index, translation_data
        )
        valid_entity_ids = {
            self._to_int(entity.get("id"))
            for entity in translation_entities
        }
        valid_entity_ids.discard(-1)
        translation_contexts = self._translation_entity_contexts(
            translation_entities
        )
        enum_constant_targets = self._global_enum_constant_targets(
            loader,
            occurrence_to_translation,
            entity_index,
        )
        dependencies: dict[int, dict[int, set[str]]] = {
            entity_id: defaultdict(set)
            for entity_id in valid_entity_ids
        }

        self._add_call_dependencies(
            loader,
            occurrence_to_translation,
            dependencies,
        )
        self._add_global_dependencies(
            loader, occurrence_to_translation, dependencies
        )
        self._add_type_dependencies(
            loader,
            occurrence_to_translation,
            entity_index,
            enum_constant_targets,
            dependencies,
        )
        self._add_source_text_type_dependencies(
            entity_index,
            translation_entities,
            occurrence_to_translation,
            translation_contexts,
            dependencies,
        )
        self._add_initializer_value_dependencies(
            loader,
            occurrence_to_translation,
            translation_entities,
            enum_constant_targets,
            dependencies,
        )
        self._add_source_text_value_dependencies(
            entity_index,
            translation_entities,
            occurrence_to_translation,
            dependencies,
        )
        self._add_pointer_typedef_relation_dependencies(
            translation_data,
            dependencies,
        )
        self._add_macro_dependencies(translation_entities, dependencies)
        co_location_groups = self._macro_family_co_location_groups(
            translation_entities,
            dependencies,
        )
        self._remove_macro_expansion_support_dependencies(
            translation_entities,
            dependencies,
            co_location_groups,
        )
        self._remove_ambiguous_kept_separate_type_dependencies(
            translation_data,
            translation_contexts,
            dependencies,
        )



        result = {
            "version": 1,
            "entities": [
                {
                    "entity_id": entity_id,
                    "dependencies": sorted(
                        dependencies[entity_id]
                    ),
                }
                for entity_id in sorted(valid_entity_ids)
            ],
            "co_location_groups": co_location_groups,
        }
        self._write_result(result)
        return self.output_path

    def _remove_ambiguous_kept_separate_type_dependencies(
        self,
        translation_data: dict[str, Any],
        translation_contexts: dict[int, dict[str, Any]],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:
        for group in self._kept_separate_type_conflict_groups(
            translation_data
        ):
            if len(group) < 2:
                continue
            for source_id, entity_dependencies in dependencies.items():
                candidates = set(entity_dependencies) & group
                if len(candidates) < 2:
                    continue
                preferred = self._prefer_local_type_targets(
                    source_id,
                    candidates,
                    translation_contexts,
                )
                if not preferred or preferred == candidates:
                    continue
                for target_id in sorted(candidates - preferred):
                    entity_dependencies.pop(target_id, None)

    def _add_pointer_typedef_relation_dependencies(
        self,
        translation_data: dict[str, Any],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:
        raw_relations = translation_data.get("pointer_typedef_relations", ())
        if not isinstance(raw_relations, list):
            return
        for relation in raw_relations:
            if not isinstance(relation, dict):
                continue
            self._add_dependency(
                dependencies,
                self._to_int(relation.get("alias_entity_id")),
                self._to_int(relation.get("pointee_entity_id")),
                "pointer_typedef_pointee",
            )

    @staticmethod
    def _kept_separate_type_conflict_groups(
        translation_data: dict[str, Any],
    ) -> tuple[set[int], ...]:
        groups: list[set[int]] = []
        seen: set[tuple[int, ...]] = set()
        for key in ("type_name_conflicts", "type_alias_name_conflicts"):
            raw_conflicts = translation_data.get(key, ())
            if not isinstance(raw_conflicts, list):
                continue
            for conflict in raw_conflicts:
                if not isinstance(conflict, dict):
                    continue
                if conflict.get("resolution") != "kept_separate":
                    continue
                declarations = conflict.get("declarations")
                if not isinstance(declarations, list):
                    continue
                group = {
                    DependencyBuilder._to_int(declaration.get("owner_entity_id"))
                    for declaration in declarations
                    if isinstance(declaration, dict)
                }
                group.discard(-1)
                if len(group) < 2:
                    continue
                identity = tuple(sorted(group))
                if identity in seen:
                    continue
                seen.add(identity)
                groups.append(group)
        return tuple(groups)

    def _add_macro_dependencies(
        self,
        translation_entities: list[Any],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:
        families = [
            entity
            for entity in translation_entities
            if isinstance(entity, dict)
            and entity.get("kind") == "macro_family"
        ]
        if not families:
            return

        macro_owner: dict[str, int] = {}
        for family in families:
            family_id = self._to_int(family.get("id"))
            if family_id < 0:
                continue
            raw_caller_names = family.get(
                "caller_macro_names",
                family.get("macro_names", ()),
            )
            for raw_name in raw_caller_names:
                name = str(raw_name).strip()
                if name:
                    macro_owner.setdefault(name, family_id)

        for entity in translation_entities:
            if not isinstance(entity, dict) or entity.get("kind") == "macro_family":
                continue
            entity_id = self._to_int(entity.get("id"))
            source = self._translation_entity_source(entity)
            if entity_id < 0 or not source:
                continue
            for macro_name, family_id in macro_owner.items():
                if self._source_mentions_macro(source, macro_name):
                    self._add_dependency(
                        dependencies,
                        entity_id,
                        family_id,
                        "macro_family",
                    )

        entities_by_name: dict[str, list[int]] = defaultdict(list)
        for entity in translation_entities:
            if not isinstance(entity, dict) or entity.get("kind") == "macro_family":
                continue
            entity_id = self._to_int(entity.get("id"))
            name = str(entity.get("name", "")).strip()
            if entity_id >= 0 and name:
                entities_by_name[name].append(entity_id)

        for family in families:
            family_id = self._to_int(family.get("id"))
            source = self._translation_entity_source(family)
            if family_id < 0 or not source:
                continue
            tokens = set(_TYPE_NAME_PATTERN.findall(source))
            for token in tokens:
                for target_id in entities_by_name.get(token, ()):
                    self._add_dependency(
                        dependencies,
                        family_id,
                        target_id,
                        "macro_reference",
                    )

    def _macro_family_co_location_groups(
        self,
        translation_entities: list[Any],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> list[dict[str, Any]]:
        entities_by_id = {
            entity_id: entity
            for entity in translation_entities
            if isinstance(entity, dict)
            and (entity_id := self._to_int(entity.get("id"))) >= 0
        }
        claimed_support: dict[int, int] = {}
        groups: list[dict[str, Any]] = []
        families = sorted(
            (
                entity
                for entity in entities_by_id.values()
                if entity.get("kind") == "macro_family"
            ),
            key=lambda entity: self._to_int(entity.get("id")),
        )

        for family in families:
            family_id = self._to_int(family.get("id"))
            family_rel_path = self._entity_rel_path(family)
            if family_id < 0 or not family_rel_path:
                continue

            support_ids: set[int] = set()
            pending = list(dependencies.get(family_id, {}))
            while pending:
                candidate_id = pending.pop()
                if candidate_id in support_ids:
                    continue
                candidate = entities_by_id.get(candidate_id)
                if not self._is_header_static_support(
                    candidate,
                    family_rel_path,
                ):
                    continue
                support_ids.add(candidate_id)
                pending.extend(dependencies.get(candidate_id, {}))

            if not support_ids:
                continue
            for support_id in sorted(support_ids):
                previous_owner = claimed_support.get(support_id)
                if previous_owner is not None and previous_owner != family_id:
                    raise DependencyBuildError(
                        f"header-static support entity {support_id} is claimed "
                        f"by macro families {previous_owner} and {family_id}"
                    )
                claimed_support[support_id] = family_id
            groups.append(
                {
                    "owner_entity_id": family_id,
                    "member_entity_ids": sorted(support_ids),
                }
            )
        return groups

    def _remove_macro_expansion_support_dependencies(
        self,
        translation_entities: list[Any],
        dependencies: dict[int, dict[int, set[str]]],
        co_location_groups: list[dict[str, Any]],
    ) -> None:
        entities_by_id = {
            entity_id: entity
            for entity in translation_entities
            if isinstance(entity, dict)
            and (entity_id := self._to_int(entity.get("id"))) >= 0
        }
        support_by_family = {
            self._to_int(group.get("owner_entity_id")): {
                self._to_int(member_id)
                for member_id in group.get("member_entity_ids", ())
            }
            for group in co_location_groups
            if isinstance(group, dict)
        }
        support_ids = {
            support_id
            for members in support_by_family.values()
            for support_id in members
        }

        for entity_id, entity_dependencies in dependencies.items():
            if entity_id in support_ids or entity_id in support_by_family:
                continue
            used_families = set(entity_dependencies) & set(support_by_family)
            if not used_families:
                continue
            hidden_support = {
                support_id
                for family_id in used_families
                for support_id in support_by_family[family_id]
            }
            source = self._translation_entity_source(
                entities_by_id.get(entity_id, {})
            )
            for support_id in hidden_support & set(entity_dependencies):
                support = entities_by_id.get(support_id, {})
                support_name = str(support.get("name", "")).strip()
                if support_name and self._source_mentions_symbol(
                    source,
                    support_name,
                ):
                    continue
                entity_dependencies.pop(support_id, None)

    @staticmethod
    def _is_header_static_support(
        entity: dict[str, Any] | None,
        family_rel_path: str,
    ) -> bool:
        if not isinstance(entity, dict):
            return False
        declaration_facts = entity.get("declaration_facts")
        return (
            isinstance(declaration_facts, dict)
            and declaration_facts.get("is_static") is True
            and DependencyBuilder._entity_rel_path(entity) == family_rel_path
            and Path(family_rel_path).suffix.lower() in {".h", ".inc"}
        )

    @staticmethod
    def _entity_rel_path(entity: dict[str, Any]) -> str:
        source = entity.get("source")
        if not isinstance(source, dict):
            return ""
        return str(source.get("rel_path", "")).replace("\\", "/")

    @staticmethod
    def _source_mentions_symbol(source: str, name: str) -> bool:
        return re.search(r"\b" + re.escape(name) + r"\b", source) is not None

    @staticmethod
    def _source_mentions_macro(source: str, name: str) -> bool:
        return re.search(r"\b" + re.escape(name) + r"\s*(?:\(|\b)", source) is not None

    @staticmethod
    def _translation_entity_source(entity: dict[str, Any]) -> str:
        raw_source = entity.get("source")
        if not isinstance(raw_source, dict):
            return ""
        try:
            path = Path(str(raw_source["path"]))
            start_line = int(raw_source["start_line"])
            end_line = int(raw_source["end_line"])
            lines = path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines(keepends=True)
        except (KeyError, TypeError, ValueError, OSError):
            return ""
        if start_line < 1 or end_line < start_line or end_line > len(lines):
            return ""
        return "".join(lines[start_line - 1 : end_line])

    def _add_call_dependencies(
        self,
        loader: Any,
        occurrence_to_translation: dict[int, int],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:
        for caller_id in self._method_ids(loader):



            callee_ids = set(self._callee_ids_p3(loader, caller_id))
            callee_ids.update(
                self._callee_ids_from_internal_calls(loader, caller_id)
            )
            for callee_id in callee_ids:
                self._add_dependency(
                    dependencies,
                    occurrence_to_translation.get(caller_id),
                    occurrence_to_translation.get(callee_id),
                    "call",
                )

    def _callee_ids_from_internal_calls(
        self,
        loader: Any,
        method_id: int,
    ) -> set[int]:
        internal_callees = getattr(loader, "get_method_internal_callees", None)
        if not callable(internal_callees):
            return set()
        convert_name = getattr(
            loader, "convert_method_name_to_method_ids", None
        )
        if not callable(convert_name):
            return set()

        result: set[int] = set()
        try:
            callees = internal_callees(method_id)
        except Exception:
            return set()
        if not callees:
            return set()

        for item in callees:
            stmt_id = self._to_int(getattr(item, "stmt_id", -1))
            if stmt_id < 0:
                continue
            try:
                gir = loader.get_stmt_gir(stmt_id)
            except Exception:
                continue
            callee_name = getattr(gir, "name", None)
            if not callee_name:
                continue
            callee_name = str(callee_name).strip()
            if not callee_name:
                continue
            try:
                method_ids = convert_name(callee_name)
            except Exception:
                continue
            resolved_ids = {
                self._to_int(mid) for mid in self._iter_values(method_ids)
            }
            resolved_ids = {
                resolved
                for resolved in resolved_ids
                if resolved > 0 and resolved != method_id
            }
            for resolved in self._prefer_same_unit_methods(
                loader,
                method_id,
                resolved_ids,
            ):
                result.add(resolved)

        return result

    def _prefer_same_unit_methods(
        self,
        loader: Any,
        caller_id: int,
        method_ids: set[int],
    ) -> set[int]:
        convert_unit = getattr(loader, "convert_stmt_id_to_unit_id", None)
        if not callable(convert_unit) or not method_ids:
            return method_ids
        try:
            caller_unit_id = self._to_int(convert_unit(caller_id))
        except Exception:
            return method_ids
        if caller_unit_id < 0:
            return method_ids

        same_unit_ids: set[int] = set()
        for method_id in method_ids:
            try:
                unit_id = self._to_int(convert_unit(method_id))
            except Exception:
                continue
            if unit_id == caller_unit_id:
                same_unit_ids.add(method_id)
        return same_unit_ids or method_ids

    def _add_global_dependencies(
        self,
        loader: Any,
        occurrence_to_translation: dict[int, int],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:
        symbol_to_declaration: dict[int, int] = {}
        method_ids = self._method_ids(loader)

        for context_id in self._p3_context_ids(loader):
            state_space = self._symbol_state_space_p3(loader, context_id)
            for item in state_space or []:
                symbol_id = self._to_int(
                    getattr(item, "symbol_id", -1)
                )
                declaration_id = self._to_int(
                    getattr(item, "stmt_id", -1)
                )
                if symbol_id > 0 and declaration_id > 0:
                    symbol_to_declaration.setdefault(
                        symbol_id, declaration_id
                    )

        for method_id in method_ids:
            source_id = occurrence_to_translation.get(method_id)
            if source_id is None:
                continue
            summary = self._method_def_use_summary(loader, method_id)
            if summary is None:
                continue
            external_ids = set(
                self._iter_values(
                    getattr(summary, "used_external_symbol_ids", ())
                )
            )
            external_ids.update(
                self._iter_values(
                    getattr(
                        summary,
                        "defined_external_symbol_ids",
                        (),
                    )
                )
            )
            for symbol_id in external_ids:
                raw_id = self._to_int(symbol_id)
                declaration_id = self._external_symbol_declaration_id(
                    raw_id,
                    symbol_to_declaration,
                    occurrence_to_translation,
                )
                self._add_dependency(
                    dependencies,
                    source_id,
                    occurrence_to_translation.get(declaration_id),
                    "global",
                )

    @staticmethod
    def _external_symbol_declaration_id(
        symbol_id: int,
        symbol_to_declaration: dict[int, int],
        occurrence_to_translation: dict[int, int],
    ) -> int:


        declaration_id = symbol_to_declaration.get(symbol_id)
        if (
            declaration_id is not None
            and declaration_id in occurrence_to_translation
        ):
            return declaration_id
        return symbol_id

    def _method_ids(self, loader: Any) -> set[int]:
        method_ids = {
            self._to_int(method_id)
            for method_id in loader.get_all_method_ids() or []
        }
        method_ids.discard(-1)
        return method_ids

    def _p3_context_ids(self, loader: Any) -> set[int]:
        entry_points = getattr(loader, "get_entry_points", None)
        if callable(entry_points):
            context_ids = {
                self._to_int(entry_point)
                for entry_point in entry_points() or []
            }
            context_ids.discard(-1)
            if context_ids:
                return context_ids
        return self._method_ids(loader)

    def _callee_ids_p3(self, loader: Any, method_id: int) -> tuple[int, ...]:
        direct = getattr(loader, "get_callee_ids_by_id_in_p3", None)
        if callable(direct):
            try:
                callee_ids = self._normalized_ids(direct(method_id))
                if callee_ids:
                    return callee_ids
            except Exception:
                pass

        generic = getattr(loader, "get_callees", None)
        if callable(generic):
            try:
                return self._normalized_ids(
                    generic(method_id, phase="p3", match="id")
                )
            except TypeError:
                try:
                    return self._normalized_ids(
                        generic(method_id, phase="p3", match_by="id")
                    )
                except Exception:
                    return ()
            except Exception:
                return ()
        return ()

    def _symbol_state_space_p3(
        self,
        loader: Any,
        context_id: int,
    ) -> tuple[Any, ...]:
        getter = getattr(loader, "get_symbol_state_space_p3", None)
        if not callable(getter):
            return ()
        try:
            return tuple(getter(context_id) or ())
        except Exception:
            return ()

    def _method_def_use_summary(
        self,
        loader: Any,
        method_id: int,
    ) -> Any | None:
        getter = getattr(loader, "get_method_def_use_summary", None)
        if not callable(getter):
            return None
        try:
            return getter(method_id)
        except Exception:
            return None

    def _add_type_dependencies(
        self,
        loader: Any,
        occurrence_to_translation: dict[int, int],
        entity_index: dict[str, Any],
        enum_constant_targets: dict[str, set[int]],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:
        translation_owner_by_stmt = dict(occurrence_to_translation)
        occurrences_by_unit: dict[int, list[int]] = defaultdict(list)
        for entity in entity_index.get("entities", []):
            for occurrence in entity.get("occurrences", []):
                unit_id = self._to_int(occurrence.get("unit_id"))
                stmt_id = self._to_int(occurrence.get("stmt_id"))
                if unit_id >= 0 and stmt_id >= 0:
                    occurrences_by_unit[unit_id].append(stmt_id)

        for unit_id, entity_occurrences in occurrences_by_unit.items():
            unit_gir = loader.get_unit_gir(unit_id)
            rows = list(unit_gir or [])
            children: dict[int, list[Any]] = defaultdict(list)
            rows_by_id: dict[int, Any] = {}
            for row in rows:
                stmt_id = self._to_int(getattr(row, "stmt_id", -1))
                if stmt_id >= 0:
                    rows_by_id[stmt_id] = row
                parent_id = self._to_int(
                    getattr(row, "parent_stmt_id", -1)
                )
                children[parent_id].append(row)

            for stmt_id in rows_by_id:
                owner_id = self._translation_owner_id(
                    stmt_id,
                    rows_by_id,
                    occurrence_to_translation,
                )
                if owner_id is not None:
                    translation_owner_by_stmt[stmt_id] = owner_id

            inline_tag_targets: dict[str, set[int]] = defaultdict(set)
            for row in rows:
                stmt_id = self._to_int(getattr(row, "stmt_id", -1))
                owner_id = translation_owner_by_stmt.get(stmt_id)
                owner_row = rows_by_id.get(
                    self._top_level_owner_stmt_id(stmt_id, rows_by_id)
                )
                if (
                    owner_id is None
                    or self._text(getattr(owner_row, "operation", None))
                    not in _TYPE_DECLARATION_OPERATIONS
                ):
                    continue
                for type_name in self._inline_tag_definition_names(row):
                    inline_tag_targets[type_name].add(owner_id)

            declarations = loader.get_unit_symbol_name_to_decl_ids(
                unit_id
            )
            if not isinstance(declarations, dict):
                declarations = {}
            for occurrence_id in entity_occurrences:
                source_id = occurrence_to_translation.get(occurrence_id)
                if source_id is None:
                    continue
                for row in self._entity_rows(
                    occurrence_id, rows, children
                ):
                    for type_name, required_operation in self._type_references(
                        row
                    ):
                        for declaration_id in self._type_declaration_ids(
                            type_name=type_name,
                            required_operation=required_operation,
                            source_id=source_id,
                            declarations=declarations,
                            rows_by_id=rows_by_id,
                            occurrence_to_translation=occurrence_to_translation,
                        ):
                            self._add_dependency(
                                dependencies,
                                source_id,
                                translation_owner_by_stmt.get(
                                    self._to_int(declaration_id)
                                ),
                                "type",
                            )
                        for target_id in inline_tag_targets.get(type_name, ()):
                            self._add_dependency(
                                dependencies,
                                source_id,
                                target_id,
                                "type",
                            )
                        for target_id in enum_constant_targets.get(
                            type_name, ()
                        ):
                            self._add_dependency(
                                dependencies,
                                source_id,
                                target_id,
                                "enum",
                            )
                    for enum_constant in self._value_reference_names(row):
                        for target_id in enum_constant_targets.get(
                            enum_constant, ()
                        ):
                            self._add_dependency(
                                dependencies,
                                source_id,
                                target_id,
                                "enum",
                            )

        type_graph = loader.get_type_graph()
        graph = getattr(type_graph, "graph", None)
        if graph is None:
            return
        for source_stmt_id, target_stmt_id, _ in graph.edges(
            data="weight"
        ):
            if not self._is_type_declaration_stmt(loader, target_stmt_id):
                continue
            self._add_dependency(
                dependencies,
                translation_owner_by_stmt.get(
                    self._to_int(source_stmt_id)
                ),
                translation_owner_by_stmt.get(
                    self._to_int(target_stmt_id)
                ),
                "type",
            )

    def _add_initializer_value_dependencies(
        self,
        loader: Any,
        occurrence_to_translation: dict[int, int],
        translation_entities: list[Any],
        enum_constant_targets: dict[str, set[int]],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:
        entities_by_unit: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for entity in translation_entities:
            if not isinstance(entity, dict):
                continue
            entity_id = self._to_int(entity.get("id"))
            unit_id = self._to_int(entity.get("unit_id"))
            member_ids = {
                self._to_int(member_id)
                for member_id in entity.get("member_entity_ids", ())
            }
            member_ids.discard(-1)
            if entity_id > 0 and unit_id >= 0 and member_ids:
                entities_by_unit[unit_id].append(
                    {
                        "entity_id": entity_id,
                        "member_ids": member_ids,
                    }
                )

        for unit_id, unit_entities in entities_by_unit.items():
            rows = list(loader.get_unit_gir(unit_id) or [])
            if not rows:
                continue
            unit_init_blocks = self._unit_init_block_ids(rows)
            if not unit_init_blocks:
                continue

            declarations = loader.get_unit_symbol_name_to_decl_ids(unit_id)
            if not isinstance(declarations, dict):
                declarations = {}

            row_by_id = {
                self._to_int(getattr(row, "stmt_id", -1)): row
                for row in rows
            }
            initializer_targets: dict[str, set[int]] = defaultdict(set)
            for entity in unit_entities:
                entity_id = self._to_int(entity.get("entity_id"))
                for stmt_id in entity.get("member_ids", ()):
                    row = row_by_id.get(stmt_id)
                    if row is None:
                        continue
                    if getattr(row, "operation", None) != "variable_decl":
                        continue
                    name = self._text(getattr(row, "name", None))
                    if name:
                        initializer_targets[name].add(entity_id)

            if not initializer_targets:
                continue

            previous_initializer_assign_by_parent: dict[int, int] = {}
            for index, row in enumerate(rows):
                if getattr(row, "operation", None) != "assign_stmt":
                    continue
                parent_id = self._to_int(
                    getattr(row, "parent_stmt_id", -1)
                )
                if parent_id not in unit_init_blocks:
                    continue
                target = self._text(getattr(row, "target", None))
                source_entity_ids = initializer_targets.get(target)
                if not source_entity_ids:
                    continue

                start_index = self._initializer_start_index(
                    rows,
                    index,
                    previous_initializer_assign_by_parent.get(parent_id),
                )
                for source_entity_id in source_entity_ids:
                    self._add_value_reference_dependencies(
                        dependencies,
                        source_entity_id,
                        rows[start_index : index + 1],
                        declarations,
                        enum_constant_targets,
                        occurrence_to_translation,
                    )
                previous_initializer_assign_by_parent[parent_id] = index

    def _add_source_text_value_dependencies(
        self,
        entity_index: dict[str, Any],
        translation_entities: list[Any],
        occurrence_to_translation: dict[int, int],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:


        value_targets = self._source_value_targets(
            entity_index,
            occurrence_to_translation,
        )
        if not value_targets:
            return

        for entity in translation_entities:
            if not isinstance(entity, dict):
                continue
            if entity.get("kind") != "global":
                continue
            source_id = self._to_int(entity.get("id"))
            if source_id <= 0:
                continue

            source_text = self._entity_source_text(entity)
            if not source_text or "=" not in source_text:
                continue
            initializer_text = source_text.split("=", 1)[1]
            for name in self._value_reference_names_from_text(
                initializer_text
            ):
                for target_id in value_targets.get(name, ()):
                    self._add_dependency(
                        dependencies,
                        source_id,
                        target_id,
                        "initializer_source",
                    )

    def _source_value_targets(
        self,
        entity_index: dict[str, Any],
        occurrence_to_translation: dict[int, int],
    ) -> dict[str, set[int]]:
        targets: dict[str, set[int]] = defaultdict(set)
        for entity in entity_index.get("entities", []):
            if not isinstance(entity, dict):
                continue
            operation = self._text(entity.get("operation"))
            if operation not in {"method_decl", "variable_decl"}:
                continue
            name = self._text(entity.get("name"))
            if not name:
                continue
            canonical_id = self._to_int(entity.get("canonical_stmt_id"))
            target_id = occurrence_to_translation.get(canonical_id)
            if target_id is not None:
                targets[name].add(target_id)
        return targets

    def _entity_source_text(self, entity: dict[str, Any]) -> str:
        entity_id = self._to_int(entity.get("id"))
        if entity_id > 0:
            hint_path = (
                self.manifest.workspace
                / "semantic_hints"
                / "entities"
                / f"entity_{entity_id}.json"
            )
            try:
                hint = self._read_json(hint_path, "entity hint")
            except DependencyBuildError:
                hint = {}
            for key in ("original_c_source", "annotated_c_source"):
                value = hint.get(key)
                if isinstance(value, str) and value.strip():
                    return value

        source = entity.get("source")
        if not isinstance(source, dict):
            return ""
        path_value = source.get("path")
        if not isinstance(path_value, str) or not path_value:
            return ""
        path = Path(path_value)
        if not path.is_absolute():
            path = self.manifest.project_root / path
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return ""
        start = self._to_int(source.get("start_line")) - 1
        end = self._to_int(source.get("end_line"))
        if start < 0 or end <= start:
            return ""
        return "\n".join(lines[start:end])

    def _add_source_text_type_dependencies(
        self,
        entity_index: dict[str, Any],
        translation_entities: list[Any],
        occurrence_to_translation: dict[int, int],
        translation_contexts: dict[int, dict[str, Any]],
        dependencies: dict[int, dict[int, set[str]]],
    ) -> None:
        type_targets: dict[tuple[str, str | None], set[int]] = defaultdict(set)
        for entity in entity_index.get("entities", ()):
            if not isinstance(entity, dict):
                continue
            operation = self._text(entity.get("operation"))
            if operation not in _TYPE_DECLARATION_OPERATIONS:
                continue
            name = self._text(entity.get("name"))
            canonical_id = self._to_int(entity.get("canonical_stmt_id"))
            target_id = occurrence_to_translation.get(canonical_id)
            if not name or target_id is None:
                continue
            type_targets[(name, operation)].add(target_id)
            type_targets[(name, None)].add(target_id)

        if not type_targets:
            return

        project_type_aliases = {
            type_name
            for type_name, operation in type_targets
            if operation == "type_alias_decl"
        }
        for entity in translation_entities:
            if not isinstance(entity, dict):
                continue
            source_id = self._to_int(entity.get("id"))
            if source_id not in dependencies:
                continue
            source = self._translation_entity_source(entity)
            if not source:
                continue
            for type_name, required_operation in self._type_references_from_text(
                source,
                type_alias_names=project_type_aliases,
            ):
                target_ids: set[int] = set()
                if required_operation is not None:
                    target_ids.update(
                        type_targets.get((type_name, required_operation), ())
                    )
                else:
                    aliases = type_targets.get((type_name, "type_alias_decl"), ())
                    target_ids.update(
                        aliases or type_targets.get((type_name, None), ())
                    )
                target_ids = self._prefer_local_type_targets(
                    source_id,
                    target_ids,
                    translation_contexts,
                )
                for target_id in target_ids:
                    self._add_dependency(
                        dependencies,
                        source_id,
                        target_id,
                        "source_type",
                    )

    @staticmethod
    def _translation_entity_contexts(
        translation_entities: list[Any],
    ) -> dict[int, dict[str, Any]]:
        contexts: dict[int, dict[str, Any]] = {}
        for entity in translation_entities:
            if not isinstance(entity, dict):
                continue
            entity_id = DependencyBuilder._to_int(entity.get("id"))
            if entity_id < 0:
                continue
            source = entity.get("origin") or entity.get("source")
            rel_path = ""
            if isinstance(source, dict):
                rel_path = DependencyBuilder._normalize_rel_path(
                    source.get("rel_path")
                )
            contexts[entity_id] = {
                "unit_id": DependencyBuilder._to_int(entity.get("unit_id")),
                "rel_path": rel_path,
            }
        return contexts

    @staticmethod
    def _prefer_local_type_targets(
        source_id: int,
        target_ids: set[int],
        translation_contexts: dict[int, dict[str, Any]],
    ) -> set[int]:
        if len(target_ids) < 2:
            return target_ids
        source = translation_contexts.get(source_id, {})
        source_unit = DependencyBuilder._to_int(source.get("unit_id"))
        source_rel_path = DependencyBuilder._normalize_rel_path(
            source.get("rel_path")
        )
        same_unit = {
            target_id
            for target_id in target_ids
            if DependencyBuilder._to_int(
                translation_contexts.get(target_id, {}).get("unit_id")
            )
            == source_unit
            and source_unit >= 0
        }
        if same_unit:
            return same_unit
        same_file = {
            target_id
            for target_id in target_ids
            if source_rel_path
            and DependencyBuilder._normalize_rel_path(
                translation_contexts.get(target_id, {}).get("rel_path")
            )
            == source_rel_path
        }
        return same_file or target_ids

    @staticmethod
    def _normalize_rel_path(value: Any) -> str:
        return str(value or "").replace("\\", "/").lstrip("./")

    def _add_value_reference_dependencies(
        self,
        dependencies: dict[int, dict[int, set[str]]],
        source_entity_id: int,
        rows: list[Any],
        declarations: dict[Any, Any],
        enum_constant_targets: dict[str, set[int]],
        occurrence_to_translation: dict[int, int],
    ) -> None:
        for row in rows:
            for name in self._value_reference_names(row):
                for declaration_id in declarations.get(name, ()):
                    self._add_dependency(
                        dependencies,
                        source_entity_id,
                        occurrence_to_translation.get(
                            self._to_int(declaration_id)
                        ),
                        "initializer",
                    )
                for target_id in enum_constant_targets.get(name, ()):
                    self._add_dependency(
                        dependencies,
                        source_entity_id,
                        target_id,
                        "enum",
                    )

    @staticmethod
    def _unit_init_block_ids(rows: list[Any]) -> set[int]:
        block_ids: set[int] = set()
        for row in rows:
            if getattr(row, "operation", None) != "method_decl":
                continue
            if getattr(row, "name", None) != "%unit_init":
                continue
            body_id = DependencyBuilder._to_int(getattr(row, "body", -1))
            if body_id > 0:
                block_ids.add(body_id)
        return block_ids

    @staticmethod
    def _initializer_start_index(
        rows: list[Any],
        assign_index: int,
        previous_assign_index: int | None,
    ) -> int:
        assign_row = rows[assign_index]
        parent_id = DependencyBuilder._to_int(
            getattr(assign_row, "parent_stmt_id", -1)
        )
        operand = DependencyBuilder._text(getattr(assign_row, "operand", None))
        if operand.startswith("%"):
            for index in range(assign_index - 1, -1, -1):
                row = rows[index]
                if (
                    DependencyBuilder._to_int(
                        getattr(row, "parent_stmt_id", -1)
                    )
                    != parent_id
                ):
                    continue
                if DependencyBuilder._text(
                    getattr(row, "target", None)
                ) == operand:
                    return index

        if previous_assign_index is not None:
            return previous_assign_index + 1
        return assign_index

    @staticmethod
    def _value_reference_names(row: Any) -> set[str]:
        if hasattr(row, "to_dict"):
            raw = row.to_dict()
        else:
            raw = vars(row)

        names: set[str] = set()
        for field, value in raw.items():
            if field in _VALUE_REFERENCE_SKIP_FIELDS:
                continue
            text = DependencyBuilder._text(value)
            if not text:
                continue
            text = _STRING_LITERAL_PATTERN.sub(" ", text)
            for token in _TYPE_NAME_PATTERN.findall(text):
                if token not in _C_TYPE_WORDS and not token.startswith("vv"):
                    names.add(token)
        return names

    @staticmethod
    def _value_reference_names_from_text(text: str) -> set[str]:
        text = _STRING_LITERAL_PATTERN.sub(" ", text)
        names: set[str] = set()
        for token in _TYPE_NAME_PATTERN.findall(text):
            if token not in _C_TYPE_WORDS and not token.startswith("vv"):
                names.add(token)
        return names

    @staticmethod
    def _enum_constant_targets(
        rows: list[Any],
        children: dict[int, list[Any]],
        occurrence_to_translation: dict[int, int],
    ) -> dict[str, set[int]]:
        targets: dict[str, set[int]] = defaultdict(set)
        for row in rows:
            if getattr(row, "operation", None) != "enum_decl":
                continue
            enum_stmt_id = DependencyBuilder._to_int(
                getattr(row, "stmt_id", -1)
            )
            target_id = occurrence_to_translation.get(enum_stmt_id)
            if target_id is None:
                continue
            for enum_row in DependencyBuilder._entity_rows(
                enum_stmt_id,
                rows,
                children,
            ):
                if getattr(enum_row, "operation", None) != "enum_constant":
                    continue
                name = DependencyBuilder._text(
                    getattr(enum_row, "name", None)
                )
                if name:
                    targets[name].add(target_id)
        return targets

    def _global_enum_constant_targets(
        self,
        loader: Any,
        occurrence_to_translation: dict[int, int],
        entity_index: dict[str, Any],
    ) -> dict[str, set[int]]:
        occurrences_by_unit: dict[int, list[int]] = defaultdict(list)
        for entity in entity_index.get("entities", []):
            if not isinstance(entity, dict):
                continue
            for occurrence in entity.get("occurrences", []):
                if not isinstance(occurrence, dict):
                    continue
                unit_id = self._to_int(occurrence.get("unit_id"))
                stmt_id = self._to_int(occurrence.get("stmt_id"))
                if unit_id >= 0 and stmt_id >= 0:
                    occurrences_by_unit[unit_id].append(stmt_id)

        targets: dict[str, set[int]] = defaultdict(set)
        for unit_id in occurrences_by_unit:
            rows = list(loader.get_unit_gir(unit_id) or [])
            if not rows:
                continue
            children: dict[int, list[Any]] = defaultdict(list)
            for row in rows:
                parent_id = self._to_int(
                    getattr(row, "parent_stmt_id", -1)
                )
                children[parent_id].append(row)
            for name, target_ids in self._enum_constant_targets(
                rows,
                children,
                occurrence_to_translation,
            ).items():
                targets[name].update(target_ids)
        return targets

    @staticmethod
    def _entity_rows(
        root_stmt_id: int,
        rows: list[Any],
        children: dict[int, list[Any]],
    ) -> Iterable[Any]:
        rows_by_id = {
            DependencyBuilder._to_int(getattr(row, "stmt_id", -1)): row
            for row in rows
        }
        root = rows_by_id.get(root_stmt_id)
        if root is None:
            return ()

        result: list[Any] = []
        worklist = [root]
        visited: set[int] = set()
        while worklist:
            row = worklist.pop()
            stmt_id = DependencyBuilder._to_int(
                getattr(row, "stmt_id", -1)
            )
            if stmt_id in visited:
                continue
            visited.add(stmt_id)
            result.append(row)
            worklist.extend(children.get(stmt_id, ()))
        return result

    @staticmethod
    def _type_references(row: Any) -> set[tuple[str, str | None]]:
        references: set[tuple[str, str | None]] = set()
        for field in _TYPE_FIELDS:
            value = getattr(row, field, "")
            text = DependencyBuilder._text(value)
            for match in _TAG_TYPE_PATTERN.finditer(text):
                references.add(
                    (match.group(2), _TAG_TYPE_OPERATIONS[match.group(1)])
                )
            remaining = _TAG_TYPE_PATTERN.sub(" ", text)
            for token in _TYPE_NAME_PATTERN.findall(remaining):
                if token not in _C_TYPE_WORDS:
                    references.add((token, None))
        return references

    @staticmethod
    def _type_references_from_text(
        text: str,
        *,
        type_alias_names: Iterable[str] = (),
    ) -> set[tuple[str, str | None]]:
        text = _STRING_LITERAL_PATTERN.sub(" ", text)
        references: set[tuple[str, str | None]] = set()
        for match in _TAG_TYPE_PATTERN.finditer(text):
            references.add(
                (match.group(2), _TAG_TYPE_OPERATIONS[match.group(1)])
            )
        remaining = _TAG_TYPE_PATTERN.sub(" ", text)
        for token in _TYPE_NAME_PATTERN.findall(remaining):
            if token not in _C_TYPE_WORDS:
                references.add((token, None))




        for alias_name in type_alias_names:
            if re.search(r"\b" + re.escape(alias_name) + r"\b", text):
                references.add((alias_name, "type_alias_decl"))
        return references

    @staticmethod
    def _type_declaration_ids(
        *,
        type_name: str,
        required_operation: str | None,
        source_id: int,
        declarations: dict[Any, Any],
        rows_by_id: dict[int, Any],
        occurrence_to_translation: dict[int, int],
    ) -> tuple[int, ...]:
        candidates: list[tuple[int, str]] = []
        for value in DependencyBuilder._iter_values(
            declarations.get(type_name, ())
        ):
            declaration_id = DependencyBuilder._to_int(value)
            if occurrence_to_translation.get(declaration_id) == source_id:
                continue
            row = rows_by_id.get(declaration_id)
            operation = DependencyBuilder._text(
                getattr(row, "operation", None)
            )
            if operation in _TYPE_DECLARATION_OPERATIONS:
                candidates.append((declaration_id, operation))

        if required_operation is not None:
            return tuple(
                declaration_id
                for declaration_id, operation in candidates
                if operation == required_operation
            )

        aliases = tuple(
            declaration_id
            for declaration_id, operation in candidates
            if operation == "type_alias_decl"
        )
        if aliases:
            return aliases
        return tuple(declaration_id for declaration_id, _ in candidates)

    @staticmethod
    def _translation_owner_id(
        stmt_id: int,
        rows_by_id: dict[int, Any],
        occurrence_to_translation: dict[int, int],
    ) -> int | None:


        current_id = stmt_id
        visited: set[int] = set()
        while current_id >= 0 and current_id not in visited:
            visited.add(current_id)
            owner_id = occurrence_to_translation.get(current_id)
            if owner_id is not None:
                return owner_id
            row = rows_by_id.get(current_id)
            if row is None:
                return None
            current_id = DependencyBuilder._to_int(
                getattr(row, "parent_stmt_id", -1)
            )
        return None

    @staticmethod
    def _top_level_owner_stmt_id(
        stmt_id: int,
        rows_by_id: dict[int, Any],
    ) -> int:
        current_id = stmt_id
        last_id = stmt_id
        visited: set[int] = set()
        while current_id > 0 and current_id not in visited:
            visited.add(current_id)
            row = rows_by_id.get(current_id)
            if row is None:
                break
            last_id = current_id
            current_id = DependencyBuilder._to_int(
                getattr(row, "parent_stmt_id", -1)
            )
        return last_id

    @staticmethod
    def _inline_tag_definition_names(row: Any) -> tuple[str, ...]:
        names: list[str] = []
        for field in _TYPE_FIELDS:
            text = DependencyBuilder._text(getattr(row, field, ""))
            for match in _INLINE_TAG_DEFINITION_PATTERN.finditer(text):
                name = match.group(2)
                if name not in names:
                    names.append(name)
        return tuple(names)

    @staticmethod
    def _is_type_declaration_stmt(loader: Any, stmt_id: Any) -> bool:
        get_stmt_gir = getattr(loader, "get_stmt_gir", None)
        if not callable(get_stmt_gir):
            return True
        try:
            row = get_stmt_gir(DependencyBuilder._to_int(stmt_id))
        except Exception:
            return True
        if row is None:
            return True
        operation = DependencyBuilder._text(
            getattr(row, "operation", None)
        )
        return operation in _TYPE_DECLARATION_OPERATIONS

    def _add_dependency(
        self,
        dependencies: dict[int, dict[int, set[str]]],
        source_id: int | None,
        target_id: int | None,
        reason: str,
    ) -> None:
        if (
            source_id is None
            or target_id is None
            or source_id == target_id
            or source_id not in dependencies
            or target_id not in dependencies
        ):
            return
        dependencies[source_id][target_id].add(reason)

    @staticmethod
    def _occurrence_mapping(
        entity_index: dict[str, Any],
        translation_data: dict[str, Any],
    ) -> dict[int, int]:
        stmt_to_canonical = entity_index.get("stmt_to_canonical")
        entity_to_translation = translation_data.get(
            "entity_to_translation_entity"
        )
        if not isinstance(stmt_to_canonical, dict):
            raise DependencyBuildError(
                "entity index has no stmt_to_canonical mapping"
            )
        if not isinstance(entity_to_translation, dict):
            raise DependencyBuildError(
                "translation entities file has no "
                "entity_to_translation_entity mapping"
            )

        result: dict[int, int] = {}
        for occurrence_id, canonical_id in stmt_to_canonical.items():
            translation_id = entity_to_translation.get(
                str(DependencyBuilder._to_int(canonical_id))
            )
            if translation_id is not None:
                result[
                    DependencyBuilder._to_int(occurrence_id)
                ] = DependencyBuilder._to_int(translation_id)
        return result

    @staticmethod
    def _read_json(path: Path, description: str) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DependencyBuildError(
                f"failed to read {description} {path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise DependencyBuildError(
                f"{description} is not a JSON object: {path}"
            )
        return data

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
            raise DependencyBuildError(
                f"failed to write entity dependencies "
                f"{self.output_path}: {exc}"
            ) from exc

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, float) and math.isnan(value):
            return ""
        return str(value)

    @staticmethod
    def _iter_values(value: Any) -> Iterable[Any]:
        if value is None:
            return ()
        if isinstance(value, float) and math.isnan(value):
            return ()
        if isinstance(value, (str, bytes)):
            return (value,)
        try:
            iter(value)
        except TypeError:
            return (value,)
        return value

    @staticmethod
    def _normalized_ids(value: Any) -> tuple[int, ...]:
        result = {
            DependencyBuilder._to_int(item)
            for item in DependencyBuilder._iter_values(value)
        }
        result.discard(-1)
        return tuple(sorted(result))

    @staticmethod
    def _to_int(value: Any, default: int = -1) -> int:
        try:
            if isinstance(value, float) and math.isnan(value):
                return default
            return int(value)
        except (TypeError, ValueError):
            return default
