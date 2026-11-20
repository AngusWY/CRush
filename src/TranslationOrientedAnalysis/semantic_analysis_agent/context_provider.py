from __future__ import annotations

import ast
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..analysis_context import AnalysisContext
from .models import (
    CalleeParameterContext,
    CallerCallSiteContext,
    CrossEntityPointerUsageContext,
    DECLARATION_TASK_KIND,
    PointerSemanticGap,
    PointerTaskContext,
    RelatedTypeContext,
    SemanticAgentContext,
    SemanticAgentTask,
    SourceCodeContext,
    UNSAFE_STMT_TASK_KIND,
    UnsafeStmtSemanticGap,
    UnsafeStmtTaskContext,
    VariableSemanticGap,
    VariableTaskContext,
)


TRANSLATION_ENTITIES_FILE_NAME = "translation-entities.json"
_TYPE_OPERATIONS = frozenset(
    {"struct_decl", "union_decl", "enum_decl", "type_alias_decl"}
)
_BUILTIN_TYPE_NAMES = frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "signed",
        "unsigned",
        "const",
        "volatile",
        "restrict",
        "struct",
        "union",
        "enum",
        "_Bool",
        "bool",
        "size_t",
        "ssize_t",
        "ptrdiff_t",
        "intptr_t",
        "uintptr_t",
        "int8_t",
        "uint8_t",
        "int16_t",
        "uint16_t",
        "int32_t",
        "uint32_t",
        "int64_t",
        "uint64_t",
    }
)
_TOKEN_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_STRING_FUNCTIONS = frozenset(
    {
        "strlen",
        "strcmp",
        "strncmp",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strchr",
        "strrchr",
        "strstr",
        "strdup",
        "strndup",
        "strtok",
        "strtok_r",
    }
)
_CALL_EFFECTS: dict[str, dict[int, tuple[str, ...]]] = {
    "free": {0: ("freed",)},
    "strlen": {0: ("pointee_read", "array_access", "string_usage")},
    "strcmp": {
        0: ("pointee_read", "array_access", "string_usage"),
        1: ("pointee_read", "array_access", "string_usage"),
    },
    "strncmp": {
        0: ("pointee_read", "array_access", "string_usage"),
        1: ("pointee_read", "array_access", "string_usage"),
    },
    "strcpy": {
        0: ("pointee_write", "array_access", "string_usage"),
        1: ("pointee_read", "array_access", "string_usage"),
    },
    "strncpy": {
        0: ("pointee_write", "array_access", "string_usage"),
        1: ("pointee_read", "array_access", "string_usage"),
    },
    "memcpy": {
        0: ("pointee_write", "array_access"),
        1: ("pointee_read", "array_access"),
    },
    "memmove": {
        0: ("pointee_write", "array_access"),
        1: ("pointee_read", "array_access"),
    },
    "memset": {0: ("pointee_write", "array_access")},
    "memcmp": {
        0: ("pointee_read", "array_access"),
        1: ("pointee_read", "array_access"),
    },
}
_MAX_STMT_SOURCE_CHARS = 16_384


def bounded_stmt_source(
    lines: tuple[str, ...] | list[str],
    *,
    start_col: int | None,
    end_col: int | None,
    max_chars: int = _MAX_STMT_SOURCE_CHARS,
) -> str:


    if max_chars < 1:
        raise ValueError("max_chars must be positive")
    selected = [line for line in lines if line]
    if not selected:
        return ""

    if (
        len(selected) == 1
        and start_col is not None
        and end_col is not None
        and 0 <= start_col <= end_col <= len(selected[0])
    ):
        exact = selected[0][start_col:end_col].strip()
        if exact:
            return exact[:max_chars]

    source = "\n".join(selected).strip()
    if len(source) <= max_chars:
        return source
    marker = "\n... [statement source truncated] ...\n"
    remaining = max_chars - len(marker)
    if remaining <= 0:
        return source[:max_chars]
    prefix_length = remaining // 2
    return source[:prefix_length] + marker + source[-(remaining - prefix_length):]


class SemanticAgentContextError(RuntimeError):
    pass


class SemanticAgentContextProvider:


    def __init__(
        self,
        *,
        context: AnalysisContext,
        workspace: Path,
        max_items_per_category: int = 50,
    ) -> None:
        if max_items_per_category <= 0:
            raise ValueError("max_items_per_category must be positive")
        self.context = context
        self.workspace = workspace.resolve()
        self.max_items_per_category = max_items_per_category
        self.translation_entities_path = (
            self.workspace / TRANSLATION_ENTITIES_FILE_NAME
        )
        self._entities = self._read_translation_entities()
        self._member_to_entity = {
            member_id: entity_id
            for entity_id, entity in self._entities.items()
            for member_id in self._entity_member_ids(entity)
        }
        self._function_entities_by_name: dict[str, list[int]] = defaultdict(
            list
        )
        self._type_entities_by_name: dict[str, list[int]] = defaultdict(list)
        self._entity_source_cache: dict[int, SourceCodeContext] = {}
        self._method_ids_by_name: dict[str, tuple[int, ...]] | None = None
        self._call_rows_by_callee: (
            dict[str, tuple[tuple[int, Any], ...]] | None
        ) = None
        self._field_usage_rows_by_name: (
            dict[str, tuple[Any, ...]] | None
        ) = None
        self._rows_by_reference_token: (
            dict[str, tuple[Any, ...]] | None
        ) = None
        self._all_unit_rows_cache: tuple[Any, ...] | None = None
        for entity_id, entity in self._entities.items():
            name = self._text(entity.get("name"))
            kind = self._text(entity.get("kind"))
            if name and kind == "function":
                self._function_entities_by_name[name].append(entity_id)
            elif name and kind == "type":
                self._type_entities_by_name[name].append(entity_id)

    def build(self, task: SemanticAgentTask) -> SemanticAgentContext:


        self._validate_task(task)
        if task.task_kind == DECLARATION_TASK_KIND:
            pointer_tasks = tuple(
                self._pointer_task_context(gap)
                for gap in task.pointer_gaps
            )
            variable_tasks = tuple(
                self._variable_task_context(gap)
                for gap in task.variable_gaps
            )
            unsafe_stmt_tasks: tuple[UnsafeStmtTaskContext, ...] = ()
            caller_sites = self._caller_call_sites(task, pointer_tasks)
            callee_contexts = self._callee_parameter_contexts(pointer_tasks)
            related_types = self._related_types(task, pointer_tasks)
            cross_entity_usages = self._cross_entity_usages(
                task, pointer_tasks
            )
        elif task.task_kind == UNSAFE_STMT_TASK_KIND:
            pointer_tasks = ()
            variable_tasks = ()
            unsafe_stmt_tasks = tuple(
                self._unsafe_stmt_task_context(gap)
                for gap in task.unsafe_stmt_gaps
            )
            caller_sites = ()
            callee_contexts = ()
            related_types = ()
            cross_entity_usages = ()
        else:
            raise SemanticAgentContextError(
                f"task {task.entity_id} has invalid task_kind: "
                f"{task.task_kind!r}"
            )

        return SemanticAgentContext(
            entity_source=self._entity_source(task.entity_id),
            pointer_tasks=pointer_tasks,
            caller_call_sites=caller_sites,
            callee_parameter_contexts=callee_contexts,
            related_types=related_types,
            cross_entity_pointer_usages=cross_entity_usages,
            variable_tasks=variable_tasks,
            unsafe_stmt_tasks=unsafe_stmt_tasks,
            cross_entity_search_complete=False,
        )

    def _validate_task(self, task: SemanticAgentTask) -> None:
        entity = self._entities.get(task.entity_id)
        if entity is None:
            raise SemanticAgentContextError(
                f"task references unknown translation entity {task.entity_id}"
            )
        if self._text(entity.get("name")) != task.entity_name:
            raise SemanticAgentContextError(
                f"task entity name mismatch for {task.entity_id}"
            )
        if (
            not task.pointer_gaps
            and not task.variable_gaps
            and not task.unsafe_stmt_gaps
        ):
            raise SemanticAgentContextError(
                f"task {task.entity_id} has no semantic gaps"
            )
        if task.task_kind == DECLARATION_TASK_KIND:
            if task.unsafe_stmt_gaps:
                raise SemanticAgentContextError(
                    f"declaration task {task.entity_id} contains unsafe gaps"
                )
            if not task.pointer_gaps and not task.variable_gaps:
                raise SemanticAgentContextError(
                    f"declaration task {task.entity_id} has no declaration gaps"
                )
        elif task.task_kind == UNSAFE_STMT_TASK_KIND:
            if task.pointer_gaps or task.variable_gaps:
                raise SemanticAgentContextError(
                    f"unsafe stmt task {task.entity_id} contains declaration gaps"
                )
            if not task.unsafe_stmt_gaps:
                raise SemanticAgentContextError(
                    f"unsafe stmt task {task.entity_id} has no unsafe gaps"
                )
        else:
            raise SemanticAgentContextError(
                f"task {task.entity_id} has invalid task_kind: "
                f"{task.task_kind!r}"
            )

    def _pointer_task_context(
        self,
        gap: PointerSemanticGap,
    ) -> PointerTaskContext:
        row = self.context.get_stmt(gap.stmt_id)
        if row is None:
            raise SemanticAgentContextError(
                f"pointer declaration {gap.stmt_id} does not exist"
            )
        name = self._field(row, "name")
        if name != gap.current_semantics.name:
            raise SemanticAgentContextError(
                f"pointer declaration name mismatch for {gap.stmt_id}"
            )
        c_type = self._field(row, "data_type", "default_data_type")
        if not c_type:
            raise SemanticAgentContextError(
                f"pointer declaration {gap.stmt_id} has no C type"
            )

        return PointerTaskContext(
            stmt_id=gap.stmt_id,
            name=name,
            c_type=c_type,
            location=self._pointer_location(gap.stmt_id),
            declaration_source=self._source_text(gap.stmt_id),
            missing_fields=tuple(gap.missing_fields),
            current_semantics=gap.current_semantics,
        )

    def _variable_task_context(
        self,
        gap: VariableSemanticGap,
    ) -> VariableTaskContext:
        row = self.context.get_stmt(gap.stmt_id)
        if row is None:
            raise SemanticAgentContextError(
                f"variable declaration {gap.stmt_id} does not exist"
            )
        name = self._field(row, "name")
        if name != gap.current_semantics.name:
            raise SemanticAgentContextError(
                f"variable declaration name mismatch for {gap.stmt_id}"
            )
        c_type = self._field(row, "data_type", "default_data_type")
        if not c_type:
            raise SemanticAgentContextError(
                f"variable declaration {gap.stmt_id} has no C type"
            )

        return VariableTaskContext(
            stmt_id=gap.stmt_id,
            name=name,
            c_type=c_type,
            location=self._pointer_location(gap.stmt_id),
            declaration_source=self._source_text(gap.stmt_id),
            missing_fields=tuple(gap.missing_fields),
            current_semantics=gap.current_semantics,
        )

    def _unsafe_stmt_task_context(
        self,
        gap: UnsafeStmtSemanticGap,
    ) -> UnsafeStmtTaskContext:
        row = self.context.get_stmt(gap.stmt_id)
        if row is None:
            raise SemanticAgentContextError(
                f"unsafe stmt {gap.stmt_id} does not exist"
            )
        operation = self._field(row, "operation")
        if operation and operation != gap.operation:
            raise SemanticAgentContextError(
                f"unsafe stmt operation mismatch for {gap.stmt_id}"
            )
        return UnsafeStmtTaskContext(
            stmt_id=gap.stmt_id,
            operation=gap.operation,
            semantic_kind=gap.semantic_kind,
            stmt_source=self._stmt_source_context(gap.stmt_id),
            missing_fields=tuple(gap.missing_fields),
            current_semantics=gap.current_semantics,
        )

    def _caller_call_sites(
        self,
        task: SemanticAgentTask,
        pointers: tuple[PointerTaskContext, ...],
    ) -> tuple[CallerCallSiteContext, ...]:
        parameter_positions = self._parameter_positions(pointers)
        if not parameter_positions:
            return ()

        target_method_name = task.entity_name
        results: list[CallerCallSiteContext] = []
        seen: set[tuple[int, int]] = set()
        for caller_method_id, row in self._call_rows_for_callee(
            target_method_name
        ):
            call_stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if call_stmt_id is None:
                continue
            arguments = self._call_arguments(row)
            for pointer_stmt_id, position in parameter_positions.items():
                if position >= len(arguments):
                    continue
                key = (call_stmt_id, pointer_stmt_id)
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    CallerCallSiteContext(
                        pointer_stmt_id=pointer_stmt_id,
                        caller_entity_id=self._method_entity_id(
                            caller_method_id
                        ),
                        caller_name=(
                            self.context.get_method_name(caller_method_id)
                            or f"method_{caller_method_id}"
                        ),
                        call_stmt_id=call_stmt_id,
                        argument_index=position,
                        argument_value=arguments[position],
                        source=self._stmt_source_context(call_stmt_id),
                    )
                )
                if len(results) >= self.max_items_per_category:
                    return tuple(results)
        return tuple(
            sorted(
                results,
                key=lambda item: (
                    item.pointer_stmt_id,
                    item.call_stmt_id,
                    item.argument_index,
                ),
            )
        )

    def _callee_parameter_contexts(
        self,
        pointers: tuple[PointerTaskContext, ...],
    ) -> tuple[CalleeParameterContext, ...]:
        results: list[CalleeParameterContext] = []
        seen: set[tuple[int, int, int]] = set()

        for pointer in pointers:
            method_id = self.context.get_method_id(pointer.stmt_id)
            if method_id is None:
                continue
            aliases = {pointer.name}
            for row in self.context.get_method_rows(method_id):
                operation = self._field(row, "operation")
                self._update_aliases(row, operation, aliases)
                if operation != "call_stmt":
                    continue
                call_stmt_id = self._positive_id(
                    getattr(row, "stmt_id", None)
                )
                if call_stmt_id is None:
                    continue
                arguments = self._call_arguments(row)
                callee_name = self._call_name(call_stmt_id, row)
                for argument_index, argument in enumerate(arguments):
                    if not self._argument_mentions_alias(
                        argument, aliases
                    ):
                        continue
                    key = (
                        pointer.stmt_id,
                        call_stmt_id,
                        argument_index,
                    )
                    if key in seen:
                        continue
                    seen.add(key)
                    results.append(
                        self._callee_context(
                            pointer=pointer,
                            call_stmt_id=call_stmt_id,
                            callee_name=callee_name,
                            argument_index=argument_index,
                        )
                    )
                    if len(results) >= self.max_items_per_category:
                        return tuple(results)

        return tuple(
            sorted(
                results,
                key=lambda item: (
                    item.pointer_stmt_id,
                    item.call_stmt_id,
                    item.argument_index,
                ),
            )
        )

    def _callee_context(
        self,
        *,
        pointer: PointerTaskContext,
        call_stmt_id: int,
        callee_name: str,
        argument_index: int,
    ) -> CalleeParameterContext:
        method_ids = self._method_ids_for_name(callee_name)
        parameter_stmt_id: int | None = None
        parameter_name: str | None = None
        effects: set[str] = set(
            _CALL_EFFECTS.get(callee_name, {}).get(argument_index, ())
        )
        relevant_sources: tuple[SourceCodeContext, ...] = ()
        callee_entity_id: int | None = None

        if method_ids:
            callee_method_id = method_ids[0]
            callee_entity_id = self._method_entity_id(callee_method_id)
            parameters = self.context.get_method_parameters(callee_method_id)
            if argument_index < len(parameters):
                parameter = parameters[argument_index]
                parameter_stmt_id = self._positive_id(
                    getattr(parameter, "stmt_id", None)
                )
                parameter_name = self._field(parameter, "name") or None
                if parameter_name:
                    effects, relevant_sources = (
                        self._scan_parameter_behavior(
                            callee_method_id, parameter_name
                        )
                    )
        elif callee_name and callee_name not in _CALL_EFFECTS:
            effects.add("passed_to_external_or_unresolved_callee")

        return CalleeParameterContext(
            pointer_stmt_id=pointer.stmt_id,
            call_stmt_id=call_stmt_id,
            callee_entity_id=callee_entity_id,
            callee_name=callee_name or "<unknown>",
            argument_index=argument_index,
            parameter_stmt_id=parameter_stmt_id,
            parameter_name=parameter_name,
            discovered_effects=tuple(sorted(effects)),
            call_source=self._stmt_source_context(call_stmt_id),
            relevant_callee_source=relevant_sources,
            analysis_complete=False,
        )

    def _scan_parameter_behavior(
        self,
        method_id: int,
        parameter_name: str,
    ) -> tuple[set[str], tuple[SourceCodeContext, ...]]:
        aliases = {parameter_name}
        effects: set[str] = set()
        sources: list[SourceCodeContext] = []
        seen_sources: set[int] = set()

        for row in self.context.get_method_rows(method_id):
            operation = self._field(row, "operation")
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            related = self._row_mentions_alias(row, aliases)
            self._update_aliases(row, operation, aliases)
            if not related or stmt_id is None:
                continue

            if operation in {"array_read", "mem_read", "field_read"}:
                effects.add("pointee_read")
            elif operation in {"array_write", "mem_write"}:
                effects.add("pointee_write")
            elif operation == "field_write":
                receiver = self._field(row, "receiver_object", "object")
                source = self._field(row, "source", "value", "operand")
                if self._mentions_alias(receiver, aliases):
                    effects.add("pointee_write")
                if self._mentions_alias(source, aliases):
                    effects.add("stored")
            elif operation == "return_stmt":
                effects.add("returned")
            elif operation == "call_stmt":
                callee = self._call_name(stmt_id, row)
                for index, argument in enumerate(
                    self._call_arguments(row)
                ):
                    if not self._argument_mentions_alias(
                        argument, aliases
                    ):
                        continue
                    effects.update(
                        _CALL_EFFECTS.get(callee, {}).get(index, ())
                    )
                    if callee not in _CALL_EFFECTS:
                        effects.add("passed_to_callee")

            if stmt_id not in seen_sources:
                seen_sources.add(stmt_id)
                sources.append(self._stmt_source_context(stmt_id))

        return effects, tuple(sources[: self.max_items_per_category])

    def _related_types(
        self,
        task: SemanticAgentTask,
        pointers: tuple[PointerTaskContext, ...],
    ) -> tuple[RelatedTypeContext, ...]:
        type_names: set[str] = set()
        for pointer in pointers:
            type_names.update(self._custom_type_names(pointer.c_type))
            if pointer.location in {"struct_member", "union_member"}:
                type_names.add(task.entity_name)

        results: list[RelatedTypeContext] = []
        seen_sources: set[tuple[str, str]] = set()
        for type_name in sorted(type_names):
            entity_ids = self._type_entities_by_name.get(type_name, [])
            if entity_ids:
                entity_id = entity_ids[0]
                entity = self._entities[entity_id]
                source = self._entity_source(entity_id)
                key = (type_name, source.source)
                if key in seen_sources:
                    continue
                seen_sources.add(key)
                results.append(
                    RelatedTypeContext(
                        type_name=type_name,
                        entity_id=entity_id,
                        declaration_stmt_ids=self._entity_member_ids(entity),
                        source=source,
                    )
                )
                continue

            declaration_ids: list[int] = []
            declaration_source: SourceCodeContext | None = None
            for unit_id in self.context.get_all_unit_ids():
                for declaration_id in self.context.get_unit_symbol_declarations(
                    unit_id
                ).get(type_name, ()):
                    row = self.context.get_stmt(declaration_id)
                    if (
                        row is None
                        or self._field(row, "operation")
                        not in _TYPE_OPERATIONS
                    ):
                        continue
                    declaration_ids.append(declaration_id)
                    if declaration_source is None:
                        declaration_source = self._stmt_source_context(
                            declaration_id
                        )
            if declaration_source is not None:
                results.append(
                    RelatedTypeContext(
                        type_name=type_name,
                        entity_id=None,
                        declaration_stmt_ids=tuple(
                            sorted(set(declaration_ids))
                        ),
                        source=declaration_source,
                    )
                )
            if len(results) >= self.max_items_per_category:
                break
        return tuple(results)

    def _cross_entity_usages(
        self,
        task: SemanticAgentTask,
        pointers: tuple[PointerTaskContext, ...],
    ) -> tuple[CrossEntityPointerUsageContext, ...]:
        results: list[CrossEntityPointerUsageContext] = []
        seen: set[tuple[int, int]] = set()

        for pointer in pointers:
            if pointer.location in {"struct_member", "union_member"}:
                candidates = self._field_usage_rows(pointer.name)
            elif pointer.location == "global":
                candidates = self._global_usage_rows(pointer)
            else:
                continue

            for row in candidates:
                stmt_id = self._positive_id(getattr(row, "stmt_id", None))
                if stmt_id is None or stmt_id == pointer.stmt_id:
                    continue
                entity_id = self._stmt_entity_id(stmt_id)
                if entity_id == task.entity_id:
                    continue
                key = (pointer.stmt_id, stmt_id)
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    CrossEntityPointerUsageContext(
                        pointer_stmt_id=pointer.stmt_id,
                        entity_id=entity_id,
                        entity_name=self._entity_name(entity_id),
                        stmt_id=stmt_id,
                        kind=self._field(row, "operation") or "unknown",
                        source=self._stmt_source_context(stmt_id),
                    )
                )
                if len(results) >= self.max_items_per_category:
                    return tuple(results)

        return tuple(
            sorted(
                results,
                key=lambda item: (
                    item.pointer_stmt_id,
                    item.entity_id or -1,
                    item.stmt_id,
                ),
            )
        )

    def _field_usage_rows(self, field_name: str) -> tuple[Any, ...]:
        if self._field_usage_rows_by_name is None:
            rows_by_name: dict[str, list[Any]] = defaultdict(list)
            for row in self._all_unit_rows():
                if self._field(row, "operation") not in {
                    "field_read",
                    "field_write",
                }:
                    continue
                name = self._field(row, "field", "field_name")
                if name:
                    rows_by_name[name].append(row)
            self._field_usage_rows_by_name = {
                name: tuple(rows) for name, rows in rows_by_name.items()
            }
        return self._field_usage_rows_by_name.get(field_name, ())

    def _global_usage_rows(
        self,
        pointer: PointerTaskContext,
    ) -> tuple[Any, ...]:
        candidates = self._rows_referencing_token(pointer.name)
        return tuple(
            row
            for row in candidates
            if self._positive_id(getattr(row, "stmt_id", None))
            != pointer.stmt_id
            and self._row_mentions_alias(row, {pointer.name})
        )

    def _parameter_positions(
        self,
        pointers: tuple[PointerTaskContext, ...],
    ) -> dict[int, int]:
        result: dict[int, int] = {}
        for pointer in pointers:
            if pointer.location != "parameter":
                continue
            method_id = self.context.get_method_id(pointer.stmt_id)
            if method_id is None:
                continue
            parameters = self.context.get_method_parameters(method_id)
            for index, parameter in enumerate(parameters):
                if self._positive_id(
                    getattr(parameter, "stmt_id", None)
                ) == pointer.stmt_id:
                    result[pointer.stmt_id] = index
                    break
        return result

    def _pointer_location(self, stmt_id: int) -> str:
        row = self.context.get_stmt(stmt_id)
        operation = self._field(row, "operation")
        if operation == "parameter_decl":
            return "parameter"
        for ancestor in self.context.get_ancestors(stmt_id):
            ancestor_operation = self._field(ancestor, "operation")
            if ancestor_operation == "struct_decl":
                return "struct_member"
            if ancestor_operation == "union_decl":
                return "union_member"
            if ancestor_operation == "method_decl":
                return "local"
        return (
            "local"
            if self.context.get_method_id(stmt_id) is not None
            else "global"
        )

    def _entity_source(self, entity_id: int) -> SourceCodeContext:
        cached = self._entity_source_cache.get(entity_id)
        if cached is not None:
            return cached
        entity = self._entities.get(entity_id)
        if entity is None:
            raise SemanticAgentContextError(
                f"translation entity {entity_id} does not exist"
            )
        raw_source = entity.get("source")
        if not isinstance(raw_source, dict):
            raise SemanticAgentContextError(
                f"translation entity {entity_id} has no source"
            )
        path = Path(self._required_text(raw_source.get("path"), "source path"))
        start_line = self._positive_id(raw_source.get("start_line"))
        end_line = self._positive_id(raw_source.get("end_line"))
        if start_line is None or end_line is None or end_line < start_line:
            raise SemanticAgentContextError(
                f"translation entity {entity_id} has invalid source lines"
            )
        try:
            lines = path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError as exc:
            raise SemanticAgentContextError(
                f"failed to read entity source {path}: {exc}"
            ) from exc
        if start_line > len(lines):
            raise SemanticAgentContextError(
                f"entity {entity_id} starts beyond source file {path}"
            )
        selected = lines[start_line - 1 : min(end_line, len(lines))]
        result = SourceCodeContext(
            path=str(path),
            rel_path=self._text(raw_source.get("rel_path")) or None,
            start_line=start_line,
            end_line=end_line,
            source="\n".join(selected),
        )
        self._entity_source_cache[entity_id] = result
        return result

    def _stmt_source_context(self, stmt_id: int) -> SourceCodeContext:
        row = self.context.get_stmt(stmt_id)
        unit_id = self.context.get_unit_id(stmt_id)
        unit_path = (
            self.context.get_unit_path(unit_id)
            if unit_id is not None
            else None
        )
        start_line = self._positive_id(
            getattr(row, "start_row", None) if row is not None else None
        )
        end_line = self._positive_id(
            getattr(row, "end_row", None) if row is not None else None
        )
        start_col = self._non_negative_int(
            self._field(row, "start_col") if row is not None else None
        )
        end_col = self._non_negative_int(
            self._field(row, "end_col") if row is not None else None
        )
        return SourceCodeContext(
            path=str(unit_path) if unit_path is not None else "",
            rel_path=None,
            start_line=start_line,
            end_line=end_line,
            source=bounded_stmt_source(
                self.context.get_stmt_source(stmt_id),
                start_col=start_col,
                end_col=end_col,
            ),
        )

    def _source_text(self, stmt_id: int) -> str:
        row = self.context.get_stmt(stmt_id)
        return bounded_stmt_source(
            self.context.get_stmt_source(stmt_id),
            start_col=self._non_negative_int(
                self._field(row, "start_col") if row is not None else None
            ),
            end_col=self._non_negative_int(
                self._field(row, "end_col") if row is not None else None
            ),
        )

    def _method_entity_id(self, method_id: int) -> int | None:
        if method_id in self._entities:
            return method_id
        member_entity = self._member_to_entity.get(method_id)
        if member_entity is not None:
            return member_entity
        method_name = self.context.get_method_name(method_id)
        if method_name:
            candidates = self._function_entities_by_name.get(method_name, [])
            if len(candidates) == 1:
                return candidates[0]
        return None

    def _stmt_entity_id(self, stmt_id: int) -> int | None:
        method_id = self.context.get_method_id(stmt_id)
        if method_id is not None:
            return self._method_entity_id(method_id)
        return self._member_to_entity.get(stmt_id)

    def _entity_name(self, entity_id: int | None) -> str | None:
        if entity_id is None:
            return None
        entity = self._entities.get(entity_id)
        if entity is None:
            return None
        return self._text(entity.get("name")) or None

    def _custom_type_names(self, c_type: str) -> set[str]:
        return {
            token
            for token in _TOKEN_PATTERN.findall(c_type)
            if token not in _BUILTIN_TYPE_NAMES
        }

    def _update_aliases(
        self,
        row: Any,
        operation: str,
        aliases: set[str],
    ) -> None:
        target = self._field(row, "target", "name")
        source = self._field(row, "operand", "source", "value")
        if operation in {"assign_stmt", "binary_expression", "type_cast_stmt"}:
            if target and self._mentions_alias(source, aliases):
                aliases.add(target)
        elif operation == "array_read":
            array = self._field(row, "array")
            if target and self._mentions_alias(array, aliases):
                aliases.add(target)

    def _call_name(self, stmt_id: int, row: Any) -> str:
        call_info = self.context.get_call_info(stmt_id)
        return self._field(
            call_info, "callee_name", "name", "callee"
        ) or self._field(row, "name", "callee_name", "callee")

    def _all_unit_rows(self) -> tuple[Any, ...]:
        if self._all_unit_rows_cache is None:
            self._all_unit_rows_cache = tuple(
                row
                for unit_id in self.context.get_all_unit_ids()
                for row in self.context.get_unit_rows(unit_id)
            )
        return self._all_unit_rows_cache

    def _method_ids_for_name(self, method_name: str) -> tuple[int, ...]:
        if not method_name:
            return ()
        if self._method_ids_by_name is None:
            ids_by_name: dict[str, list[int]] = defaultdict(list)
            for method_id in self.context.get_all_method_ids():
                name = self.context.get_method_name(method_id)
                if name:
                    ids_by_name[name].append(method_id)
            self._method_ids_by_name = {
                name: tuple(ids) for name, ids in ids_by_name.items()
            }
        return self._method_ids_by_name.get(method_name, ())

    def _call_rows_for_callee(
        self, callee_name: str
    ) -> tuple[tuple[int, Any], ...]:
        if not callee_name:
            return ()
        if self._call_rows_by_callee is None:
            rows_by_callee: dict[str, list[tuple[int, Any]]] = defaultdict(
                list
            )
            for method_id in self.context.get_all_method_ids():
                for row in self.context.get_method_rows(method_id):
                    if self._field(row, "operation") != "call_stmt":
                        continue
                    stmt_id = self._positive_id(
                        getattr(row, "stmt_id", None)
                    )
                    if stmt_id is None:
                        continue
                    name = self._call_name(stmt_id, row)
                    if name:
                        rows_by_callee[name].append((method_id, row))
            self._call_rows_by_callee = {
                name: tuple(rows) for name, rows in rows_by_callee.items()
            }
        return self._call_rows_by_callee.get(callee_name, ())

    def _rows_referencing_token(self, token: str) -> tuple[Any, ...]:
        if not token:
            return ()
        if self._rows_by_reference_token is None:
            rows_by_token: dict[str, list[Any]] = defaultdict(list)
            for row in self._all_unit_rows():
                stmt_id = self._positive_id(getattr(row, "stmt_id", None))
                if stmt_id is None:
                    continue
                for item in self._row_reference_tokens(row):
                    rows_by_token[item].append(row)
            self._rows_by_reference_token = {
                item: tuple(rows) for item, rows in rows_by_token.items()
            }
        return self._rows_by_reference_token.get(token, ())

    @classmethod
    def _row_reference_tokens(cls, row: Any) -> set[str]:
        tokens: set[str] = set()
        for field_name in (
            "target",
            "name",
            "operand",
            "operand2",
            "source",
            "address",
            "array",
            "receiver_object",
            "object",
            "positional_args",
        ):
            value = getattr(row, field_name, None)
            if value is None:
                continue
            tokens.update(re.findall(r"[A-Za-z_%][A-Za-z0-9_%]*", str(value)))
        return tokens

    @staticmethod
    def _call_arguments(row: Any) -> list[str]:
        raw = getattr(row, "positional_args", None)
        if raw is None:
            return []
        if isinstance(raw, (list, tuple)):
            return [str(item) for item in raw]
        try:
            parsed = ast.literal_eval(str(raw))
        except (SyntaxError, TypeError, ValueError):
            return []
        if not isinstance(parsed, list):
            return []
        return [str(item) for item in parsed]

    @classmethod
    def _row_mentions_alias(cls, row: Any, aliases: set[str]) -> bool:
        return any(
            cls._mentions_alias(getattr(row, field_name, None), aliases)
            for field_name in (
                "target",
                "name",
                "operand",
                "operand2",
                "source",
                "address",
                "array",
                "receiver_object",
                "object",
                "positional_args",
            )
        )

    @staticmethod
    def _mentions_alias(value: Any, aliases: set[str]) -> bool:
        if value is None or not aliases:
            return False
        text = str(value)
        if text in aliases:
            return True
        tokens = set(re.findall(r"[A-Za-z_%][A-Za-z0-9_%]*", text))
        return bool(tokens & aliases)

    @classmethod
    def _argument_mentions_alias(
        cls,
        argument: str,
        aliases: set[str],
    ) -> bool:
        text = argument.strip()
        if len(text) >= 2 and text[0] == text[-1] == '"':
            return False
        return cls._mentions_alias(text, aliases)

    @staticmethod
    def _field(value: Any, *field_names: str) -> str:
        for field_name in field_names:
            if isinstance(value, dict):
                raw = value.get(field_name)
            else:
                raw = (
                    getattr(value, field_name, None)
                    if value is not None
                    else None
                )
            text = SemanticAgentContextProvider._text(raw)
            if text:
                return text
        return ""

    def _read_translation_entities(self) -> dict[int, dict[str, Any]]:
        try:
            value = json.loads(
                self.translation_entities_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise SemanticAgentContextError(
                "failed to read translation entities "
                f"{self.translation_entities_path}: {exc}"
            ) from exc
        if not isinstance(value, dict) or value.get("version") != 1:
            raise SemanticAgentContextError(
                "unsupported translation entities file: "
                f"{self.translation_entities_path}"
            )
        raw_entities = value.get("entities")
        if not isinstance(raw_entities, list):
            raise SemanticAgentContextError(
                "translation entities file has no entities array"
            )
        result: dict[int, dict[str, Any]] = {}
        for raw_entity in raw_entities:
            if not isinstance(raw_entity, dict):
                raise SemanticAgentContextError(
                    "translation entities contains a non-object entry"
                )
            entity_id = self._positive_id(raw_entity.get("id"))
            if entity_id is None or entity_id in result:
                raise SemanticAgentContextError(
                    "translation entities contains an invalid or duplicate ID"
                )
            result[entity_id] = raw_entity
        return result

    @classmethod
    def _entity_member_ids(
        cls, entity: dict[str, Any]
    ) -> tuple[int, ...]:
        raw_ids = entity.get("member_entity_ids")
        if not isinstance(raw_ids, list):
            return ()
        return tuple(
            member_id
            for member_id in (
                cls._positive_id(raw_id) for raw_id in raw_ids
            )
            if member_id is not None
        )

    @staticmethod
    def _positive_id(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result > 0 else None

    @staticmethod
    def _non_negative_int(value: Any) -> int | None:
        if isinstance(value, bool) or value in (None, ""):
            return None
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result >= 0 else None

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        return "" if text == "nan" else text

    @classmethod
    def _required_text(cls, value: Any, description: str) -> str:
        text = cls._text(value)
        if not text:
            raise SemanticAgentContextError(
                f"{description} must be non-empty"
            )
        return text
