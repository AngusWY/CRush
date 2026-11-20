from __future__ import annotations

import ast
import inspect
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from TranslationOrientedAnalysis.analysis_context import AnalysisContext
from TranslationPreprocess.c_macro import load_project_macro_catalog

from .context_provider import bounded_stmt_source


JsonObject = dict[str, Any]
ToolHandler = Callable[[Mapping[str, Any]], JsonObject]

_CALL_OPERATIONS = {"call_stmt"}
_TYPE_OPERATIONS = {"struct_decl", "union_decl", "type_alias_decl"}
_FIELD_OPERATIONS = {"field_read", "field_write"}
_TOKEN_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    description: str
    parameters: JsonObject

    def to_dict(self) -> JsonObject:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    tool: str
    data: JsonObject | None = None
    error: str | None = None

    def to_dict(self) -> JsonObject:
        result: JsonObject = {"ok": self.ok, "tool": self.tool}
        if self.data is not None:
            result["data"] = self.data
        if self.error is not None:
            result["error"] = self.error
        return result


class ToolRegistry:


    def __init__(self) -> None:
        self._definitions: dict[str, ToolDefinition] = {}
        self._handlers: dict[str, ToolHandler] = {}

    def register(
        self,
        definition: ToolDefinition,
        handler: ToolHandler,
    ) -> None:
        if definition.name in self._definitions:
            raise ValueError(f"tool already registered: {definition.name}")
        self._definitions[definition.name] = definition
        self._handlers[definition.name] = handler

    @property
    def definitions(self) -> list[ToolDefinition]:
        return list(self._definitions.values())

    def get_definition(self, name: str) -> ToolDefinition | None:
        return self._definitions.get(name)

    def describe_tools(self) -> list[JsonObject]:
        return [definition.to_dict() for definition in self.definitions]

    async def execute(
        self,
        name: str,
        arguments: Mapping[str, Any] | str | None,
    ) -> ToolResult:
        handler = self._handlers.get(name)
        if handler is None:
            return ToolResult(ok=False, tool=name, error=f"unknown tool: {name}")

        try:
            parsed_arguments = _parse_arguments(arguments)
            output = handler(parsed_arguments)
            if inspect.isawaitable(output):
                output = await output
            return ToolResult(ok=True, tool=name, data=output)
        except (KeyError, TypeError, ValueError) as exc:
            return ToolResult(ok=False, tool=name, error=str(exc))
        except Exception as exc:
            return ToolResult(
                ok=False,
                tool=name,
                error=f"{type(exc).__name__}: {exc}",
            )


class SemanticAnalysisTools:


    def __init__(
        self,
        context: AnalysisContext,
        workspace: str | Path,
    ) -> None:
        self.context = context
        self.workspace = Path(workspace)
        self._entities = self._load_entities()
        self._macro_catalog = load_project_macro_catalog(self.workspace)
        self._macro_definitions_by_name: dict[str, list[JsonObject]] = (
            defaultdict(list)
        )
        for definition in self._macro_catalog.get("definitions", ()):
            if not isinstance(definition, dict):
                continue
            name = definition.get("name")
            if isinstance(name, str) and name:
                self._macro_definitions_by_name[name].append(definition)
        self._macro_invocations = tuple(
            invocation
            for invocation in self._macro_catalog.get("invocations", ())
            if isinstance(invocation, dict)
        )
        self._entity_by_id = {
            entity_id: entity
            for entity in self._entities
            if (entity_id := _as_optional_int(entity.get("id"))) is not None
        }
        self._member_to_entity = {
            member_id: entity_id
            for entity_id, entity in self._entity_by_id.items()
            for member_id in _integer_list(entity.get("member_entity_ids"))
        }
        self._method_entity_cache: dict[int, int | None] = {}
        self._project_source_dirs: tuple[Path, ...] = (
            self._collect_project_dirs()
        )

        self._source_files_by_name: dict[str, list[Path]] = defaultdict(list)
        for src_dir in self._project_source_dirs:
            for file_path in src_dir.rglob("*"):
                if (
                    file_path.is_file()
                    and file_path.suffix in {".c", ".h"}
                ):
                    self._source_files_by_name[file_path.name].append(
                        file_path
                    )

    def create_registry(self) -> ToolRegistry:
        registry = ToolRegistry()
        for definition, handler in (
            (self._function_source_definition(), self.get_function_source),
            (self._pointer_usages_definition(), self.get_pointer_usages),
            (self._callers_definition(), self.get_callers),
            (
                self._callee_parameter_usage_definition(),
                self.get_callee_parameter_usage,
            ),
            (self._type_definition_definition(), self.get_type_definition),
            (self._field_usages_definition(), self.get_field_usages),
            (self._read_source_file_definition(), self.read_source_file),
            (
                self._find_function_source_definition(),
                self.find_function_source,
            ),
            (
                self._search_in_project_definition(),
                self.search_in_project,
            ),
        ):
            registry.register(definition, handler)
        return registry

    def get_function_source(self, arguments: Mapping[str, Any]) -> JsonObject:
        entity_id = _optional_int_argument(arguments, "entity_id")
        method_id = _optional_int_argument(arguments, "method_id")
        if entity_id is None and method_id is None:
            raise ValueError("entity_id or method_id is required")

        if entity_id is None:
            entity_id = self._method_entity_id(_require_value(method_id, "method_id"))
        if method_id is None and entity_id is not None:
            method_id = self._entity_method_id(entity_id)

        source = self._entity_source(entity_id) if entity_id is not None else None
        if source is None and method_id is not None:
            source = self._stmt_source(method_id)
        if source is None:
            raise ValueError("function source could not be resolved")

        return {
            "entity_id": entity_id,
            "method_id": method_id,
            "function_name": self._method_name(method_id)
            if method_id is not None
            else self._entity_name(entity_id),
            "source": source,
            "analysis_complete": source.get("text") is not None,
        }

    def get_pointer_usages(self, arguments: Mapping[str, Any]) -> JsonObject:
        stmt_id = _required_int_argument(arguments, "stmt_id")
        scope = _string_argument(arguments, "scope", default="entity")
        if scope not in {"entity", "project"}:
            raise ValueError("scope must be 'entity' or 'project'")
        limit = _bounded_int_argument(arguments, "limit", 50, 1, 200)
        return self._pointer_usages(stmt_id, scope=scope, limit=limit)

    def get_callers(self, arguments: Mapping[str, Any]) -> JsonObject:
        method_id = _optional_int_argument(arguments, "method_id")
        entity_id = _optional_int_argument(arguments, "entity_id")
        limit = _bounded_int_argument(arguments, "limit", 50, 1, 200)
        if method_id is None and entity_id is None:
            raise ValueError("method_id or entity_id is required")
        if method_id is None:
            method_id = self._entity_method_id(
                _require_value(entity_id, "entity_id")
            )
        if method_id is None:
            raise ValueError("target method could not be resolved")

        callee_name = self._method_name(method_id)
        if not callee_name:
            raise ValueError(f"method name could not be resolved for {method_id}")

        callers: list[JsonObject] = []
        seen_stmt_ids: set[int] = set()
        for caller_method_id in self.context.get_all_method_ids():
            for row in self.context.get_method_rows(caller_method_id):
                if self._operation(row) not in _CALL_OPERATIONS:
                    continue
                if self._call_name(row) != callee_name:
                    continue
                stmt_id = self._row_stmt_id(row)
                if stmt_id is None or stmt_id in seen_stmt_ids:
                    continue
                seen_stmt_ids.add(stmt_id)
                callers.append(
                    {
                        "call_stmt_id": stmt_id,
                        "caller_method_id": caller_method_id,
                        "caller_entity_id": self._method_entity_id(caller_method_id),
                        "caller_name": self._method_name(caller_method_id),
                        "callee_name": callee_name,
                        "arguments": self._call_arguments(row),
                        "source": self._stmt_source(stmt_id),
                    }
                )
                if len(callers) >= limit:
                    break
            if len(callers) >= limit:
                break

        return {
            "method_id": method_id,
            "entity_id": entity_id or self._method_entity_id(method_id),
            "function_name": callee_name,
            "callers": callers,
            "analysis_complete": len(callers) < limit,
        }

    def get_callee_parameter_usage(
        self,
        arguments: Mapping[str, Any],
    ) -> JsonObject:
        call_stmt_id = _required_int_argument(arguments, "call_stmt_id")
        argument_index = _required_int_argument(arguments, "argument_index")
        if argument_index < 0:
            raise ValueError("argument_index must be non-negative")
        limit = _bounded_int_argument(arguments, "limit", 50, 1, 200)

        call_row = self.context.get_stmt(call_stmt_id)
        if call_row is None or self._operation(call_row) not in _CALL_OPERATIONS:
            raise ValueError(f"statement {call_stmt_id} is not a call")
        arguments_list = self._call_arguments(call_row)
        if argument_index >= len(arguments_list):
            raise ValueError(
                f"argument_index {argument_index} is outside the call's "
                f"{len(arguments_list)} arguments"
            )

        callee_name = self._call_name(call_row)
        callee_method_id = self._resolve_method_by_name(callee_name)
        if callee_method_id is None:
            return {
                "call_stmt_id": call_stmt_id,
                "argument_index": argument_index,
                "argument": arguments_list[argument_index],
                "callee_name": callee_name,
                "callee_method_id": None,
                "parameter": None,
                "effects": self._known_external_call_effects(
                    callee_name,
                    argument_index,
                ),
                "usages": [],
                "analysis_complete": False,
                "note": "callee body is unavailable",
            }

        parameters = self.context.get_method_parameters(callee_method_id)
        if argument_index >= len(parameters):
            raise ValueError(
                f"callee {callee_name} has no parameter at index {argument_index}"
            )
        parameter = parameters[argument_index]
        parameter_stmt_id = self._row_stmt_id(parameter)
        if parameter_stmt_id is None:
            raise ValueError("callee parameter has no statement id")

        usage_result = self._pointer_usages(
            parameter_stmt_id,
            scope="entity",
            limit=limit,
        )
        usages = usage_result["usages"]
        effects = sorted(
            {
                effect
                for usage in usages
                if (effect := self._usage_effect(usage.get("kind"))) is not None
            }
        )
        return {
            "call_stmt_id": call_stmt_id,
            "argument_index": argument_index,
            "argument": arguments_list[argument_index],
            "callee_name": callee_name,
            "callee_method_id": callee_method_id,
            "callee_entity_id": self._method_entity_id(callee_method_id),
            "parameter": {
                "stmt_id": parameter_stmt_id,
                "name": self._row_value(parameter, "name"),
                "c_type": self._row_value(parameter, "data_type"),
            },
            "effects": effects,
            "usages": usages,
            "analysis_complete": usage_result["analysis_complete"],
        }

    def get_type_definition(self, arguments: Mapping[str, Any]) -> JsonObject:
        type_name = _required_string_argument(arguments, "type_name")
        definitions = self._find_type_definitions(type_name)
        if not definitions:
            definitions = self._find_macro_type_instantiations(type_name)
        if not definitions:
            raise ValueError(f"type definition not found: {type_name}")
        return {
            "type_name": type_name,
            "definitions": definitions,
            "symbol_kind": (
                "macro_instantiation"
                if definitions[0].get("kind") == "macro_instantiation"
                else "type"
            ),
            "analysis_complete": True,
        }

    def get_field_usages(self, arguments: Mapping[str, Any]) -> JsonObject:
        type_name = _required_string_argument(arguments, "type_name")
        field_name = _required_string_argument(arguments, "field_name")
        limit = _bounded_int_argument(arguments, "limit", 50, 1, 200)
        definitions = self._find_type_definitions(type_name)
        if not definitions:
            raise ValueError(f"type definition not found: {type_name}")
        if not any(
            self._definition_mentions_field(definition, field_name)
            for definition in definitions
        ):
            raise ValueError(f"field {field_name!r} not found in type {type_name!r}")

        usages: list[JsonObject] = []
        for method_id in self.context.get_all_method_ids():
            for row in self.context.get_method_rows(method_id):
                operation = self._operation(row)
                if operation not in _FIELD_OPERATIONS:
                    continue
                if self._row_value(row, "field") != field_name:
                    continue
                stmt_id = self._row_stmt_id(row)
                if stmt_id is None:
                    continue
                usages.append(
                    {
                        "stmt_id": stmt_id,
                        "kind": operation,
                        "receiver": self._row_value(row, "receiver_object"),
                        "method_id": method_id,
                        "entity_id": self._method_entity_id(method_id),
                        "function_name": self._method_name(method_id),
                        "source": self._stmt_source(stmt_id),
                    }
                )
                if len(usages) >= limit:
                    break
            if len(usages) >= limit:
                break

        return {
            "type_name": type_name,
            "field_name": field_name,
            "type_definitions": definitions,
            "usages": usages,
            "analysis_complete": False,
            "note": (
                "GIR field accesses do not always retain receiver type; results "
                "are exact by field name but may include same-named fields."
            ),
        }



    def read_source_file(
        self,
        arguments: Mapping[str, Any],
    ) -> JsonObject:
        path_str = _required_string_argument(arguments, "path")
        start_line = _bounded_int_argument(arguments, "start_line", 1, 1, 999999)
        end_line = _bounded_int_argument(
            arguments, "end_line", start_line + 199, start_line, 999999
        )

        resolved = self._resolve_source_path(path_str)
        if resolved is None:
            raise ValueError(
                f"source file not found: {path_str}. "
                f"Provide an absolute path or a path relative to the project."
            )

        try:
            lines = resolved.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError as exc:
            raise ValueError(f"failed to read {resolved}: {exc}") from exc

        if start_line > len(lines):
            raise ValueError(
                f"start_line {start_line} exceeds file length {len(lines)}"
            )

        end_line = min(end_line, len(lines))
        selected = lines[start_line - 1 : end_line]

        return {
            "path": str(resolved),
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": len(lines),
            "source": "\n".join(selected),
        }

    def find_function_source(
        self,
        arguments: Mapping[str, Any],
    ) -> JsonObject:
        name = _required_string_argument(arguments, "name")


        for entity_id, entity in self._entity_by_id.items():
            entity_name = entity.get("name")
            if entity_name != name:
                continue
            kind = str(entity.get("kind", "")).lower()
            if "function" not in kind:
                continue
            source = self._entity_source(entity_id)
            if source is not None and source.get("text"):
                return {
                    "name": name,
                    "entity_id": entity_id,
                    "symbol_kind": "function",
                    "source": source,
                    "analysis_complete": True,
                }


        macro_definitions = [
            dict(definition)
            for definition in self._macro_definitions_by_name.get(name, ())
            if definition.get("function_like") is True
        ]
        if macro_definitions:
            return {
                "name": name,
                "entity_id": None,
                "symbol_kind": "function_like_macro",
                "definitions": macro_definitions,
                "analysis_complete": True,
                "note": (
                    "This symbol is a C function-like macro, not a callable "
                    "function. Analyze its replacement and transitive macro "
                    "dependencies."
                ),
            }


        candidates = self._grep_function_definition(name)
        if not candidates:
            raise ValueError(
                f"function {name!r} not found in translation entities "
                f"or project source files"
            )

        best = candidates[0]
        try:
            text = best.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError as exc:
            raise ValueError(f"failed to read {best}: {exc}") from exc

        return {
            "name": name,
            "entity_id": None,
            "symbol_kind": "function",
            "source": {
                "path": str(best),
                "rel_path": None,
                "start_line": None,
                "end_line": None,
                "text": text.strip(),
            },
            "analysis_complete": False,
            "note": "Found by grepping project source. Entity ID unavailable.",
        }

    def search_in_project(
        self,
        arguments: Mapping[str, Any],
    ) -> JsonObject:
        pattern = _required_string_argument(arguments, "pattern")
        limit = _bounded_int_argument(arguments, "limit", 20, 1, 100)

        results: list[JsonObject] = []
        compiled: re.Pattern[str]
        try:
            compiled = re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"invalid regex pattern: {exc}") from exc

        for src_dir in self._project_source_dirs:
            for file_path in src_dir.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.suffix not in {".c", ".h"}:
                    continue
                try:
                    lines = file_path.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                except OSError:
                    continue
                for line_no, line_text in enumerate(lines, start=1):
                    if compiled.search(line_text):
                        results.append(
                            {
                                "path": str(file_path),
                                "line": line_no,
                                "text": line_text.strip(),
                            }
                        )
                        if len(results) >= limit:
                            break
                if len(results) >= limit:
                    break
            if len(results) >= limit:
                break

        return {
            "pattern": pattern,
            "matches": results,
            "analysis_complete": len(results) < limit,
        }



    def _pointer_usages(
        self,
        stmt_id: int,
        *,
        scope: str,
        limit: int,
    ) -> JsonObject:
        declaration = self.context.get_stmt(stmt_id)
        if declaration is None:
            raise ValueError(f"pointer declaration not found: {stmt_id}")
        pointer_name = self._row_value(declaration, "name")
        if not isinstance(pointer_name, str) or not pointer_name:
            raise ValueError(f"statement {stmt_id} has no pointer name")

        method_id = self.context.get_method_id(stmt_id)
        entity_id = self._method_entity_id(method_id) if method_id is not None else None
        location = self._pointer_location(declaration, method_id)
        rows = self._usage_rows(
            pointer_name,
            method_id=method_id,
            location=location,
            scope=scope,
        )

        aliases = {pointer_name}
        usages: list[JsonObject] = []
        for row_method_id, row in rows:
            current_stmt_id = self._row_stmt_id(row)
            if current_stmt_id is None or current_stmt_id == stmt_id:
                continue
            related_before = self._row_mentions_alias(row, aliases)
            events = self._classify_pointer_usage(row, aliases)
            self._update_aliases(row, aliases)
            if not related_before and not events:
                continue
            if not events:
                events = [("reference", {})]
            for kind, details in events:
                usages.append(
                    {
                        "stmt_id": current_stmt_id,
                        "kind": kind,
                        "method_id": row_method_id,
                        "entity_id": self._method_entity_id(row_method_id),
                        "function_name": self._method_name(row_method_id),
                        "source": self._stmt_source(current_stmt_id),
                        "details": details,
                    }
                )
                if len(usages) >= limit:
                    break
            if len(usages) >= limit:
                break

        return {
            "pointer": {
                "stmt_id": stmt_id,
                "entity_id": entity_id,
                "method_id": method_id,
                "name": pointer_name,
                "c_type": self._row_value(declaration, "data_type"),
                "location": location,
                "source": self._stmt_source(stmt_id),
            },
            "scope": scope,
            "aliases": sorted(aliases),
            "usages": usages,
            "analysis_complete": len(usages) < limit,
        }

    def _usage_rows(
        self,
        pointer_name: str,
        *,
        method_id: int | None,
        location: str,
        scope: str,
    ) -> list[tuple[int, Any]]:
        method_ids: tuple[int, ...]
        if scope == "entity" and method_id is not None:
            method_ids = (method_id,)
        elif location in {"parameter", "local"} and method_id is not None:
            method_ids = (method_id,)
        else:
            method_ids = self.context.get_all_method_ids()
        return [
            (candidate_method_id, row)
            for candidate_method_id in method_ids
            for row in self.context.get_method_rows(candidate_method_id)
            if self._row_mentions_name(row, pointer_name)
        ]

    def _classify_pointer_usage(
        self,
        row: Any,
        aliases: set[str],
    ) -> list[tuple[str, JsonObject]]:
        operation = self._operation(row)
        events: list[tuple[str, JsonObject]] = []

        if operation == "binary_expression":
            operator = self._row_value(row, "operator")
            operands = [
                self._row_value(row, "operand"),
                self._row_value(row, "operand2"),
            ]
            if operator in {"==", "!="} and any(
                self._is_null_value(value) for value in operands
            ):
                events.append(("null_check", {"operator": operator}))
            elif operator in {"+", "-", "+=", "-="}:
                events.append(("pointer_arithmetic", {"operator": operator}))
        elif operation == "unary_expression":
            if self._row_value(row, "operator") == "!":
                events.append(("null_check", {"operator": "!"}))
            elif self._row_value(row, "operator") in {"*", "dereference"}:
                events.append(("pointee_read", {}))
        elif operation in {"array_read", "mem_read"}:
            events.append(("pointee_read", {"operation": operation}))
        elif operation in {"array_write", "mem_write"}:
            events.append(("pointee_write", {"operation": operation}))
        elif operation == "field_read":
            events.append(
                ("field_read", {"field": self._row_value(row, "field")})
            )
        elif operation == "field_write":
            events.append(
                ("field_write", {"field": self._row_value(row, "field")})
            )
        elif operation == "return_stmt":
            events.append(("returned", {}))
        elif operation == "assign_stmt":
            target = self._row_value(row, "target")
            operand = self._row_value(row, "operand")
            if self._value_mentions_alias(operand, aliases):
                events.append(("alias_created", {"alias": target}))
            elif self._value_mentions_alias(target, aliases):
                events.append(("reassigned", {}))
        elif operation in _CALL_OPERATIONS:
            callee_name = self._call_name(row)
            for index, argument in enumerate(self._call_arguments(row)):
                if not self._value_mentions_alias(argument, aliases):
                    continue
                kind = (
                    "freed"
                    if callee_name in {"free", "cfree"} and index == 0
                    else "call_argument"
                )
                events.append(
                    (
                        kind,
                        {
                            "callee_name": callee_name,
                            "argument_index": index,
                        },
                    )
                )
        return events

    def _update_aliases(self, row: Any, aliases: set[str]) -> None:
        operation = self._operation(row)
        if operation not in {
            "assign_stmt",
            "binary_expression",
            "type_cast_stmt",
            "variable_decl",
        }:
            return
        target = self._row_value(row, "target") or self._row_value(row, "name")
        operand = (
            self._row_value(row, "operand")
            or self._row_value(row, "value")
            or self._row_value(row, "initializer")
        )
        if isinstance(target, str) and self._value_mentions_alias(operand, aliases):
            aliases.add(target)

    def _row_mentions_alias(self, row: Any, aliases: set[str]) -> bool:
        return any(
            self._value_mentions_alias(value, aliases)
            for _, value in self._row_items(row)
        )

    def _row_mentions_name(self, row: Any, name: str) -> bool:
        return any(
            self._value_mentions_name(value, name)
            for _, value in self._row_items(row)
        )

    def _value_mentions_alias(self, value: Any, aliases: set[str]) -> bool:
        return any(self._value_mentions_name(value, alias) for alias in aliases)

    def _value_mentions_name(self, value: Any, name: str) -> bool:
        if isinstance(value, str):
            return name in _TOKEN_PATTERN.findall(value)
        if isinstance(value, Mapping):
            return any(self._value_mentions_name(item, name) for item in value.values())
        if isinstance(value, (list, tuple, set)):
            return any(self._value_mentions_name(item, name) for item in value)
        return False

    def _pointer_location(self, row: Any, method_id: int | None) -> str:
        operation = self._operation(row)
        if operation == "parameter_decl":
            return "parameter"
        if method_id is not None:
            return "local"
        stmt_id = self._row_stmt_id(row)
        if stmt_id is not None:
            for ancestor in self.context.get_ancestors(stmt_id):
                if self._operation(ancestor) == "struct_decl":
                    return "struct_member"
                if self._operation(ancestor) == "union_decl":
                    return "union_member"
        return "global"

    def _find_type_definitions(self, type_name: str) -> list[JsonObject]:
        definitions: list[JsonObject] = []
        seen: set[tuple[int | None, int | None]] = set()

        for entity_id, entity in self._entity_by_id.items():
            entity_name = entity.get("name")
            entity_kind = str(entity.get("kind", "")).lower()
            if entity_name != type_name:
                continue
            if not any(kind in entity_kind for kind in ("struct", "union", "type")):
                continue
            source = self._entity_source(entity_id)
            definitions.append(
                {
                    "entity_id": entity_id,
                    "stmt_id": None,
                    "name": entity_name,
                    "kind": entity.get("kind"),
                    "source": source,
                }
            )
            seen.add((entity_id, None))

        for unit_id in self.context.get_all_unit_ids():
            for row in self.context.get_unit_rows(unit_id):
                if self._operation(row) not in _TYPE_OPERATIONS:
                    continue
                row_name = self._row_value(row, "name")
                if row_name != type_name:
                    continue
                stmt_id = self._row_stmt_id(row)
                key = (None, stmt_id)
                if key in seen:
                    continue
                definitions.append(
                    {
                        "entity_id": None,
                        "stmt_id": stmt_id,
                        "name": row_name,
                        "kind": self._operation(row),
                        "source": self._stmt_source(stmt_id)
                        if stmt_id is not None
                        else None,
                    }
                )
                seen.add(key)
        return definitions

    def _find_macro_type_instantiations(
        self,
        type_name: str,
    ) -> list[JsonObject]:
        target = self._normalized_macro_type_name(type_name)
        if not target:
            return []
        definitions: list[JsonObject] = []
        for invocation in self._macro_invocations:
            macro_name = invocation.get("name")
            raw_arguments = invocation.get("arguments")
            if not isinstance(macro_name, str) or not isinstance(
                raw_arguments, list
            ):
                continue
            arguments = [str(argument) for argument in raw_arguments]
            candidates = {
                self._normalized_macro_type_name(macro_name + argument)
                for argument in arguments
            }
            candidates.add(
                self._normalized_macro_type_name(
                    macro_name + "".join(arguments)
                )
            )
            source = self._macro_invocation_source(invocation)
            if source:
                candidates.update(
                    self._normalized_macro_type_name(token)
                    for token in _TOKEN_PATTERN.findall(source["text"])
                )
            if target not in candidates:
                continue
            macro_definitions = [
                dict(definition)
                for definition in self._macro_definitions_by_name.get(
                    macro_name, ()
                )
            ]
            definitions.append(
                {
                    "entity_id": None,
                    "stmt_id": None,
                    "name": type_name,
                    "kind": "macro_instantiation",
                    "macro_name": macro_name,
                    "arguments": arguments,
                    "source": source,
                    "macro_definitions": macro_definitions,
                }
            )
        return definitions

    @staticmethod
    def _normalized_macro_type_name(value: str) -> str:
        return re.sub(r"[^A-Za-z0-9]", "", value).lower()

    @staticmethod
    def _macro_invocation_source(
        invocation: Mapping[str, Any],
    ) -> JsonObject | None:
        path_value = invocation.get("path")
        start_line = _as_optional_int(invocation.get("start_line"))
        end_line = _as_optional_int(invocation.get("end_line"))
        if (
            not isinstance(path_value, str)
            or start_line is None
            or end_line is None
            or end_line < start_line
        ):
            return None
        path = Path(path_value)
        try:
            lines = path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        except OSError:
            return None
        return {
            "path": str(path),
            "rel_path": invocation.get("rel_path"),
            "start_line": start_line,
            "end_line": end_line,
            "text": "\n".join(lines[start_line - 1 : end_line]).strip(),
        }

    def _definition_mentions_field(
        self,
        definition: Mapping[str, Any],
        field_name: str,
    ) -> bool:
        source = definition.get("source")
        if isinstance(source, Mapping):
            text = source.get("text")
            if isinstance(text, str) and field_name in _TOKEN_PATTERN.findall(text):
                return True
        stmt_id = _as_optional_int(definition.get("stmt_id"))
        if stmt_id is None:
            return False
        return any(
            self._row_value(child, "name") == field_name
            for child in self.context.get_children(stmt_id)
        )

    def _method_entity_id(self, method_id: int | None) -> int | None:
        if method_id is None:
            return None
        if method_id in self._method_entity_cache:
            return self._method_entity_cache[method_id]
        if method_id in self._entity_by_id:
            self._method_entity_cache[method_id] = method_id
            return method_id
        member_entity_id = self._member_to_entity.get(method_id)
        if member_entity_id is not None:
            self._method_entity_cache[method_id] = member_entity_id
            return member_entity_id
        method_name = self._method_name(method_id)
        candidates = [
            entity_id
            for entity_id, entity in self._entity_by_id.items()
            if entity.get("name") == method_name
            and "function" in str(entity.get("kind", "")).lower()
        ]
        result = candidates[0] if len(candidates) == 1 else None
        self._method_entity_cache[method_id] = result
        return result

    def _entity_method_id(self, entity_id: int) -> int | None:
        entity = self._entity_by_id.get(entity_id)
        if entity is None:
            return None
        method_members = [
            member_id
            for member_id in _integer_list(entity.get("member_entity_ids"))
            if member_id in self.context.get_all_method_ids()
        ]
        if len(method_members) == 1:
            return method_members[0]
        if entity_id in self.context.get_all_method_ids():
            return entity_id
        entity_name = entity.get("name")
        return self._resolve_method_by_name(entity_name)

    def _resolve_method_by_name(self, name: Any) -> int | None:
        if not isinstance(name, str) or not name:
            return None
        matches = [
            method_id
            for method_id in self.context.get_all_method_ids()
            if self._method_name(method_id) == name
        ]
        return matches[0] if len(matches) == 1 else None

    def _method_name(self, method_id: int | None) -> str | None:
        if method_id is None:
            return None
        value = self.context.get_method_name(method_id)
        return value if isinstance(value, str) else None

    def _entity_name(self, entity_id: int | None) -> str | None:
        if entity_id is None:
            return None
        entity = self._entity_by_id.get(entity_id)
        value = entity.get("name") if entity else None
        return value if isinstance(value, str) else None

    def _entity_source(self, entity_id: int | None) -> JsonObject | None:
        if entity_id is None:
            return None
        entity = self._entity_by_id.get(entity_id)
        if entity is None:
            return None
        raw_source = entity.get("source")
        if not isinstance(raw_source, Mapping):
            return None
        path_value = raw_source.get("path")
        start_line = _as_optional_int(raw_source.get("start_line"))
        end_line = _as_optional_int(raw_source.get("end_line"))
        if (
            not isinstance(path_value, str)
            or start_line is None
            or end_line is None
            or end_line < start_line
        ):
            return None
        path = Path(path_value)
        try:
            lines = path.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
        except OSError:
            return None
        text = "\n".join(lines[start_line - 1 : min(end_line, len(lines))])
        return {
            "path": str(path),
            "rel_path": raw_source.get("rel_path"),
            "start_line": start_line,
            "end_line": end_line,
            "text": text,
        }

    def _stmt_source(self, stmt_id: int) -> JsonObject:
        source = self.context.get_stmt_source(stmt_id)
        row = self.context.get_stmt(stmt_id)
        unit_id = self.context.get_unit_id(stmt_id)
        unit_path = self.context.get_unit_path(unit_id) if unit_id else None
        return {
            "path": str(unit_path) if unit_path is not None else None,
            "start_line": self._row_value(row, "start_row"),
            "end_line": self._row_value(row, "end_row"),
            "text": bounded_stmt_source(
                source,
                start_col=_as_optional_int(
                    self._row_value(row, "start_col")
                ),
                end_col=_as_optional_int(
                    self._row_value(row, "end_col")
                ),
            ),
        }

    def _load_entities(self) -> list[JsonObject]:
        path = self.workspace / "translation-entities.json"
        if not path.is_file():
            return []
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            entities = payload.get("entities", [])
            if isinstance(entities, list):
                return [item for item in entities if isinstance(item, dict)]
        return []

    def _collect_project_dirs(self) -> tuple[Path, ...]:

        dirs: set[Path] = set()
        for entity in self._entities:
            raw_source = entity.get("source")
            if not isinstance(raw_source, Mapping):
                continue
            path_value = raw_source.get("path")
            if not isinstance(path_value, str):
                continue
            source_path = Path(path_value)
            if source_path.is_file():
                dirs.add(source_path.parent)
        project_root = self._macro_catalog.get("project_root")
        if isinstance(project_root, str) and Path(project_root).is_dir():
            dirs.add(Path(project_root))
        if not dirs:

            origin_dir = self.workspace / "preprocessed_origin"
            if origin_dir.is_dir():
                for json_file in origin_dir.glob("*.json"):
                    try:
                        data = json.loads(
                            json_file.read_text(encoding="utf-8")
                        )
                    except (OSError, json.JSONDecodeError):
                        continue
                    if isinstance(data, dict):
                        path_value = data.get("original_path")
                        if isinstance(path_value, str):
                            source_path = Path(path_value)
                            if source_path.is_file():
                                dirs.add(source_path.parent)
        return tuple(sorted(dirs))

    def _resolve_source_path(self, path_str: str) -> Path | None:

        candidate = Path(path_str)
        if candidate.is_file():
            return candidate.resolve()


        for src_dir in self._project_source_dirs:
            resolved = (src_dir / path_str).resolve()
            if resolved.is_file():
                return resolved


        basename = candidate.name
        if basename in self._source_files_by_name:
            return self._source_files_by_name[basename][0]

        return None

    def _grep_function_definition(
        self, name: str
    ) -> list[Path]:

        results: list[Path] = []

        pattern = re.compile(
            r"^\s*[\w\s*]+\s+" + re.escape(name) + r"\s*\([^)]*\)\s*\{?"
        )
        for src_dir in self._project_source_dirs:
            if not src_dir.is_dir():
                continue
            for file_path in src_dir.rglob("*"):
                if not file_path.is_file():
                    continue
                if file_path.suffix not in {".c", ".h"}:
                    continue
                try:
                    text = file_path.read_text(
                        encoding="utf-8", errors="replace"
                    )
                except OSError:
                    continue
                if pattern.search(text):
                    results.append(file_path)
                    if len(results) >= 3:
                        return results
        return results

    def _call_name(self, row: Any) -> str | None:
        for key in ("name", "callee", "function", "method"):
            value = self._row_value(row, key)
            if isinstance(value, str) and value:
                return value
        stmt_id = self._row_stmt_id(row)
        if stmt_id is not None:
            call_info = self.context.get_call_info(stmt_id)
            if isinstance(call_info, Mapping):
                value = call_info.get("callee_name")
                if isinstance(value, str):
                    return value
        return None

    def _call_arguments(self, row: Any) -> list[Any]:
        for key in ("positional_args", "arguments", "args"):
            value = self._row_value(row, key)
            parsed = _parse_list_value(value)
            if parsed is not None:
                return parsed
        return []

    def _known_external_call_effects(
        self,
        callee_name: str | None,
        argument_index: int,
    ) -> list[str]:
        if argument_index != 0 or callee_name is None:
            return []
        if callee_name in {"free", "cfree"}:
            return ["freed"]
        if callee_name in {"strlen", "strcmp", "strchr", "memcmp"}:
            return ["pointee_read"]
        if callee_name in {"memcpy", "memmove", "memset", "strcpy", "strncpy"}:
            return ["pointee_write"]
        return []

    def _usage_effect(self, kind: Any) -> str | None:
        return {
            "pointee_read": "pointee_read",
            "field_read": "pointee_read",
            "pointee_write": "pointee_write",
            "field_write": "pointee_write",
            "freed": "freed",
            "returned": "returned",
            "alias_created": "aliased",
            "call_argument": "passed_to_callee",
            "pointer_arithmetic": "pointer_arithmetic",
            "null_check": "null_checked",
        }.get(kind)

    @staticmethod
    def _operation(row: Any) -> str | None:
        value = SemanticAnalysisTools._row_value(row, "operation")
        return value if isinstance(value, str) else None

    @staticmethod
    def _row_stmt_id(row: Any) -> int | None:
        for key in ("stmt_id", "id"):
            value = SemanticAnalysisTools._row_value(row, key)
            parsed = _as_optional_int(value)
            if parsed is not None:
                return parsed
        return None

    @staticmethod
    def _row_value(row: Any, key: str) -> Any:
        if isinstance(row, Mapping):
            return row.get(key)
        return getattr(row, key, None)

    @staticmethod
    def _row_items(row: Any) -> list[tuple[str, Any]]:
        if isinstance(row, Mapping):
            return list(row.items())
        as_dict = getattr(row, "_asdict", None)
        if callable(as_dict):
            return list(as_dict().items())
        schema = getattr(row, "_schema", None)
        if isinstance(schema, Mapping):
            return [(name, getattr(row, name, None)) for name in schema]
        if hasattr(row, "__dict__"):
            values = list(vars(row).items())
            if values:
                return values
        field_names = (
            "target",
            "name",
            "operand",
            "operand2",
            "source",
            "value",
            "address",
            "array",
            "receiver_object",
            "object",
            "field",
            "positional_args",
        )
        return [(name, getattr(row, name, None)) for name in field_names]

    @staticmethod
    def _is_null_value(value: Any) -> bool:
        return value is None or value in {"NULL", "nullptr", "0", 0}

    @staticmethod
    def _function_source_definition() -> ToolDefinition:
        return ToolDefinition(
            name="get_function_source",
            description="Get the complete source of one function entity.",
            parameters={
                "type": "object",
                "properties": {
                    "entity_id": {"type": "integer"},
                    "method_id": {"type": "integer"},
                },
                "additionalProperties": False,
            },
        )

    @staticmethod
    def _pointer_usages_definition() -> ToolDefinition:
        return ToolDefinition(
            name="get_pointer_usages",
            description="Find and classify discovered uses of a pointer declaration.",
            parameters={
                "type": "object",
                "properties": {
                    "stmt_id": {"type": "integer"},
                    "scope": {"type": "string", "enum": ["entity", "project"]},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "required": ["stmt_id"],
                "additionalProperties": False,
            },
        )

    @staticmethod
    def _callers_definition() -> ToolDefinition:
        return ToolDefinition(
            name="get_callers",
            description="Find direct call sites for a function.",
            parameters={
                "type": "object",
                "properties": {
                    "method_id": {"type": "integer"},
                    "entity_id": {"type": "integer"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "additionalProperties": False,
            },
        )

    @staticmethod
    def _callee_parameter_usage_definition() -> ToolDefinition:
        return ToolDefinition(
            name="get_callee_parameter_usage",
            description=(
                "Inspect how the callee uses the parameter receiving one call "
                "argument."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "call_stmt_id": {"type": "integer"},
                    "argument_index": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "required": ["call_stmt_id", "argument_index"],
                "additionalProperties": False,
            },
        )

    @staticmethod
    def _type_definition_definition() -> ToolDefinition:
        return ToolDefinition(
            name="get_type_definition",
            description="Get a directly related struct, union, or typedef definition.",
            parameters={
                "type": "object",
                "properties": {"type_name": {"type": "string"}},
                "required": ["type_name"],
                "additionalProperties": False,
            },
        )

    @staticmethod
    def _field_usages_definition() -> ToolDefinition:
        return ToolDefinition(
            name="get_field_usages",
            description="Find discovered project-wide reads and writes of a field.",
            parameters={
                "type": "object",
                "properties": {
                    "type_name": {"type": "string"},
                    "field_name": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                },
                "required": ["type_name", "field_name"],
                "additionalProperties": False,
            },
        )

    @staticmethod
    def _read_source_file_definition() -> ToolDefinition:
        return ToolDefinition(
            name="read_source_file",
            description=(
                "Read a range of lines from a C source file.  Use this to "
                "inspect caller or callee source code that is not covered by "
                "the prepared context."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or project-relative path to a .c or .h file.",
                    },
                    "start_line": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "First line to read (1-based).",
                    },
                    "end_line": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "Last line to read (inclusive, max start_line+199).",
                    },
                },
                "required": ["path", "start_line", "end_line"],
                "additionalProperties": False,
            },
        )

    @staticmethod
    def _find_function_source_definition() -> ToolDefinition:
        return ToolDefinition(
            name="find_function_source",
            description=(
                "Find and return the complete source code of a function by "
                "name.  Tries translation entities first, then greps the "
                "project source tree."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Exact function name to search for.",
                    },
                },
                "required": ["name"],
                "additionalProperties": False,
            },
        )

    @staticmethod
    def _search_in_project_definition() -> ToolDefinition:
        return ToolDefinition(
            name="search_in_project",
            description=(
                "Search all .c and .h files in the project for lines "
                "matching a regex pattern.  Use this to find usages of a "
                "symbol, function calls, or patterns that Lian may have "
                "missed."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex pattern to search for.",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                        "description": "Maximum number of matches (default 20).",
                    },
                },
                "required": ["pattern"],
                "additionalProperties": False,
            },
        )


def build_tool_registry(
    context: AnalysisContext,
    workspace: str | Path,
) -> ToolRegistry:
    return SemanticAnalysisTools(context, workspace).create_registry()


def _parse_arguments(arguments: Mapping[str, Any] | str | None) -> Mapping[str, Any]:
    if arguments is None:
        return {}
    if isinstance(arguments, str):
        parsed = json.loads(arguments)
        if not isinstance(parsed, dict):
            raise TypeError("tool arguments must decode to a JSON object")
        return parsed
    if not isinstance(arguments, Mapping):
        raise TypeError("tool arguments must be an object")
    return arguments


def _required_int_argument(arguments: Mapping[str, Any], name: str) -> int:
    value = _optional_int_argument(arguments, name)
    if value is None:
        raise ValueError(f"{name} is required and must be an integer")
    return value


def _optional_int_argument(arguments: Mapping[str, Any], name: str) -> int | None:
    if name not in arguments or arguments[name] is None:
        return None
    value = arguments[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    return int(value)


def _bounded_int_argument(
    arguments: Mapping[str, Any],
    name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    if name not in arguments:
        return default
    value = _required_int_argument(arguments, name)
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _required_string_argument(arguments: Mapping[str, Any], name: str) -> str:
    value = _string_argument(arguments, name)
    if value is None or not value.strip():
        raise ValueError(f"{name} is required and must be a non-empty string")
    return value.strip()


def _string_argument(
    arguments: Mapping[str, Any],
    name: str,
    *,
    default: str | None = None,
) -> str | None:
    if name not in arguments:
        return default
    value = arguments[name]
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    return value


def _as_optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _require_value(value: Any, name: str) -> Any:
    if value is None:
        raise ValueError(f"{name} is required")
    return value


def _parse_list_value(value: Any) -> list[Any] | None:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return []
    try:
        parsed = ast.literal_eval(stripped)
    except (SyntaxError, TypeError, ValueError):
        return None
    return parsed if isinstance(parsed, list) else None


def _integer_list(value: Any) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(
        parsed
        for item in value
        if (parsed := _as_optional_int(item)) is not None
    )
