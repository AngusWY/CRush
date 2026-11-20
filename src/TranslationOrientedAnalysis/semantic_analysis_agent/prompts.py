from __future__ import annotations

import json
from collections.abc import Mapping
from enum import Enum

from ..semantic_hint_schemas import (
    Lifetime,
    Mutability,
    Nullability,
    Ownership,
    PointeeShape,
    ResourceCapability,
    ResourceKind,
    ResourceOpenMode,
    ResourceOperationEffect,
)
from .models import (
    ChatMessage,
    DECLARATION_TASK_KIND,
    JsonValue,
    SemanticAgentContext,
    SemanticAgentTask,
    TASK_KINDS,
    UNSAFE_STMT_TASK_KIND,
)
from .skill_loader import (
    load_c_string_analysis_skill,
    load_resource_io_analysis_skill,
    select_unsafe_analysis_skill_sections,
)


TOOL_USE_INSTRUCTIONS = """
== How to use tools ==

Use tools only when the provided context does not contain enough evidence for a
requested field. You may request multiple independent tools in one response.

To request tools, return strict JSON:
{
  "type": "tool_calls",
  "tool_calls": [
    {"tool": "tool_name", "arguments": {...}},
    {"tool": "another_tool", "arguments": {...}}
  ]
}

After the tool results are provided, continue your analysis in the next
response — you may call more tools or return a final answer.
""".strip()


UNSAFE_FIELD_DESCRIPTIONS = {
    "borrow_kind": (
        "Whether this operation behaves like a shared borrow or mutable borrow "
        "of the accessed memory."
    ),
    "resolves_to_element": (
        "Concrete C object or element this access resolves to, such as buf[i] "
        "or msg->buf."
    ),
    "canonical_read": (
        "Canonical C-level read expression for this statement."
    ),
    "canonical_write": (
        "Canonical C-level write target for this statement."
    ),
    "write_source_deps": (
        "Symbols or expressions that the written value depends on."
    ),
    "c_string_termination": (
        "Structured contract for an explicit C NUL-terminator write, including "
        "the buffer, terminator index, minimum capacity, and write target."
    ),
    "c_string_read": (
        "Structured contract for a read that relies on the readable NUL at a "
        "C string's logical end."
    ),
    "via_alias": (
        "Alias path or alias variable through which this access is reached."
    ),
    "via_addr_of_source": (
        "Address-of source that produced the pointer used by this operation."
    ),
    "array_role": (
        "Role of the accessed array or buffer, such as parameter array, local "
        "array, global array, or alias."
    ),
    "source_element": (
        "Concrete C object or element whose address is taken."
    ),
    "escape": (
        "How the address or pointer escapes its local context, such as return, "
        "field/global store, or call argument."
    ),
    "ownership": (
        "Ownership meaning of this operation's produced or transferred value."
    ),
    "origin_kind": (
        "Origin category of a produced value, such as allocation, parameter, "
        "global, field, or call return."
    ),
    "storage_kind": (
        "Storage category of the relevant object, such as parameter, local, "
        "global, field, or heap."
    ),
    "transfer_kind": (
        "Whether this operation transfers ownership, borrows, frees, or performs "
        "no ownership transfer."
    ),
    "allocation_shape": (
        "Shape of allocated memory, such as single object or array/buffer."
    ),
    "allocation_size_bytes": (
        "Byte-size expression used by an allocation or byte operation."
    ),
    "escape_kind": (
        "Escape category for a value passed through a call or stored outside "
        "the current scope."
    ),
    "byte_count": (
        "Byte-count expression used by memcpy/memmove/memset-like operations."
    ),
    "source_storage_kind": (
        "Storage category of the source value read by this operation."
    ),
    "return_lifetime": (
        "Structured lifetime hint for a returned value."
    ),
    "cast_kind": (
        "Kind of cast, such as pointer-to-pointer, pointer-to-integer, "
        "integer-to-pointer, or qualifier change."
    ),
    "offset_base": (
        "Base object used by a pointer-offset or cast-related access."
    ),
    "offset": (
        "Offset expression associated with a pointer/cast access."
    ),
    "constraints": (
        "Translation constraints or safety notes that should be respected."
    ),
    "is_pointer_field": (
        "Whether the accessed field itself is a pointer field."
    ),
    "establishes_alias": (
        "Whether this field write or assignment establishes a pointer/array alias."
    ),
    "flow_kind": (
        "High-level assignment flow category, such as alias creation, value copy, "
        "or pointer offset."
    ),
    "alias": (
        "Alias variable or field introduced by this statement."
    ),
    "base": (
        "Base object that an alias or pointer arithmetic expression derives from."
    ),
    "base_path": (
        "Full base access path when the alias derives from a field or nested path."
    ),
    "offset_expr": (
        "Offset expression used to derive an alias from its base."
    ),
    "derived_from": (
        "Original expression or symbol from which the alias derives."
    ),
    "escape_sites": (
        "Places where the alias escapes through return, store, or call."
    ),
    "mutating_access_sites": (
        "Statement ids where the alias is used for mutation."
    ),
    "valid_until_stmt_id": (
        "Last statement id where this alias relation is known to remain valid."
    ),
    "ownership_kind": (
        "Ownership category attached to an alias relation, if known."
    ),
    "ownership_source": (
        "Symbol or expression that provides the ownership for an alias relation."
    ),
    "arith_kind": (
        "Kind of pointer arithmetic, such as pointer offset or difference."
    ),
    "base_left": (
        "Left base operand in pointer arithmetic or pointer difference."
    ),
    "base_right": (
        "Right base operand in pointer arithmetic or pointer difference."
    ),
    "result_semantics": (
        "Meaning of the pointer arithmetic result for translation."
    ),
}


DECLARATION_AGENT_SYSTEM_PROMPT = f"""
You are a semantic analysis Agent for a C-to-Rust translation system.

Fill missing declaration semantic fields for the current translation entity.
Declaration gaps may include pointer declarations and ordinary variable
declarations. Use each gap's missing_fields to decide which fields to analyze.
Do not generate Rust code or semantic-hint text.

== Evidence ==

Use the provided context and C source evidence. Treat current_semantics as existing
programmatic analysis, not as final truth. If the evidence is insufficient,
leave the field unresolved instead of guessing.

== Update Policy ==

1. Analyze every gap in the task exactly once.
2. Only update fields listed in missing_fields.
3. If you change a non-null current_semantics value, include a conflict entry
   with evidence_refs and a reason.
4. If a field cannot be determined, omit it from updates and add
   {{"field":"<field_name>"}} to unresolved_fields.
5. unresolved_fields must be an array of objects, not strings.
6. Never use null, "", "unknown", [], or {{}} in updates.

== Allowed Values ==

- nullability: nonnull | nullable
- ownership: none | borrowed | owned
- pointer mutability: const | mutable
- variable mutability: const | mutable
- pointee_shape: single | array
- lifetime: owned | local | param | stored | static | unknown
- resource_semantics: a structured stateful-resource contract; when this field
  is missing, follow the supplied resource_io_analysis_skill exactly
- string_semantics: a structured NUL-terminated byte-string contract; when this
  field is missing, follow the supplied c_string_analysis_skill exactly

The resource_semantics object may use these enum values:
- resource_kind: file_stream
- capabilities: read | write | seek | flush
- open_mode: read_existing | write_truncate | append |
  read_write_existing | read_write_truncate | read_append |
  inherited_descriptor | process_pipe
- operation effect: open_resource | read_bytes_and_advance_cursor |
  write_bytes_and_advance_cursor | set_cursor | query_cursor |
  rewind_cursor | flush_buffered_output | close_resource | test_eof_state |
  test_error_state | push_back_byte | clear_eof_and_error_state
- handle role: direct | sequence | slot | unknown
- operation origin: direct | callee | caller

The resource contract describes observable C behavior. Never add or infer a
Rust representation, and never emit rust_representation or
stateful_across_calls.

{TOOL_USE_INSTRUCTIONS}

== Final Response Format ==

Return strict JSON without Markdown:

{{
  "type": "final",
  "pointer_patches": [
    {{
      "stmt_id": 456,
      "updates": {{
        "nullability": "nonnull"
      }},
      "unresolved_fields": [],
      "conflicts": []
    }}
  ],
  "variable_patches": [
    {{
      "stmt_id": 567,
      "updates": {{
        "mutability": "mutable"
      }},
      "unresolved_fields": [],
      "conflicts": []
    }}
  ]
}}

Every pointer in pointer_declarations MUST appear in pointer_patches,
even if you could not fill any fields (use an empty updates dict).
Every variable in variable_declarations MUST appear in variable_patches,
even if you could not fill any fields (use an empty updates dict).
Only update fields listed in missing_fields.
""".strip()


UNSAFE_AGENT_SYSTEM_PROMPT = f"""
You are a semantic analysis Agent for a C-to-Rust translation system.

Fill missing semantic fields for unsafe-related C statements in the current
translation entity. Use each gap's missing_fields to decide which fields to
analyze. Do not analyze declaration semantics. Do not generate Rust code or
semantic-hint text.

== Evidence ==

Use the provided context and C source evidence. Treat current_semantics as existing
programmatic analysis, not as final truth. If the evidence is insufficient,
leave the field unresolved instead of guessing.

== Update Policy ==

1. Analyze every gap in the task exactly once.
2. Only update fields listed in missing_fields.
3. If you change a non-null current_semantics value, include a conflict entry
   with evidence_refs and a reason.
4. If a field cannot be determined, omit it from updates and add
   {{"field":"<field_name>"}} to unresolved_fields.
5. unresolved_fields must be an array of objects, not strings.
6. Never use null, "", "unknown", [], or {{}} in updates.

{TOOL_USE_INSTRUCTIONS}

== Final Response Format ==

Return strict JSON without Markdown:

{{
  "type": "final",
  "unsafe_stmt_patches": [
    {{
      "stmt_id": 789,
      "updates": {{
        "resolves_to_element": "arr[i]"
      }},
      "unresolved_fields": [],
      "conflicts": []
    }},
    {{
      "stmt_id": 790,
      "updates": {{}},
      "unresolved_fields": [
        {{"field": "resolves_to_element"}}
      ],
      "conflicts": []
    }}
  ]
}}

Every unsafe stmt in unsafe_statements MUST appear in
unsafe_stmt_patches, even if you could not fill any fields.
Only update fields listed in missing_fields.
""".strip()


SEMANTIC_AGENT_SYSTEM_PROMPT = """
You are a semantic analysis Agent for a C-to-Rust translation system.

Fill missing semantic fields for the current translation entity. Use each
gap's missing_fields to decide which fields to analyze. Do not generate Rust
code or semantic-hint text.

== Evidence ==

Use the provided context and C source evidence. Treat current_semantics as existing
programmatic analysis, not as final truth. If the evidence is insufficient,
leave the field unresolved instead of guessing.

== Update Policy ==

1. Analyze every gap in the task exactly once.
2. Only update fields listed in missing_fields.
3. If you change a non-null current_semantics value, include a conflict entry
   with evidence_refs and a reason.
4. If a field cannot be determined, omit it from updates and add
   {"field":"<field_name>"} to unresolved_fields.
5. unresolved_fields must be an array of objects, not strings.
6. Never use null, "", "unknown", [], or {} in updates.

== Allowed Values ==

- nullability: nonnull | nullable
- ownership: none | borrowed | owned | shared owned
- pointer mutability: const | mutable
- variable mutability: const | mutable
- pointee_shape: single | array
- lifetime: owned | local | param | stored | static | unknown

{TOOL_USE_INSTRUCTIONS}

== Final Response Format ==

Return strict JSON without Markdown:

{
  "type": "final",
  "pointer_patches": [
    {
      "stmt_id": 456,
      "updates": {
        "nullability": "nonnull"
      },
      "unresolved_fields": [],
      "conflicts": []
    }
  ],
  "variable_patches": [
    {
      "stmt_id": 567,
      "updates": {
        "mutability": "mutable"
      },
      "unresolved_fields": [],
      "conflicts": []
    }
  ],
  "unsafe_stmt_patches": [
    {
      "stmt_id": 789,
      "updates": {
        "resolves_to_element": "arr[i]"
      },
      "unresolved_fields": [],
      "conflicts": []
    },
    {
      "stmt_id": 790,
      "updates": {},
      "unresolved_fields": [
        {"field": "resolves_to_element"}
      ],
      "conflicts": []
    }
  ]
}

Every pointer in pointer_declarations MUST appear in pointer_patches,
even if you could not fill any fields (use an empty updates dict).
Every variable in variable_declarations MUST appear in variable_patches,
even if you could not fill any fields (use an empty updates dict).
Every unsafe stmt in unsafe_statements MUST appear in
unsafe_stmt_patches, even if you could not fill any fields.

Only update fields listed in missing_fields.
""".strip().replace("{TOOL_USE_INSTRUCTIONS}", TOOL_USE_INSTRUCTIONS)


class SemanticPromptError(ValueError):
    pass


class SemanticPromptBuilder:


    def __init__(self, *, tools_description: str = "") -> None:
        self.tools_description = tools_description.strip()

    def build(
        self,
        *,
        task: SemanticAgentTask,
        context: Mapping[str, JsonValue] | SemanticAgentContext,
    ) -> tuple[ChatMessage, ...]:
        if task.entity_id <= 0:
            raise SemanticPromptError(
                f"task has invalid entity ID: {task.entity_id}"
            )
        if (
            not task.pointer_gaps
            and not task.variable_gaps
            and not task.unsafe_stmt_gaps
        ):
            raise SemanticPromptError(
                f"entity task {task.entity_id} has no semantic gaps"
            )
        if task.task_kind not in TASK_KINDS:
            raise SemanticPromptError(
                f"entity task {task.entity_id} has invalid task_kind: "
                f"{task.task_kind!r}"
            )
        if (
            task.task_kind == DECLARATION_TASK_KIND
            and task.unsafe_stmt_gaps
        ):
            raise SemanticPromptError(
                f"declaration task {task.entity_id} contains unsafe gaps"
            )
        if (
            task.task_kind == UNSAFE_STMT_TASK_KIND
            and (task.pointer_gaps or task.variable_gaps)
        ):
            raise SemanticPromptError(
                f"unsafe_stmt task {task.entity_id} contains declaration gaps"
            )

        system_prompt = self._system_prompt_for_task(task)
        if self.tools_description:
            system_prompt = (
                f"{system_prompt}\n\n"
                "== Available Tools ==\n"
                f"{self.tools_description}"
            )

        payload = self._model_payload(task=task, context=context)
        field_descriptions = self._field_descriptions(task)
        if field_descriptions:
            payload["field_descriptions"] = field_descriptions
        unsafe_skill = self._unsafe_analysis_skill(task)
        if unsafe_skill:
            payload["unsafe_analysis_skill"] = unsafe_skill
        resource_skill = self._resource_io_analysis_skill(task)
        if resource_skill:
            payload["resource_io_analysis_skill"] = resource_skill
        c_string_skill = self._c_string_analysis_skill(task)
        if c_string_skill:
            payload["c_string_analysis_skill"] = c_string_skill
        user_prompt = (
            "Analyze the following entity and return the required strict JSON "
            "response.\n\n"
            + json.dumps(payload, ensure_ascii=False, indent=2)
        )
        return (
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(role="user", content=user_prompt),
        )

    @staticmethod
    def _system_prompt_for_task(task: SemanticAgentTask) -> str:
        if task.task_kind == DECLARATION_TASK_KIND:
            return DECLARATION_AGENT_SYSTEM_PROMPT
        if task.task_kind == UNSAFE_STMT_TASK_KIND:
            return UNSAFE_AGENT_SYSTEM_PROMPT
        return SEMANTIC_AGENT_SYSTEM_PROMPT

    @classmethod
    def _model_payload(
        cls,
        *,
        task: SemanticAgentTask,
        context: Mapping[str, JsonValue] | SemanticAgentContext,
    ) -> dict[str, JsonValue]:


        cls._validate_gap_ids(task)
        entity_payload = cls._entity_payload(task)
        if isinstance(context, SemanticAgentContext):
            source = context.entity_source.source
            if task.task_kind == DECLARATION_TASK_KIND:
                payload: dict[str, JsonValue] = {
                    "entity": entity_payload,
                    "source": source,
                    "pointer_declarations": [
                        cls._pointer_context_payload(pointer)
                        for pointer in context.pointer_tasks
                    ],
                    "variable_declarations": [
                        cls._variable_context_payload(variable)
                        for variable in context.variable_tasks
                    ],
                }
            elif task.task_kind == UNSAFE_STMT_TASK_KIND:
                payload = {
                    "entity": entity_payload,
                    "source": source,
                    "unsafe_statements": [
                        cls._unsafe_stmt_context_payload(stmt)
                        for stmt in context.unsafe_stmt_tasks
                    ],
                }
            else:
                payload = {
                    "entity": entity_payload,
                    "source": source,
                    "pointer_declarations": [
                        cls._pointer_context_payload(pointer)
                        for pointer in context.pointer_tasks
                    ],
                    "variable_declarations": [
                        cls._variable_context_payload(variable)
                        for variable in context.variable_tasks
                    ],
                    "unsafe_statements": [
                        cls._unsafe_stmt_context_payload(stmt)
                        for stmt in context.unsafe_stmt_tasks
                    ],
                }
        else:
            payload = {
                "entity": entity_payload,
                "source": cls._source_from_mapping(context),
                "pointer_declarations": cls._pointer_gaps_payload(task),
                "variable_declarations": cls._variable_gaps_payload(task),
                "unsafe_statements": cls._unsafe_stmt_gaps_payload(task),
            }

        cls._ensure_json_serializable(payload)
        return payload

    @staticmethod
    def _entity_payload(task: SemanticAgentTask) -> dict[str, JsonValue]:
        return {
            "entity_id": task.entity_id,
            "method_id": task.entity_id
            if task.entity_kind == "function"
            else None,
            "name": task.entity_name,
            "kind": task.entity_kind,
        }

    @classmethod
    def _field_descriptions(
        cls,
        task: SemanticAgentTask,
    ) -> dict[str, JsonValue]:


        if task.task_kind == DECLARATION_TASK_KIND:
            fields = {
                field
                for gap in task.pointer_gaps
                for field in gap.missing_fields
            }
            descriptions: dict[str, JsonValue] = {}
            if "resource_semantics" in fields:
                descriptions["resource_semantics"] = (
                    "Structured FILE stream resource contract containing the "
                    "handle shape, ownership, operations, cross-function flow, "
                    "state obligations, open mode, and lifetime boundary."
                )
            if "string_semantics" in fields:
                descriptions["string_semantics"] = (
                    "Structured NUL-terminated byte-string boundary contract."
                )
            return descriptions
        elif task.task_kind == UNSAFE_STMT_TASK_KIND:
            fields = {
                field
                for gap in task.unsafe_stmt_gaps
                for field in gap.missing_fields
            }
            descriptions = UNSAFE_FIELD_DESCRIPTIONS
        else:
            fields = set()
            descriptions = {}

        result: dict[str, JsonValue] = {}
        for field in sorted(fields):
            description = descriptions.get(field)
            if description is not None:
                result[field] = description
        return result

    @staticmethod
    def _unsafe_analysis_skill(task: SemanticAgentTask) -> str:
        if task.task_kind != UNSAFE_STMT_TASK_KIND:
            return ""
        return select_unsafe_analysis_skill_sections(
            gap.operation for gap in task.unsafe_stmt_gaps
        )

    @staticmethod
    def _resource_io_analysis_skill(task: SemanticAgentTask) -> str:
        if task.task_kind != DECLARATION_TASK_KIND:
            return ""
        if not any(
            "resource_semantics" in gap.missing_fields
            for gap in task.pointer_gaps
        ):
            return ""
        return load_resource_io_analysis_skill()

    @staticmethod
    def _c_string_analysis_skill(task: SemanticAgentTask) -> str:
        if task.task_kind == DECLARATION_TASK_KIND:
            required = any(
                "string_semantics" in gap.missing_fields
                for gap in task.pointer_gaps
            )
        elif task.task_kind == UNSAFE_STMT_TASK_KIND:
            required = any(
                field in {"c_string_read", "c_string_termination"}
                for gap in task.unsafe_stmt_gaps
                for field in gap.missing_fields
            )
        else:
            required = False
        return load_c_string_analysis_skill() if required else ""

    @classmethod
    def _validate_gap_ids(
        cls,
        task: SemanticAgentTask,
    ) -> None:
        seen_stmt_ids: set[int] = set()
        for gap in task.pointer_gaps:
            if gap.stmt_id <= 0:
                raise SemanticPromptError(
                    f"task has invalid pointer stmt_id: {gap.stmt_id}"
                )
            if gap.stmt_id in seen_stmt_ids:
                raise SemanticPromptError(
                    f"task has duplicate pointer stmt_id: {gap.stmt_id}"
                )
            seen_stmt_ids.add(gap.stmt_id)
            if not gap.missing_fields:
                raise SemanticPromptError(
                    f"pointer {gap.stmt_id} has no missing fields"
                )
        seen_stmt_ids.clear()
        for gap in task.variable_gaps:
            if gap.stmt_id <= 0:
                raise SemanticPromptError(
                    f"task has invalid variable stmt_id: {gap.stmt_id}"
                )
            if gap.stmt_id in seen_stmt_ids:
                raise SemanticPromptError(
                    f"task has duplicate variable stmt_id: {gap.stmt_id}"
                )
            seen_stmt_ids.add(gap.stmt_id)
            if not gap.missing_fields:
                raise SemanticPromptError(
                    f"variable {gap.stmt_id} has no missing fields"
                )
        seen_stmt_ids.clear()
        for gap in task.unsafe_stmt_gaps:
            if gap.stmt_id <= 0:
                raise SemanticPromptError(
                    f"task has invalid unsafe stmt_id: {gap.stmt_id}"
                )
            if gap.stmt_id in seen_stmt_ids:
                raise SemanticPromptError(
                    f"task has duplicate unsafe stmt_id: {gap.stmt_id}"
                )
            seen_stmt_ids.add(gap.stmt_id)
            if not gap.missing_fields:
                raise SemanticPromptError(
                    f"unsafe stmt {gap.stmt_id} has no missing fields"
                )

    @classmethod
    def _pointer_context_payload(cls, pointer: object) -> dict[str, JsonValue]:
        return {
            "stmt_id": getattr(pointer, "stmt_id"),
            "name": str(getattr(pointer, "name")),
            "c_type": str(getattr(pointer, "c_type")),
            "declaration": str(getattr(pointer, "declaration_source")),
            "missing_fields": list(getattr(pointer, "missing_fields")),
            "current_semantics": cls._semantic_payload(
                getattr(pointer, "current_semantics").to_dict()
            ),
        }

    @classmethod
    def _variable_context_payload(cls, variable: object) -> dict[str, JsonValue]:
        return {
            "stmt_id": getattr(variable, "stmt_id"),
            "name": str(getattr(variable, "name")),
            "c_type": str(getattr(variable, "c_type")),
            "declaration": str(getattr(variable, "declaration_source")),
            "missing_fields": list(getattr(variable, "missing_fields")),
            "current_semantics": cls._semantic_payload(
                getattr(variable, "current_semantics").to_dict()
            ),
        }

    @classmethod
    def _unsafe_stmt_context_payload(cls, stmt: object) -> dict[str, JsonValue]:
        stmt_source = getattr(stmt, "stmt_source")
        return {
            "stmt_id": getattr(stmt, "stmt_id"),
            "operation": str(getattr(stmt, "operation")),
            "statement": str(getattr(stmt_source, "source")),
            "missing_fields": list(getattr(stmt, "missing_fields")),
            "current_semantics": cls._semantic_payload(
                getattr(stmt, "current_semantics").semantic_hints
            ),
        }

    @classmethod
    def _variable_gaps_payload(
        cls,
        task: SemanticAgentTask,
    ) -> list[JsonValue]:
        variable_gaps: list[JsonValue] = []
        seen_stmt_ids: set[int] = set()
        for gap in task.variable_gaps:
            if gap.stmt_id <= 0:
                raise SemanticPromptError(
                    f"task has invalid variable stmt_id: {gap.stmt_id}"
                )
            if gap.stmt_id in seen_stmt_ids:
                raise SemanticPromptError(
                    f"task has duplicate variable stmt_id: {gap.stmt_id}"
                )
            seen_stmt_ids.add(gap.stmt_id)
            if not gap.missing_fields:
                raise SemanticPromptError(
                    f"variable {gap.stmt_id} has no missing fields"
                )
            variable_gaps.append(
                {
                    "stmt_id": gap.stmt_id,
                    "current_semantics": cls._semantic_payload(
                        gap.current_semantics.to_dict()
                    ),
                    "missing_fields": list(gap.missing_fields),
                }
            )
        return variable_gaps

    @classmethod
    def _pointer_gaps_payload(
        cls,
        task: SemanticAgentTask,
    ) -> list[JsonValue]:
        pointer_gaps: list[JsonValue] = []
        seen_stmt_ids: set[int] = set()
        for gap in task.pointer_gaps:
            if gap.stmt_id <= 0:
                raise SemanticPromptError(
                    f"task has invalid pointer stmt_id: {gap.stmt_id}"
                )
            if gap.stmt_id in seen_stmt_ids:
                raise SemanticPromptError(
                    f"task has duplicate pointer stmt_id: {gap.stmt_id}"
                )
            seen_stmt_ids.add(gap.stmt_id)
            if not gap.missing_fields:
                raise SemanticPromptError(
                    f"pointer {gap.stmt_id} has no missing fields"
                )
            pointer_gaps.append(
                {
                    "stmt_id": gap.stmt_id,
                    "current_semantics": cls._semantic_payload(
                        gap.current_semantics.to_dict()
                    ),
                    "missing_fields": list(gap.missing_fields),
                }
            )
        return pointer_gaps

    @classmethod
    def _unsafe_stmt_gaps_payload(
        cls,
        task: SemanticAgentTask,
    ) -> list[JsonValue]:
        unsafe_stmt_gaps: list[JsonValue] = []
        seen_stmt_ids: set[int] = set()
        for gap in task.unsafe_stmt_gaps:
            if gap.stmt_id <= 0:
                raise SemanticPromptError(
                    f"task has invalid unsafe stmt_id: {gap.stmt_id}"
                )
            if gap.stmt_id in seen_stmt_ids:
                raise SemanticPromptError(
                    f"task has duplicate unsafe stmt_id: {gap.stmt_id}"
                )
            seen_stmt_ids.add(gap.stmt_id)
            if not gap.missing_fields:
                raise SemanticPromptError(
                    f"unsafe stmt {gap.stmt_id} has no missing fields"
                )
            unsafe_stmt_gaps.append(
                {
                    "stmt_id": gap.stmt_id,
                    "operation": gap.operation,
                    "current_semantics": cls._semantic_payload(
                        gap.current_semantics.semantic_hints
                    ),
                    "missing_fields": list(gap.missing_fields),
                }
            )
        return unsafe_stmt_gaps

    @classmethod
    def _source_from_mapping(
        cls,
        context: Mapping[str, JsonValue],
    ) -> JsonValue:
        source = context.get("entity_source")
        if isinstance(source, Mapping):
            raw_source = source.get("source")
            if isinstance(raw_source, str):
                return raw_source
        raw_source = context.get("source")
        if isinstance(raw_source, str):
            return raw_source
        return ""

    @classmethod
    def _ensure_json_serializable(
        cls,
        payload: Mapping[str, JsonValue],
    ) -> None:
        try:
            json.dumps(payload, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise SemanticPromptError(
                f"model payload is not JSON serializable: {exc}"
            ) from exc

    @classmethod
    def _semantic_payload(
        cls,
        value: Mapping[str, object],
    ) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text in {
                "stmt_id",
                "name",
                "operation",
                "entity_id",
                "semantic_kind",
                "is_struct_member",
                "usage_path",
                "source_snippet",
                "related_symbols",
                "raw_gir",
                "programmatic_facts",
                "semantic_hints",
                "agent_missing_fields",
                "needs_agent",
            }:
                continue
            json_item = cls._json_value(item)
            if cls._is_empty_semantic_value(json_item):
                continue
            result[key_text] = json_item
        return result

    @staticmethod
    def _is_empty_semantic_value(value: JsonValue) -> bool:
        if value is None:
            return True
        if value == "":
            return True
        if value == [] or value == {}:
            return True
        return False

    @classmethod
    def _json_value(cls, value: object) -> JsonValue:
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
        raise SemanticPromptError(
            f"value is not JSON-compatible: {type(value).__name__}"
        )


def allowed_pointer_semantic_values() -> dict[str, tuple[str, ...]]:


    return {
        "nullability": tuple(value.value for value in Nullability),
        "ownership": tuple(value.value for value in Ownership),
        "mutability": tuple(value.value for value in Mutability),
        "pointee_shape": tuple(value.value for value in PointeeShape),
        "lifetime": tuple(value.value for value in Lifetime),
        "resource_kind": tuple(value.value for value in ResourceKind),
        "resource_capability": tuple(
            value.value for value in ResourceCapability
        ),
        "resource_open_mode": tuple(value.value for value in ResourceOpenMode),
        "resource_operation_effect": tuple(
            value.value for value in ResourceOperationEffect
        ),
    }


def build_correction_prompt(parse_error: str, task_kind: str | None = None) -> str:


    if task_kind == DECLARATION_TASK_KIND:
        final_shape = (
            '{"type":"final","pointer_patches":[...],'
            '"variable_patches":[...]}'
        )
        domain_note = (
            "This is a declaration task. Do not return unsafe_stmt_patches.\n\n"
        )
    elif task_kind == UNSAFE_STMT_TASK_KIND:
        final_shape = (
            '{"type":"final","unsafe_stmt_patches":[...]}'
        )
        domain_note = (
            "This is an unsafe stmt task. Do not return pointer_patches or "
            "variable_patches.\n\n"
        )
    else:
        final_shape = (
            '{"type":"final","pointer_patches":[...],'
            '"variable_patches":[...],"unsafe_stmt_patches":[...]}'
        )
        domain_note = ""

    return (
        "Your previous response could not be parsed or did not match the "
        "required schema: "
        f"{parse_error}\n\n"
        f"{domain_note}"
        "Return only strict JSON, without Markdown.\n\n"
        "Final answer shape:\n"
        f"{final_shape}\n\n"
        "Patch entry shape:\n"
        '{"stmt_id":<int>,"updates":{...},'
        '"unresolved_fields":[{"field":"<field_name>"}],"conflicts":[]}\n\n'
        'If a field cannot be determined, omit it from updates and add '
        '{"field":"<field_name>"} to unresolved_fields. '
        "unresolved_fields must be an array of objects, not strings. "
        'Never use null, "", "unknown", [], or {} in updates.\n\n'
        "Tool call shape:\n"
        '{"type":"tool_calls","tool_calls":['
        '{"tool":"<name>","arguments":{...}}]}'
    )
