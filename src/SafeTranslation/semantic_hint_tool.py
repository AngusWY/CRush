from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from pathlib import Path

from .loader import load_hint_store
from .models import JsonDict, TranslationTask

GET_SEMANTIC_HINT_TOOL: JsonDict = {
    "type": "function",
    "function": {
        "name": "get_semantic_hint",
        "description": (
            "Return a concise plain-text semantic hint for one @SH anchor in "
            "the current translation task."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "anchor_id": {
                    "type": "string",
                    "description": (
                        "Semantic hint anchor ID from annotated C source, "
                        "for example SH_E263_S265."
                    ),
                }
            },
            "required": ["anchor_id"],
            "additionalProperties": False,
        },
    },
}


class SemanticHintToolError(RuntimeError):
    pass


@dataclass(frozen=True)
class SemanticHintTool:


    hints: dict[str, JsonDict]

    @classmethod
    def from_workspace(cls, workspace: Path | str) -> "SemanticHintTool":
        return cls(hints=load_hint_store(workspace))

    def get_semantic_hint(self, anchor_id: str) -> JsonDict:


        hint = self.hints.get(anchor_id)
        if hint is None:
            raise SemanticHintToolError(
                f"semantic hint anchor not found: {anchor_id!r}"
            )
        return copy.deepcopy(hint)

    def get_semantic_hint_for_task(
        self,
        task: TranslationTask,
        anchor_id: str,
    ) -> JsonDict:


        if anchor_id not in task.package.hint_anchor_ids:
            raise SemanticHintToolError(
                f"semantic hint anchor {anchor_id!r} is not available for "
                f"entity {task.entity_id}"
            )
        return self.get_semantic_hint(anchor_id)

    def execute_for_task(
        self,
        task: TranslationTask,
        arguments_json: str,
    ) -> str:


        try:
            arguments = json.loads(arguments_json or "{}")
            if not isinstance(arguments, dict):
                raise SemanticHintToolError("tool arguments must be an object")
            anchor_id = arguments.get("anchor_id")
            if not isinstance(anchor_id, str) or not anchor_id.strip():
                raise SemanticHintToolError(
                    "get_semantic_hint requires non-empty anchor_id"
                )
            hint = self.get_semantic_hint_for_task(task, anchor_id.strip())
            return format_semantic_hint_for_model(hint)
        except (json.JSONDecodeError, SemanticHintToolError) as exc:
            return f"ERROR: {exc}"

    def critical_context_for_task(self, task: TranslationTask) -> str:


        sections: list[str] = []
        for anchor_id in task.package.hint_anchor_ids:
            hint = self.get_semantic_hint_for_task(task, anchor_id)
            facts = hint.get("facts")
            if not isinstance(facts, dict):
                continue
            external_interface = facts.get("external_interface")
            if isinstance(external_interface, dict) and external_interface:
                lines = self._external_interface_lines(
                    anchor_id,
                    external_interface,
                )
                if lines:
                    sections.append("\n".join(lines))
            callback_interface = facts.get("callback_interface")
            if isinstance(callback_interface, list) and callback_interface:
                lines = self._callback_interface_lines(
                    anchor_id,
                    callback_interface,
                )
                if lines:
                    sections.append("\n".join(lines))
            constraint = facts.get("translation_constraint")
            if isinstance(constraint, dict) and constraint:
                parameter = _string_value(
                    constraint.get("indexes_parameter")
                )
                preferred = _string_value(
                    constraint.get("preferred_rust_type")
                )
                avoid = constraint.get("avoid_rust_types")
                avoided = (
                    ", ".join(item for item in avoid if isinstance(item, str))
                    if isinstance(avoid, list)
                    else ""
                )
                if parameter and preferred:
                    lines = [f"<{anchor_id}>"]
                    lines.append(
                        f"- Represent the returned selection as an index into "
                        f"`{parameter}` (`{preferred}`)."
                    )
                    if avoided:
                        lines.append(f"- Avoid `{avoided}`.")
                    lines.append(
                        "- The caller retains a selection while selecting "
                        "another element from the same array."
                    )
                    sections.append("\n".join(lines))
                    continue
            derived_pointer = facts.get("derived_pointer")
            if not isinstance(derived_pointer, dict) or not derived_pointer:
                continue

            lines = [f"<{anchor_id}>"]
            return_lifetime = facts.get("return_lifetime")
            if isinstance(return_lifetime, dict):
                for key, value in return_lifetime.items():
                    if value is not None:
                        lines.append(
                            f"- return_lifetime.{key}: {_plain_value(value)}"
                        )
            for key, value in derived_pointer.items():
                if value is not None:
                    lines.append(
                        f"- derived_pointer.{key}: {_plain_value(value)}"
                    )
            sections.append("\n".join(lines))

        if not sections:
            return ""
        return "\n".join(
            [
                "Critical semantic context recovered by static analysis.",
                *sections,
            ]
        )

    @staticmethod
    def _external_interface_lines(
        anchor_id: str,
        facts: JsonDict,
    ) -> list[str]:
        lines = [f"<{anchor_id}>", "- Project-wide external interface facts:"]
        external_types = facts.get("external_types")
        if isinstance(external_types, list):
            for item in external_types:
                if not isinstance(item, dict):
                    continue
                name = _string_value(item.get("name"))
                role = _string_value(item.get("role"))
                member = _string_value(item.get("member"))
                if name and role == "aggregate_member" and member:
                    lines.append(
                        f"  - Member `{member}` embeds external type `{name}`."
                    )
                elif name and role:
                    lines.append(f"  - External type `{name}` is used as {role}.")
        aliases = facts.get("function_pointer_types")
        if isinstance(aliases, list):
            for alias in aliases:
                if not isinstance(alias, dict):
                    continue
                name = _string_value(alias.get("name"))
                signature = _string_value(alias.get("signature"))
                use = _string_value(alias.get("use"))
                if not name:
                    continue
                label = f"`{name}`"
                if use:
                    label += f" used by `{use}`"
                if signature:
                    label += f" has C signature `{signature}`"
                lines.append(f"  - {label}.")
        observed_fields = facts.get("observed_fields")
        if isinstance(observed_fields, dict):
            for type_name, fields in sorted(observed_fields.items()):
                if not isinstance(fields, dict) or not fields:
                    continue
                rendered = []
                for field_name, operations in sorted(fields.items()):
                    if not isinstance(operations, list):
                        continue
                    rendered.append(
                        f"`{field_name}` ({'/'.join(str(op) for op in operations)})"
                    )
                if rendered:
                    lines.append(
                        f"  - `{type_name}` fields used: "
                        + ", ".join(rendered)
                        + "."
                    )
        ambiguous = facts.get("ambiguous_field_receivers")
        if isinstance(ambiguous, list):
            for item in ambiguous:
                if not isinstance(item, dict):
                    continue
                candidates = item.get("candidate_types")
                field = _string_value(item.get("field"))
                if isinstance(candidates, list) and field:
                    names = [name for name in candidates if isinstance(name, str)]
                    if len(names) > 1:
                        lines.append(
                            f"  - Field `{field}` has ambiguous receiver type "
                            f"among {', '.join(f'`{name}`' for name in names)}; "
                            "preserve this uncertainty."
                        )
        return lines if len(lines) > 2 else []

    @staticmethod
    def _callback_interface_lines(
        anchor_id: str,
        interfaces: list[Any],
    ) -> list[str]:
        lines = [f"<{anchor_id}>", "- Callback interface contract:"]
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            name = _string_value(interface.get("name"))
            if name:
                lines.append(f"  - Callback-bearing configuration: `{name}`.")
            callbacks = interface.get("callbacks")
            if isinstance(callbacks, list):
                callback_names = [
                    _string_value(item.get("name"))
                    for item in callbacks
                    if isinstance(item, dict)
                ]
                callback_names = [item for item in callback_names if item]
                if callback_names:
                    lines.append(
                        "  - Callback operations: "
                        + ", ".join(f"`{item}`" for item in callback_names)
                        + "."
                    )
                for callback in callbacks if isinstance(callbacks, list) else ():
                    if not isinstance(callback, dict):
                        continue
                    callback_name = _string_value(callback.get("name"))
                    signature = _string_value(callback.get("signature"))
                    if callback_name and signature:
                        lines.append(
                            f"  - C callback signature for `{callback_name}`: "
                            f"`{signature}`."
                        )
            context_members = interface.get("context_members")
            if isinstance(context_members, list):
                opaque_contexts = [
                    _string_value(item.get("name"))
                    for item in context_members
                    if isinstance(item, dict) and item.get("opaque_pointer") is True
                ]
                if opaque_contexts:
                    lines.append(
                        "  - Opaque callback context fields: "
                        + ", ".join(f"`{item}`" for item in opaque_contexts)
                        + "."
                    )
            owners = interface.get("owners")
            if isinstance(owners, list):
                for owner in owners:
                    if not isinstance(owner, dict):
                        continue
                    aggregate = _string_value(owner.get("aggregate"))
                    field = _string_value(owner.get("field"))
                    if aggregate and field and owner.get("shared_const_reference") is True:
                        lines.append(
                            f"  - `{aggregate}.{field}` retains this configuration "
                            "through a const-qualified C reference."
                        )
            callsites = interface.get("callsites")
            if isinstance(callsites, list):
                for call in callsites:
                    if not isinstance(call, dict):
                        continue
                    method = _string_value(call.get("method"))
                    callback = _string_value(call.get("callback"))
                    if not method or not callback:
                        continue
                    if call.get("operation_effect") == "name_inferred_may_mutate_device_state":
                        lines.append(
                            f"  - `{method}` invokes `{callback}`; its name suggests "
                            "device-state mutation, but this effect is inferred from "
                            "the callback name. Keep callback access consistent with "
                            "the configuration's shared-reference model and do not "
                            "borrow a mutable device directly through a shared config reference."
                        )
                    else:
                        lines.append(
                            f"  - `{method}` invokes callback `{callback}`; use the "
                            "same callback abstraction as the configuration type."
                        )
        return lines if len(lines) > 2 else []


def format_semantic_hint_for_model(hint: JsonDict) -> str:


    anchor_id = _string_value(hint.get("anchor_id")) or "<unknown>"
    lines = [f"<{anchor_id}>", "facts:"]

    facts = hint.get("facts")
    if isinstance(facts, dict):
        fact_lines = _format_facts(facts)
        lines.extend(fact_lines or ["- none"])
    else:
        lines.append("- none")

    usage_lines = _selected_usage_path_lines(hint)
    if usage_lines:
        lines.append("usage_path:")
        lines.extend(f"- {line}" for line in usage_lines)

    return "\n".join(lines)


def _format_facts(facts: JsonDict) -> list[str]:
    result: list[str] = []
    for key, value in facts.items():
        if key in {"stmt_id", "name", "operation", "usage_path"}:
            continue
        if value is None or value == [] or value == {}:
            continue
        result.append(f"- {key}: {_plain_value(value)}")
    return result


def _selected_usage_path_lines(hint: JsonDict, *, limit: int = 10) -> list[str]:
    facts = hint.get("facts")
    if not isinstance(facts, dict):
        return []
    raw_usage_path = facts.get("usage_path")
    if not isinstance(raw_usage_path, list):
        return []
    usage_path = [
        item.strip()
        for item in raw_usage_path
        if isinstance(item, str) and item.strip()
    ]
    if len(usage_path) <= limit:
        return usage_path

    target = hint.get("target")
    target_name = ""
    if isinstance(target, dict):
        target_name = _string_value(target.get("name"))
    if target_name:
        matching = [line for line in usage_path if target_name in line]
        if len(matching) >= limit:
            return _first_and_last(matching, limit=limit)

    return _first_and_last(usage_path, limit=limit)


def _first_and_last(lines: list[str], *, limit: int) -> list[str]:
    if len(lines) <= limit:
        return lines
    if limit <= 1:
        return lines[:limit]
    return [*lines[: limit - 1], lines[-1]]


def _plain_value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _string_value(value: object) -> str:
    return value if isinstance(value, str) else ""
