from __future__ import annotations

import dataclasses
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .analysis_context import AnalysisContext


class CallbackInterfaceAnalysisError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class CallbackInterfaceAnalysisResult:
    interfaces: tuple[dict[str, Any], ...]
    entity_contracts: tuple[dict[str, Any], ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "kind": "callback_interface_semantics",
            "interfaces": [dict(item) for item in self.interfaces],
            "entity_contracts": [dict(item) for item in self.entity_contracts],
        }


class CallbackInterfaceAnalyzer:


    _CALLBACK_MEMBER_RE = re.compile(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)")
    _INDIRECT_CALL_RE = re.compile(r"^%[A-Za-z0-9_]+$")
    _MUTATING_CALLBACK_NAMES = {"write", "prog", "program", "erase", "sync", "flush"}

    def __init__(
        self,
        context: AnalysisContext,
        *,
        translation_entities_path: Path,
    ) -> None:
        self.context = context
        self.translation_entities_path = translation_entities_path

    def analyze(self) -> CallbackInterfaceAnalysisResult:
        entities = self._read_entities()
        entity_ids_by_name = {
            str(item["name"]): int(item["id"])
            for item in entities
            if isinstance(item.get("name"), str)
            and isinstance(item.get("id"), int)
        }
        aggregate_members: dict[str, list[dict[str, Any]]] = defaultdict(list)
        aggregates_by_unit: dict[int, dict[int, str]] = {}
        for unit_id in self.context.get_all_unit_ids():
            rows = self.context.get_unit_rows(unit_id)
            rows_by_id = {
                stmt_id: row
                for row in rows
                if (stmt_id := self._positive_int(getattr(row, "stmt_id", None)))
                is not None
            }
            names: dict[int, str] = {}
            for row in rows:
                if self._text(getattr(row, "operation", "")) not in {
                    "struct_decl",
                    "union_decl",
                }:
                    continue
                stmt_id = self._positive_int(getattr(row, "stmt_id", None))
                name = self._text(getattr(row, "name", ""))
                if stmt_id is not None and name:
                    names[stmt_id] = name
            aggregates_by_unit[unit_id] = names
            for row in rows:
                if self._text(getattr(row, "operation", "")) != "variable_decl":
                    continue
                member_name = self._text(getattr(row, "name", ""))
                callback_match = self._CALLBACK_MEMBER_RE.search(member_name)
                if callback_match is None:
                    continue
                aggregate_name = self._enclosing_aggregate(
                    row,
                    rows_by_id,
                    names,
                )
                if not aggregate_name:
                    continue
                attrs = self._text(getattr(row, "attrs", ""))
                aggregate_members[aggregate_name].append(
                    {
                        "name": callback_match.group(1),
                        "declaration": member_name,
                        "return_type": self._text(getattr(row, "data_type", "")),
                        "signature": self._source_declaration(
                            unit_id,
                            callback_match.group(1),
                        ),
                        "stmt_id": self._positive_int(getattr(row, "stmt_id", None)),
                        "unit_id": unit_id,
                        "pointer_depth": member_name.count("*"),
                        "signature_available": False,
                        "source_evidence": "gir_member_declarator",
                        "attrs": attrs,
                    }
                )

        interfaces: dict[str, dict[str, Any]] = {}
        for aggregate_name, callbacks in aggregate_members.items():
            if not callbacks:
                continue
            interfaces[aggregate_name] = {
                "name": aggregate_name,
                "entity_id": entity_ids_by_name.get(aggregate_name),
                "callback_members": sorted(
                    callbacks,
                    key=lambda item: (item["name"], item["stmt_id"] or 0),
                ),
                "context_members": self._context_members(
                    aggregate_name,
                    aggregates_by_unit,
                ),
                "owners": [],
                "callsites": [],
            }

        self._collect_owners(interfaces, aggregates_by_unit)
        self._collect_callsites(interfaces, entity_ids_by_name)
        contracts: dict[int, dict[str, Any]] = {}
        for interface in interfaces.values():
            related_ids = {
                interface.get("entity_id"),
                *(owner.get("entity_id") for owner in interface["owners"]),
                *(call.get("entity_id") for call in interface["callsites"]),
            }
            related_ids.discard(None)
            for entity_id in related_ids:
                contracts.setdefault(entity_id, {"entity_id": entity_id, "callback_interfaces": []})[
                    "callback_interfaces"
                ].append(self._compact_interface(interface))

        return CallbackInterfaceAnalysisResult(
            interfaces=tuple(
                interfaces[name]
                for name in sorted(interfaces)
            ),
            entity_contracts=tuple(
                {
                    **record,
                    "callback_interfaces": self._dedupe_dicts(
                        record["callback_interfaces"]
                    ),
                }
                for _, record in sorted(contracts.items())
            ),
        )

    def _collect_owners(
        self,
        interfaces: dict[str, dict[str, Any]],
        aggregates_by_unit: dict[int, dict[int, str]],
    ) -> None:
        aggregate_names = set(interfaces)
        for unit_id in self.context.get_all_unit_ids():
            rows = self.context.get_unit_rows(unit_id)
            rows_by_id = {
                stmt_id: row
                for row in rows
                if (stmt_id := self._positive_int(getattr(row, "stmt_id", None)))
                is not None
            }
            for row in rows:
                if self._text(getattr(row, "operation", "")) != "variable_decl":
                    continue
                data_type = self._text(getattr(row, "data_type", ""))
                aggregate_name = next(
                    (name for name in aggregate_names if re.search(rf"\b{re.escape(name)}\b", data_type)),
                    None,
                )
                if aggregate_name is None:
                    continue
                parent_id = self._positive_int(getattr(row, "parent_stmt_id", None))
                parent = rows_by_id.get(parent_id or -1)
                owner_name = ""
                while parent is not None:
                    if self._text(getattr(parent, "operation", "")) in {"struct_decl", "union_decl"}:
                        owner_name = self._text(getattr(parent, "name", ""))
                        break
                    parent_id = self._positive_int(getattr(parent, "parent_stmt_id", None))
                    parent = rows_by_id.get(parent_id or -1)
                if not owner_name:
                    continue
                attrs = self._text(getattr(row, "attrs", ""))
                is_const = bool(re.search(r"\bconst\b", attrs, re.IGNORECASE))
                interfaces[aggregate_name]["owners"].append(
                    {
                        "aggregate": owner_name,
                        "field": self._text(getattr(row, "name", "")),
                        "shared_const_reference": is_const,
                        "stmt_id": self._positive_int(getattr(row, "stmt_id", None)),
                        "unit_id": unit_id,
                    }
                )

    def _collect_callsites(
        self,
        interfaces: dict[str, dict[str, Any]],
        entity_ids_by_name: dict[str, int],
    ) -> None:
        callbacks = {
            member["name"]: aggregate
            for aggregate, interface in interfaces.items()
            for member in interface["callback_members"]
        }
        callback_names = set(callbacks)
        for method_id in self.context.get_all_method_ids():
            method_name = self.context.get_method_name(method_id) or ""
            rows = self.context.get_method_rows(method_id)
            by_target: dict[str, list[Any]] = defaultdict(list)
            for row in rows:
                target = self._text(getattr(row, "target", ""))
                if target:
                    by_target[target].append(row)
            for index, row in enumerate(rows):
                if self._text(getattr(row, "operation", "")) != "call_stmt":
                    continue
                callee = self._text(getattr(row, "name", ""))
                if not self._INDIRECT_CALL_RE.fullmatch(callee):
                    continue
                prior_defs = [
                    definition
                    for definition in by_target.get(callee, ())
                    if (self._positive_int(getattr(definition, "stmt_id", None)) or 0)
                    < (self._positive_int(getattr(row, "stmt_id", None)) or 0)
                ]
                member_name = ""
                for definition in reversed(prior_defs):
                    if self._text(getattr(definition, "operation", "")) != "field_read":
                        continue
                    candidate = self._text(getattr(definition, "field", ""))
                    if candidate in callback_names:
                        member_name = candidate
                        break
                aggregate_name = callbacks.get(member_name)
                if aggregate_name is None:
                    continue
                prior_fields = [
                    self._text(getattr(definition, "field", ""))
                    for definition in rows[:index]
                    if self._text(getattr(definition, "operation", "")) == "field_read"
                ]
                interface = interfaces[aggregate_name]
                owner_fields = {owner["field"] for owner in interface["owners"]}
                config_field = next(
                    (field for field in reversed(prior_fields) if field in owner_fields),
                    None,
                )
                callback = next(
                    item for item in interface["callback_members"]
                    if item["name"] == member_name
                )
                mutability = (
                    "name_inferred_may_mutate_device_state"
                    if member_name.lower() in self._MUTATING_CALLBACK_NAMES
                    else "not_inferred"
                )
                interface["callsites"].append(
                    {
                        "entity_id": entity_ids_by_name.get(method_name, method_id),
                        "method_id": method_id,
                        "method": method_name,
                        "callback": member_name,
                        "callback_stmt_id": callback["stmt_id"],
                        "call_stmt_id": self._positive_int(getattr(row, "stmt_id", None)),
                        "config_field": config_field,
                        "operation_effect": mutability,
                    }
                )

    def _context_members(
        self,
        aggregate_name: str,
        aggregates_by_unit: dict[int, dict[int, str]],
    ) -> list[dict[str, Any]]:
        result = []
        for unit_id, names in aggregates_by_unit.items():
            for stmt_id, name in names.items():
                if name != aggregate_name:
                    continue
                for row in self.context.get_unit_rows(unit_id):
                    if self._text(getattr(row, "operation", "")) != "variable_decl":
                        continue
                    parent_id = self._positive_int(getattr(row, "parent_stmt_id", None))
                    parent = self.context.get_stmt(parent_id) if parent_id else None
                    if parent is None or self._positive_int(getattr(parent, "parent_stmt_id", None)) != stmt_id:
                        continue
                    if "context" not in self._text(getattr(row, "name", "")).lower():
                        continue
                    result.append(
                        {
                            "name": self._text(getattr(row, "name", "")),
                            "type": self._text(getattr(row, "data_type", "")),
                            "stmt_id": self._positive_int(getattr(row, "stmt_id", None)),
                            "opaque_pointer": "void" in self._text(getattr(row, "data_type", "")).lower()
                            and "*" in self._text(getattr(row, "data_type", "")),
                        }
                    )
        return result

    def _source_declaration(self, unit_id: int, member_name: str) -> str | None:
        source_path = self.context.get_unit_path(unit_id)
        if source_path is None:
            return None
        try:
            source = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        declaration = re.search(
            rf"[^;{{}}]*\(\s*\*\s*{re.escape(member_name)}\s*\)\s*\([^;]*\)\s*;",
            source,
            re.DOTALL,
        )
        return (
            self._normalize_space(declaration.group(0))
            if declaration is not None
            else None
        )

    @staticmethod
    def _normalize_space(value: str) -> str:
        return re.sub(r"\s+", " ", value).strip()

    @staticmethod
    def _compact_interface(interface: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": interface["name"],
            "entity_id": interface.get("entity_id"),
            "callbacks": [
                {
                    "name": item["name"],
                    "declaration": item["declaration"],
                    "return_type": item["return_type"],
                    "signature": item.get("signature"),
                }
                for item in interface["callback_members"]
            ],
            "context_members": list(interface["context_members"]),
            "owners": [
                {
                    "aggregate": item["aggregate"],
                    "field": item["field"],
                    "shared_const_reference": item["shared_const_reference"],
                }
                for item in interface["owners"]
            ],
            "callsites": [
                {
                    "entity_id": item["entity_id"],
                    "method": item["method"],
                    "callback": item["callback"],
                    "call_stmt_id": item["call_stmt_id"],
                    "config_field": item["config_field"],
                    "operation_effect": item["operation_effect"],
                }
                for item in interface["callsites"]
            ],
        }

    @staticmethod
    def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique = {json.dumps(value, sort_keys=True): value for value in values}
        return [unique[key] for key in sorted(unique)]

    @staticmethod
    def _enclosing_aggregate(row: Any, rows_by_id: dict[int, Any], names: dict[int, str]) -> str:
        parent_id = CallbackInterfaceAnalyzer._positive_int(getattr(row, "parent_stmt_id", None))
        while parent_id is not None:
            if parent_id in names:
                return names[parent_id]
            parent = rows_by_id.get(parent_id)
            parent_id = CallbackInterfaceAnalyzer._positive_int(
                getattr(parent, "parent_stmt_id", None)
            ) if parent is not None else None
        return ""

    def _read_entities(self) -> tuple[dict[str, Any], ...]:
        try:
            payload = json.loads(self.translation_entities_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise CallbackInterfaceAnalysisError(
                f"failed to read {self.translation_entities_path}: {exc}"
            ) from exc
        entities = payload.get("entities") if isinstance(payload, dict) else None
        if not isinstance(entities, list):
            raise CallbackInterfaceAnalysisError("translation entities has no entities array")
        return tuple(item for item in entities if isinstance(item, dict))

    @staticmethod
    def _positive_int(value: Any) -> int | None:
        try:
            parsed = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return parsed if parsed > 0 else None

    @staticmethod
    def _text(value: Any) -> str:
        if value is None or isinstance(value, float) and math.isnan(value):
            return ""
        return str(value).strip()
