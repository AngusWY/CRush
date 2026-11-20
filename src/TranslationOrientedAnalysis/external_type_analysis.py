from __future__ import annotations

import dataclasses
import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from .analysis_context import AnalysisContext
from .declaration_analysis import PointerAnalyzer


class ExternalTypeAnalysisError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ExternalTypeAnalysisResult:


    external_types: tuple[dict[str, Any], ...]
    entity_contracts: tuple[dict[str, Any], ...]

    def to_payload(self) -> dict[str, Any]:
        return {
            "version": 1,
            "kind": "external_type_semantics",
            "external_types": [dict(item) for item in self.external_types],
            "entity_contracts": [dict(item) for item in self.entity_contracts],
        }


class ExternalTypeAnalyzer:


    _STRUCT_TYPE_RE = re.compile(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)")
    _TYPE_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
    _FUNCTION_POINTER_RE = re.compile(
        r"(?P<result>.*?)\(\s*\*\s*\)\s*\((?P<params>.*)\)", re.DOTALL
    )

    def __init__(
        self,
        context: AnalysisContext,
        *,
        translation_entities_path: Path,
    ) -> None:
        self.context = context
        self.translation_entities_path = translation_entities_path
        self._type_resolver = PointerAnalyzer(context)

    def analyze(self) -> ExternalTypeAnalysisResult:
        entities = self._read_entities()
        entities_by_id = {int(item["id"]): item for item in entities}
        entity_ids_by_name: dict[str, int] = {
            str(item["name"]): int(item["id"])
            for item in entities
            if isinstance(item.get("name"), str)
        }
        local_aggregates = self._local_aggregate_names()
        external_names = self._referenced_struct_names() - local_aggregates

        external_records: dict[str, dict[str, Any]] = {
            name: {
                "name": name,
                "kind": "struct",
                "defined_in_project": False,
                "fields": {},
                "member_declarations": [],
            }
            for name in sorted(external_names)
        }
        per_entity: dict[int, dict[str, Any]] = {}

        def contract(entity_id: int) -> dict[str, Any]:
            return per_entity.setdefault(
                entity_id,
                {
                    "entity_id": entity_id,
                    "function_pointer_types": [],
                    "external_types": [],
                    "field_usage": [],
                    "ambiguous_field_receivers": [],
                    "return_contract": None,
                },
            )

        self._collect_external_members(
            external_records,
            entities_by_id,
            entity_ids_by_name,
            contract,
        )
        self._collect_function_pointer_aliases(
            external_names,
            external_records,
            entities_by_id,
            entity_ids_by_name,
            contract,
        )
        self._collect_method_field_usage(
            external_names,
            external_records,
            entity_ids_by_name,
            contract,
        )
        self._collect_alias_users(
            entities,
            entity_ids_by_name,
            contract,
        )

        normalized_external = tuple(
            self._normalize_external_record(record)
            for _, record in sorted(external_records.items())
        )
        normalized_contracts = tuple(
            self._normalize_entity_contract(record)
            for _, record in sorted(per_entity.items())
        )
        return ExternalTypeAnalysisResult(
            external_types=normalized_external,
            entity_contracts=normalized_contracts,
        )

    def _collect_external_members(
        self,
        external_records: dict[str, dict[str, Any]],
        entities_by_id: dict[int, dict[str, Any]],
        entity_ids_by_name: dict[str, int],
        contract: Any,
    ) -> None:
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
                names = self._struct_names(data_type)
                external_name = next(
                    (name for name in names if name in external_records),
                    None,
                )
                if external_name is None:
                    continue
                parent_id = self._positive_int(
                    getattr(row, "parent_stmt_id", None)
                )
                parent = rows_by_id.get(parent_id or -1)
                aggregate_name = ""
                while parent is not None:
                    if self._text(getattr(parent, "operation", "")) in {
                        "struct_decl",
                        "union_decl",
                    }:
                        aggregate_name = self._text(
                            getattr(parent, "name", "")
                        )
                        break
                    parent_id = self._positive_int(
                        getattr(parent, "parent_stmt_id", None)
                    )
                    parent = rows_by_id.get(parent_id or -1)
                entity_id = entity_ids_by_name.get(aggregate_name)
                record = external_records[external_name]
                record["member_declarations"].append(
                    {
                        "aggregate": aggregate_name or None,
                        "member": self._text(getattr(row, "name", "")),
                        "source_type": data_type,
                        "entity_id": entity_id,
                        "stmt_id": self._positive_int(
                            getattr(row, "stmt_id", None)
                        ),
                    }
                )
                if entity_id is not None:
                    contract(entity_id)["external_types"].append(
                        {
                            "name": external_name,
                            "role": "aggregate_member",
                            "member": self._text(getattr(row, "name", "")),
                        }
                    )

    def _collect_function_pointer_aliases(
        self,
        external_names: set[str],
        external_records: dict[str, dict[str, Any]],
        entities_by_id: dict[int, dict[str, Any]],
        entity_ids_by_name: dict[str, int],
        contract: Any,
    ) -> None:
        aliases: dict[str, dict[str, Any]] = {}
        for unit_id in self.context.get_all_unit_ids():
            for row in self.context.get_unit_rows(unit_id):
                if self._text(getattr(row, "operation", "")) != "type_alias_decl":
                    continue
                alias_name = self._text(getattr(row, "name", ""))
                signature = self._text(getattr(row, "data_type", ""))
                match = self._FUNCTION_POINTER_RE.search(signature)
                if not alias_name or match is None:
                    continue
                result_type = self._normalize_type_text(match.group("result"))
                parameters = self._split_parameters(match.group("params"))
                referenced = sorted(self._mentioned_external_names(signature, external_names))
                if not referenced:
                    continue
                entity_id = entity_ids_by_name.get(alias_name)
                alias = {
                    "name": alias_name,
                    "entity_id": entity_id,
                    "signature": signature,
                    "parameters": parameters,
                    "return_type": result_type,
                    "nullable_function_pointer": True,
                    "external_types": referenced,
                }
                aliases[alias_name] = alias
                if entity_id is not None:
                    contract(entity_id)["function_pointer_types"].append(alias)
                    contract(entity_id)["external_types"].extend(
                        {"name": name, "role": "function_pointer_signature"}
                        for name in referenced
                    )
                if "*" in result_type:
                    for name in self._mentioned_external_names(result_type, external_names):
                        record = external_records[name]
                        record.setdefault("returned_by_aliases", []).append(
                            alias_name
                        )

        self._function_pointer_aliases = aliases

    def _collect_method_field_usage(
        self,
        external_names: set[str],
        external_records: dict[str, dict[str, Any]],
        entity_ids_by_name: dict[str, int],
        contract: Any,
    ) -> None:
        for method_id in self.context.get_all_method_ids():
            method_name = self.context.get_method_name(method_id) or ""
            entity_id = entity_ids_by_name.get(method_name, method_id)
            method_rows = self.context.get_method_rows(method_id)
            for row in method_rows:
                operation = self._text(getattr(row, "operation", ""))
                if operation not in {"field_read", "field_write"}:
                    continue
                stmt_id = self._positive_int(getattr(row, "stmt_id", None))
                receiver = self._text(
                    getattr(row, "receiver_object", "")
                )
                field = self._text(getattr(row, "field", ""))
                if stmt_id is None or not receiver or not field:
                    continue
                receiver_types = self._type_resolver._receiver_type_names(
                    method_id,
                    stmt_id,
                    receiver,
                )
                candidates = sorted(receiver_types & external_names)
                if not candidates:
                    continue
                access = {
                    "entity_id": entity_id,
                    "method_id": method_id,
                    "method": method_name,
                    "stmt_id": stmt_id,
                    "operation": "read" if operation == "field_read" else "write",
                    "field": field,
                    "receiver": receiver,
                }
                if len(candidates) > 1:
                    contract(entity_id)["ambiguous_field_receivers"].append(
                        {
                            "candidate_types": candidates,
                            "field": field,
                            "operation": access["operation"],
                            "stmt_id": stmt_id,
                        }
                    )
                    continue
                external_type = candidates[0]
                external_records[external_type]["fields"].setdefault(
                    field,
                    {"read_by": [], "written_by": []},
                )
                key = "read_by" if operation == "field_read" else "written_by"
                external_records[external_type]["fields"][field][key].append(
                    {"entity_id": entity_id, "stmt_id": stmt_id}
                )
                contract(entity_id)["field_usage"].append(
                    {
                        "external_type": external_type,
                        "field": field,
                        "operation": access["operation"],
                        "stmt_id": stmt_id,
                    }
                )

            method_decl = next(
                (
                    row
                    for row in method_rows
                    if self._text(getattr(row, "operation", ""))
                    == "method_decl"
                ),
                None,
            )
            if method_decl is not None:
                return_type = self._text(getattr(method_decl, "data_type", ""))
                returned_types = sorted(
                    self._struct_names(return_type) & external_names
                )
                if returned_types:
                    contract(entity_id)["return_contract"] = {
                        "return_type": return_type,
                        "external_types": returned_types,
                        "nullable": "*" in return_type,
                    }

    def _collect_alias_users(
        self,
        entities: tuple[dict[str, Any], ...],
        entity_ids_by_name: dict[str, int],
        contract: Any,
    ) -> None:
        aliases = getattr(self, "_function_pointer_aliases", {})
        if not aliases:
            return
        for unit_id in self.context.get_all_unit_ids():
            for row in self.context.get_unit_rows(unit_id):
                operation = self._text(getattr(row, "operation", ""))
                if operation not in {"variable_decl", "parameter_decl"}:
                    continue
                data_type = self._text(getattr(row, "data_type", ""))
                alias = aliases.get(data_type)
                if alias is None:
                    continue
                stmt_id = self._positive_int(getattr(row, "stmt_id", None))
                entity_id = stmt_id if stmt_id in {
                    int(item["id"]) for item in entities
                } else None
                method_id = self.context.get_method_id(stmt_id or 0)
                if entity_id is None and method_id is not None:
                    method_name = self.context.get_method_name(method_id) or ""
                    entity_id = entity_ids_by_name.get(method_name, method_id)
                if entity_id is None:
                    continue
                contract(entity_id)["function_pointer_types"].append(
                    {
                        "name": alias["name"],
                        "use": self._text(getattr(row, "name", "")),
                        "entity_id": alias.get("entity_id"),
                        "nullable_function_pointer": True,
                        "external_types": list(alias["external_types"]),
                    }
                )
                contract(entity_id)["external_types"].extend(
                    {"name": name, "role": "function_pointer_value"}
                    for name in alias["external_types"]
                )

    def _local_aggregate_names(self) -> set[str]:
        names: set[str] = set()
        for unit_id in self.context.get_all_unit_ids():
            for row in self.context.get_unit_rows(unit_id):
                if self._text(getattr(row, "operation", "")) in {
                    "struct_decl",
                    "union_decl",
                }:
                    name = self._text(getattr(row, "name", ""))
                    if name:
                        names.add(name)
        return names

    def _referenced_struct_names(self) -> set[str]:
        names: set[str] = set()
        for unit_id in self.context.get_all_unit_ids():
            for row in self.context.get_unit_rows(unit_id):
                names.update(
                    self._struct_names(
                        getattr(row, "data_type", "")
                    )
                )
        return names

    @classmethod
    def _struct_names(cls, value: Any) -> set[str]:
        return set(cls._STRUCT_TYPE_RE.findall(cls._text(value)))

    @classmethod
    def _mentioned_external_names(
        cls,
        value: Any,
        external_names: set[str],
    ) -> set[str]:
        text = cls._text(value)
        explicit = cls._struct_names(text)
        if explicit:
            return explicit & external_names
        identifiers = set(cls._TYPE_NAME_RE.findall(text))
        return identifiers & external_names

    @staticmethod
    def _split_parameters(value: str) -> list[str]:
        if not value.strip() or value.strip() == "void":
            return []
        result: list[str] = []
        depth = 0
        start = 0
        for index, char in enumerate(value):
            if char in "([":
                depth += 1
            elif char in ")]":
                depth = max(0, depth - 1)
            elif char == "," and depth == 0:
                result.append(ExternalTypeAnalyzer._normalize_type_text(value[start:index]))
                start = index + 1
        result.append(ExternalTypeAnalyzer._normalize_type_text(value[start:]))
        return [item for item in result if item]

    @staticmethod
    def _normalize_type_text(value: Any) -> str:
        return re.sub(r"\s+", " ", ExternalTypeAnalyzer._text(value)).strip()

    def _read_entities(self) -> tuple[dict[str, Any], ...]:
        try:
            payload = json.loads(
                self.translation_entities_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise ExternalTypeAnalysisError(
                f"failed to read {self.translation_entities_path}: {exc}"
            ) from exc
        entities = payload.get("entities") if isinstance(payload, dict) else None
        if not isinstance(entities, list):
            raise ExternalTypeAnalysisError(
                "translation entities has no entities array"
            )
        return tuple(
            item
            for item in entities
            if isinstance(item, dict)
            and isinstance(item.get("id"), int)
            and isinstance(item.get("name"), str)
        )

    @classmethod
    def _normalize_external_record(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        fields = {
            name: {
                key: sorted(
                    entries,
                    key=lambda item: (
                        item.get("entity_id", 0), item.get("stmt_id", 0)
                    ),
                )
                for key, entries in field_value.items()
            }
            for name, field_value in sorted(value["fields"].items())
        }
        return {
            **value,
            "fields": fields,
            "member_declarations": sorted(
                value["member_declarations"],
                key=lambda item: (
                    item.get("aggregate") or "",
                    item.get("member") or "",
                ),
            ),
        }

    @classmethod
    def _normalize_entity_contract(
        cls,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        value["external_types"] = cls._dedupe_dicts(value["external_types"])
        value["function_pointer_types"] = cls._dedupe_dicts(
            value["function_pointer_types"]
        )
        value["field_usage"] = cls._dedupe_dicts(value["field_usage"])
        value["ambiguous_field_receivers"] = cls._dedupe_dicts(
            value["ambiguous_field_receivers"]
        )
        return value

    @staticmethod
    def _dedupe_dicts(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique = {
            json.dumps(value, sort_keys=True, ensure_ascii=True): value
            for value in values
        }
        return [unique[key] for key in sorted(unique)]

    @staticmethod
    def _positive_int(value: Any) -> int | None:
        try:
            parsed = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return parsed if parsed > 0 else None

    @staticmethod
    def _text(value: Any) -> str:
        if value is None or (isinstance(value, float) and math.isnan(value)):
            return ""
        return str(value).strip()
