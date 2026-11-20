from __future__ import annotations

import dataclasses
import re
from collections.abc import Mapping, Sequence
from typing import Any

from TranslationPreprocess.c_source_lex import comment_start_columns, mask_c_non_code
from TranslationOrientedAnalysis.semantic_hint_schemas import PointerDeclarationSemantics

from .models import (
    AnchorPlacement,
    AnchorPlacementKind,
    EntityHintPackage,
    EntityMetadata,
    SemanticHint,
    SemanticHintManifestEntry,
    SemanticTarget,
    SourceSpan,
)


class SemanticHintGenerationError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class TargetLinePlacement:


    target: SemanticTarget
    line_index: int
    kind: AnchorPlacementKind
    fallback_reason: str | None = None


@dataclasses.dataclass(frozen=True)
class SemanticHintInput:


    target: SemanticTarget
    facts: dict[str, Any]
    unresolved_fields: tuple[str, ...] = ()


@dataclasses.dataclass(frozen=True)
class GeneratedEntityHints:


    package: EntityHintPackage
    semantic_hints: tuple[SemanticHint, ...]


class SemanticHintGenerator:


    def generate_entity_hints(
        self,
        *,
        entity: EntityMetadata,
        original_c_source: str,
        analysis_c_source: str | None = None,
        pointer_records: Sequence[Mapping[str, Any]],
        unsafe_stmt_records: Sequence[Mapping[str, Any]] = (),
        function_return_record: Mapping[str, Any] | None = None,
        external_type_record: Mapping[str, Any] | None = None,
        callback_interface_record: Mapping[str, Any] | None = None,
        human_comment_ids: Sequence[str] = (),
        macro_context: Sequence[Mapping[str, Any]] = (),
    ) -> GeneratedEntityHints:


        hint_inputs = self.construct_hint_inputs(
            entity=entity,
            pointer_records=pointer_records,
            unsafe_stmt_records=unsafe_stmt_records,
            function_return_record=function_return_record,
            external_type_record=external_type_record,
            callback_interface_record=callback_interface_record,
        )
        if not hint_inputs:
            return GeneratedEntityHints(
                package=EntityHintPackage(
                    version=4,
                    entity=entity,
                    original_c_source=(
                        original_c_source
                        if analysis_c_source is None
                        else analysis_c_source
                    ),
                    annotated_c_source=original_c_source,
                    hint_anchor_ids=(),
                    human_comment_ids=tuple(human_comment_ids),
                    macro_context=tuple(dict(item) for item in macro_context),
                ),
                semantic_hints=(),
            )

        line_placements = self.choose_anchor_lines(
            entity=entity,
            original_c_source=original_c_source,
            hint_inputs=hint_inputs,
        )
        anchor_placements = self.allocate_anchor_ids(line_placements)
        annotated_c_source = self.annotate_line_ends(
            original_c_source=original_c_source,
            placements=anchor_placements,
        )
        semantic_hints = self.build_semantic_hints(
            placements=anchor_placements,
            hint_inputs=hint_inputs,
        )

        return GeneratedEntityHints(
            package=EntityHintPackage(
                version=4,
                entity=entity,
                original_c_source=(
                    original_c_source
                    if analysis_c_source is None
                    else analysis_c_source
                ),
                annotated_c_source=annotated_c_source,
                hint_anchor_ids=tuple(
                    hint.anchor_id for hint in semantic_hints
                ),
                human_comment_ids=tuple(human_comment_ids),
                macro_context=tuple(dict(item) for item in macro_context),
            ),
            semantic_hints=semantic_hints,
        )

    def generate_package(
        self,
        *,
        entity: EntityMetadata,
        original_c_source: str,
        analysis_c_source: str | None = None,
        pointer_records: Sequence[Mapping[str, Any]],
        unsafe_stmt_records: Sequence[Mapping[str, Any]] = (),
        function_return_record: Mapping[str, Any] | None = None,
        external_type_record: Mapping[str, Any] | None = None,
        callback_interface_record: Mapping[str, Any] | None = None,
        human_comment_ids: Sequence[str] = (),
        macro_context: Sequence[Mapping[str, Any]] = (),
    ) -> EntityHintPackage:


        return self.generate_entity_hints(
            entity=entity,
            original_c_source=original_c_source,
            analysis_c_source=analysis_c_source,
            pointer_records=pointer_records,
            unsafe_stmt_records=unsafe_stmt_records,
            function_return_record=function_return_record,
            external_type_record=external_type_record,
            callback_interface_record=callback_interface_record,
            human_comment_ids=human_comment_ids,
            macro_context=macro_context,
        ).package

    def construct_hint_inputs(
        self,
        *,
        entity: EntityMetadata,
        pointer_records: Sequence[Mapping[str, Any]],
        unsafe_stmt_records: Sequence[Mapping[str, Any]] = (),
        function_return_record: Mapping[str, Any] | None = None,
        external_type_record: Mapping[str, Any] | None = None,
        callback_interface_record: Mapping[str, Any] | None = None,
    ) -> tuple[SemanticHintInput, ...]:


        inputs: list[SemanticHintInput] = []
        seen_stmt_ids: set[int] = set()

        for index, record in enumerate(pointer_records):
            hint_input = self._construct_pointer_input(entity, record, index)
            if hint_input.target.stmt_id in seen_stmt_ids:
                raise SemanticHintGenerationError(
                    f"entity {entity.entity_id} has duplicate semantic hint "
                    f"stmt_id {hint_input.target.stmt_id}"
                )
            seen_stmt_ids.add(hint_input.target.stmt_id)
            inputs.append(hint_input)

        for index, record in enumerate(unsafe_stmt_records):
            unsafe_input = self._construct_unsafe_stmt_input(entity, record, index)
            if unsafe_input is None:
                continue
            if unsafe_input.target.stmt_id in seen_stmt_ids:
                raise SemanticHintGenerationError(
                    f"entity {entity.entity_id} has duplicate semantic hint "
                    f"stmt_id {unsafe_input.target.stmt_id}"
                )
            seen_stmt_ids.add(unsafe_input.target.stmt_id)
            inputs.append(unsafe_input)

        if function_return_record is not None:
            function_input = self._construct_function_return_input(
                entity,
                function_return_record,
            )
            if function_input is not None:
                if function_input.target.stmt_id in seen_stmt_ids:
                    raise SemanticHintGenerationError(
                        f"entity {entity.entity_id} has duplicate function "
                        "return semantic target"
                    )
                inputs.append(function_input)

        if external_type_record is not None and inputs:
            external_facts = self._compact_external_type_facts(
                external_type_record
            )
            if external_facts:
                first = inputs[0]
                inputs[0] = dataclasses.replace(
                    first,
                    facts={**first.facts, "external_interface": external_facts},
                )

        if callback_interface_record is not None:
            callback_facts = self._compact_callback_interface_facts(
                callback_interface_record
            )
            if callback_facts:
                if inputs:
                    first = inputs[0]
                    inputs[0] = dataclasses.replace(
                        first,
                        facts={**first.facts, "callback_interface": callback_facts},
                    )
                else:
                    callback_target = SemanticTarget(
                        entity_id=entity.entity_id,
                        stmt_id=entity.entity_id,
                        unit_id=entity.unit_id,
                        method_id=None,
                        source=entity.source,
                        operation="callback_interface_contract",
                        name=entity.name,
                        location="type" if entity.kind == "type" else "function",
                        semantic_kind="callback_interface",
                    )
                    inputs.append(
                        SemanticHintInput(
                            target=callback_target,
                            facts={"callback_interface": callback_facts},
                        )
                    )

        return tuple(
            sorted(
                inputs,
                key=lambda item: (
                    item.target.source.start_line,
                    item.target.source.start_col,
                    item.target.source.end_line,
                    item.target.source.end_col,
                    item.target.stmt_id,
                ),
            )
        )

    @staticmethod
    def _compact_external_type_facts(
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        external_types = record.get("external_types")
        pointer_types = record.get("function_pointer_types")
        field_usage = record.get("field_usage")
        ambiguous_field_receivers = record.get("ambiguous_field_receivers")
        return_contract = record.get("return_contract")
        result: dict[str, Any] = {}
        if isinstance(external_types, list):
            result["external_types"] = [
                dict(item)
                for item in external_types
                if isinstance(item, Mapping)
            ]
        if isinstance(pointer_types, list):
            result["function_pointer_types"] = [
                {
                    key: value
                    for key, value in item.items()
                    if key in {
                        "name",
                        "use",
                        "signature",
                        "parameters",
                        "return_type",
                        "nullable_function_pointer",
                        "external_types",
                    }
                }
                for item in pointer_types
                if isinstance(item, Mapping)
            ]
        if isinstance(field_usage, list):
            grouped: dict[str, dict[str, set[str]]] = {}
            for item in field_usage:
                if not isinstance(item, Mapping):
                    continue
                type_name = item.get("external_type")
                field_name = item.get("field")
                operation = item.get("operation")
                if not all(isinstance(value, str) for value in (type_name, field_name, operation)):
                    continue
                grouped.setdefault(type_name, {}).setdefault(field_name, set()).add(operation)
            result["observed_fields"] = {
                type_name: {
                    field_name: sorted(operations)
                    for field_name, operations in sorted(fields.items())
                }
                for type_name, fields in sorted(grouped.items())
            }
        if isinstance(ambiguous_field_receivers, list):
            result["ambiguous_field_receivers"] = [
                {
                    key: item[key]
                    for key in ("candidate_types", "field", "operation")
                    if key in item
                }
                for item in ambiguous_field_receivers
                if isinstance(item, Mapping)
                and isinstance(item.get("candidate_types"), list)
            ]
        if isinstance(return_contract, Mapping):
            result["return_contract"] = {
                key: value
                for key, value in return_contract.items()
                if key in {"return_type", "external_types", "nullable"}
            }
        return result

    @staticmethod
    def _compact_callback_interface_facts(
        record: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        interfaces = record.get("callback_interfaces")
        if not isinstance(interfaces, list):
            return []
        compact = []
        for interface in interfaces:
            if not isinstance(interface, Mapping):
                continue
            callbacks = interface.get("callbacks")
            if not isinstance(callbacks, list) or not callbacks:
                continue
            compact.append(
                {
                    "name": interface.get("name"),
                    "callbacks": [
                        {
                            key: callback[key]
                            for key in ("name", "declaration", "return_type", "signature")
                            if key in callback
                        }
                        for callback in callbacks
                        if isinstance(callback, Mapping)
                    ],
                    "context_members": [
                        {
                            key: member[key]
                            for key in ("name", "type", "opaque_pointer")
                            if key in member
                        }
                        for member in interface.get("context_members", [])
                        if isinstance(member, Mapping)
                    ],
                    "owners": [
                        {
                            key: owner[key]
                            for key in ("aggregate", "field", "shared_const_reference")
                            if key in owner
                        }
                        for owner in interface.get("owners", [])
                        if isinstance(owner, Mapping)
                    ],
                    "callsites": [
                        {
                            key: call[key]
                            for key in (
                                "entity_id",
                                "method",
                                "callback",
                                "config_field",
                                "operation_effect",
                            )
                            if key in call
                        }
                        for call in interface.get("callsites", [])
                        if isinstance(call, Mapping)
                    ],
                }
            )
        return compact

    def _construct_function_return_input(
        self,
        entity: EntityMetadata,
        record: Mapping[str, Any],
    ) -> SemanticHintInput | None:
        provenance = record.get("return_provenance")
        caller_usage = record.get("caller_usage")
        if not isinstance(provenance, Mapping):
            raise SemanticHintGenerationError(
                f"function return record for entity {entity.entity_id} has "
                "no return_provenance object"
            )
        if not isinstance(caller_usage, Mapping):
            caller_usage = {}
        origins = provenance.get("origins")
        if not isinstance(origins, list):
            origins = []
        non_null_origins = [
            item
            for item in origins
            if isinstance(item, Mapping) and item.get("kind") != "null"
        ]
        if not non_null_origins:
            return None

        facts: dict[str, Any] = {
            "return_provenance": dict(provenance),
            "caller_usage": dict(caller_usage),
        }
        single_array_origin = self._single_array_origin(
            provenance,
            caller_usage,
        )
        if single_array_origin is not None:
            parameter = single_array_origin.get("parameter")
            if isinstance(parameter, str) and parameter:
                facts["translation_constraint"] = {
                    "preferred_rust_type": "Option<usize>",
                    "indexes_parameter": parameter,
                    "avoid_rust_types": ["Option<&mut Element>"],
                    "reason_code": "retained_across_same_slice_reselection",
                }
        target = record.get("target")
        if not isinstance(target, Mapping):
            raise SemanticHintGenerationError(
                f"function return record for entity {entity.entity_id} "
                "has no target object"
            )
        target = dict(target)
        target["source"] = self._normalize_function_source(
            target.get("source"), entity
        )
        semantic_target = self._target_from_dict(
            target,
            f"function return record for entity {entity.entity_id}",
        )
        if semantic_target.entity_id != entity.entity_id:
            raise SemanticHintGenerationError(
                f"function return record belongs to entity "
                f"{semantic_target.entity_id}, expected {entity.entity_id}"
            )
        self._validate_source_membership(
            entity,
            semantic_target,
            f"function return record for entity {entity.entity_id}",
        )
        return SemanticHintInput(target=semantic_target, facts=facts)

    @staticmethod
    def _single_array_origin(
        provenance: Mapping[str, Any],
        caller_usage: Mapping[str, Any],
    ) -> Mapping[str, Any] | None:
        if provenance.get("confidence") != "exact":
            return None
        if caller_usage.get("retained_across_repeated_call") is not True:
            return None
        if caller_usage.get("repeated_call_uses_same_base") is not True:
            return None
        if caller_usage.get("simultaneous_element_access") is not True:
            return None
        raw_origins = provenance.get("origins")
        if not isinstance(raw_origins, list):
            return None
        origins = [
            item
            for item in raw_origins
            if isinstance(item, Mapping) and item.get("kind") != "null"
        ]
        if not origins:
            return None
        first = origins[0]
        if any(
            item.get("kind") != "parameter_projection"
            or item.get("parameter") != first.get("parameter")
            or item.get("parameter_index") != first.get("parameter_index")
            or not isinstance(item.get("projection"), Mapping)
            or item["projection"].get("kind") != "array_element"
            for item in origins
        ):
            return None
        return first

    @staticmethod
    def _normalize_function_source(
        source: Any,
        entity: EntityMetadata,
    ) -> dict[str, Any]:
        if not isinstance(source, Mapping):
            return entity.source.to_dict()
        normalized = dict(source)
        normalized.setdefault("path", entity.source.path)
        normalized.setdefault("rel_path", entity.source.rel_path)
        normalized.setdefault("start_line", entity.source.start_line)
        normalized.setdefault("start_col", entity.source.start_col)
        normalized.setdefault("end_line", entity.source.end_line)
        normalized.setdefault("end_col", entity.source.end_col)
        return normalized

    def construct_semantic_targets(
        self,
        *,
        entity: EntityMetadata,
        pointer_records: Sequence[Mapping[str, Any]],
    ) -> tuple[SemanticTarget, ...]:


        return tuple(
            item.target
            for item in self.construct_hint_inputs(
                entity=entity,
                pointer_records=pointer_records,
            )
        )

    def choose_anchor_lines(
        self,
        *,
        entity: EntityMetadata,
        original_c_source: str,
        hint_inputs: Sequence[SemanticHintInput],
    ) -> tuple[TargetLinePlacement, ...]:


        line_count = self._source_line_count(original_c_source)
        placements = [
            self._choose_anchor_line(
                entity,
                hint_input.target,
                original_c_source,
                line_count,
            )
            for hint_input in hint_inputs
        ]
        return tuple(
            sorted(
                placements,
                key=lambda placement: (
                    placement.line_index,
                    placement.target.source.start_col,
                    placement.target.stmt_id,
                ),
            )
        )

    def allocate_anchor_ids(
        self,
        placements: Sequence[TargetLinePlacement],
    ) -> tuple[AnchorPlacement, ...]:


        ordered = sorted(
            placements,
            key=lambda placement: (
                placement.line_index,
                placement.target.source.start_col,
                placement.target.stmt_id,
            ),
        )
        anchor_placements = tuple(
            AnchorPlacement(
                anchor_id=self._anchor_id_for_target(placement.target),
                target=placement.target,
                line_index=placement.line_index,
                kind=placement.kind,
                fallback_reason=placement.fallback_reason,
            )
            for placement in ordered
        )
        anchor_ids = [placement.anchor_id for placement in anchor_placements]
        if len(anchor_ids) != len(set(anchor_ids)):
            raise SemanticHintGenerationError(
                "duplicate semantic hint anchor IDs generated"
            )
        return anchor_placements

    def annotate_line_ends(
        self,
        *,
        original_c_source: str,
        placements: Sequence[AnchorPlacement],
    ) -> str:


        if not placements:
            return original_c_source

        lines = original_c_source.splitlines(keepends=True)
        if not lines:
            lines = [""]

        anchors_by_line: dict[int, list[AnchorPlacement]] = {}
        comment_columns = comment_start_columns(original_c_source)
        for placement in placements:
            if placement.line_index >= len(lines):
                raise SemanticHintGenerationError(
                    f"anchor {placement.anchor_id} line index "
                    f"{placement.line_index} is outside source with "
                    f"{len(lines)} lines"
                )
            anchors_by_line.setdefault(placement.line_index, []).append(
                placement
            )

        for line_index, line_placements in anchors_by_line.items():
            ordered = sorted(
                line_placements,
                key=lambda placement: (
                    placement.target.source.start_col,
                    placement.target.stmt_id,
                    placement.anchor_id,
                ),
            )
            body, line_ending = self._split_line_ending(lines[line_index])
            anchor = self._render_anchor_comment(
                [placement.anchor_id for placement in ordered]
            )
            comment_column = comment_columns.get(line_index)
            if comment_column is None or comment_column >= len(body):
                annotated_body = body + " " + anchor
            else:
                annotated_body = (
                    body[:comment_column]
                    + anchor
                    + " "
                    + body[comment_column:]
                )
            lines[line_index] = annotated_body + line_ending

        return "".join(lines)

    def build_semantic_hints(
        self,
        *,
        placements: Sequence[AnchorPlacement],
        hint_inputs: Sequence[SemanticHintInput],
    ) -> tuple[SemanticHint, ...]:


        inputs_by_stmt = {item.target.stmt_id: item for item in hint_inputs}
        hints: list[SemanticHint] = []
        seen_anchor_ids: set[str] = set()
        for placement in sorted(
            placements,
            key=lambda item: (
                item.line_index,
                item.target.source.start_col,
                item.target.stmt_id,
            ),
        ):
            if placement.anchor_id in seen_anchor_ids:
                raise SemanticHintGenerationError(
                    f"duplicate anchor_id: {placement.anchor_id}"
                )
            seen_anchor_ids.add(placement.anchor_id)

            hint_input = inputs_by_stmt.get(placement.target.stmt_id)
            if hint_input is None:
                raise SemanticHintGenerationError(
                    f"anchor {placement.anchor_id} has no semantic facts "
                    f"for stmt {placement.target.stmt_id}"
                )
            hints.append(
                SemanticHint(
                    anchor_id=placement.anchor_id,
                    target=placement.target,
                    facts=hint_input.facts,
                    placement_kind=placement.kind,
                    line_index=placement.line_index,
                    unresolved_fields=hint_input.unresolved_fields,
                    fallback_reason=placement.fallback_reason,
                )
            )
        return tuple(hints)

    @staticmethod
    def manifest_entry_for_package(
        *,
        package: EntityHintPackage,
        package_file: str,
    ) -> SemanticHintManifestEntry:


        return SemanticHintManifestEntry(
            entity_id=package.entity.entity_id,
            kind=package.entity.kind,
            package_file=package_file,
            hint_count=len(package.hint_anchor_ids),
            human_comment_count=len(package.human_comment_ids),
        )

    def _construct_pointer_input(
        self,
        entity: EntityMetadata,
        record: Mapping[str, Any],
        index: int,
    ) -> SemanticHintInput:
        description = (
            f"pointer record {index} for entity {entity.entity_id}"
        )
        record_entity_id = self._positive_int(
            record.get("entity_id"),
            f"{description} entity_id",
        )
        if record_entity_id != entity.entity_id:
            raise SemanticHintGenerationError(
                f"{description} belongs to entity {record_entity_id}"
            )

        raw_target = record.get("target")
        if not isinstance(raw_target, Mapping):
            raise SemanticHintGenerationError(
                f"{description} has no target object; regenerate semantic "
                "analysis output with pointer semantics version 4"
            )

        try:
            semantics = PointerDeclarationSemantics.from_dict(dict(record))
        except (KeyError, TypeError, ValueError) as exc:
            raise SemanticHintGenerationError(
                f"{description} has invalid semantic facts: {exc}"
            ) from exc

        target = self._target_from_dict(raw_target, description)
        self._validate_pointer_target_identity(
            entity=entity,
            semantics=semantics,
            target=target,
            record_entity_id=record_entity_id,
            description=description,
        )
        self._validate_source_membership(entity, target, description)
        facts = semantics.to_dict()
        unresolved_fields = tuple(semantics.missing_fields())
        return SemanticHintInput(
            target=target,
            facts=facts,
            unresolved_fields=unresolved_fields,
        )

    def _construct_unsafe_stmt_input(
        self,
        entity: EntityMetadata,
        record: Mapping[str, Any],
        index: int,
    ) -> SemanticHintInput | None:
        description = (
            f"unsafe stmt record {index} for entity {entity.entity_id}"
        )
        record_entity_id = self._positive_int(
            record.get("entity_id"),
            f"{description} entity_id",
        )
        if record_entity_id != entity.entity_id:
            raise SemanticHintGenerationError(
                f"{description} belongs to entity {record_entity_id}"
            )
        raw_target = record.get("target")
        if not isinstance(raw_target, Mapping):
            raise SemanticHintGenerationError(
                f"{description} has no target object"
            )
        raw_facts = record.get("semantic_hints")
        if not isinstance(raw_facts, Mapping):
            raise SemanticHintGenerationError(
                f"{description} semantic_hints must be an object"
            )
        facts = self._json_object(raw_facts, f"{description} semantic_hints")
        if not facts:
            return None

        target = self._target_from_dict(raw_target, description)
        self._validate_unsafe_target_identity(
            entity=entity,
            record=record,
            target=target,
            record_entity_id=record_entity_id,
            description=description,
        )
        self._validate_source_membership(entity, target, description)
        return SemanticHintInput(target=target, facts=facts)

    def _target_from_dict(
        self,
        value: Mapping[str, Any],
        description: str,
    ) -> SemanticTarget:
        raw_source = value.get("source")
        if not isinstance(raw_source, dict):
            raise SemanticHintGenerationError(
                f"{description} target has no source object"
            )

        try:
            source = SourceSpan.from_dict(raw_source)
        except (KeyError, TypeError, ValueError) as exc:
            raise SemanticHintGenerationError(
                f"{description} has invalid target metadata: {exc}"
            ) from exc

        return SemanticTarget(
            entity_id=self._positive_int(
                value.get("entity_id"),
                f"{description} target entity_id",
            ),
            stmt_id=self._positive_int(
                value.get("stmt_id"),
                f"{description} target stmt_id",
            ),
            unit_id=self._positive_int(
                value.get("unit_id"),
                f"{description} target unit_id",
            ),
            method_id=self._optional_positive_int(
                value.get("method_id"),
                f"{description} target method_id",
            ),
            name=self._optional_text(value.get("name")),
            c_type=self._optional_text(value.get("c_type")),
            operation=self._required_text(
                value.get("operation"),
                f"{description} target operation",
            ),
            location=self._optional_text(value.get("location")),
            semantic_kind=self._optional_text(value.get("semantic_kind")),
            aggregate_id=self._optional_positive_int(
                value.get("aggregate_id"),
                f"{description} target aggregate_id",
            ),
            aggregate_name=self._optional_text(value.get("aggregate_name")),
            source=source,
        )

    @staticmethod
    def _validate_pointer_target_identity(
        *,
        entity: EntityMetadata,
        semantics: PointerDeclarationSemantics,
        target: SemanticTarget,
        record_entity_id: int,
        description: str,
    ) -> None:
        if target.entity_id != record_entity_id:
            raise SemanticHintGenerationError(
                f"{description} target entity_id {target.entity_id} does not "
                f"match record entity_id {record_entity_id}"
            )
        if target.entity_id != entity.entity_id:
            raise SemanticHintGenerationError(
                f"{description} target belongs to entity {target.entity_id}"
            )
        if target.stmt_id != semantics.stmt_id:
            raise SemanticHintGenerationError(
                f"{description} target stmt_id {target.stmt_id} does not "
                f"match semantic stmt_id {semantics.stmt_id}"
            )
        if target.name != semantics.name:
            raise SemanticHintGenerationError(
                f"{description} target name {target.name!r} does not match "
                f"semantic name {semantics.name!r}"
            )
        if target.operation != semantics.operation.value:
            raise SemanticHintGenerationError(
                f"{description} target operation {target.operation!r} "
                "does not match semantic operation "
                f"{semantics.operation.value!r}"
            )
        if target.location == "parameter":
            if target.operation != "parameter_decl":
                raise SemanticHintGenerationError(
                    f"{description} parameter target is not a parameter_decl"
                )
        elif target.location == "type_alias":
            if target.operation != "type_alias_decl":
                raise SemanticHintGenerationError(
                    f"{description} type_alias target is not a type_alias_decl"
                )
        elif target.operation != "variable_decl":
            raise SemanticHintGenerationError(
                f"{description} non-parameter target is not a variable_decl"
            )

        aggregate_location = target.location in {"struct_member", "union_member"}
        if aggregate_location != semantics.is_struct_member:
            raise SemanticHintGenerationError(
                f"{description} aggregate-member identity does not match "
                "semantic facts"
            )
        if aggregate_location and target.aggregate_id is None:
            raise SemanticHintGenerationError(
                f"{description} aggregate member has no aggregate_id"
            )
        if not aggregate_location and (
            target.aggregate_id is not None
            or target.aggregate_name is not None
        ):
            raise SemanticHintGenerationError(
                f"{description} non-member target has aggregate metadata"
            )

    @staticmethod
    def _validate_unsafe_target_identity(
        *,
        entity: EntityMetadata,
        record: Mapping[str, Any],
        target: SemanticTarget,
        record_entity_id: int,
        description: str,
    ) -> None:
        if target.entity_id != record_entity_id:
            raise SemanticHintGenerationError(
                f"{description} target entity_id {target.entity_id} does not "
                f"match record entity_id {record_entity_id}"
            )
        if target.entity_id != entity.entity_id:
            raise SemanticHintGenerationError(
                f"{description} target belongs to entity {target.entity_id}"
            )
        stmt_id = SemanticHintGenerator._positive_int(
            record.get("stmt_id"), f"{description} stmt_id"
        )
        if target.stmt_id != stmt_id:
            raise SemanticHintGenerationError(
                f"{description} target stmt_id {target.stmt_id} does not "
                f"match record stmt_id {stmt_id}"
            )
        operation = SemanticHintGenerator._required_text(
            record.get("operation"), f"{description} operation"
        )
        if target.operation != operation:
            raise SemanticHintGenerationError(
                f"{description} target operation {target.operation!r} does "
                f"not match record operation {operation!r}"
            )
        semantic_kind = SemanticHintGenerator._required_text(
            record.get("semantic_kind"), f"{description} semantic_kind"
        )
        if target.semantic_kind != semantic_kind:
            raise SemanticHintGenerationError(
                f"{description} target semantic_kind "
                f"{target.semantic_kind!r} does not match record "
                f"semantic_kind {semantic_kind!r}"
            )

    @staticmethod
    def _validate_source_membership(
        entity: EntityMetadata,
        target: SemanticTarget,
        description: str,
    ) -> None:
        entity_source = entity.source
        target_source = target.source
        same_file = (
            target_source.path == entity_source.path
            or target_source.rel_path == entity_source.rel_path
        )
        if not same_file:





            return
        if (
            target_source.start_line,
            target_source.start_col,
        ) < (
            entity_source.start_line,
            entity_source.start_col,
        ) or (
            target_source.end_line,
            target_source.end_col,
        ) > (
            entity_source.end_line,
            entity_source.end_col,
        ):
            raise SemanticHintGenerationError(
                f"{description} source range lies outside entity "
                f"{entity.entity_id}"
            )

    def _choose_anchor_line(
        self,
        entity: EntityMetadata,
        target: SemanticTarget,
        original_c_source: str,
        line_count: int,
    ) -> TargetLinePlacement:




        entity_source = entity.source
        target_source = target.source
        same_file = (
            target_source.path == entity_source.path
            or target_source.rel_path == entity_source.rel_path
        )
        if same_file:
            member_line_index = self._aggregate_member_line_index(
                original_c_source,
                target,
            )
            if member_line_index is not None and member_line_index < line_count:
                return TargetLinePlacement(
                    target=target,
                    line_index=member_line_index,
                    kind=AnchorPlacementKind.LINE_END,
                )

            target_line = self._preferred_original_line(target)
            line_index = target_line - entity_source.start_line
            if 0 <= line_index < line_count:
                return TargetLinePlacement(
                    target=target,
                    line_index=line_index,
                    kind=AnchorPlacementKind.LINE_END,
                )

        return TargetLinePlacement(
            target=target,
            line_index=0,
            kind=AnchorPlacementKind.ENTITY_LEVEL_FALLBACK,
            fallback_reason=(
                "target source line is outside the extracted entity source"
                if same_file
                else "target belongs to a different source file"
            ),
        )

    @staticmethod
    def _preferred_original_line(target: SemanticTarget) -> int:
        return target.source.start_line

    @classmethod
    def _aggregate_member_line_index(
        cls,
        original_c_source: str,
        target: SemanticTarget,
    ) -> int | None:
        if target.location not in {"struct_member", "union_member"}:
            return None
        if not target.name:
            return None

        lines = original_c_source.splitlines()
        field_pattern = re.compile(
            rf"\b{re.escape(target.name)}\b"
            rf"\s*(?:\[[^\]]*\]\s*)*(?::\s*\d+)?(?:[,;=])"
        )
        fallback_index: int | None = None
        for index, line in enumerate(lines):
            if "{" in line or ";" not in line:
                continue
            code = cls._line_code_before_comment(line)
            if not re.search(rf"\b{re.escape(target.name)}\b", code):
                continue
            if field_pattern.search(code):
                return index
            if fallback_index is None:
                fallback_index = index
        return fallback_index

    @staticmethod
    def _line_code_before_comment(line: str) -> str:
        return mask_c_non_code(line, mask_literals=False)

    @staticmethod
    def _source_line_count(source: str) -> int:
        if not source:
            return 1
        return len(source.splitlines()) or 1

    @staticmethod
    def _render_anchor_comment(anchor_ids: Sequence[str]) -> str:
        if not anchor_ids:
            raise SemanticHintGenerationError(
                "cannot render an empty anchor comment"
            )
        return "/* " + " ".join(f"@SH:{anchor_id}" for anchor_id in anchor_ids) + " */"

    @staticmethod
    def _anchor_id_for_target(target: SemanticTarget) -> str:
        return f"SH_E{target.entity_id}_S{target.stmt_id}"

    @staticmethod
    def _split_line_ending(line: str) -> tuple[str, str]:
        if line.endswith("\r\n"):
            return line[:-2], "\r\n"
        if line.endswith("\n") or line.endswith("\r"):
            return line[:-1], line[-1]
        return line, ""

    @staticmethod
    def _positive_int(value: Any, description: str) -> int:
        if isinstance(value, bool):
            raise SemanticHintGenerationError(
                f"{description} must be a positive integer"
            )
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise SemanticHintGenerationError(
                f"{description} must be a positive integer"
            ) from exc
        if result <= 0:
            raise SemanticHintGenerationError(
                f"{description} must be a positive integer"
            )
        return result

    @classmethod
    def _optional_positive_int(
        cls,
        value: Any,
        description: str,
    ) -> int | None:
        return None if value is None else cls._positive_int(value, description)

    @staticmethod
    def _required_text(value: Any, description: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise SemanticHintGenerationError(
                f"{description} must be non-empty text"
            )
        return value.strip()

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise SemanticHintGenerationError(
                "optional target text must be a string or null"
            )
        text = value.strip()
        return text or None

    @classmethod
    def _json_object(
        cls,
        value: Mapping[str, Any],
        description: str,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise SemanticHintGenerationError(
                    f"{description} keys must be strings"
                )
            json_value = cls._json_value(item, f"{description}.{key}")
            if cls._is_empty_hint_value(json_value):
                continue
            result[key] = json_value
        return result

    @classmethod
    def _json_value(cls, value: Any, description: str) -> Any:
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, Mapping):
            return cls._json_object(value, description)
        if isinstance(value, list):
            return [cls._json_value(item, description) for item in value]
        raise SemanticHintGenerationError(
            f"{description} must be JSON-compatible"
        )

    @staticmethod
    def _is_empty_hint_value(value: Any) -> bool:
        return value is None or value == "" or value == [] or value == {}
