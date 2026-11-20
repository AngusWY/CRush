from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import re
import shutil
import sys
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from TranslationOrientedAnalysis.semantic_hint_schemas import PointerDeclarationSemantics
from TranslationPreprocess.c_macro import (
    load_project_macro_catalog,
    select_macro_context,
)
from TranslationPreprocess.c_source_lex import CCommentSpan, scan_c_comments
from TranslationPreprocess.config import DEFAULT_WORKSPACE

from .generator import SemanticHintGenerationError, SemanticHintGenerator
from .type_source import isolate_type_source
from .models import (
    EntityHintPackage,
    EntityMetadata,
    HumanComment,
    JsonValue,
    SemanticHint,
    SemanticHintManifest,
    SemanticHintManifestEntry,
    SemanticHintStore,
    SourceSpan,
)


TRANSLATION_ENTITIES_FILE_NAME = "translation-entities.json"
SEMANTIC_ANALYSIS_DIR_NAME = "semantic_analysis"
POINTER_SEMANTICS_FILE_NAME = "pointer-semantics.json"
UNSAFE_STMT_SEMANTICS_FILE_NAME = "unsafe-stmt-semantics.json"
FUNCTION_RETURN_SEMANTICS_FILE_NAME = "function-return-semantics.json"
EXTERNAL_TYPE_SEMANTICS_FILE_NAME = "external-type-semantics.json"
CALLBACK_INTERFACE_SEMANTICS_FILE_NAME = "callback-interface-semantics.json"
SEMANTIC_HINTS_DIR_NAME = "semantic_hints"
SEMANTIC_HINT_ENTITIES_DIR_NAME = "entities"
SEMANTIC_HINT_MANIFEST_FILE_NAME = "manifest.json"
SEMANTIC_HINT_STORE_FILE_NAME = "hint-store.json"
HUMAN_COMMENT_STORE_FILE_NAME = "human-comment-store.json"
PREPROCESSED_ORIGIN_DIR_NAME = "preprocessed_origin"
COMMENTED_PREPROCESSED_ORIGIN_DIR_NAME = "preprocessed_with_comments_origin"
_ANCHOR_PATTERN = re.compile(r"@SH:(SH_E[1-9][0-9]*_S[1-9][0-9]*)")
_MAX_LEADING_COMMENT_LINES = 50
_MAX_LEADING_COMMENT_CHARS = 8192


class SemanticHintPipelineError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class SemanticHintPipelineResult:


    entity_count: int
    package_count: int
    hint_count: int
    output_dir: Path
    manifest_path: Path
    hint_store_path: Path
    human_comment_store_path: Path


class SemanticHintPipeline:


    def __init__(self, *, workspace: Path) -> None:
        self.workspace = workspace.resolve()
        self.translation_entities_path = (
            self.workspace / TRANSLATION_ENTITIES_FILE_NAME
        )
        self.pointer_semantics_path = (
            self.workspace
            / SEMANTIC_ANALYSIS_DIR_NAME
            / POINTER_SEMANTICS_FILE_NAME
        )
        self.unsafe_stmt_semantics_path = (
            self.workspace
            / SEMANTIC_ANALYSIS_DIR_NAME
            / UNSAFE_STMT_SEMANTICS_FILE_NAME
        )
        self.function_return_semantics_path = (
            self.workspace
            / SEMANTIC_ANALYSIS_DIR_NAME
            / FUNCTION_RETURN_SEMANTICS_FILE_NAME
        )
        self.external_type_semantics_path = (
            self.workspace
            / SEMANTIC_ANALYSIS_DIR_NAME
            / EXTERNAL_TYPE_SEMANTICS_FILE_NAME
        )
        self.callback_interface_semantics_path = (
            self.workspace
            / SEMANTIC_ANALYSIS_DIR_NAME
            / CALLBACK_INTERFACE_SEMANTICS_FILE_NAME
        )
        self.output_dir = self.workspace / SEMANTIC_HINTS_DIR_NAME
        self.entities_dir = (
            self.output_dir / SEMANTIC_HINT_ENTITIES_DIR_NAME
        )
        self.manifest_path = (
            self.output_dir / SEMANTIC_HINT_MANIFEST_FILE_NAME
        )
        self.hint_store_path = self.output_dir / SEMANTIC_HINT_STORE_FILE_NAME
        self.human_comment_store_path = (
            self.output_dir / HUMAN_COMMENT_STORE_FILE_NAME
        )
        self.generator = SemanticHintGenerator()
        self._source_text_cache: dict[Path, str] = {}

    def run(self) -> SemanticHintPipelineResult:
        self._validate_inputs()
        entities = self._read_entities()
        pointer_records = self._read_pointer_records(entities)
        unsafe_stmt_records = self._read_unsafe_stmt_records(entities)
        function_return_records = self._read_function_return_records(entities)
        external_type_records = self._read_external_type_records(entities)
        callback_interface_records = self._read_callback_interface_records(entities)
        macro_catalog = load_project_macro_catalog(self.workspace)

        self._reset_output_dir()
        manifest_entries: list[SemanticHintManifestEntry] = []
        store_hints: dict[str, SemanticHint] = {}
        human_comments: dict[str, HumanComment] = {}
        package_count = 0
        hint_count = 0

        for entity in entities:
            records = tuple(pointer_records.get(entity.entity_id, ()))
            unsafe_records = tuple(
                unsafe_stmt_records.get(entity.entity_id, ())
            )
            function_return_record = function_return_records.get(
                entity.entity_id
            )
            external_type_record = external_type_records.get(entity.entity_id)
            callback_interface_record = callback_interface_records.get(entity.entity_id)
            analysis_source = self._extract_entity_source(entity)
            commented_source = self._extract_commented_entity_source(entity)
            origin_source = self._extract_original_entity_source(entity)
            macro_context = select_macro_context(
                origin_source,
                macro_catalog,
            )
            translation_source = commented_source
            comments = self._extract_leading_comments(entity)
            for comment in comments:
                existing = human_comments.get(comment.comment_id)
                if existing is not None and existing != comment:
                    raise SemanticHintPipelineError(
                        f"human comment ID collision: {comment.comment_id}"
                    )
                human_comments[comment.comment_id] = comment
            try:
                generated = self.generator.generate_entity_hints(
                    entity=entity,
                    original_c_source=translation_source,
                    analysis_c_source=None,
                    pointer_records=records,
                    unsafe_stmt_records=unsafe_records,
                    function_return_record=function_return_record,
                    external_type_record=external_type_record,
                    callback_interface_record=callback_interface_record,
                    human_comment_ids=tuple(
                        comment.comment_id for comment in comments
                    ),
                    macro_context=macro_context,
                )
            except SemanticHintGenerationError as exc:
                raise SemanticHintPipelineError(
                    f"failed to generate hints for entity "
                    f"{entity.entity_id}: {exc}"
                ) from exc
            package = generated.package
            semantic_hints = generated.semantic_hints

            package_file = (
                f"{SEMANTIC_HINT_ENTITIES_DIR_NAME}/"
                f"entity_{entity.entity_id}.json"
            )
            self._validate_package(
                package,
                semantic_hints,
            )
            for hint in semantic_hints:
                if hint.anchor_id in store_hints:
                    raise SemanticHintPipelineError(
                        f"duplicate semantic hint anchor ID: {hint.anchor_id}"
                    )
                store_hints[hint.anchor_id] = hint
            self._write_package(package, self.output_dir / package_file)
            manifest_entries.append(
                self.generator.manifest_entry_for_package(
                    package=package,
                    package_file=package_file,
                )
            )
            package_count += 1
            hint_count += len(semantic_hints)

        manifest = SemanticHintManifest(
            version=4,
            hint_store_file=SEMANTIC_HINT_STORE_FILE_NAME,
            human_comment_store_file=HUMAN_COMMENT_STORE_FILE_NAME,
            entities=tuple(manifest_entries),
        )
        hint_store = SemanticHintStore(version=1, hints=store_hints)
        self._validate_hint_store(hint_store)
        self._validate_manifest(
            manifest=manifest,
            entity_count=len(entities),
            hint_count=hint_count,
        )
        self._atomic_write_json(self.hint_store_path, hint_store.to_dict())
        self._atomic_write_json(
            self.human_comment_store_path,
            {
                "version": 1,
                "comments": {
                    comment_id: comment.to_dict()
                    for comment_id, comment in sorted(human_comments.items())
                },
            },
        )
        self._atomic_write_json(self.manifest_path, manifest.to_dict())

        return SemanticHintPipelineResult(
            entity_count=len(entities),
            package_count=package_count,
            hint_count=hint_count,
            output_dir=self.output_dir,
            manifest_path=self.manifest_path,
            hint_store_path=self.hint_store_path,
            human_comment_store_path=self.human_comment_store_path,
        )

    def _validate_inputs(self) -> None:
        if not self.workspace.is_dir():
            raise SemanticHintPipelineError(
                f"workspace directory does not exist: {self.workspace}"
            )
        if not self.translation_entities_path.is_file():
            raise SemanticHintPipelineError(
                "translation entities file does not exist: "
                f"{self.translation_entities_path}"
            )
        if not self.pointer_semantics_path.is_file():
            raise SemanticHintPipelineError(
                "pointer semantics file does not exist: "
                f"{self.pointer_semantics_path}"
            )

    def _read_entities(self) -> tuple[EntityMetadata, ...]:
        data = self._read_json_object(
            self.translation_entities_path,
            "translation entities",
        )
        raw_entities = data.get("entities")
        if not isinstance(raw_entities, list):
            raise SemanticHintPipelineError(
                "translation entities file has no entities array: "
                f"{self.translation_entities_path}"
            )

        entities: list[EntityMetadata] = []
        seen_entity_ids: set[int] = set()
        for index, raw_entity in enumerate(raw_entities):
            if not isinstance(raw_entity, dict):
                raise SemanticHintPipelineError(
                    f"translation entity {index} is not an object"
                )
            try:
                entity = EntityMetadata.from_dict(raw_entity)
            except (KeyError, TypeError, ValueError) as exc:
                raise SemanticHintPipelineError(
                    f"invalid translation entity {index}: {exc}"
                ) from exc
            if entity.entity_id in seen_entity_ids:
                raise SemanticHintPipelineError(
                    f"duplicate translation entity ID: {entity.entity_id}"
                )
            seen_entity_ids.add(entity.entity_id)
            if not Path(entity.source.path).is_file():
                raise SemanticHintPipelineError(
                    f"source file for entity {entity.entity_id} does not "
                    f"exist: {entity.source.path}"
                )
            entities.append(entity)
        return tuple(entities)

    def _read_pointer_records(
        self,
        entities: tuple[EntityMetadata, ...],
    ) -> dict[int, tuple[Mapping[str, Any], ...]]:
        data = self._read_json_object(
            self.pointer_semantics_path,
            "pointer semantics",
        )
        if data.get("version") != 4:
            raise SemanticHintPipelineError(
                "unsupported pointer semantics version in "
                f"{self.pointer_semantics_path}: {data.get('version')!r}; "
                "expected 4; regenerate semantic analysis"
            )
        if data.get("kind") != "pointer_declarations":
            raise SemanticHintPipelineError(
                "unsupported pointer semantics kind in "
                f"{self.pointer_semantics_path}: {data.get('kind')!r}"
            )
        raw_pointers = data.get("pointers")
        if not isinstance(raw_pointers, list):
            raise SemanticHintPipelineError(
                "pointer semantics file has no pointers array: "
                f"{self.pointer_semantics_path}"
            )

        entity_ids = {entity.entity_id for entity in entities}
        mutable_records: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
        seen_keys: set[tuple[int, int]] = set()

        for index, raw_pointer in enumerate(raw_pointers):
            if not isinstance(raw_pointer, dict):
                raise SemanticHintPipelineError(
                    f"pointer record {index} is not an object"
                )
            entity_id = self._positive_int(
                raw_pointer.get("entity_id"),
                f"pointer record {index} entity_id",
            )
            if entity_id not in entity_ids:
                raise SemanticHintPipelineError(
                    f"pointer record {index} references unknown entity "
                    f"{entity_id}"
                )
            if not isinstance(raw_pointer.get("target"), dict):
                raise SemanticHintPipelineError(
                    f"pointer record {index} has no target object"
                )
            try:
                semantics = PointerDeclarationSemantics.from_dict(
                    raw_pointer
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise SemanticHintPipelineError(
                    f"invalid pointer record {index}: {exc}"
                ) from exc
            key = (entity_id, semantics.stmt_id)
            if key in seen_keys:
                raise SemanticHintPipelineError(
                    "duplicate pointer semantics record for entity "
                    f"{entity_id}, stmt {semantics.stmt_id}"
                )
            seen_keys.add(key)
            mutable_records[entity_id].append(raw_pointer)

        return {
            entity_id: tuple(records)
            for entity_id, records in mutable_records.items()
        }

    def _read_unsafe_stmt_records(
        self,
        entities: tuple[EntityMetadata, ...],
    ) -> dict[int, tuple[Mapping[str, Any], ...]]:
        if not self.unsafe_stmt_semantics_path.is_file():
            return {}

        data = self._read_json_object(
            self.unsafe_stmt_semantics_path,
            "unsafe stmt semantics",
        )
        if data.get("version") != 3:
            raise SemanticHintPipelineError(
                "unsupported unsafe stmt semantics version in "
                f"{self.unsafe_stmt_semantics_path}: "
                f"{data.get('version')!r}; expected 3"
            )
        if data.get("kind") != "unsafe_stmts":
            raise SemanticHintPipelineError(
                "unsupported unsafe stmt semantics kind in "
                f"{self.unsafe_stmt_semantics_path}: {data.get('kind')!r}"
            )
        raw_records = data.get("unsafe_stmts")
        if not isinstance(raw_records, list):
            raise SemanticHintPipelineError(
                "unsafe stmt semantics file has no unsafe_stmts array: "
                f"{self.unsafe_stmt_semantics_path}"
            )

        entity_ids = {entity.entity_id for entity in entities}
        mutable_records: dict[int, list[Mapping[str, Any]]] = defaultdict(list)
        seen_keys: set[tuple[int, int]] = set()

        for index, raw_record in enumerate(raw_records):
            if not isinstance(raw_record, dict):
                raise SemanticHintPipelineError(
                    f"unsafe stmt record {index} is not an object"
                )
            entity_id = self._positive_int(
                raw_record.get("entity_id"),
                f"unsafe stmt record {index} entity_id",
            )
            if entity_id not in entity_ids:
                raise SemanticHintPipelineError(
                    f"unsafe stmt record {index} references unknown entity "
                    f"{entity_id}"
                )
            stmt_id = self._positive_int(
                raw_record.get("stmt_id"),
                f"unsafe stmt record {index} stmt_id",
            )
            if not isinstance(raw_record.get("target"), dict):
                raise SemanticHintPipelineError(
                    f"unsafe stmt record {index} has no target object"
                )
            if not isinstance(raw_record.get("semantic_hints"), dict):
                raise SemanticHintPipelineError(
                    f"unsafe stmt record {index} semantic_hints must be "
                    "an object"
                )
            key = (entity_id, stmt_id)
            if key in seen_keys:
                raise SemanticHintPipelineError(
                    "duplicate unsafe stmt semantics record for entity "
                    f"{entity_id}, stmt {stmt_id}"
                )
            seen_keys.add(key)
            if raw_record["semantic_hints"]:
                mutable_records[entity_id].append(raw_record)

        return {
            entity_id: tuple(records)
            for entity_id, records in mutable_records.items()
        }

    def _read_function_return_records(
        self,
        entities: tuple[EntityMetadata, ...],
    ) -> dict[int, Mapping[str, Any]]:
        if not self.function_return_semantics_path.is_file():
            return {}
        data = self._read_json_object(
            self.function_return_semantics_path,
            "function return semantics",
        )
        if data.get("version") != 1 or data.get("kind") != "function_return_semantics":
            raise SemanticHintPipelineError(
                "unsupported function return semantics format in "
                f"{self.function_return_semantics_path}"
            )
        raw_functions = data.get("functions")
        if not isinstance(raw_functions, list):
            raise SemanticHintPipelineError(
                "function return semantics file has no functions array: "
                f"{self.function_return_semantics_path}"
            )
        entity_ids = {entity.entity_id for entity in entities}
        records: dict[int, Mapping[str, Any]] = {}
        for index, record in enumerate(raw_functions):
            if not isinstance(record, dict):
                raise SemanticHintPipelineError(
                    f"function return record {index} is not an object"
                )
            entity_id = self._positive_int(
                record.get("entity_id"),
                f"function return record {index} entity_id",
            )
            if entity_id not in entity_ids:
                raise SemanticHintPipelineError(
                    f"function return record {index} references unknown "
                    f"entity {entity_id}"
                )
            if entity_id in records:
                raise SemanticHintPipelineError(
                    f"duplicate function return record for entity {entity_id}"
                )
            records[entity_id] = record
        return records

    def _read_external_type_records(
        self,
        entities: tuple[EntityMetadata, ...],
    ) -> dict[int, Mapping[str, Any]]:
        if not self.external_type_semantics_path.is_file():
            return {}
        data = self._read_json_object(
            self.external_type_semantics_path,
            "external type semantics",
        )
        if data.get("version") != 1 or data.get("kind") != "external_type_semantics":
            raise SemanticHintPipelineError(
                "unsupported external type semantics format in "
                f"{self.external_type_semantics_path}"
            )
        raw_contracts = data.get("entity_contracts")
        if not isinstance(raw_contracts, list):
            raise SemanticHintPipelineError(
                "external type semantics file has no entity_contracts array: "
                f"{self.external_type_semantics_path}"
            )
        entity_ids = {entity.entity_id for entity in entities}
        records: dict[int, Mapping[str, Any]] = {}
        for index, record in enumerate(raw_contracts):
            if not isinstance(record, dict):
                raise SemanticHintPipelineError(
                    f"external type contract {index} is not an object"
                )
            entity_id = self._positive_int(
                record.get("entity_id"),
                f"external type contract {index} entity_id",
            )
            if entity_id not in entity_ids:
                continue
            if entity_id in records:
                raise SemanticHintPipelineError(
                    f"duplicate external type contract for entity {entity_id}"
                )
            records[entity_id] = record
        return records

    def _read_callback_interface_records(
        self,
        entities: tuple[EntityMetadata, ...],
    ) -> dict[int, Mapping[str, Any]]:
        if not self.callback_interface_semantics_path.is_file():
            return {}
        data = self._read_json_object(
            self.callback_interface_semantics_path,
            "callback interface semantics",
        )
        if data.get("version") != 1 or data.get("kind") != "callback_interface_semantics":
            raise SemanticHintPipelineError(
                "unsupported callback interface semantics format in "
                f"{self.callback_interface_semantics_path}"
            )
        raw_contracts = data.get("entity_contracts")
        if not isinstance(raw_contracts, list):
            raise SemanticHintPipelineError(
                "callback interface semantics file has no entity_contracts array: "
                f"{self.callback_interface_semantics_path}"
            )
        entity_ids = {entity.entity_id for entity in entities}
        records: dict[int, Mapping[str, Any]] = {}
        for index, record in enumerate(raw_contracts):
            if not isinstance(record, dict):
                raise SemanticHintPipelineError(
                    f"callback interface contract {index} is not an object"
                )
            entity_id = self._positive_int(
                record.get("entity_id"),
                f"callback interface contract {index} entity_id",
            )
            if entity_id not in entity_ids:
                continue
            if entity_id in records:
                raise SemanticHintPipelineError(
                    f"duplicate callback interface contract for entity {entity_id}"
                )
            records[entity_id] = record
        return records

    def _extract_entity_source(self, entity: EntityMetadata) -> str:
        source_path = Path(entity.source.path)
        try:
            source_path.relative_to(self.workspace / "preprocessed")
        except ValueError:
            pass
        else:
            return self._extract_line_span(
                path=source_path,
                start_line=entity.source.start_line,
                end_line=entity.source.end_line,
                entity_id=entity.entity_id,
            )
        preprocessed_source = self._extract_preprocessed_entity_source(
            entity,
            origin_dir_name=PREPROCESSED_ORIGIN_DIR_NAME,
        )
        if preprocessed_source is not None:
            return preprocessed_source

        return self._extract_original_entity_source(entity)

    def _extract_original_entity_source(
        self,
        entity: EntityMetadata,
    ) -> str:
        source_span = self._extract_origin_source_span(entity)
        path = Path(source_span.path)
        try:
            lines = path.read_text(encoding="utf-8").splitlines(
                keepends=True
            )
        except OSError as exc:
            raise SemanticHintPipelineError(
                f"failed to read source file for entity {entity.entity_id}: "
                f"{path}: {exc}"
            ) from exc

        start_index = source_span.start_line - 1
        end_index = source_span.end_line
        if start_index < 0 or end_index > len(lines) or start_index >= end_index:
            raise SemanticHintPipelineError(
                f"entity {entity.entity_id} source range is outside file "
                f"{path}: {source_span.start_line}-{source_span.end_line}"
            )
        return isolate_type_source(
            "".join(lines[start_index:end_index]),
            dataclasses.replace(entity, source=source_span),
            original_coordinates=True,
        )

    @staticmethod
    def _extract_origin_source_span(entity: EntityMetadata) -> SourceSpan:
        origin = getattr(entity, "origin", None)
        return origin if isinstance(origin, SourceSpan) else entity.source

    def _extract_commented_entity_source(self, entity: EntityMetadata) -> str:


        return self._extract_entity_source(entity)

    def _extract_leading_comments(
        self,
        entity: EntityMetadata,
    ) -> tuple[HumanComment, ...]:
        source_span = self._extract_origin_source_span(entity)
        path = Path(source_span.path)
        try:
            source = self._source_text_cache.get(path)
            if source is None:
                source = path.read_text(encoding="utf-8")
                self._source_text_cache[path] = source
        except OSError as exc:
            raise SemanticHintPipelineError(
                f"failed to read source comments for entity "
                f"{entity.entity_id}: {path}: {exc}"
            ) from exc
        return _extract_leading_human_comments(
            source=source,
            path=path,
            rel_path=source_span.rel_path,
            entity_start_line=source_span.start_line,
        )

    def _extract_preprocessed_entity_source(
        self,
        entity: EntityMetadata,
        *,
        origin_dir_name: str,
    ) -> str | None:
        origin_dir = self.workspace / origin_dir_name
        if not origin_dir.is_dir():
            return None

        for mapping_path in sorted(origin_dir.rglob("*.json")):
            mapping = self._read_json_object(
                mapping_path,
                "preprocessed origin mapping",
            )
            ranges = mapping.get("ranges")
            if not isinstance(ranges, list):
                continue
            clean_path_value = mapping.get("clean_path")
            if not isinstance(clean_path_value, str):
                continue
            clean_path = Path(clean_path_value)
            if not clean_path.is_file():
                continue

            for item in ranges:
                if not isinstance(item, dict):
                    continue
                if not self._range_matches_entity(item, entity):
                    continue
                clean_start = int(item["clean_start"]) + (
                    entity.source.start_line - int(item["origin_start"])
                )
                clean_end = int(item["clean_start"]) + (
                    entity.source.end_line - int(item["origin_start"])
                )
                source = self._extract_line_span(
                    path=clean_path,
                    start_line=clean_start,
                    end_line=clean_end,
                    entity_id=entity.entity_id,
                )
                return isolate_type_source(source, entity)

            spans = self._preprocessed_clean_spans_for_entity(ranges, entity)
            if spans:
                source = self._extract_line_spans(
                    path=clean_path,
                    spans=spans,
                    entity_id=entity.entity_id,
                )
                return isolate_type_source(source, entity)

        return None

    def _preprocessed_clean_spans_for_entity(
        self,
        ranges: list[Any],
        entity: EntityMetadata,
    ) -> tuple[tuple[int, int], ...]:
        spans: list[tuple[int, int, int, int]] = []
        covers_start = False
        covers_end = False

        for item in ranges:
            if not isinstance(item, dict):
                continue
            try:
                origin_rel_path = str(item["origin_rel_path"])
                origin_start = int(item["origin_start"])
                origin_end = int(item["origin_end"])
                clean_start = int(item["clean_start"])
            except (KeyError, TypeError, ValueError):
                continue
            if origin_rel_path != entity.source.rel_path:
                continue

            overlap_start = max(entity.source.start_line, origin_start)
            overlap_end = min(entity.source.end_line, origin_end)
            if overlap_start > overlap_end:
                continue

            covers_start = covers_start or (
                origin_start <= entity.source.start_line <= origin_end
            )
            covers_end = covers_end or (
                origin_start <= entity.source.end_line <= origin_end
            )
            mapped_clean_start = clean_start + (overlap_start - origin_start)
            mapped_clean_end = clean_start + (overlap_end - origin_start)
            spans.append(
                (
                    overlap_start,
                    overlap_end,
                    mapped_clean_start,
                    mapped_clean_end,
                )
            )

        if not spans or not covers_start or not covers_end:
            return ()

        spans.sort(key=lambda span: (span[0], span[2]))
        if len(spans) > 1:
            clean_start = min(span[2] for span in spans)
            clean_end = max(span[3] for span in spans)
            return ((clean_start, clean_end),)

        clean_spans: list[tuple[int, int]] = []
        for _, _, clean_start, clean_end in spans:
            if clean_spans and clean_start <= clean_spans[-1][1] + 1:
                previous_start, previous_end = clean_spans[-1]
                clean_spans[-1] = (previous_start, max(previous_end, clean_end))
            else:
                clean_spans.append((clean_start, clean_end))
        return tuple(clean_spans)

    def _range_matches_entity(
        self,
        item: Mapping[str, Any],
        entity: EntityMetadata,
    ) -> bool:
        try:
            origin_rel_path = str(item["origin_rel_path"])
            origin_start = int(item["origin_start"])
            origin_end = int(item["origin_end"])
            int(item["clean_start"])
        except (KeyError, TypeError, ValueError):
            return False
        return (
            origin_rel_path == entity.source.rel_path
            and origin_start <= entity.source.start_line
            and entity.source.end_line <= origin_end
        )

    def _extract_line_span(
        self,
        *,
        path: Path,
        start_line: int,
        end_line: int,
        entity_id: int,
    ) -> str:
        try:
            lines = path.read_text(encoding="utf-8").splitlines(
                keepends=True
            )
        except OSError as exc:
            raise SemanticHintPipelineError(
                f"failed to read preprocessed source for entity {entity_id}: "
                f"{path}: {exc}"
            ) from exc

        start_index = start_line - 1
        end_index = end_line
        if start_index < 0 or end_index > len(lines) or start_index >= end_index:
            raise SemanticHintPipelineError(
                f"preprocessed source range is outside file for entity "
                f"{entity_id}: {path}: {start_line}-{end_line}"
            )
        return "".join(lines[start_index:end_index])

    def _extract_line_spans(
        self,
        *,
        path: Path,
        spans: tuple[tuple[int, int], ...],
        entity_id: int,
    ) -> str:
        try:
            lines = path.read_text(encoding="utf-8").splitlines(
                keepends=True
            )
        except OSError as exc:
            raise SemanticHintPipelineError(
                f"failed to read preprocessed source for entity {entity_id}: "
                f"{path}: {exc}"
            ) from exc

        pieces: list[str] = []
        for start_line, end_line in spans:
            start_index = start_line - 1
            end_index = end_line
            if start_index < 0 or end_index > len(lines) or start_index >= end_index:
                raise SemanticHintPipelineError(
                    f"preprocessed source range is outside file for entity "
                    f"{entity_id}: {path}: {start_line}-{end_line}"
                )
            pieces.append("".join(lines[start_index:end_index]))
        return "".join(pieces)

    def _reset_output_dir(self) -> None:
        if self.output_dir.exists():
            if not self.output_dir.is_dir():
                raise SemanticHintPipelineError(
                    f"semantic hints output path is not a directory: "
                    f"{self.output_dir}"
                )
            shutil.rmtree(self.output_dir)
        self.entities_dir.mkdir(parents=True, exist_ok=True)

    def _write_package(self, package: EntityHintPackage, path: Path) -> None:
        self._atomic_write_json(path, package.to_dict())

    def _validate_package(
        self,
        package: EntityHintPackage,
        semantic_hints: tuple[SemanticHint, ...],
    ) -> None:
        if len(package.hint_anchor_ids) != len(semantic_hints):
            raise SemanticHintPipelineError(
                f"entity {package.entity.entity_id} package hint count "
                f"{len(package.hint_anchor_ids)} does not match generated "
                f"hint count {len(semantic_hints)}"
            )

        hint_ids = set(package.hint_anchor_ids)
        store_hint_ids = {hint.anchor_id for hint in semantic_hints}
        if hint_ids != store_hint_ids:
            raise SemanticHintPipelineError(
                f"entity {package.entity.entity_id} package anchor IDs "
                f"{sorted(hint_ids)} do not match generated store hint IDs "
                f"{sorted(store_hint_ids)}"
            )

        source_anchor_ids = set(
            _ANCHOR_PATTERN.findall(package.annotated_c_source)
        )
        if hint_ids != source_anchor_ids:
            raise SemanticHintPipelineError(
                f"entity {package.entity.entity_id} anchor IDs in source "
                f"{sorted(source_anchor_ids)} do not match hint IDs "
                f"{sorted(hint_ids)}"
            )

    def _validate_hint_store(self, store: SemanticHintStore) -> None:
        for anchor_id, hint in store.hints.items():
            if anchor_id != hint.anchor_id:
                raise SemanticHintPipelineError(
                    f"hint store key {anchor_id!r} does not match hint "
                    f"anchor_id {hint.anchor_id!r}"
                )
            expected_anchor_id = (
                f"SH_E{hint.target.entity_id}_S{hint.target.stmt_id}"
            )
            if anchor_id != expected_anchor_id:
                raise SemanticHintPipelineError(
                    f"hint {anchor_id!r} does not match target identity "
                    f"{expected_anchor_id!r}"
                )

    def _validate_manifest(
        self,
        *,
        manifest: SemanticHintManifest,
        entity_count: int,
        hint_count: int,
    ) -> None:
        if len(manifest.entities) != entity_count:
            raise SemanticHintPipelineError(
                "manifest entity count does not match translation entity "
                f"count: {len(manifest.entities)} != {entity_count}"
            )
        if sum(entry.hint_count for entry in manifest.entities) != hint_count:
            raise SemanticHintPipelineError(
                "manifest hint count does not match generated packages"
            )

    def _atomic_write_json(self, path: Path, payload: Mapping[str, JsonValue]) -> None:
        temporary_path = path.with_suffix(path.suffix + ".tmp")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(path)
        except OSError as exc:
            raise SemanticHintPipelineError(
                f"failed to write {path}: {exc}"
            ) from exc

    @staticmethod
    def _read_json_object(path: Path, description: str) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SemanticHintPipelineError(
                f"failed to read {description} {path}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise SemanticHintPipelineError(
                f"{description} must be a JSON object: {path}"
            )
        return value

    @staticmethod
    def _positive_int(value: Any, description: str) -> int:
        if isinstance(value, bool):
            raise SemanticHintPipelineError(
                f"{description} must be a positive integer"
            )
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise SemanticHintPipelineError(
                f"{description} must be a positive integer"
            ) from exc
        if result <= 0:
            raise SemanticHintPipelineError(
                f"{description} must be a positive integer"
            )
        return result


def _extract_leading_human_comments(
    *,
    source: str,
    path: Path,
    rel_path: str,
    entity_start_line: int,
) -> tuple[HumanComment, ...]:


    if entity_start_line <= 1:
        return ()
    line_offsets = _line_offsets(source)
    if entity_start_line - 1 >= len(line_offsets):
        return ()
    entity_start = line_offsets[entity_start_line - 1]
    candidates = [
        span for span in scan_c_comments(source) if span.end <= entity_start
    ]
    if not candidates:
        return ()

    selected: list[CCommentSpan] = []
    cursor = entity_start
    total_chars = 0
    total_lines = 0
    for span in reversed(candidates):
        between = source[span.end:cursor]
        if between.strip() or between.count("\n") > 2:
            break
        candidate_chars = cursor - span.start
        candidate_lines = max(1, span.end_line - span.start_line + 1)
        if (
            total_chars + candidate_chars > _MAX_LEADING_COMMENT_CHARS
            or total_lines + candidate_lines > _MAX_LEADING_COMMENT_LINES
        ):
            break
        selected.append(span)
        total_chars += candidate_chars
        total_lines += candidate_lines
        cursor = span.start

    if not selected:
        return ()
    selected.reverse()
    start = selected[0].start
    end = selected[-1].end
    text = source[start:end]
    start_line = selected[0].start_line
    end_line = selected[-1].end_line
    start_col = start - (source.rfind("\n", 0, start) + 1)
    end_col = end - (source.rfind("\n", 0, end) + 1)
    kind = "file_header" if not source[:start].strip() else "leading"
    comment_id = _human_comment_id(
        rel_path=rel_path,
        start_line=start_line,
        end_line=end_line,
        text=text,
    )
    return (
        HumanComment(
            comment_id=comment_id,
            kind=kind,
            source=SourceSpan(
                path=str(path),
                rel_path=rel_path,
                start_line=start_line,
                start_col=start_col,
                end_line=end_line,
                end_col=end_col,
            ),
            text=text,
        ),
    )


def _line_offsets(source: str) -> list[int]:
    offsets = [0]
    for index, char in enumerate(source):
        if char == "\n":
            offsets.append(index + 1)
    return offsets


def _human_comment_id(
    *,
    rel_path: str,
    start_line: int,
    end_line: int,
    text: str,
) -> str:
    identity = json.dumps(
        [rel_path, start_line, end_line, text],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    return f"HC_{digest}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate semantic-hint input packages for Translate Agent."
    )
    parser.add_argument(
        "-w",
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help=f"workflow workspace directory (default: {DEFAULT_WORKSPACE})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = SemanticHintPipeline(workspace=args.workspace).run()
    except SemanticHintPipelineError as exc:
        print(f"error: semantic hint generation failed: {exc}", file=sys.stderr)
        return 2

    print(f"semantic hint packages: {result.package_count}")
    print(f"translation entities: {result.entity_count}")
    print(f"semantic hints: {result.hint_count}")
    print(f"output dir: {result.output_dir}")
    print(f"manifest: {result.manifest_path}")
    print(f"hint store: {result.hint_store_path}")
    print(f"human comment store: {result.human_comment_store_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
