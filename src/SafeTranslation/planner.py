from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .loader import (
    load_entity_dependencies,
    load_entity_packages,
    load_entity_placements,
    load_expected_exports,
)
from .models import TranslationBatch, TranslationTask


def build_translation_batches(workspace: Path | str) -> tuple[TranslationBatch, ...]:


    workspace_path = Path(workspace)
    packages = load_entity_packages(workspace_path)
    placements = load_entity_placements(workspace_path)
    dependencies = load_entity_dependencies(workspace_path)
    expected_exports = load_expected_exports(workspace_path)
    plan = _load_translation_plan(workspace_path)

    package_ids = set(packages)
    placement_ids = set(placements)
    dependency_ids = set(dependencies)
    expected_export_ids = set(expected_exports)

    missing_placements = package_ids - placement_ids
    if missing_placements:
        raise ValueError(
            "Missing rust-module-layout placement for entities: "
            f"{_format_ids(missing_placements)}"
        )

    missing_dependency_entries = package_ids - dependency_ids
    if missing_dependency_entries:
        raise ValueError(
            "Missing dependency entries for entities: "
            f"{_format_ids(missing_dependency_entries)}"
        )

    unknown_dependency_owners = dependency_ids - package_ids
    if unknown_dependency_owners:
        raise ValueError(
            "Dependency file contains unknown entities: "
            f"{_format_ids(unknown_dependency_owners)}"
        )

    missing_expected_exports = package_ids - expected_export_ids
    if missing_expected_exports:
        raise ValueError(
            "Missing expected exports for entities: "
            f"{_format_ids(missing_expected_exports)}"
        )

    for entity_id, deps in dependencies.items():
        unknown_deps = set(deps) - package_ids
        if unknown_deps:
            raise ValueError(
                f"Entity {entity_id} depends on unknown entities: "
                f"{_format_ids(unknown_deps)}"
            )

    seen_entities: set[int] = set()
    batches: list[TranslationBatch] = []
    for batch_id, entity_ids in plan:
        duplicate_in_batch = _duplicates(entity_ids)
        if duplicate_in_batch:
            raise ValueError(
                f"translation-plan batch {batch_id} has duplicate entities: "
                f"{_format_ids(duplicate_in_batch)}"
            )

        repeated = seen_entities.intersection(entity_ids)
        if repeated:
            raise ValueError(
                "translation-plan contains entities in multiple batches: "
                f"{_format_ids(repeated)}"
            )

        unknown_in_plan = set(entity_ids) - package_ids
        if unknown_in_plan:
            raise ValueError(
                f"translation-plan batch {batch_id} references unknown entities: "
                f"{_format_ids(unknown_in_plan)}"
            )

        tasks = tuple(
            TranslationTask(
                entity_id=entity_id,
                kind=packages[entity_id].kind,
                package=packages[entity_id],
                placement=placements[entity_id],
                dependency_ids=dependencies[entity_id],
                expected_exports=expected_exports[entity_id],
            )
            for entity_id in entity_ids
        )
        batches.append(TranslationBatch(batch_id=batch_id, tasks=tasks))
        seen_entities.update(entity_ids)

    missing_from_plan = package_ids - seen_entities
    if missing_from_plan:
        raise ValueError(
            "translation-plan does not cover entities: "
            f"{_format_ids(missing_from_plan)}"
        )

    return tuple(batches)


class TranslationPlanner:


    def __init__(self, workspace: Path | str) -> None:
        self.workspace = Path(workspace)

    def build_batches(self) -> tuple[TranslationBatch, ...]:
        return build_translation_batches(self.workspace)


def _load_translation_plan(workspace: Path) -> tuple[tuple[int, tuple[int, ...]], ...]:
    plan_path = workspace / "translation-plan.json"
    if not plan_path.is_file():
        raise FileNotFoundError(plan_path)
    data = json.loads(plan_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{plan_path} must be an object")
    batches_value = data.get("batches")
    if not isinstance(batches_value, list):
        raise ValueError(f"{plan_path}: field 'batches' must be a list")

    batches: list[tuple[int, tuple[int, ...]]] = []
    seen_batch_ids: set[int] = set()
    for index, batch_value in enumerate(batches_value):
        if not isinstance(batch_value, dict):
            raise ValueError(f"{plan_path}: batches[{index}] must be an object")
        batch_id_value = batch_value.get("batch_id")
        if not isinstance(batch_id_value, int):
            raise ValueError(f"{plan_path}: batches[{index}].batch_id must be an int")
        if batch_id_value in seen_batch_ids:
            raise ValueError(f"{plan_path}: duplicate batch_id {batch_id_value}")
        seen_batch_ids.add(batch_id_value)

        entity_ids_value = batch_value.get("entity_ids")
        if not isinstance(entity_ids_value, list):
            raise ValueError(
                f"{plan_path}: batches[{index}].entity_ids must be a list"
            )
        entity_ids: list[int] = []
        for entity_index, entity_id_value in enumerate(entity_ids_value):
            if not isinstance(entity_id_value, int):
                raise ValueError(
                    f"{plan_path}: batches[{index}].entity_ids[{entity_index}] "
                    "must be an int"
                )
            entity_ids.append(entity_id_value)

        batches.append((batch_id_value, tuple(entity_ids)))

    return tuple(batches)


def _duplicates(values: tuple[int, ...]) -> set[int]:
    seen: set[int] = set()
    duplicates: set[int] = set()
    for value in values:
        if value in seen:
            duplicates.add(value)
        seen.add(value)
    return duplicates


def _format_ids(values: set[int]) -> str:
    return ", ".join(str(value) for value in sorted(values))
