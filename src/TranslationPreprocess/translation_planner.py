from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .config import (
    ENTITY_DEPENDENCIES_NAME,
    RUST_MODULE_LAYOUT_NAME,
    TRANSLATION_ENTITIES_NAME,
    TRANSLATION_PLAN_NAME,
)
from .models import PreprocessManifest


_KIND_PRIORITY = {
    "type": 0,
    "macro_family": 0,
    "global": 1,
    "function": 2,
}


class TranslationPlanError(RuntimeError):
    pass


class TranslationPlanner:


    def __init__(self, *, manifest: PreprocessManifest) -> None:
        self.manifest = manifest
        self.entities_path = (
            manifest.workspace / TRANSLATION_ENTITIES_NAME
        )
        self.dependencies_path = (
            manifest.workspace / ENTITY_DEPENDENCIES_NAME
        )
        self.layout_path = (
            manifest.workspace / RUST_MODULE_LAYOUT_NAME
        )
        self.output_path = (
            manifest.workspace / TRANSLATION_PLAN_NAME
        )

    def run(self) -> Path:
        entities = self._read_entities()
        dependencies = self._read_dependencies(set(entities))
        placements = self._read_placements(set(entities))

        components = self._strongly_connected_components(
            dependencies
        )
        component_layers = self._topological_layers(
            components,
            dependencies,
            entities,
            placements,
        )
        component_by_entity = {
            entity_id: component_id
            for component_id, component in enumerate(components)
            for entity_id in component
        }

        batch_components = self._split_layers_by_kind(
            component_layers, entities, placements
        )
        batches: list[dict[str, Any]] = []
        entity_to_batch: dict[str, int] = {}
        for batch_id, components_in_batch in enumerate(
            batch_components
        ):
            entity_ids = sorted(
                (
                    entity_id
                    for component in components_in_batch
                    for entity_id in component
                ),
                key=lambda entity_id: self._entity_sort_key(
                    entity_id, entities, placements
                ),
            )
            batches.append(
                {
                    "batch_id": batch_id,
                    "entity_ids": entity_ids,
                }
            )
            for entity_id in entity_ids:
                entity_to_batch[str(entity_id)] = batch_id

        self._validate_plan(
            entities=set(entities),
            dependencies=dependencies,
            batches=batches,
            entity_to_batch=entity_to_batch,
            component_by_entity=component_by_entity,
        )
        self._write_result(
            {
                "version": 1,
                "batches": batches,
                "entity_to_batch": entity_to_batch,
            }
        )
        return self.output_path

    def _read_entities(self) -> dict[int, dict[str, Any]]:
        data = self._read_json(
            self.entities_path, "translation entities"
        )
        raw_entities = data.get("entities")
        if not isinstance(raw_entities, list):
            raise TranslationPlanError(
                "translation entities file has no entities array: "
                f"{self.entities_path}"
            )

        entities: dict[int, dict[str, Any]] = {}
        for raw_entity in raw_entities:
            if not isinstance(raw_entity, dict):
                raise TranslationPlanError(
                    "translation entity must be a JSON object"
                )
            entity_id = self._int_field(raw_entity, "id")
            if entity_id in entities:
                raise TranslationPlanError(
                    f"duplicate translation entity id: {entity_id}"
                )
            source = raw_entity.get("source")
            if not isinstance(source, dict):
                raise TranslationPlanError(
                    f"translation entity {entity_id} has no source"
                )
            entities[entity_id] = raw_entity
        return entities

    def _read_dependencies(
        self, entity_ids: set[int]
    ) -> dict[int, set[int]]:
        data = self._read_json(
            self.dependencies_path, "entity dependencies"
        )
        rows = data.get("entities")
        if not isinstance(rows, list):
            raise TranslationPlanError(
                "entity dependencies file has no entities array: "
                f"{self.dependencies_path}"
            )

        dependencies: dict[int, set[int]] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise TranslationPlanError(
                    "entity dependency row must be a JSON object"
                )
            entity_id = self._int_field(row, "entity_id")
            if entity_id in dependencies:
                raise TranslationPlanError(
                    f"duplicate dependency row for entity {entity_id}"
                )
            if entity_id not in entity_ids:
                raise TranslationPlanError(
                    f"dependency row references unknown entity {entity_id}"
                )
            raw_dependencies = row.get("dependencies")
            if not isinstance(raw_dependencies, list):
                raise TranslationPlanError(
                    f"dependencies for entity {entity_id} must be a list"
                )

            dependency_ids: set[int] = set()
            for raw_dependency in raw_dependencies:
                dependency_id = self._to_int(raw_dependency)
                if dependency_id is None:
                    raise TranslationPlanError(
                        f"entity {entity_id} has invalid dependency "
                        f"{raw_dependency!r}"
                    )
                if dependency_id not in entity_ids:
                    raise TranslationPlanError(
                        f"entity {entity_id} depends on unknown entity "
                        f"{dependency_id}"
                    )
                if dependency_id == entity_id:
                    raise TranslationPlanError(
                        f"entity {entity_id} depends on itself"
                    )
                dependency_ids.add(dependency_id)
            dependencies[entity_id] = dependency_ids

        missing = sorted(entity_ids - set(dependencies))
        if missing:
            raise TranslationPlanError(
                f"missing dependency rows for entities: {missing}"
            )
        return dependencies

    def _read_placements(
        self, entity_ids: set[int]
    ) -> dict[int, dict[str, str]]:
        data = self._read_json(
            self.layout_path, "Rust module layout"
        )
        raw_placements = data.get("entity_placements")
        if not isinstance(raw_placements, dict):
            raise TranslationPlanError(
                "Rust module layout has no entity_placements mapping: "
                f"{self.layout_path}"
            )

        placements: dict[int, dict[str, str]] = {}
        for entity_id in entity_ids:
            placement = raw_placements.get(str(entity_id))
            if not isinstance(placement, dict):
                raise TranslationPlanError(
                    f"missing Rust placement for entity {entity_id}"
                )
            module = placement.get("module")
            rust_file = placement.get("rust_file")
            if not isinstance(module, str) or not module:
                raise TranslationPlanError(
                    f"entity {entity_id} has invalid Rust module"
                )
            if not isinstance(rust_file, str) or not rust_file:
                raise TranslationPlanError(
                    f"entity {entity_id} has invalid Rust file"
                )
            placements[entity_id] = {
                "module": module,
                "rust_file": rust_file,
            }
        return placements

    @staticmethod
    def _strongly_connected_components(
        dependencies: dict[int, set[int]],
    ) -> list[set[int]]:
        index = 0
        stack: list[int] = []
        on_stack: set[int] = set()
        indices: dict[int, int] = {}
        lowlinks: dict[int, int] = {}
        components: list[set[int]] = []

        def visit(entity_id: int) -> None:
            nonlocal index
            indices[entity_id] = index
            lowlinks[entity_id] = index
            index += 1
            stack.append(entity_id)
            on_stack.add(entity_id)

            for dependency_id in sorted(dependencies[entity_id]):
                if dependency_id not in indices:
                    visit(dependency_id)
                    lowlinks[entity_id] = min(
                        lowlinks[entity_id],
                        lowlinks[dependency_id],
                    )
                elif dependency_id in on_stack:
                    lowlinks[entity_id] = min(
                        lowlinks[entity_id],
                        indices[dependency_id],
                    )

            if lowlinks[entity_id] != indices[entity_id]:
                return
            component: set[int] = set()
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.add(member)
                if member == entity_id:
                    break
            components.append(component)

        for entity_id in sorted(dependencies):
            if entity_id not in indices:
                visit(entity_id)
        return components

    def _topological_layers(
        self,
        components: list[set[int]],
        dependencies: dict[int, set[int]],
        entities: dict[int, dict[str, Any]],
        placements: dict[int, dict[str, str]],
    ) -> list[list[set[int]]]:
        component_by_entity = {
            entity_id: component_id
            for component_id, component in enumerate(components)
            for entity_id in component
        }
        successors: dict[int, set[int]] = {
            component_id: set()
            for component_id in range(len(components))
        }
        indegrees = {
            component_id: 0
            for component_id in range(len(components))
        }

        for dependent_id, dependency_ids in dependencies.items():
            dependent_component = component_by_entity[dependent_id]
            for dependency_id in dependency_ids:
                dependency_component = component_by_entity[dependency_id]
                if dependency_component == dependent_component:
                    continue
                if dependent_component in successors[dependency_component]:
                    continue
                successors[dependency_component].add(
                    dependent_component
                )
                indegrees[dependent_component] += 1

        ready = {
            component_id
            for component_id, indegree in indegrees.items()
            if indegree == 0
        }
        result: list[list[set[int]]] = []
        processed_count = 0
        while ready:
            current_ids = sorted(
                ready,
                key=lambda component_id: self._component_sort_key(
                    components[component_id],
                    entities,
                    placements,
                ),
            )
            result.append(
                [components[component_id] for component_id in current_ids]
            )
            processed_count += len(current_ids)

            next_ready: set[int] = set()
            for component_id in current_ids:
                for successor_id in successors[component_id]:
                    indegrees[successor_id] -= 1
                    if indegrees[successor_id] == 0:
                        next_ready.add(successor_id)
            ready = next_ready

        if processed_count != len(components):
            raise TranslationPlanError(
                "failed to topologically order dependency components"
            )
        return result

    def _split_layers_by_kind(
        self,
        component_layers: list[list[set[int]]],
        entities: dict[int, dict[str, Any]],
        placements: dict[int, dict[str, str]],
    ) -> list[list[set[int]]]:
        batches: list[list[set[int]]] = []
        for layer in component_layers:
            homogeneous: dict[int, list[set[int]]] = {}
            mixed: list[set[int]] = []
            for component in layer:
                priorities = {
                    _KIND_PRIORITY.get(
                        str(entities[entity_id].get("kind", "")), 3
                    )
                    for entity_id in component
                }
                if len(priorities) == 1:
                    priority = next(iter(priorities))
                    homogeneous.setdefault(priority, []).append(
                        component
                    )
                else:
                    mixed.append(component)

            for priority in sorted(homogeneous):
                batches.append(
                    sorted(
                        homogeneous[priority],
                        key=lambda component: (
                            self._component_sort_key(
                                component, entities, placements
                            )
                        ),
                    )
                )
            for component in sorted(
                mixed,
                key=lambda item: self._component_sort_key(
                    item, entities, placements
                ),
            ):
                batches.append([component])
        return batches

    def _component_sort_key(
        self,
        component: set[int],
        entities: dict[int, dict[str, Any]],
        placements: dict[int, dict[str, str]],
    ) -> tuple[Any, ...]:
        return min(
            self._schedule_sort_key(
                entity_id, entities, placements
            )
            for entity_id in component
        )

    @staticmethod
    def _schedule_sort_key(
        entity_id: int,
        entities: dict[int, dict[str, Any]],
        placements: dict[int, dict[str, str]],
    ) -> tuple[Any, ...]:
        entity = entities[entity_id]
        source = entity["source"]
        placement = placements[entity_id]
        return (
            placement["rust_file"],
            str(source.get("rel_path", "")),
            TranslationPlanner._source_position(source, "start_line"),
            TranslationPlanner._source_position(source, "start_col"),
            entity_id,
        )

    @staticmethod
    def _entity_sort_key(
        entity_id: int,
        entities: dict[int, dict[str, Any]],
        placements: dict[int, dict[str, str]],
    ) -> tuple[Any, ...]:
        entity = entities[entity_id]
        return (
            _KIND_PRIORITY.get(str(entity.get("kind", "")), 3),
            *TranslationPlanner._schedule_sort_key(
                entity_id, entities, placements
            ),
        )

    @staticmethod
    def _validate_plan(
        *,
        entities: set[int],
        dependencies: dict[int, set[int]],
        batches: list[dict[str, Any]],
        entity_to_batch: dict[str, int],
        component_by_entity: dict[int, int],
    ) -> None:
        planned = [
            entity_id
            for batch in batches
            for entity_id in batch["entity_ids"]
        ]
        if len(planned) != len(set(planned)):
            raise TranslationPlanError(
                "translation plan contains duplicate entities"
            )
        if set(planned) != entities:
            raise TranslationPlanError(
                "translation plan does not contain every entity"
            )

        for entity_id, dependency_ids in dependencies.items():
            entity_batch = entity_to_batch[str(entity_id)]
            for dependency_id in dependency_ids:
                dependency_batch = entity_to_batch[str(dependency_id)]
                same_component = (
                    component_by_entity[entity_id]
                    == component_by_entity[dependency_id]
                )
                if dependency_batch > entity_batch or (
                    dependency_batch == entity_batch
                    and not same_component
                ):
                    raise TranslationPlanError(
                        f"entity {entity_id} is scheduled before "
                        f"dependency {dependency_id}"
                    )

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
            raise TranslationPlanError(
                f"failed to write translation plan "
                f"{self.output_path}: {exc}"
            ) from exc

    @staticmethod
    def _read_json(
        path: Path, description: str
    ) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise TranslationPlanError(
                f"failed to read {description} {path}: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise TranslationPlanError(
                f"{description} is not a JSON object: {path}"
            )
        return data

    @staticmethod
    def _int_field(data: dict[str, Any], field: str) -> int:
        value = TranslationPlanner._to_int(data.get(field))
        if value is None:
            raise TranslationPlanError(
                f"invalid integer field {field}: {data.get(field)!r}"
            )
        return value

    @staticmethod
    def _to_int(value: Any) -> int | None:
        if isinstance(value, bool):
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _source_position(
        source: dict[str, Any], field: str
    ) -> int:
        value = TranslationPlanner._to_int(source.get(field))
        return value if value is not None else 0
