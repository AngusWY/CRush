from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from ..semantic_hint_schemas import (
    PointerDeclarationSemantics,
    UnsafeStmtSemantics,
    VariableDeclarationSemantics,
)
from .models import (
    DECLARATION_TASK_KIND,
    EntitySource,
    PointerSemanticGap,
    SemanticAgentTask,
    UNSAFE_STMT_TASK_KIND,
    UnsafeStmtSemanticGap,
    VariableSemanticGap,
)


TRANSLATION_ENTITIES_FILE_NAME = "translation-entities.json"
SEMANTIC_ANALYSIS_DIR_NAME = "semantic_analysis"
POINTER_SEMANTICS_FILE_NAME = "pointer-semantics.json"
VARIABLE_SEMANTICS_FILE_NAME = "variable-semantics.json"
UNSAFE_STMT_SEMANTICS_FILE_NAME = "unsafe-stmt-semantics.json"
AGENT_REQUIRED_ENTITIES_FILE_NAME = "agent-required-entities.json"


class SemanticAgentTaskBuildError(RuntimeError):
    pass


class SemanticAgentTaskBuilder:


    def __init__(self, *, workspace: Path) -> None:
        self.workspace = workspace.resolve()
        semantic_dir = self.workspace / SEMANTIC_ANALYSIS_DIR_NAME
        self.translation_entities_path = (
            self.workspace / TRANSLATION_ENTITIES_FILE_NAME
        )
        self.pointer_semantics_path = (
            semantic_dir / POINTER_SEMANTICS_FILE_NAME
        )
        self.variable_semantics_path = (
            semantic_dir / VARIABLE_SEMANTICS_FILE_NAME
        )
        self.unsafe_stmt_semantics_path = (
            semantic_dir / UNSAFE_STMT_SEMANTICS_FILE_NAME
        )
        self.agent_required_entities_path = (
            semantic_dir / AGENT_REQUIRED_ENTITIES_FILE_NAME
        )

    def build(self) -> tuple[SemanticAgentTask, ...]:
        required_entity_ids = self._read_required_entity_ids()
        entities = self._read_translation_entities()
        gaps_by_entity = self._read_pointer_gaps(entities)
        variable_gaps_by_entity = self._read_variable_gaps(entities)
        unsafe_gaps_by_entity = self._read_unsafe_stmt_gaps(entities)

        pointer_gap_entity_ids = set(gaps_by_entity)
        variable_gap_entity_ids = set(variable_gaps_by_entity)
        unsafe_gap_entity_ids = set(unsafe_gaps_by_entity)
        gap_entity_ids = (
            pointer_gap_entity_ids
            | variable_gap_entity_ids
            | unsafe_gap_entity_ids
        )
        missing_schedule_ids = sorted(
            gap_entity_ids - required_entity_ids
        )
        if missing_schedule_ids:
            raise SemanticAgentTaskBuildError(
                "entities with unresolved semantics are missing from "
                "the Agent schedule: "
                f"{missing_schedule_ids}"
            )

        unknown_schedule_ids = sorted(
            required_entity_ids - set(entities)
        )
        if unknown_schedule_ids:
            raise SemanticAgentTaskBuildError(
                "Agent schedule references unknown translation entities: "
                f"{unknown_schedule_ids}"
            )

        tasks: list[SemanticAgentTask] = []
        for entity_id in sorted(required_entity_ids & gap_entity_ids):
            pointer_gaps = gaps_by_entity.get(entity_id, ())
            variable_gaps = variable_gaps_by_entity.get(entity_id, ())
            unsafe_stmt_gaps = unsafe_gaps_by_entity.get(entity_id, ())
            if pointer_gaps or variable_gaps:
                tasks.append(
                    self._make_task(
                        entity=entities[entity_id],
                        task_kind=DECLARATION_TASK_KIND,
                        gaps=pointer_gaps,
                        variable_gaps=variable_gaps,
                        unsafe_stmt_gaps=(),
                    )
                )
            if unsafe_stmt_gaps:
                tasks.append(
                    self._make_task(
                        entity=entities[entity_id],
                        task_kind=UNSAFE_STMT_TASK_KIND,
                        gaps=(),
                        variable_gaps=(),
                        unsafe_stmt_gaps=unsafe_stmt_gaps,
                    )
                )
        return tuple(tasks)

    def _read_required_entity_ids(self) -> set[int]:
        data = self._read_json_object(
            self.agent_required_entities_path,
            "Agent-required entities",
        )
        if data.get("version") != 1:
            raise SemanticAgentTaskBuildError(
                "unsupported Agent-required entities version in "
                f"{self.agent_required_entities_path}: "
                f"{data.get('version')!r}"
            )

        raw_entity_ids = data.get("entity_ids")
        if not isinstance(raw_entity_ids, list):
            raise SemanticAgentTaskBuildError(
                "Agent-required entities file has no entity_ids array: "
                f"{self.agent_required_entities_path}"
            )

        entity_ids: set[int] = set()
        for raw_entity_id in raw_entity_ids:
            entity_id = self._required_positive_int(
                raw_entity_id, "Agent-required entity ID"
            )
            if entity_id in entity_ids:
                raise SemanticAgentTaskBuildError(
                    "duplicate Agent-required entity ID: "
                    f"{entity_id}"
                )
            entity_ids.add(entity_id)
        return entity_ids

    def _read_translation_entities(self) -> dict[int, dict[str, Any]]:
        data = self._read_json_object(
            self.translation_entities_path,
            "translation entities",
        )
        if data.get("version") != 1:
            raise SemanticAgentTaskBuildError(
                "unsupported translation entities version in "
                f"{self.translation_entities_path}: "
                f"{data.get('version')!r}"
            )

        raw_entities = data.get("entities")
        if not isinstance(raw_entities, list):
            raise SemanticAgentTaskBuildError(
                "translation entities file has no entities array: "
                f"{self.translation_entities_path}"
            )

        entities: dict[int, dict[str, Any]] = {}
        for raw_entity in raw_entities:
            if not isinstance(raw_entity, dict):
                raise SemanticAgentTaskBuildError(
                    "translation entities array contains a non-object entry"
                )
            entity_id = self._required_positive_int(
                raw_entity.get("id"), "translation entity ID"
            )
            if entity_id in entities:
                raise SemanticAgentTaskBuildError(
                    f"duplicate translation entity ID: {entity_id}"
                )
            entities[entity_id] = raw_entity
        return entities

    def _read_pointer_gaps(
        self,
        entities: dict[int, dict[str, Any]],
    ) -> dict[int, tuple[PointerSemanticGap, ...]]:
        data = self._read_json_object(
            self.pointer_semantics_path,
            "pointer semantics",
        )
        if data.get("version") != 4:
            raise SemanticAgentTaskBuildError(
                "unsupported pointer semantics version in "
                f"{self.pointer_semantics_path}: "
                f"{data.get('version')!r}; expected 4; regenerate semantic analysis"
            )
        if data.get("kind") != "pointer_declarations":
            raise SemanticAgentTaskBuildError(
                "unsupported pointer semantics kind in "
                f"{self.pointer_semantics_path}: "
                f"{data.get('kind')!r}"
            )

        raw_pointers = data.get("pointers")
        if not isinstance(raw_pointers, list):
            raise SemanticAgentTaskBuildError(
                "pointer semantics file has no pointers array: "
                f"{self.pointer_semantics_path}"
            )

        mutable_gaps: dict[int, list[PointerSemanticGap]] = defaultdict(list)
        seen_stmt_ids: set[int] = set()
        for raw_pointer in raw_pointers:
            if not isinstance(raw_pointer, dict):
                raise SemanticAgentTaskBuildError(
                    "pointer semantics array contains a non-object entry"
                )

            entity_id = self._required_positive_int(
                raw_pointer.get("entity_id"), "pointer entity_id"
            )
            if entity_id not in entities:
                raise SemanticAgentTaskBuildError(
                    "pointer semantics references unknown translation entity "
                    f"{entity_id}"
                )
            stmt_id = self._required_positive_int(
                raw_pointer.get("stmt_id"), "pointer stmt_id"
            )

            try:
                semantics = PointerDeclarationSemantics.from_dict(
                    raw_pointer
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise SemanticAgentTaskBuildError(
                    "invalid pointer semantics record for entity "
                    f"{entity_id}: {exc}"
                ) from exc

            if semantics.stmt_id != stmt_id:
                raise SemanticAgentTaskBuildError(
                    "pointer semantics stmt_id changed while parsing: "
                    f"{stmt_id} != {semantics.stmt_id}"
                )
            if semantics.stmt_id in seen_stmt_ids:
                raise SemanticAgentTaskBuildError(
                    "duplicate pointer semantics stmt_id: "
                    f"{semantics.stmt_id}"
                )
            seen_stmt_ids.add(semantics.stmt_id)

            missing_fields = tuple(semantics.missing_fields())
            if not missing_fields:
                continue
            mutable_gaps[entity_id].append(
                PointerSemanticGap(
                    stmt_id=semantics.stmt_id,
                    current_semantics=semantics,
                    missing_fields=missing_fields,
                )
            )

        return {
            entity_id: tuple(
                sorted(gaps, key=lambda gap: gap.stmt_id)
            )
            for entity_id, gaps in mutable_gaps.items()
        }

    def _read_variable_gaps(
        self,
        entities: dict[int, dict[str, Any]],
    ) -> dict[int, tuple[VariableSemanticGap, ...]]:
        if not self.variable_semantics_path.is_file():
            return {}
        data = self._read_json_object(
            self.variable_semantics_path,
            "variable semantics",
        )
        if data.get("version") != 1:
            raise SemanticAgentTaskBuildError(
                "unsupported variable semantics version in "
                f"{self.variable_semantics_path}: "
                f"{data.get('version')!r}; expected 1"
            )
        if data.get("kind") != "variable_declarations":
            raise SemanticAgentTaskBuildError(
                "unsupported variable semantics kind in "
                f"{self.variable_semantics_path}: "
                f"{data.get('kind')!r}"
            )

        raw_variables = data.get("variables")
        if not isinstance(raw_variables, list):
            raise SemanticAgentTaskBuildError(
                "variable semantics file has no variables array: "
                f"{self.variable_semantics_path}"
            )

        mutable_gaps: dict[int, list[VariableSemanticGap]] = defaultdict(list)
        seen_stmt_ids: set[int] = set()
        for raw_variable in raw_variables:
            if not isinstance(raw_variable, dict):
                raise SemanticAgentTaskBuildError(
                    "variable semantics array contains a non-object entry"
                )
            entity_id = self._required_positive_int(
                raw_variable.get("entity_id"), "variable entity_id"
            )
            if entity_id not in entities:
                raise SemanticAgentTaskBuildError(
                    "variable semantics references unknown translation entity "
                    f"{entity_id}"
                )
            stmt_id = self._required_positive_int(
                raw_variable.get("stmt_id"), "variable stmt_id"
            )
            try:
                semantics = VariableDeclarationSemantics.from_dict(
                    raw_variable
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise SemanticAgentTaskBuildError(
                    "invalid variable semantics record for entity "
                    f"{entity_id}: {exc}"
                ) from exc
            if semantics.stmt_id != stmt_id:
                raise SemanticAgentTaskBuildError(
                    "variable semantics stmt_id changed while parsing: "
                    f"{stmt_id} != {semantics.stmt_id}"
                )
            if semantics.stmt_id in seen_stmt_ids:
                raise SemanticAgentTaskBuildError(
                    "duplicate variable semantics stmt_id: "
                    f"{semantics.stmt_id}"
                )
            seen_stmt_ids.add(semantics.stmt_id)

            missing_fields = tuple(semantics.missing_fields())
            if not missing_fields:
                continue
            mutable_gaps[entity_id].append(
                VariableSemanticGap(
                    stmt_id=semantics.stmt_id,
                    current_semantics=semantics,
                    missing_fields=missing_fields,
                )
            )

        return {
            entity_id: tuple(
                sorted(gaps, key=lambda gap: gap.stmt_id)
            )
            for entity_id, gaps in mutable_gaps.items()
        }

    def _read_unsafe_stmt_gaps(
        self,
        entities: dict[int, dict[str, Any]],
    ) -> dict[int, tuple[UnsafeStmtSemanticGap, ...]]:
        if not self.unsafe_stmt_semantics_path.is_file():
            return {}
        data = self._read_json_object(
            self.unsafe_stmt_semantics_path,
            "unsafe stmt semantics",
        )
        if data.get("version") != 3:
            raise SemanticAgentTaskBuildError(
                "unsupported unsafe stmt semantics version in "
                f"{self.unsafe_stmt_semantics_path}: "
                f"{data.get('version')!r}; expected 3"
            )
        if data.get("kind") != "unsafe_stmts":
            raise SemanticAgentTaskBuildError(
                "unsupported unsafe stmt semantics kind in "
                f"{self.unsafe_stmt_semantics_path}: "
                f"{data.get('kind')!r}"
            )

        raw_stmts = data.get("unsafe_stmts")
        if not isinstance(raw_stmts, list):
            raise SemanticAgentTaskBuildError(
                "unsafe stmt semantics file has no unsafe_stmts array: "
                f"{self.unsafe_stmt_semantics_path}"
            )

        mutable_gaps: dict[int, list[UnsafeStmtSemanticGap]] = defaultdict(list)
        seen_stmt_ids: set[int] = set()
        for raw_stmt in raw_stmts:
            if not isinstance(raw_stmt, dict):
                raise SemanticAgentTaskBuildError(
                    "unsafe_stmts array contains a non-object entry"
                )
            entity_id = self._required_positive_int(
                raw_stmt.get("entity_id"), "unsafe stmt entity_id"
            )
            if entity_id not in entities:
                raise SemanticAgentTaskBuildError(
                    "unsafe stmt semantics references unknown translation "
                    f"entity {entity_id}"
                )
            stmt_id = self._required_positive_int(
                raw_stmt.get("stmt_id"), "unsafe stmt stmt_id"
            )
            try:
                semantics = UnsafeStmtSemantics.from_dict(raw_stmt)
            except (KeyError, TypeError, ValueError) as exc:
                raise SemanticAgentTaskBuildError(
                    "invalid unsafe stmt semantics record for entity "
                    f"{entity_id}: {exc}"
                ) from exc
            if semantics.stmt_id != stmt_id:
                raise SemanticAgentTaskBuildError(
                    "unsafe stmt semantics stmt_id changed while parsing: "
                    f"{stmt_id} != {semantics.stmt_id}"
                )
            if semantics.stmt_id in seen_stmt_ids:
                raise SemanticAgentTaskBuildError(
                    "duplicate unsafe stmt semantics stmt_id: "
                    f"{semantics.stmt_id}"
                )
            seen_stmt_ids.add(semantics.stmt_id)

            missing_fields = tuple(semantics.missing_fields())
            if not missing_fields:
                continue
            mutable_gaps[entity_id].append(
                UnsafeStmtSemanticGap(
                    stmt_id=semantics.stmt_id,
                    operation=semantics.operation.value,
                    semantic_kind=semantics.semantic_kind.value,
                    current_semantics=semantics,
                    missing_fields=missing_fields,
                )
            )

        return {
            entity_id: tuple(
                sorted(gaps, key=lambda gap: gap.stmt_id)
            )
            for entity_id, gaps in mutable_gaps.items()
        }

    def _make_task(
        self,
        *,
        entity: dict[str, Any],
        task_kind: str,
        gaps: tuple[PointerSemanticGap, ...],
        variable_gaps: tuple[VariableSemanticGap, ...],
        unsafe_stmt_gaps: tuple[UnsafeStmtSemanticGap, ...],
    ) -> SemanticAgentTask:
        entity_id = self._required_positive_int(
            entity.get("id"), "translation entity ID"
        )
        entity_name = self._required_text(
            entity.get("name"), f"translation entity {entity_id} name"
        )
        entity_kind = self._required_text(
            entity.get("kind"), f"translation entity {entity_id} kind"
        )
        unit_id = self._required_positive_int(
            entity.get("unit_id"),
            f"translation entity {entity_id} unit_id",
        )
        member_entity_ids = self._member_entity_ids(entity_id, entity)
        source = self._entity_source(entity_id, entity.get("source"))

        return SemanticAgentTask(
            task_kind=task_kind,
            entity_id=entity_id,
            entity_name=entity_name,
            entity_kind=entity_kind,
            unit_id=unit_id,
            member_entity_ids=member_entity_ids,
            source=source,
            pointer_gaps=gaps,
            variable_gaps=variable_gaps,
            unsafe_stmt_gaps=unsafe_stmt_gaps,
        )

    def _member_entity_ids(
        self,
        entity_id: int,
        entity: dict[str, Any],
    ) -> tuple[int, ...]:
        raw_member_ids = entity.get("member_entity_ids")
        if not isinstance(raw_member_ids, list) or not raw_member_ids:
            raise SemanticAgentTaskBuildError(
                f"translation entity {entity_id} has no member_entity_ids"
            )

        member_ids: list[int] = []
        seen: set[int] = set()
        for raw_member_id in raw_member_ids:
            member_id = self._required_positive_int(
                raw_member_id,
                f"translation entity {entity_id} member ID",
            )
            if member_id in seen:
                raise SemanticAgentTaskBuildError(
                    f"translation entity {entity_id} has duplicate member ID "
                    f"{member_id}"
                )
            seen.add(member_id)
            member_ids.append(member_id)
        return tuple(member_ids)

    def _entity_source(
        self,
        entity_id: int,
        raw_source: Any,
    ) -> EntitySource:
        if not isinstance(raw_source, dict):
            raise SemanticAgentTaskBuildError(
                f"translation entity {entity_id} has no source object"
            )

        source = EntitySource(
            path=self._required_text(
                raw_source.get("path"),
                f"translation entity {entity_id} source path",
            ),
            rel_path=self._required_text(
                raw_source.get("rel_path"),
                f"translation entity {entity_id} relative source path",
            ),
            start_line=self._required_nonnegative_int(
                raw_source.get("start_line"),
                f"translation entity {entity_id} source start_line",
            ),
            start_col=self._required_nonnegative_int(
                raw_source.get("start_col"),
                f"translation entity {entity_id} source start_col",
            ),
            end_line=self._required_nonnegative_int(
                raw_source.get("end_line"),
                f"translation entity {entity_id} source end_line",
            ),
            end_col=self._required_nonnegative_int(
                raw_source.get("end_col"),
                f"translation entity {entity_id} source end_col",
            ),
        )
        if (source.end_line, source.end_col) < (
            source.start_line,
            source.start_col,
        ):
            raise SemanticAgentTaskBuildError(
                f"translation entity {entity_id} has an invalid source range"
            )
        return source

    @staticmethod
    def _read_json_object(path: Path, description: str) -> dict[str, Any]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SemanticAgentTaskBuildError(
                f"failed to read {description} {path}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise SemanticAgentTaskBuildError(
                f"{description} must be a JSON object: {path}"
            )
        return value

    @staticmethod
    def _required_positive_int(value: Any, description: str) -> int:
        result = SemanticAgentTaskBuilder._required_int(
            value, description
        )
        if result <= 0:
            raise SemanticAgentTaskBuildError(
                f"{description} must be positive; got {value!r}"
            )
        return result

    @staticmethod
    def _required_nonnegative_int(value: Any, description: str) -> int:
        result = SemanticAgentTaskBuilder._required_int(
            value, description
        )
        if result < 0:
            raise SemanticAgentTaskBuildError(
                f"{description} must be nonnegative; got {value!r}"
            )
        return result

    @staticmethod
    def _required_int(value: Any, description: str) -> int:
        if isinstance(value, bool):
            raise SemanticAgentTaskBuildError(
                f"{description} must be an integer; got {value!r}"
            )
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise SemanticAgentTaskBuildError(
                f"{description} must be an integer; got {value!r}"
            ) from exc

    @staticmethod
    def _required_text(value: Any, description: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise SemanticAgentTaskBuildError(
                f"{description} must be non-empty text; got {value!r}"
            )
        return value.strip()
