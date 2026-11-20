from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import traceback
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable

from TranslationPreprocess.c_source_lex import mask_c_non_code

from .agents.llm_client import OpenAICompatibleTranslationLLMClient, TranslationLLMError
from .agents.runtime import TranslationAgentRuntime
from .compiler import RustCompiler
from .import_manager import ImportManager
from .library_profiles import (
    CargoDependency,
    cargo_dependencies_for_matches,
    library_profile_matches_for_source,
)
from .models import (
    CargoDependencySpec,
    CheckerSummary,
    CompileResult,
    EntityPlacement,
    EntityTranslationState,
    JsonDict,
    RepairAttempt,
    ResourceDecision,
    TranslatedEntity,
    TranslatedSignature,
    TranslationBatch,
    TranslationTask,
)
from .module_writer import ModuleWriter
from .planner import build_translation_batches
from .project_inspection_tool import ProjectInspectionTool
from .semantic_hint_tool import SemanticHintTool


_RUST_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_C_SIMPLE_TYPEDEF_PATTERN = re.compile(
    r"\btypedef\s+"
    r"(?P<underlying>(?:(?:const|volatile|signed|unsigned|short|long)\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;"
)
_RUST_PRIMITIVE_TYPE_NAMES = frozenset(
    {
        "bool",
        "char",
        "f32",
        "f64",
        "i8",
        "i16",
        "i32",
        "i64",
        "i128",
        "isize",
        "str",
        "u8",
        "u16",
        "u32",
        "u64",
        "u128",
        "usize",
    }
)
_SELF_REFERENTIAL_TYPE_ALIAS_PATTERN = re.compile(
    r"(?P<prefix>\b(?:pub(?:\s*\([^)]*\))?\s+)?type\s+)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<equals>\s*=\s*)"
    r"(?P=name)"
    r"(?P<suffix>\s*;)"
)
@dataclass(frozen=True)
class _InitialTranslationWork:
    task: TranslationTask
    state: EntityTranslationState
    dependency_context: str
    external_symbol_context: str


@dataclass(frozen=True)
class _InitialTranslationResult:
    task: TranslationTask
    state: EntityTranslationState
    translated: TranslatedEntity
    dependency_context: str
    external_symbol_context: str
    fallback_used: bool = False


class _MissingGlobalDefinitionsError(ValueError):
    def __init__(
        self,
        *,
        entity_id: int,
        missing_exports: tuple[str, ...],
        require_public: bool,
    ) -> None:
        self.entity_id = entity_id
        self.missing_exports = missing_exports
        visibility = "public Rust exports" if require_public else "Rust definitions"
        super().__init__(
            f"global entity {entity_id} translation omitted required "
            f"{visibility}: {', '.join(missing_exports)}. "
            "Every required_export for this C global declaration must be emitted."
        )


class _EntityOutputContractError(ValueError):
    def __init__(
        self,
        *,
        entity_id: int,
        violations: tuple[str, ...],
    ) -> None:
        self.entity_id = entity_id
        self.violations = violations
        super().__init__(
            f"entity {entity_id} output contract violation: "
            + "; ".join(violations)
        )


class TranslationPipeline:


    def __init__(
        self,
        *,
        workspace: Path | str,
        runtime: TranslationAgentRuntime,
        max_repair_attempts: int = 3,
        translation_concurrency: int = 3,
        compiler: RustCompiler | None = None,
        writer: ModuleWriter | None = None,
        report_path: Path | str | None = None,
        state_path: Path | str | None = None,
        log: Callable[[str], None] | None = print,
        reset_generated: bool = True,
        resume_from_entity: int | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self.runtime = runtime
        self.max_repair_attempts = max_repair_attempts
        if translation_concurrency < 1:
            raise ValueError("translation_concurrency must be at least 1")
        self.translation_concurrency = translation_concurrency
        self.batches = build_translation_batches(self.workspace)
        self.rust_project = _read_rust_project(self.workspace)
        self.compiler = compiler or RustCompiler(self.rust_project)
        self.writer = writer or ModuleWriter()
        self.report_path = (
            Path(report_path)
            if report_path is not None
            else self.workspace / "translation-report.json"
        )
        self.state_path = (
            Path(state_path)
            if state_path is not None
            else self.workspace / "translation-state.json"
        )
        self._log = log
        self.resume_from_entity = resume_from_entity
        self.reset_generated = False if resume_from_entity is not None else reset_generated

        self.placements = _placements_from_batches(self.batches)
        self.kind_by_entity = _kinds_from_batches(self.batches)
        self.tasks_by_entity = _tasks_from_batches(self.batches)
        self.c_type_aliases = _collect_c_type_aliases(
            self.tasks_by_entity.values()
        )
        self.exports_by_entity: dict[int, tuple[str, ...]] = {}
        self.support_exports_by_entity: dict[int, tuple[str, ...]] = {}
        self.resource_decisions_by_entity: dict[int, tuple[ResourceDecision, ...]] = {}
        self.cargo_dependencies_by_entity: dict[int, tuple[CargoDependencySpec, ...]] = {}
        self._managed_cargo_dependencies: tuple[CargoDependency, ...] = ()
        self.rust_by_entity: dict[int, str] = {}
        self._no_import_dependency_ids: set[int] = set()
        self.states: dict[int, EntityTranslationState] = {}
        self._report_entities: list[JsonDict] = []
        self._library_profile_report: list[JsonDict] = []
        if self.resume_from_entity is not None and not _plan_has_entity(
            self.batches,
            self.resume_from_entity,
        ):
            raise ValueError(
                f"resume entity {self.resume_from_entity} is not in translation plan"
            )
        self._state_entities = (
            {} if self.reset_generated else self._load_translation_state()
        )

    async def run(self) -> JsonDict:
        self._emit(
            f"translation start workspace={self.workspace} "
            f"batches={len(self.batches)} rust_project={self.rust_project}"
        )
        if self.reset_generated:
            rust_files = _rust_files_from_batches(self.batches)
            self._emit(f"clearing generated Translation code from {len(rust_files)} files")
            self.writer.clear_generated_content(rust_files)
            self._write_translation_state()
        self._configure_library_profiles()
        for batch in self.batches:
            self._emit(
                f"batch {batch.batch_id} start entities="
                f"{[task.entity_id for task in batch.tasks]}"
            )
            tasks_to_run = await self._tasks_to_run_for_batch(batch)
            if not tasks_to_run:
                continue
            self._prepare_extern_global_declaration_noops(batch)
            self._prepare_cyclic_type_placeholders(batch)
            await self._prepare_cyclic_batch_skeletons(batch)
            await self._run_batch_tasks(batch=batch, tasks=tasks_to_run)

        final_compile_result = self.compiler.check()
        report = {
            "version": 1,
            "workspace": str(self.workspace),
            "rust_project": str(self.rust_project),
            "entities": self._report_entities,
            "library_profiles": self._library_profile_report,
            "llm_token_usage": self._token_usage_summary(),
            "final_compile": {
                "passed": final_compile_result.passed,
                "exit_code": final_compile_result.exit_code,
                "stdout": final_compile_result.stdout,
                "stderr": final_compile_result.stderr,
            },
        }
        self.report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self._emit(f"translation report written: {self.report_path}")
        return report

    def _configure_library_profiles(self) -> None:
        matches = tuple(
            match
            for batch in self.batches
            for task in batch.tasks
            for match in library_profile_matches_for_source(
                task.package.original_c_source,
                exclude_functions=frozenset({task.package.name}),
            )
        )
        dependencies = cargo_dependencies_for_matches(matches)
        self._managed_cargo_dependencies = dependencies

        profiles: dict[str, dict[str, Any]] = {}
        for match in matches:
            entry = profiles.setdefault(
                match.profile.key,
                {
                    "key": match.profile.key,
                    "used_functions": set(),
                    "cargo_dependencies": {
                        dependency.name: dependency.version
                        for dependency in match.profile.cargo_dependencies
                    },
                    "strategy": "native",
                    "unsupported_functions": set(),
                },
            )
            entry["used_functions"].update(match.used_functions)
            entry["unsupported_functions"].update(
                match.unsupported_functions
            )

        self._library_profile_report = [
            {
                **entry,
                "used_functions": sorted(entry["used_functions"]),
                "unsupported_functions": sorted(
                    entry["unsupported_functions"]
                ),
            }
            for _, entry in sorted(profiles.items())
        ]
        if self._library_profile_report:
            selected = [entry["key"] for entry in self._library_profile_report]
            self._emit(
                f"configured library profiles={selected} "
                f"required_cargo_dependencies={[dependency.name for dependency in dependencies]} "
                "(must already be configured manually)"
            )

    def _external_symbol_context(self, task: TranslationTask) -> str:
        project_inspection_tool = getattr(
            self.runtime,
            "project_inspection_tool",
            None,
        )
        if project_inspection_tool is None:
            return ""



        cargo_context = project_inspection_tool.build_cargo_dependency_context()
        try:
            symbol_context = project_inspection_tool.build_external_symbol_context(task)
        except Exception as exc:
            self._emit(
                f"{_task_label(task)} external symbol context unavailable: {exc}"
            )
            symbol_context = ""
        return "\n\n".join(part for part in (cargo_context, symbol_context) if part)

    def run_sync(self) -> JsonDict:
        return asyncio.run(self.run())

    async def _tasks_to_run_for_batch(
        self,
        batch: TranslationBatch,
    ) -> tuple[TranslationTask, ...]:
        if self.resume_from_entity is None:
            return batch.tasks

        batch_entity_ids = {task.entity_id for task in batch.tasks}
        if self.resume_from_entity not in batch_entity_ids:
            for task in batch.tasks:
                self._restore_completed_task(task)
            return ()

        tasks_to_run: list[TranslationTask] = []
        resume_reached = False
        for task in batch.tasks:
            if task.entity_id == self.resume_from_entity:
                resume_reached = True
            if resume_reached:
                tasks_to_run.append(task)
            else:
                self._restore_completed_task(task)
        self.resume_from_entity = None
        return tuple(tasks_to_run)

    async def _prepare_cyclic_batch_skeletons(
        self,
        batch: TranslationBatch,
    ) -> None:
        skeleton_tasks = self._cyclic_function_tasks_needing_skeleton(batch)
        if not skeleton_tasks:
            return

        self._emit(
            f"batch {batch.batch_id} cyclic skeleton pass entities="
            f"{[task.entity_id for task in skeleton_tasks]}"
        )
        for task in skeleton_tasks:
            self.exports_by_entity.setdefault(
                task.entity_id,
                _expected_export_names(task),
            )
        batch_entity_ids = {task.entity_id for task in batch.tasks}
        for task in skeleton_tasks:
            if task.entity_id in self.rust_by_entity:
                continue
            dependency_context = self._dependency_context_for_task(
                task,
                allow_missing_dependency_ids=batch_entity_ids,
            )
            external_symbol_context = self._external_symbol_context(task)
            self._emit(f"{_task_label(task)} translating cyclic signature")
            signature = await self.runtime.translate_signature(
                task,
                dependency_context=dependency_context,
                external_symbol_context=external_symbol_context,
            )
            signature = self._stabilize_signature(task, signature)
            skeleton = self._signature_skeleton(task, signature)
            self._record_translation(task, skeleton)
            self._write_translation(task, skeleton)
            self._emit(
                f"{_task_label(task)} wrote cyclic skeleton "
                f"exports={list(skeleton.exports)}"
            )

    def _prepare_extern_global_declaration_noops(
        self,
        batch: TranslationBatch,
    ) -> None:
        tasks_by_id = {task.entity_id: task for task in batch.tasks}
        for task in batch.tasks:
            if task.entity_id in self.rust_by_entity:
                continue
            if not _is_extern_global_declaration(task):
                continue
            if not any(
                _is_global_definition_of(tasks_by_id.get(dependency_id), task)
                for dependency_id in task.dependency_ids
            ):
                continue
            translated = _extern_global_declaration_noop(task)
            self._record_translation(task, translated)
            self._mark_no_import_dependency(task.entity_id)
            self._write_translation_without_imports(task, translated)
            self._emit(
                f"{_task_label(task)} normalized extern global declaration "
                f"to no-op exports={list(translated.exports)}"
            )

    def _prepare_cyclic_type_placeholders(
        self,
        batch: TranslationBatch,
    ) -> None:
        placeholder_tasks = self._cyclic_type_tasks_needing_placeholder(batch)
        if not placeholder_tasks:
            return

        self._emit(
            f"batch {batch.batch_id} cyclic type placeholder pass entities="
            f"{[task.entity_id for task in placeholder_tasks]}"
        )
        for task in placeholder_tasks:
            if task.entity_id in self.rust_by_entity:
                continue
            placeholder = _cyclic_type_placeholder(task)
            self._record_translation(task, placeholder)
            self._write_translation_without_imports(task, placeholder)
            self._emit(
                f"{_task_label(task)} wrote cyclic type placeholder "
                f"exports={list(placeholder.exports)}"
            )

    def _cyclic_function_tasks_needing_skeleton(
        self,
        batch: TranslationBatch,
    ) -> tuple[TranslationTask, ...]:
        batch_entity_ids = {task.entity_id for task in batch.tasks}
        result: list[TranslationTask] = []
        for task in batch.tasks:
            if task.kind != "function":
                continue
            if task.entity_id in self.rust_by_entity:
                continue
            if any(dependency_id in batch_entity_ids for dependency_id in task.dependency_ids):
                result.append(task)
        return tuple(result)

    def _cyclic_type_tasks_needing_placeholder(
        self,
        batch: TranslationBatch,
    ) -> tuple[TranslationTask, ...]:
        batch_entity_ids = {task.entity_id for task in batch.tasks}
        result: list[TranslationTask] = []
        for task in batch.tasks:
            if task.kind not in {"type", "macro_family"}:
                continue
            if task.entity_id in self.rust_by_entity:
                continue
            if any(dependency_id in batch_entity_ids for dependency_id in task.dependency_ids):
                result.append(task)
        return tuple(result)

    async def _run_batch_tasks(
        self,
        *,
        batch: TranslationBatch,
        tasks: tuple[TranslationTask, ...],
    ) -> None:
        works: list[_InitialTranslationWork] = []
        batch_entity_ids = {batch_task.entity_id for batch_task in batch.tasks}
        for task in tasks:
            state = self._start_task_state(task)
            if _is_prepared_extern_global_declaration_noop(
                task, self.rust_by_entity.get(task.entity_id)
            ):
                self._run_prepared_noop_task(
                    batch=batch,
                    task=task,
                    state=state,
                )
                continue
            if self._is_static_function_forward_declaration(task):
                self._run_prepared_noop_task(
                    batch=batch,
                    task=task,
                    state=state,
                    translated=_static_function_forward_declaration_noop(task),
                )
                continue
            works.append(
                _InitialTranslationWork(
                    task=task,
                    state=state,
                    dependency_context=self._dependency_context_for_task(
                        task,
                        allow_missing_dependency_ids=batch_entity_ids,
                    ),
                    external_symbol_context=self._external_symbol_context(task),
                )
            )

        if not works:
            return

        semaphore = asyncio.Semaphore(self.translation_concurrency)

        async def translate_one(
            work: _InitialTranslationWork,
        ) -> _InitialTranslationResult:
            async with semaphore:
                return await self._translate_task_initial(work)

        pending = [asyncio.create_task(translate_one(work)) for work in works]
        self._emit(
            f"batch {batch.batch_id} translating {len(works)} entities "
            f"with concurrency={self.translation_concurrency}"
        )
        try:
            for completed in asyncio.as_completed(pending):
                result = await completed
                await self._commit_initial_translation(
                    batch=batch,
                    result=result,
                )
        except Exception:
            for task in pending:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            raise

    async def _run_task(
        self,
        *,
        batch: TranslationBatch,
        task: TranslationTask,
    ) -> None:
        await self._run_batch_tasks(batch=batch, tasks=(task,))

    def _start_task_state(self, task: TranslationTask) -> EntityTranslationState:
        state = EntityTranslationState(
            entity_id=task.entity_id,
            status="translating",
            attempt=0,
            max_attempts=self.max_repair_attempts,
        )
        self.states[task.entity_id] = state
        return state

    def _emit_task_start(self, task: TranslationTask) -> None:
        self._emit(
            f"{_task_label(task)} start kind={task.kind} "
            f"target={task.placement.rust_file}"
        )

    def _run_prepared_noop_task(
        self,
        *,
        batch: TranslationBatch,
        task: TranslationTask,
        state: EntityTranslationState,
        translated: TranslatedEntity | None = None,
    ) -> None:
        self._emit_task_start(task)
        if translated is None:
            self._mark_no_import_dependency(task.entity_id)
            translated = TranslatedEntity(
                entity_id=task.entity_id,
                rust_code=self.rust_by_entity[task.entity_id],
                exports=self.exports_by_entity.get(
                    task.entity_id, _expected_export_names(task)
                ),
                summary=(
                    "Extern global declaration omitted; Rust definition is "
                    "emitted by the corresponding C definition entity."
                ),
            )
        else:
            self._record_translation(task, translated)
            self._mark_no_import_dependency(task.entity_id)
        state.current_rust = translated.rust_code
        state.status = "passed"
        compile_result = CompileResult(
            passed=True,
            exit_code=0,
            stdout="",
            stderr="",
        )
        self._emit(
            f"{_task_label(task)} skipped prepared no-op "
            f"exports={list(translated.exports)}"
        )
        self._append_report(
            batch=batch,
            task=task,
            state=state,
            translated=translated,
            compile_result=compile_result,
            fallback_used=False,
        )
        self._persist_translation_state(
            task=task,
            state=state,
            translated=translated,
            compile_result=compile_result,
            fallback_used=False,
        )

    def _is_static_function_forward_declaration(
        self,
        task: TranslationTask,
    ) -> bool:
        tasks_by_entity = getattr(self, "tasks_by_entity", {})
        return _is_static_function_forward_declaration(
            task,
            tasks_by_entity.values(),
        )

    async def _translate_task_initial(
        self,
        work: _InitialTranslationWork,
    ) -> _InitialTranslationResult:
        task = work.task
        self._emit_task_start(task)
        self._emit(f"{_task_label(task)} translating")
        try:
            translated = await self.runtime.translate_initial(
                task,
                dependency_context=work.dependency_context,
                external_symbol_context=work.external_symbol_context,
            )
        except TranslationLLMError as exc:
            if not _is_model_timeout_error(exc):
                raise
            self._emit(
                f"{_task_label(task)} model request timed out; using fallback skeleton"
            )
            fallback = await self._fallback_entity_after_model_failure(
                task=task,
                error=exc,
                dependency_context=work.dependency_context,
                external_symbol_context=work.external_symbol_context,
            )
            return _InitialTranslationResult(
                task=task,
                state=work.state,
                translated=fallback,
                dependency_context=work.dependency_context,
                external_symbol_context=work.external_symbol_context,
                fallback_used=True,
            )
        return _InitialTranslationResult(
            task=task,
            state=work.state,
            translated=translated,
            dependency_context=work.dependency_context,
            external_symbol_context=work.external_symbol_context,
            fallback_used=False,
        )

    async def _commit_initial_translation(
        self,
        *,
        batch: TranslationBatch,
        result: _InitialTranslationResult,
    ) -> None:
        task = result.task
        state = result.state
        translated = result.translated
        target_snapshot = self._translation_target_snapshot(task)
        if result.fallback_used:
            self._write_translation(task, translated)
            fallback_compile_result = self.compiler.check()
            fallback_compile_result = self._resource_checked_compile_result(
                task,
                translated,
                fallback_compile_result,
            )
            state.current_rust = translated.rust_code
            state.status = "fallback" if fallback_compile_result.passed else "failed"
            if fallback_compile_result.passed:
                self._record_translation(task, translated)
            else:
                self._restore_translation_target(task, target_snapshot)
            self._emit(
                f"{_task_label(task)} fallback status={state.status} "
                f"exit_code={fallback_compile_result.exit_code}"
            )
            self._append_report(
                batch=batch,
                task=task,
                state=state,
                translated=translated,
                compile_result=fallback_compile_result,
                fallback_used=True,
            )
            if fallback_compile_result.passed:
                self._persist_translation_state(
                    task=task,
                    state=state,
                    translated=translated,
                    compile_result=fallback_compile_result,
                    fallback_used=True,
                )
            return

        translated = await self._stabilize_initial_translation(
            task=task,
            state=state,
            translated=translated,
            dependency_context=result.dependency_context,
            external_symbol_context=result.external_symbol_context,
        )
        self._write_translation(task, translated)
        _validate_entity_output_contract(
            task,
            translated.rust_code,
            support_exports=translated.support_exports,
        )
        self._emit(
            f"{_task_label(task)} wrote initial translation "
            f"exports={list(translated.exports)}"
        )
        state.current_rust = translated.rust_code
        state.status = "checking"

        self._emit(f"{_task_label(task)} cargo check")
        compile_result = self.compiler.check()
        if compile_result.passed:
            self._record_translation(task, translated)
            state.status = "passed"
            self._emit(f"{_task_label(task)} passed")
            self._append_report(
                batch=batch,
                task=task,
                state=state,
                translated=translated,
                compile_result=compile_result,
                fallback_used=False,
            )
            self._persist_translation_state(
                task=task,
                state=state,
                translated=translated,
                compile_result=compile_result,
                fallback_used=False,
            )
            return
        current = translated
        last_compile_result = compile_result
        for attempt in range(1, self.max_repair_attempts + 1):
            state.attempt = attempt
            state.status = "repairing"
            self._emit(
                f"{_task_label(task)} compile failed "
                f"exit_code={last_compile_result.exit_code}; "
                f"checker summary attempt={attempt}"
            )
            checker_summary = await self.runtime.summarize_compile_error(
                task,
                current_rust=current.rust_code,
                compile_result=last_compile_result,
            )
            state.last_checker_summary = checker_summary
            self._emit(
                f"{_task_label(task)} repair attempt={attempt}: "
                f"{checker_summary.summary}"
            )
            repaired = await self.runtime.repair_compile_error(
                task,
                current_rust=current.rust_code,
                compile_result=last_compile_result,
                checker_summary=checker_summary,
                repair_history=tuple(state.repair_history or ()),
                dependency_context=result.dependency_context,
                external_symbol_context=self._external_symbol_context(task),
            )
            repaired = await self._stabilize_initial_translation(
                task=task,
                state=state,
                translated=repaired,
                dependency_context=result.dependency_context,
                external_symbol_context=result.external_symbol_context,
            )
            self._write_translation(task, repaired)
            _validate_entity_output_contract(
                task,
                repaired.rust_code,
                support_exports=repaired.support_exports,
            )
            self._emit(f"{_task_label(task)} wrote repair attempt={attempt}")
            repair_compile_result = self.compiler.check()
            repair_result = "passed" if repair_compile_result.passed else "failed"
            assert state.repair_history is not None
            state.repair_history.append(
                RepairAttempt(
                    attempt=attempt,
                    rust_before=current.rust_code,
                    rust_after=repaired.rust_code,
                    diagnostic_summary=checker_summary.summary,
                    repair_summary=repaired.summary,
                    result=repair_result,
                )
            )
            state.current_rust = repaired.rust_code
            current = repaired
            last_compile_result = repair_compile_result
            if repair_compile_result.passed:
                self._record_translation(task, repaired)
                state.status = "passed"
                self._emit(
                    f"{_task_label(task)} passed after repair attempt={attempt}"
                )
                self._append_report(
                    batch=batch,
                    task=task,
                    state=state,
                    translated=repaired,
                    compile_result=repair_compile_result,
                    fallback_used=False,
                )
                self._persist_translation_state(
                    task=task,
                    state=state,
                    translated=repaired,
                    compile_result=repair_compile_result,
                    fallback_used=False,
                )
                return
        self._emit(f"{_task_label(task)} using fallback skeleton")
        fallback = self._fallback_entity(
            task=task,
            current=current,
            initial=translated,
        )
        self._write_translation(task, fallback)
        fallback_compile_result = self.compiler.check()
        fallback_compile_result = self._resource_checked_compile_result(
            task,
            fallback,
            fallback_compile_result,
        )
        state.current_rust = fallback.rust_code
        state.status = "fallback" if fallback_compile_result.passed else "failed"
        if fallback_compile_result.passed:
            self._record_translation(task, fallback)
        else:
            self._restore_translation_target(task, target_snapshot)
        self._emit(
            f"{_task_label(task)} fallback status={state.status} "
            f"exit_code={fallback_compile_result.exit_code}"
        )
        self._append_report(
            batch=batch,
            task=task,
            state=state,
            translated=fallback,
            compile_result=fallback_compile_result,
            fallback_used=True,
        )
        if fallback_compile_result.passed:
            self._persist_translation_state(
                task=task,
                state=state,
                translated=fallback,
                compile_result=fallback_compile_result,
                fallback_used=True,
            )

    async def _stabilize_initial_translation(
        self,
        *,
        task: TranslationTask,
        state: EntityTranslationState,
        translated: TranslatedEntity,
        dependency_context: str,
        external_symbol_context: str,
    ) -> TranslatedEntity:
        global_name_repaired = False
        contract_repairs = 0
        while True:
            try:
                stabilized = self._stabilize_translation(task, translated)
                return stabilized
            except _MissingGlobalDefinitionsError as exc:
                if global_name_repaired:
                    raise
                global_name_repaired = True
                self._emit(
                    f"{_task_label(task)} repairing missing global definitions: "
                    f"{', '.join(exc.missing_exports)}"
                )
                state.status = "repairing"
                translated = await self.runtime.repair_global_export_names(
                    task,
                    current_rust=translated.rust_code,
                    missing_exports=exc.missing_exports,
                    dependency_context=dependency_context,
                    external_symbol_context=external_symbol_context,
                )
            except _EntityOutputContractError as exc:
                if contract_repairs >= max(1, self.max_repair_attempts):
                    raise
                contract_repairs += 1
                self._emit(
                    f"{_task_label(task)} repairing entity output contract: "
                    + "; ".join(exc.violations)
                )
                state.status = "repairing"
                translated = await self.runtime.repair_entity_output_contract(
                    task,
                    current_rust=translated.rust_code,
                    violations=exc.violations,
                    dependency_context=dependency_context,
                    external_symbol_context=external_symbol_context,
                )

    def _validate_resource_translation(
        self,
        task: TranslationTask,
        translated: TranslatedEntity,
    ) -> None:
        return None

    def _resource_checked_compile_result(
        self,
        task: TranslationTask,
        translated: TranslatedEntity,
        compile_result: CompileResult,
    ) -> CompileResult:
        return compile_result

    def _emit(self, message: str) -> None:
        if self._log is not None:
            self._log(f"[translation] {message}")

    @staticmethod
    def _translation_target_snapshot(task: TranslationTask) -> str | None:
        rust_file = task.placement.rust_file
        if not rust_file.is_file():
            return None
        return rust_file.read_text(encoding="utf-8")

    def _restore_translation_target(
        self,
        task: TranslationTask,
        snapshot: str | None,
    ) -> None:
        if snapshot is None:
            return
        task.placement.rust_file.write_text(snapshot, encoding="utf-8")
        self._emit(
            f"{_task_label(task)} rolled back after fallback failed"
        )

    def _sync_tool_call_count(
        self,
        task: TranslationTask,
        state: EntityTranslationState,
    ) -> int:
        counter = getattr(self.runtime, "tool_call_count_for_task", None)
        if callable(counter):
            state.tool_call = counter(task)
        return state.tool_call

    def _token_usage_summary(
        self,
        task: TranslationTask | None = None,
    ) -> JsonDict:
        summary = getattr(self.runtime, "token_usage_summary", None)
        if callable(summary):
            return summary(task)
        return {}

    def _record_translation(
        self,
        task: TranslationTask,
        translated: TranslatedEntity,
    ) -> None:
        if translated.entity_id != task.entity_id:
            raise ValueError(
                f"translated entity id {translated.entity_id} does not match "
                f"task entity id {task.entity_id}"
            )
        if not hasattr(self, "support_exports_by_entity"):
            self.support_exports_by_entity = {}
        if not hasattr(self, "resource_decisions_by_entity"):
            self.resource_decisions_by_entity = {}
        if not hasattr(self, "cargo_dependencies_by_entity"):
            self.cargo_dependencies_by_entity = {}
        self.exports_by_entity[task.entity_id] = translated.exports
        self.support_exports_by_entity[task.entity_id] = translated.support_exports
        self.resource_decisions_by_entity[task.entity_id] = (
            translated.resource_decisions
        )
        self.cargo_dependencies_by_entity[task.entity_id] = (
            translated.cargo_dependencies
        )
        self.rust_by_entity[task.entity_id] = translated.rust_code

    def _write_translation(
        self,
        task: TranslationTask,
        translated: TranslatedEntity,
    ) -> None:
        self._record_cargo_dependencies(task, translated.cargo_dependencies)
        import_manager = ImportManager(
            placements=self.placements,
            exports_by_entity=self.exports_by_entity,
            support_exports_by_entity=getattr(
                self,
                "support_exports_by_entity",
                {},
            ),
            rust_by_entity=self.rust_by_entity,
            skip_dependency_ids=getattr(self, "_no_import_dependency_ids", frozenset()),
            rust_project=self.rust_project,
        )
        dependency_ids = tuple(
            dependency_id
            for dependency_id in self._dependency_context_ids_for_task(task)
            if dependency_id in self.exports_by_entity
        )
        imports = import_manager.imports_for_task(
            task,
            dependency_ids=dependency_ids,
        )
        self.writer.write_entity(task, translated.rust_code, imports=imports)

    def _record_cargo_dependencies(
        self,
        task: TranslationTask,
        dependencies: tuple[CargoDependencySpec, ...],
    ) -> None:
        if not hasattr(self, "cargo_dependencies_by_entity"):
            self.cargo_dependencies_by_entity = {}
        self.cargo_dependencies_by_entity[task.entity_id] = dependencies

    def _write_translation_without_imports(
        self,
        task: TranslationTask,
        translated: TranslatedEntity,
    ) -> None:
        self.writer.write_entity(task, translated.rust_code, imports=())

    def _mark_no_import_dependency(self, entity_id: int) -> None:
        if not hasattr(self, "_no_import_dependency_ids"):
            self._no_import_dependency_ids = set()
        self._no_import_dependency_ids.add(entity_id)

    def _restore_completed_task(self, task: TranslationTask) -> None:
        raw_entry = self._state_entities.get(str(task.entity_id))
        if not isinstance(raw_entry, dict):
            raise ValueError(
                f"cannot resume from entity {self.resume_from_entity}: "
                f"missing completed state for prior entity {task.entity_id}"
            )

        entity_id = _required_int(raw_entry, "entity_id", self.state_path)
        if entity_id != task.entity_id:
            raise ValueError(
                f"{self.state_path}: entry for entity {task.entity_id} has "
                f"mismatched entity_id {entity_id}"
            )
        kind = _required_str(raw_entry, "kind", self.state_path)
        if kind != task.kind:
            raise ValueError(
                f"{self.state_path}: entry for entity {task.entity_id} has "
                f"kind {kind!r}, expected {task.kind!r}"
            )
        status = _required_str(raw_entry, "status", self.state_path)
        if status not in {"passed", "fallback"}:
            raise ValueError(
                f"{self.state_path}: entry for entity {task.entity_id} has "
                f"non-resumable status {status!r}"
            )
        rust_code = _required_str(raw_entry, "rust_code", self.state_path)
        if not rust_code.strip():
            raise ValueError(
                f"{self.state_path}: entry for entity {task.entity_id} has "
                "empty rust_code"
            )
        exports = _required_str_tuple(raw_entry, "exports", self.state_path)
        if not exports:
            raise ValueError(
                f"{self.state_path}: entry for entity {task.entity_id} has "
                "empty exports"
            )
        self.exports_by_entity[task.entity_id] = exports
        support_exports = _required_str_tuple(
            raw_entry,
            "support_exports",
            self.state_path,
        )
        decisions: tuple[ResourceDecision, ...] = ()
        cargo_dependencies = _optional_cargo_dependency_specs(
            raw_entry,
            "cargo_dependencies",
            self.state_path,
        )
        self.support_exports_by_entity[task.entity_id] = support_exports
        self.resource_decisions_by_entity[task.entity_id] = decisions
        self.cargo_dependencies_by_entity[task.entity_id] = cargo_dependencies
        self.rust_by_entity[task.entity_id] = rust_code
        if _is_prepared_extern_global_declaration_noop(task, rust_code):
            self._mark_no_import_dependency(task.entity_id)
        self._emit(
            f"entity {task.entity_id} restored from {self.state_path} "
            f"exports={list(exports)}"
        )

    def _load_translation_state(self) -> JsonDict:
        if not self.state_path.is_file():
            if self.resume_from_entity is not None:
                raise FileNotFoundError(
                    f"cannot resume from entity {self.resume_from_entity}: "
                    f"translation state not found: {self.state_path}"
                )
            return {}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"failed to parse {self.state_path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{self.state_path}: translation state must be an object")
        version = data.get("version")
        if version != 2:
            raise ValueError(
                f"{self.state_path}: unsupported translation-state version "
                f"{version!r}; expected 2; restart translation"
            )
        entities = data.get("entities")
        if not isinstance(entities, dict):
            raise ValueError(f"{self.state_path}: entities must be an object")
        return dict(entities)

    def _persist_translation_state(
        self,
        *,
        task: TranslationTask,
        state: EntityTranslationState,
        translated: TranslatedEntity,
        compile_result: CompileResult,
        fallback_used: bool,
    ) -> None:
        self._sync_tool_call_count(task, state)
        entry = {
            "entity_id": task.entity_id,
            "kind": task.kind,
            "status": state.status,
            "attempts": state.attempt,
            "max_attempts": state.max_attempts,
            "fallback_used": fallback_used,
            "tool_call": state.tool_call,
            "llm_token_usage": self._token_usage_summary(task),
            "exports": list(translated.exports),
            "support_exports": list(translated.support_exports),
            "resource_decisions": [],
            "cargo_dependencies": [
                {
                    "name": dependency.name,
                    "version": dependency.version,
                    "features": list(dependency.features),
                }
                for dependency in translated.cargo_dependencies
            ],
            "rust_file": str(task.placement.rust_file),
            "rust_code": translated.rust_code,
            "summary": translated.summary,
            "compile": {
                "passed": compile_result.passed,
                "exit_code": compile_result.exit_code,
                "blocked_by_preexisting_errors": False,
            },
        }
        self._state_entities[str(task.entity_id)] = entry
        self._write_translation_state()
        self._emit(f"entity {task.entity_id} state persisted: {self.state_path}")

    def _write_translation_state(self) -> None:
        state_json = {
            "version": 2,
            "workspace": str(self.workspace),
            "rust_project": str(self.rust_project),
            "entities": self._state_entities,
        }
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.state_path.with_suffix(self.state_path.suffix + ".tmp")
        temporary_path.write_text(
            json.dumps(state_json, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(self.state_path)

    def _stabilize_translation(
        self,
        task: TranslationTask,
        translated: TranslatedEntity,
    ) -> TranslatedEntity:
        if _is_redundant_same_name_tag_typedef(task):
            expected_exports = _expected_export_names(task)
            rust_code = _redundant_typedef_noop_code(task)
            if (
                translated.rust_code.strip() == rust_code
                and translated.exports == expected_exports
            ):
                return translated
            self._emit(
                f"entity {task.entity_id} normalized redundant typedef "
                f"{task.package.name!r} to no-op"
            )
            return replace(
                translated,
                rust_code=rust_code,
                exports=expected_exports,
                summary=(
                    "Redundant same-name tag typedef; the concrete type is "
                    "translated by its tag declaration entity."
                ),
            )
        expected_exports = _expected_export_names(task)
        translated = _sanitize_translated_rust_code(translated)
        if task.kind in {"type", "macro_family"}:
            translated = _qualify_self_referential_primitive_alias(translated)
            if task.kind == "macro_family":
                return translated
            if not _is_anonymous_enum_task(task):
                _validate_entity_output_contract(
                    task,
                    translated.rust_code,
                    support_exports=translated.support_exports,
                )
                violations = (
                    *_placeholder_type_violations(translated.rust_code),
                    *_type_field_preservation_violations(
                        task,
                        translated.rust_code,
                        support_exports=translated.support_exports,
                    ),
                )
                if violations:
                    raise _EntityOutputContractError(
                        entity_id=task.entity_id,
                        violations=violations,
                    )
                return translated
            missing_code = tuple(
                name
                for name in expected_exports
                if not _rust_code_defines_top_level_const(
                    translated.rust_code,
                    name,
                )
            )
            if missing_code:
                raise _MissingGlobalDefinitionsError(
                    entity_id=task.entity_id,
                    missing_exports=missing_code,
                    require_public=True,
                )
            if translated.exports == expected_exports:
                return translated
            self._emit(
                f"entity {task.entity_id} normalized anonymous enum exports "
                f"{list(translated.exports)} -> {list(expected_exports)}"
            )
            return replace(translated, exports=expected_exports)
        if task.kind == "global":
            translated = self._stabilize_global_translation(
                task,
                translated,
                expected_exports,
            )
            _validate_entity_output_contract(
                task,
                translated.rust_code,
                support_exports=translated.support_exports,
            )
            return translated
        if task.kind != "function":
            return translated
        if translated.exports != expected_exports:
            self._emit(
                f"entity {task.entity_id} normalized exports "
                f"{list(translated.exports)} -> {list(expected_exports)}"
            )
            translated = replace(translated, exports=expected_exports)
        _validate_entity_output_contract(
            task,
            translated.rust_code,
            support_exports=translated.support_exports,
        )
        return translated

    def _stabilize_global_translation(
        self,
        task: TranslationTask,
        translated: TranslatedEntity,
        expected_exports: tuple[str, ...],
    ) -> TranslatedEntity:
        require_public_definition = not _is_internal_static_global(task)
        if len(expected_exports) == 1:
            translated = self._normalize_single_global_definition_name(
                task,
                translated,
                expected_exports[0],
                require_public_definition=require_public_definition,
            )
        missing_code = tuple(
            name
            for name in expected_exports
            if not _rust_code_defines_global_export(
                translated.rust_code,
                name,
                require_public=require_public_definition,
            )
        )
        if missing_code:
            raise _MissingGlobalDefinitionsError(
                entity_id=task.entity_id,
                missing_exports=missing_code,
                require_public=require_public_definition,
            )

        if translated.exports == expected_exports:
            return translated

        self._emit(
            f"entity {task.entity_id} normalized global exports "
            f"{list(translated.exports)} -> {list(expected_exports)}"
        )
        return replace(translated, exports=expected_exports)

    def _normalize_single_global_definition_name(
        self,
        task: TranslationTask,
        translated: TranslatedEntity,
        expected_export: str,
        *,
        require_public_definition: bool,
    ) -> TranslatedEntity:
        if _rust_code_defines_global_export(
            translated.rust_code,
            expected_export,
            require_public=require_public_definition,
        ):
            return translated

        normalized_code = _rename_single_rust_global_definition(
            translated.rust_code,
            expected_export,
            require_public=require_public_definition,
        )
        if normalized_code is None:
            return translated

        self._emit(
            f"entity {task.entity_id} normalized single global definition "
            f"name to {expected_export!r}"
        )
        return replace(
            translated,
            rust_code=normalized_code,
            exports=tuple(dict.fromkeys((*translated.exports, expected_export))),
        )

    def _stabilize_signature(
        self,
        task: TranslationTask,
        signature: TranslatedSignature,
    ) -> TranslatedSignature:
        if task.kind != "function":
            return signature
        expected_exports = _expected_export_names(task)
        if signature.exports == expected_exports:
            return signature
        self._emit(
            f"entity {task.entity_id} normalized signature exports "
            f"{list(signature.exports)} -> {list(expected_exports)}"
        )
        return replace(
            signature,
            exports=expected_exports,
        )

    def _signature_skeleton(
        self,
        task: TranslationTask,
        signature: TranslatedSignature,
        *,
        summary: str = "Cyclic dependency skeleton generated from translated signature.",
    ) -> TranslatedEntity:
        if signature.entity_id != task.entity_id:
            raise ValueError(
                f"signature entity id {signature.entity_id} does not match "
                f"task entity id {task.entity_id}"
            )
        rust_code = f"{signature.rust_signature.rstrip(';').strip()} {{\n    unimplemented!()\n}}"
        return TranslatedEntity(
            entity_id=task.entity_id,
            rust_code=rust_code,
            exports=signature.exports,
            summary=summary,
            raw_model_output=signature.raw_model_output,
            resource_decisions=signature.resource_decisions,
            support_exports=signature.support_exports,
            cargo_dependencies=signature.cargo_dependencies,
        )

    def _dependency_context(self, task: TranslationTask) -> str:
        return self._dependency_context_for_task(
            task,
            allow_missing_dependency_ids=frozenset(),
        )

    def _dependency_context_for_task(
        self,
        task: TranslationTask,
        *,
        allow_missing_dependency_ids: set[int] | frozenset[int],
    ) -> str:
        dependency_ids = self._dependency_context_ids_for_task(task)
        type_alias_context = self._type_alias_context_for_task(task)
        if not dependency_ids and not type_alias_context:
            return "(none)"

        chunks: list[str] = []
        if type_alias_context:
            chunks.append(type_alias_context)
        for dependency_id in dependency_ids:
            rust_code = self.rust_by_entity.get(dependency_id)
            if rust_code is None:
                if dependency_id in allow_missing_dependency_ids:
                    chunks.append(
                        self._missing_dependency_context_chunk(dependency_id)
                    )
                    continue
                raise ValueError(
                    f"Dependency entity {dependency_id} for entity {task.entity_id} "
                    "has not been translated yet. Cyclic batches need a skeleton pass."
                )
            kind = self.kind_by_entity.get(dependency_id, "unknown")
            if kind == "function":
                content = _function_signature(rust_code)
                support_definitions = [
                    definition
                    for name in self.support_exports_by_entity.get(
                        dependency_id, ()
                    )
                    if (
                        definition := _top_level_type_definition(
                            rust_code,
                            name,
                        )
                    )
                ]
                if support_definitions:
                    content = "\n\n".join((content, *support_definitions))
            else:
                content = rust_code.strip()
            chunk = f"```rust\n{content}\n```"
            chunks.append(chunk)

        return "\n\n".join(chunks) if chunks else "(none)"

    def _type_alias_context_for_task(self, task: TranslationTask) -> str:
        if not self.c_type_aliases:
            return ""

        sources = [task.package.original_c_source]
        for dependency_id in self._dependency_context_ids_for_task(task):
            dependency_task = self.tasks_by_entity.get(dependency_id)
            if dependency_task is not None:
                sources.append(dependency_task.package.original_c_source)

        relevant_names = tuple(
            name
            for name in self.c_type_aliases
            if any(
                re.search(r"\b" + re.escape(name) + r"\b", source)
                for source in sources
            )
        )
        if not relevant_names:
            return ""

        lines = [
            "Project-wide C typedef contracts:",
            (
                "These aliases are shared project representations. Preserve "
                "the alias identity and C width/layout across all entities; "
                "do not replace a project typedef with a Rust primitive that "
                "happens to have the same spelling."
            ),
        ]
        for name in relevant_names:
            underlying = self.c_type_aliases[name]
            lines.append(
                f"- C typedef `{name}` = `{underlying}`. Use the shared Rust "
                f"alias `{name}` consistently for fields, arrays, parameters, "
                "return values, allocation sizes, and serialization."
            )
        return "\n".join(lines)

    def _resource_obligations_for_task(
        self,
        task: TranslationTask,
    ) -> tuple[JsonDict, ...]:
        return ()

    def _dependency_context_ids_for_task(
        self,
        task: TranslationTask,
    ) -> tuple[int, ...]:


        ordered: list[int] = []
        seen: set[int] = {task.entity_id}
        tasks_by_entity = getattr(self, "tasks_by_entity", {})

        def append_dependency(dependency_id: int) -> bool:
            if dependency_id in seen:
                return False
            seen.add(dependency_id)
            ordered.append(dependency_id)
            return True

        def append_nested_type_dependencies(dependency_id: int) -> None:
            dependency_task = tasks_by_entity.get(dependency_id)
            if dependency_task is None:
                return
            for nested_id in dependency_task.dependency_ids:
                if self.kind_by_entity.get(nested_id) not in {
                    "type",
                    "macro_family",
                }:
                    continue
                if append_dependency(nested_id):
                    append_nested_type_dependencies(nested_id)

        for dependency_id in task.dependency_ids:
            append_dependency(dependency_id)
            append_nested_type_dependencies(dependency_id)

        return tuple(ordered)

    def _missing_dependency_context_chunk(self, dependency_id: int) -> str:
        dependency_task = getattr(self, "tasks_by_entity", {}).get(dependency_id)
        if dependency_task is None:
            content = (
                "// Cyclic dependency translated later in the same batch.\n"
                f"// Entity id: {dependency_id}."
            )
        else:
            expected_names = _expected_export_names(dependency_task)
            source = dependency_task.package.annotated_c_source.strip()
            content = (
                "Cyclic dependency translated later in the same batch.\n"
                f"Expected Rust item names: {', '.join(expected_names)}.\n"
                f"C entity kind: {dependency_task.kind}."
            )
            comments = _human_comment_dependency_context(dependency_task)
            if comments:
                content = f"{content}\n\nHuman comments:\n{comments}"
            if source:
                content = f"{content}\n\nC dependency source:\n{source}"
        return content

    def _fallback_entity(
        self,
        *,
        task: TranslationTask,
        current: TranslatedEntity,
        initial: TranslatedEntity,
    ) -> TranslatedEntity:
        if _is_redundant_same_name_tag_typedef(task):
            exports = _expected_export_names(task)
            rust_code = _redundant_typedef_noop_code(task)
        elif task.kind == "function":
            exports = _expected_export_names(task)
            signature_source = (
                current.rust_code
                if _has_pub_function_named(current.rust_code, exports[0])
                else initial.rust_code
            )
            rust_code = _fallback_function(signature_source, exports[0])
        elif task.kind in {"type", "macro_family"}:
            exports = current.exports or _expected_export_names(task)
            rust_code = "\n".join(f"pub struct {name};" for name in exports)
        else:
            exports = current.exports or _expected_export_names(task)
            rust_code = "\n".join(f"pub static {name}: () = ();" for name in exports)

        return TranslatedEntity(
            entity_id=task.entity_id,
            rust_code=rust_code,
            exports=exports,
            summary="Fallback skeleton generated after repair attempts failed.",
            raw_model_output=current.raw_model_output,
        )

    async def _fallback_entity_after_model_failure(
        self,
        *,
        task: TranslationTask,
        error: TranslationLLMError,
        dependency_context: str = "",
        external_symbol_context: str = "",
    ) -> TranslatedEntity:
        exports = _expected_export_names(task)
        if task.kind == "function":
            existing = self.rust_by_entity.get(task.entity_id, "")
            if existing.strip():
                rust_code = _fallback_function(existing, exports[0])
            else:
                try:
                    self._emit(f"{_task_label(task)} translating fallback signature")
                    signature = await self.runtime.translate_signature(
                        task,
                        dependency_context=dependency_context,
                        external_symbol_context=external_symbol_context,
                    )
                    signature = self._stabilize_signature(task, signature)
                    return self._signature_skeleton(
                        task,
                        signature,
                        summary=(
                            "Fallback skeleton generated after full model request "
                            f"failed; signature-only translation succeeded. Initial "
                            f"failure: {error}"
                        ),
                    )
                except TranslationLLMError as signature_error:
                    self._emit(
                        f"{_task_label(task)} fallback signature failed: "
                        f"{signature_error}; using local C signature fallback"
                    )
                    rust_code = _fallback_function_from_c_source(
                        task.package.original_c_source,
                        exports[0],
                    )
                except Exception as signature_error:
                    self._emit(
                        f"{_task_label(task)} fallback signature failed: "
                        f"{signature_error}; using local C signature fallback"
                    )
                    rust_code = _fallback_function_from_c_source(
                        task.package.original_c_source,
                        exports[0],
                    )
        elif task.kind in {"type", "macro_family"}:
            rust_code = "\n".join(f"pub struct {name};" for name in exports)
        else:
            rust_code = "\n".join(f"pub static {name}: () = ();" for name in exports)

        return TranslatedEntity(
            entity_id=task.entity_id,
            rust_code=rust_code,
            exports=exports,
            summary=(
                "Fallback skeleton generated because the model request failed: "
                f"{error}"
            ),
            raw_model_output="",
        )

    def _append_report(
        self,
        *,
        batch: TranslationBatch,
        task: TranslationTask,
        state: EntityTranslationState,
        translated: TranslatedEntity,
        compile_result: CompileResult,
        fallback_used: bool,
    ) -> None:
        self._sync_tool_call_count(task, state)
        self._report_entities.append(
            {
                "entity_id": task.entity_id,
                "batch_id": batch.batch_id,
                "kind": task.kind,
                "status": state.status,
                "attempts": state.attempt,
                "max_attempts": state.max_attempts,
                "fallback_used": fallback_used,
                "tool_call": state.tool_call,
                "llm_token_usage": self._token_usage_summary(task),
                "exports": list(translated.exports),
                "rust_file": str(task.placement.rust_file),
                "summary": translated.summary,
                "compile": {
                    "passed": compile_result.passed,
                    "exit_code": compile_result.exit_code,
                    "blocked_by_preexisting_errors": False,
                    "stdout": compile_result.stdout,
                    "stderr": compile_result.stderr,
                },
                "repair_history": [
                    {
                        "attempt": item.attempt,
                        "diagnostic_summary": item.diagnostic_summary,
                        "repair_summary": item.repair_summary,
                        "result": item.result,
                    }
                    for item in (state.repair_history or [])
                ],
            }
        )


def _read_rust_project(workspace: Path) -> Path:
    layout_path = workspace / "rust-module-layout.json"
    data = json.loads(layout_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{layout_path} must be an object")
    value = data.get("rust_project")
    if not isinstance(value, str) or not value:
        raise ValueError(f"{layout_path}: missing rust_project")
    path = Path(value)
    if path.is_absolute():
        return path.resolve()
    return (workspace / path).resolve()


def _required_int(data: JsonDict, key: str, path: Path) -> int:
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{path}: field {key!r} must be an int")
    return value


def _required_str(data: JsonDict, key: str, path: Path) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{path}: field {key!r} must be a string")
    return value


def _required_str_tuple(data: JsonDict, key: str, path: Path) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list):
        raise ValueError(f"{path}: field {key!r} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(f"{path}: field {key!r}[{index}] must be a string")
        text = item.strip()
        if text:
            result.append(text)
    return tuple(result)


def _optional_cargo_dependency_specs(
    data: JsonDict,
    key: str,
    path: Path,
) -> tuple[CargoDependencySpec, ...]:
    value = data.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"{path}: field {key!r} must be a list")
    result: list[CargoDependencySpec] = []
    seen_names: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"{path}: field {key!r}[{index}] must be an object")
        name = _required_str(item, "name", path).strip()
        version = _required_str(item, "version", path).strip()
        features = _required_str_tuple(item, "features", path)
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError(
                f"{path}: field {key!r}[{index}].name must be a Cargo crate name"
            )
        if not version:
            raise ValueError(
                f"{path}: field {key!r}[{index}].version must not be empty"
            )
        if name in seen_names:
            raise ValueError(f"{path}: duplicate cargo dependency {name!r}")
        seen_names.add(name)
        result.append(
            CargoDependencySpec(
                name=name,
                version=version,
                features=features,
            )
        )
    return tuple(result)


def _plan_has_entity(
    batches: tuple[TranslationBatch, ...],
    entity_id: int,
) -> bool:
    return any(task.entity_id == entity_id for batch in batches for task in batch.tasks)


def _placements_from_batches(
    batches: tuple[TranslationBatch, ...],
) -> dict[int, EntityPlacement]:
    return {
        task.entity_id: task.placement
        for batch in batches
        for task in batch.tasks
    }


def _rust_files_from_batches(batches: tuple[TranslationBatch, ...]) -> tuple[Path, ...]:
    return tuple(
        sorted(
            {
                task.placement.rust_file
                for batch in batches
                for task in batch.tasks
            }
        )
    )


def _kinds_from_batches(batches: tuple[TranslationBatch, ...]) -> dict[int, str]:
    return {
        task.entity_id: task.kind
        for batch in batches
        for task in batch.tasks
    }


def _tasks_from_batches(
    batches: tuple[TranslationBatch, ...],
) -> dict[int, TranslationTask]:
    return {
        task.entity_id: task
        for batch in batches
        for task in batch.tasks
    }


def _collect_c_type_aliases(
    tasks: Iterable[TranslationTask],
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for task in tasks:
        if task.kind != "type":
            continue
        source = mask_c_non_code(
            task.package.original_c_source,
            mask_literals=True,
        )
        for match in _C_SIMPLE_TYPEDEF_PATTERN.finditer(source):
            name = match.group("name")
            underlying = " ".join(match.group("underlying").split())
            aliases.setdefault(name, underlying)
    return dict(sorted(aliases.items()))


def _task_label(task: TranslationTask) -> str:
    name = task.package.name.strip()
    if name:
        return f"entity {task.entity_id} ({name})"
    return f"entity {task.entity_id}"


def _is_model_timeout_error(error: TranslationLLMError) -> bool:
    message = str(error).lower()
    return "timed out" in message or "timeout" in message


def _expected_export_name(task: TranslationTask) -> str:
    if _RUST_IDENTIFIER_RE.match(task.package.name):
        return task.package.name
    return f"entity_{task.entity_id}"


def _expected_export_names(task: TranslationTask) -> tuple[str, ...]:
    names = tuple(
        name
        for name in task.expected_exports
        if name and _RUST_IDENTIFIER_RE.match(name)
    )
    if names:
        return names
    return (_expected_export_name(task),)


def _is_internal_static_global(task: TranslationTask) -> bool:
    if task.kind != "global":
        return False
    return task.package.is_static


def _is_anonymous_enum_task(task: TranslationTask) -> bool:
    return (
        task.kind == "type"
        and task.package.name.startswith("%")
        and bool(task.package.export_names)
        and task.expected_exports == task.package.export_names
    )


def _rust_code_defines_global_export(
    rust_code: str,
    name: str,
    *,
    require_public: bool = True,
) -> bool:
    escaped = re.escape(name)
    visibility = r"pub\s+" if require_public else r"(?:pub\s+)?"
    patterns = (
        rf"\b{visibility}static(?:\s+mut)?\s+{escaped}\b",
        rf"\b{visibility}const\s+{escaped}\b",
    )
    return any(re.search(pattern, rust_code) for pattern in patterns)


def _validate_entity_output_contract(
    task: TranslationTask,
    rust_code: str,
    *,
    support_exports: tuple[str, ...] = (),
) -> None:
    if _is_redundant_same_name_tag_typedef(task):
        return

    items = _top_level_rust_items(rust_code)
    expected_exports = set(_expected_export_names(task))
    support_export_names = set(support_exports)
    violations: list[str] = []

    if task.kind == "global":
        global_names = _rust_code_global_export_names(rust_code, items)
        violations.extend(
            f"global entity must define required top-level global {name!r}"
            for name in sorted(expected_exports - global_names)
        )
        allowed_items = {
            (kind, name)
            for name in expected_exports
            for kind in ("static", "const")
        }
        allowed_items.update(
            (kind, name)
            for name in support_export_names
            for kind in ("struct", "enum", "union", "type")
        )
    elif task.kind == "function":
        function_names = {name for kind, name in items if kind == "fn"}
        violations.extend(
            f"function entity must define required top-level function {name!r}"
            for name in sorted(expected_exports - function_names)
        )
        allowed_items = {
            ("fn", name)
            for name in expected_exports
        }
        allowed_items.update(
            (kind, name)
            for name in support_export_names
            for kind in ("struct", "enum", "union", "type")
        )
    elif task.kind == "type" and _is_anonymous_enum_task(task):
        const_names = {name for kind, name in items if kind == "const"}
        violations.extend(
            f"anonymous enum entity must define required top-level const {name!r}"
            for name in sorted(expected_exports - const_names)
        )
        allowed_items = {
            ("const", name)
            for name in expected_exports
        }
    elif task.kind == "type":
        type_items = {
            name
            for kind, name in items
            if kind in {"struct", "enum", "union", "type"}
        }
        violations.extend(
            f"type entity must define required top-level type {name!r}"
            for name in sorted(expected_exports - type_items)
        )
        allowed_items = {
            (kind, name)
            for name in expected_exports | support_export_names
            for kind in ("struct", "enum", "union", "type")
        }
    else:
        return

    violations.extend(
        f"{task.kind} entity must not define unexpected top-level {kind} {name!r}"
        for kind, name in items
        if (kind, name) not in allowed_items
    )

    if violations:
        raise _EntityOutputContractError(
            entity_id=task.entity_id,
            violations=tuple(violations),
        )


def _rust_code_global_export_names(
    rust_code: str,
    items: tuple[tuple[str, str], ...],
) -> frozenset[str]:
    names = {name for kind, name in items if kind in {"static", "const"}}
    masked = mask_c_non_code(rust_code, mask_literals=True)
    for block_match in re.finditer(
        r"\bthread_local\s*!\s*\{(?P<body>.*)\}",
        masked,
        flags=re.S,
    ):
        body = block_match.group("body")
        names.update(
            static_match.group("name")
            for static_match in re.finditer(
                r"\bstatic(?:\s+mut)?\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
                body,
            )
        )
    return frozenset(names)


def _placeholder_type_violations(rust_code: str) -> tuple[str, ...]:
    masked = mask_c_non_code(rust_code, mask_literals=True)
    violations: list[str] = []
    if re.search(r"\b(?:std::any::|core::any::)?Any\b", masked):
        violations.append(
            "entity must not use Any/dyn Any as an opaque placeholder for an "
            "unresolved C type"
        )
    if re.search(r":\s*\(\s*\)", masked):
        violations.append(
            "entity must not use unit type () as an opaque placeholder for an "
            "unresolved C type"
        )
    if re.search(r"\bOption\s*<\s*\(\s*\)>", masked):
        violations.append(
            "entity must not use Option<()> as an opaque placeholder for an "
            "unresolved C type"
        )
    return tuple(violations)


def _type_field_preservation_violations(
    task: TranslationTask,
    rust_code: str,
    *,
    support_exports: tuple[str, ...] = (),
) -> tuple[str, ...]:
    if task.kind != "type":
        return ()
    expected_fields = _c_struct_field_names_for_task(task)
    if not expected_fields:
        return ()
    rust_fields = _rust_struct_field_names(
        rust_code,
        tuple(dict.fromkeys((*_expected_export_names(task), *support_exports))),
    )
    missing = tuple(field for field in expected_fields if field not in rust_fields)
    return tuple(
        f"type entity must preserve C struct field {field!r}"
        for field in missing
    )


def _c_struct_field_names_for_task(task: TranslationTask) -> tuple[str, ...]:
    names = _expected_export_names(task)
    if not names:
        return ()
    source = task.package.original_c_source or task.package.annotated_c_source
    source = mask_c_non_code(source, mask_literals=True)
    typedef_match = re.search(
        rf"\btypedef\s+struct(?:\s+[A-Za-z_][A-Za-z0-9_]*)?\s*"
        rf"\{{(?P<body>.*?)\}}\s*"
        rf"(?P<name>{'|'.join(re.escape(name) for name in names)})\s*;",
        source,
        flags=re.S,
    )
    if typedef_match is None:
        struct_match = re.search(
            rf"\bstruct\s+"
            rf"(?P<name>{'|'.join(re.escape(name) for name in names)})\s*"
            rf"\{{(?P<body>.*?)\}}\s*;",
            source,
            flags=re.S,
        )
        if struct_match is None:
            return ()
        body = struct_match.group("body")
    else:
        body = typedef_match.group("body")
    fields: list[str] = []
    for declaration in body.split(";"):
        declaration = declaration.strip()
        if not declaration or declaration.startswith("#"):
            continue
        if re.search(r"\b(?:struct|union|enum)\s*$", declaration):
            continue

        declaration = re.sub(r":\s*\d+\s*$", "", declaration).strip()
        match = re.search(
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
            r"(?:\s*\[[^\]]*\])?\s*$",
            declaration,
        )
        if match is not None:
            fields.append(match.group("name"))
    return tuple(dict.fromkeys(fields))


def _rust_struct_field_names(
    rust_code: str,
    struct_names: tuple[str, ...],
) -> frozenset[str]:
    if not struct_names:
        return frozenset()
    lifetime_safe = re.sub(
        r"'(?=[A-Za-z_][A-Za-z0-9_]*\b(?!'))",
        " ",
        rust_code,
    )
    masked = mask_c_non_code(lifetime_safe, mask_literals=True)
    fields: set[str] = set()
    for name in struct_names:
        match = re.search(
            rf"\b(?:pub\s+)?struct\s+{re.escape(name)}(?:\s*<[^{{;]+>)?"
            rf"\s*\{{(?P<body>.*?)\}}",
            masked,
            flags=re.S,
        )
        if match is None:
            continue
        body = match.group("body")
        for field_match in re.finditer(
            r"\b(?:pub(?:\([^)]*\))?\s+)?(?P<name>r#[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*)\s*:",
            body,
        ):
            fields.add(field_match.group("name").removeprefix("r#"))
    return frozenset(fields)


def _top_level_rust_items(rust_code: str) -> tuple[tuple[str, str], ...]:
    lifetime_safe = re.sub(
        r"'(?=[A-Za-z_][A-Za-z0-9_]*\b(?!'))",
        " ",
        rust_code,
    )
    masked = mask_c_non_code(lifetime_safe, mask_literals=True)
    name = r"(?:r#)?[A-Za-z_][A-Za-z0-9_]*"
    patterns = (
        re.compile(
            rf"\b(?P<kind>struct|enum|union|type)\s+"
            rf"(?P<name>{name})\b"
        ),
        re.compile(rf"\b(?P<kind>static)\s+(?:mut\s+)?(?P<name>{name})\b"),
        re.compile(rf"\b(?P<kind>const)\s+(?!fn\b)(?P<name>{name})\b"),
        re.compile(rf"\b(?P<kind>fn)\s+(?P<name>{name})\b"),
        re.compile(
            rf"\b(?P<kind>macro_rules)\s*!\s*(?P<name>{name})\b"
        ),
    )
    candidates: list[tuple[int, str, str]] = []
    for pattern in patterns:
        for match in pattern.finditer(masked):
            item_name = match.group("name")
            candidates.append(
                (
                    match.start(),
                    match.group("kind"),
                    item_name.removeprefix("r#"),
                )
            )

    items: list[tuple[int, str, str]] = []
    current_item_end = 0
    for start, kind, item_name in sorted(candidates):




        if start < current_item_end:
            continue
        if not _rust_position_is_top_level(masked, start):
            continue
        items.append((start, kind, item_name))
        current_item_end = _rust_top_level_item_end(masked, start, kind)

    return tuple(
        (kind, item_name)
        for _, kind, item_name in sorted(items)
    )


def _rust_position_is_top_level(masked: str, position: int) -> bool:
    prefix = masked[:position]
    return all(
        prefix.count(opening) == prefix.count(closing)
        for opening, closing in (("{", "}"), ("(", ")"), ("[", "]"))
    )


def _rust_top_level_item_end(masked: str, start: int, kind: str) -> int:
    parentheses = 0
    brackets = 0
    braces = 0
    has_body = False
    body_kinds = {"struct", "enum", "union", "fn", "macro_rules"}

    for index in range(start, len(masked)):
        character = masked[index]
        if character == "(":
            parentheses += 1
        elif character == ")" and parentheses:
            parentheses -= 1
        elif character == "[":
            brackets += 1
        elif character == "]" and brackets:
            brackets -= 1
        elif character == "{":
            if (
                kind in body_kinds
                and parentheses == 0
                and brackets == 0
                and braces == 0
            ):
                has_body = True
            braces += 1
        elif character == "}" and braces:
            braces -= 1
            if has_body and braces == 0 and parentheses == 0 and brackets == 0:
                return index + 1
        elif (
            character == ";"
            and parentheses == 0
            and brackets == 0
            and braces == 0
        ):
            return index + 1
    return len(masked)


def _rust_code_defines_top_level_const(rust_code: str, name: str) -> bool:
    masked = mask_c_non_code(rust_code, mask_literals=True)
    pattern = re.compile(
        rf"\bpub\s+const\s+{re.escape(name)}\b"
    )
    for match in pattern.finditer(masked):
        prefix = masked[: match.start()]
        if prefix.count("{") == prefix.count("}"):
            return True
    return False


def _rename_single_rust_global_definition(
    rust_code: str,
    expected_name: str,
    *,
    require_public: bool = True,
) -> str | None:
    if not _RUST_IDENTIFIER_RE.match(expected_name):
        return None

    visibility = r"pub\s+" if require_public else r"(?:pub\s+)?"
    pattern = re.compile(
        rf"\b(?P<prefix>{visibility}(?:static(?:\s+mut)?|const)\s+)"
        rf"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
    )
    matches = tuple(pattern.finditer(rust_code))
    if len(matches) != 1:
        return None

    match = matches[0]
    actual_name = match.group("name")
    if actual_name == expected_name:
        return rust_code
    return (
        rust_code[: match.start("name")]
        + expected_name
        + rust_code[match.end("name") :]
    )


def _is_redundant_same_name_tag_typedef(task: TranslationTask) -> bool:
    if task.kind != "type":
        return False
    name = task.package.name.strip()
    if not name or not _RUST_IDENTIFIER_RE.match(name):
        return False
    source = mask_c_non_code(
        task.package.original_c_source, mask_literals=False
    ).strip()
    pattern = re.compile(
        rf"^typedef\s+(?:struct|union|enum)\s+{re.escape(name)}\s+"
        rf"{re.escape(name)}\s*;\s*$"
    )
    return bool(pattern.match(source))


def _qualify_self_referential_primitive_alias(
    translated: TranslatedEntity,
) -> TranslatedEntity:
    def replace_alias(match: re.Match[str]) -> str:
        name = match.group("name")
        if name not in _RUST_PRIMITIVE_TYPE_NAMES:
            return match.group(0)
        return (
            f'{match.group("prefix")}{name}{match.group("equals")}'
            f"std::primitive::{name}{match.group('suffix')}"
        )

    rust_code = _SELF_REFERENTIAL_TYPE_ALIAS_PATTERN.sub(
        replace_alias,
        translated.rust_code,
    )
    if rust_code == translated.rust_code:
        return translated
    return replace(
        translated,
        rust_code=rust_code,
    )


def _redundant_typedef_noop_code(task: TranslationTask) -> str:
    return (
        f"// Redundant C typedef alias for tag {task.package.name}; "
        "the Rust type is emitted by the tag declaration entity."
    )


def _is_extern_global_declaration(task: TranslationTask) -> bool:
    if task.kind != "global":
        return False
    source = mask_c_non_code(
        task.package.original_c_source, mask_literals=False
    ).strip()
    if not source:
        return False
    return task.package.is_extern and "=" not in source


def _is_global_definition_of(
    candidate: TranslationTask | None,
    declaration: TranslationTask,
) -> bool:
    if candidate is None:
        return False
    if candidate.kind != "global":
        return False
    if candidate.package.name != declaration.package.name:
        return False
    return not _is_extern_global_declaration(candidate)


def _extern_global_declaration_noop(task: TranslationTask) -> TranslatedEntity:
    exports = _expected_export_names(task)
    return TranslatedEntity(
        entity_id=task.entity_id,
        rust_code=_extern_global_declaration_noop_code(task),
        exports=exports,
        summary=(
            "Extern global declaration omitted; Rust definition is emitted by "
            "the corresponding C definition entity."
        ),
    )


def _extern_global_declaration_noop_code(task: TranslationTask) -> str:
    return (
        f"// Extern C global declaration for {task.package.name}; "
        "the Rust item is emitted by the definition entity."
    )


def _is_static_function_forward_declaration(
    task: TranslationTask,
    all_tasks: Any,
) -> bool:
    if task.kind != "global":
        return False
    name = task.package.name.strip()
    if not name or not _RUST_IDENTIFIER_RE.match(name):
        return False
    source = mask_c_non_code(
        task.package.original_c_source, mask_literals=False
    ).strip()
    if (
        not task.package.is_static
        or not source.endswith(";")
        or "{" in source
        or _extract_c_function_signature(source, name) is None
    ):
        return False
    return any(
        other.entity_id != task.entity_id
        and other.kind == "function"
        and other.package.name == name
        for other in all_tasks
    )


def _static_function_forward_declaration_noop(
    task: TranslationTask,
) -> TranslatedEntity:
    exports = _expected_export_names(task)
    return TranslatedEntity(
        entity_id=task.entity_id,
        rust_code=_static_function_forward_declaration_noop_code(task),
        exports=exports,
        summary=(
            "Static C function forward declaration omitted; Rust does not "
            "need separate function prototypes."
        ),
    )


def _static_function_forward_declaration_noop_code(task: TranslationTask) -> str:
    return (
        f"// Static C function forward declaration for {task.package.name}; "
        "the Rust function is emitted by the function definition entity."
    )


def _cyclic_type_placeholder(task: TranslationTask) -> TranslatedEntity:
    exports = _expected_export_names(task)
    if _is_redundant_same_name_tag_typedef(task):
        return TranslatedEntity(
            entity_id=task.entity_id,
            rust_code=_redundant_typedef_noop_code(task),
            exports=exports,
            summary=(
                "Redundant same-name C tag typedef placeholder omitted; "
                "the Rust type is emitted by the tag declaration entity."
            ),
        )
    return TranslatedEntity(
        entity_id=task.entity_id,
        rust_code=_cyclic_type_placeholder_code(task),
        exports=exports,
        summary=(
            "Temporary type placeholder for a cyclic batch dependency; "
            "the entity is translated normally when its turn is reached."
        ),
    )


def _cyclic_type_placeholder_code(task: TranslationTask) -> str:
    names = _expected_export_names(task)
    definitions = "\n".join(f"pub struct {name};" for name in names)
    return (
        f"// Temporary placeholder for cyclic C type {task.package.name}.\n"
        f"{definitions}"
    )


def _is_prepared_extern_global_declaration_noop(
    task: TranslationTask,
    rust_code: str | None,
) -> bool:
    return (
        _is_extern_global_declaration(task)
        and rust_code is not None
        and rust_code.strip() == _extern_global_declaration_noop_code(task)
    )


def _function_signature(rust_code: str) -> str:
    text = rust_code.strip()
    match = re.search(r"\bpub\s+fn\b", text)
    if match is None:
        return text

    start = match.start()
    brace_index = _find_signature_body_start(text, start)
    if brace_index is None:
        first_line = text[start:].splitlines()[0].strip()
        return first_line if first_line.endswith(";") else f"{first_line};"
    return f"{text[start:brace_index].strip()};"


def _top_level_type_definition(rust_code: str, name: str) -> str | None:
    masked = mask_c_non_code(rust_code, mask_literals=True)
    pattern = re.compile(
        rf"\bpub\s+(?P<kind>struct|enum|union|type)\s+{re.escape(name)}\b"
    )
    for match in pattern.finditer(masked):
        if masked[: match.start()].count("{") != masked[: match.start()].count("}"):
            continue
        semicolon = masked.find(";", match.end())
        brace = masked.find("{", match.end())
        if match.group("kind") == "type" or (
            semicolon >= 0 and (brace < 0 or semicolon < brace)
        ):
            return rust_code[match.start() : semicolon + 1].strip()
        if brace < 0:
            return None
        end = _find_matching_brace(masked, brace)
        if end is None:
            return None
        if end + 1 < len(masked) and masked[end + 1] == ";":
            end += 1
        return rust_code[match.start() : end + 1].strip()
    return None


def _find_matching_brace(text: str, opening_index: int) -> int | None:
    depth = 0
    for index in range(opening_index, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _fallback_function(rust_code: str, fallback_name: str) -> str:
    text = rust_code.strip()
    match = _find_pub_function_named(text, fallback_name)
    if match is None:
        return _fallback_function_from_c_source("", fallback_name)

    brace_index = _find_signature_body_start(text, match.start())
    if brace_index is None:
        signature = _function_signature(text).rstrip(";")
    else:
        signature = text[match.start():brace_index].strip()
    return f"{signature} {{\n    unimplemented!()\n}}"


def _fallback_function_from_c_source(c_source: str, fallback_name: str) -> str:
    signature = _rust_signature_from_c_source(c_source, fallback_name)
    return f"{signature} {{\n    unimplemented!()\n}}"


def _rust_signature_from_c_source(c_source: str, fallback_name: str) -> str:
    c_signature = _extract_c_function_signature(c_source, fallback_name)
    if c_signature is None:
        return f"pub fn {fallback_name}()"

    return_type, params = c_signature
    rust_params = _rust_params_from_c_params(params)
    rust_return = _rust_type_from_c_type(return_type, is_return=True)
    if rust_return == "()":
        return f"pub fn {fallback_name}({rust_params})"
    return f"pub fn {fallback_name}({rust_params}) -> {rust_return}"


def _extract_c_function_signature(
    c_source: str,
    function_name: str,
) -> tuple[str, str] | None:
    c_source = mask_c_non_code(c_source, mask_literals=False)
    name_match = re.search(rf"\b{re.escape(function_name)}\s*\(", c_source)
    if name_match is None:
        return None

    open_paren = c_source.find("(", name_match.start())
    close_paren = _find_matching_paren(c_source, open_paren)
    if close_paren is None:
        return None

    prefix = c_source[: name_match.start()].rstrip()
    line_start = max(prefix.rfind("\n"), prefix.rfind(";"), prefix.rfind("}")) + 1
    return_type = prefix[line_start:].strip()
    if not return_type:
        return None
    params = c_source[open_paren + 1 : close_paren].strip()
    return (return_type, params)


def _human_comment_dependency_context(task: TranslationTask) -> str:
    chunks: list[str] = []
    for comment in task.package.human_comments:
        chunks.append(
            f"[{comment.rel_path}:{comment.start_line}-{comment.end_line}]\n"
            f"{comment.text.rstrip()}"
        )
    return "\n\n".join(chunks)


def _find_matching_paren(text: str, open_paren: int) -> int | None:
    depth = 0
    for index in range(open_paren, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _rust_params_from_c_params(c_params: str) -> str:
    params = _split_c_params(c_params)
    if not params or (len(params) == 1 and params[0].strip() == "void"):
        return ""

    rust_params: list[str] = []
    for index, c_param in enumerate(params):
        param = c_param.strip()
        if not param or param == "...":
            continue
        name, c_type = _c_param_name_and_type(param, index)
        rust_params.append(f"{name}: {_rust_type_from_c_type(c_type)}")
    return ", ".join(rust_params)


def _split_c_params(c_params: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(c_params):
        if char == "(":
            depth += 1
        elif char == ")" and depth > 0:
            depth -= 1
        elif char == "," and depth == 0:
            result.append(c_params[start:index])
            start = index + 1
    tail = c_params[start:].strip()
    if tail:
        result.append(tail)
    return result


def _c_param_name_and_type(c_param: str, index: int) -> tuple[str, str]:
    param = re.sub(r"\s+", " ", c_param.replace("*", " * ")).strip()
    array_suffix = ""
    array_match = re.search(r"\[[^\]]*\]\s*$", param)
    if array_match:
        array_suffix = "*"
        param = param[: array_match.start()].rstrip()

    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*$", param)
    if match is None:
        return (f"_arg{index}", f"{param}{array_suffix}")

    name = match.group(1)
    c_type = f"{param[: match.start()].strip()} {array_suffix}".strip()
    if not c_type:
        return (f"_arg{index}", param)
    if name in _C_TYPE_WORDS:
        return (f"_arg{index}", param)
    return (_sanitize_rust_param_name(name, index), c_type)


def _sanitize_rust_param_name(name: str, index: int) -> str:
    if not _RUST_IDENTIFIER_RE.match(name):
        return f"_arg{index}"
    if name in _RUST_KEYWORDS:
        return f"{name}_"
    return name


def _rust_type_from_c_type(c_type: str, *, is_return: bool = False) -> str:
    text = _normalize_c_type(c_type)
    pointer_depth = text.count("*")
    base = text.replace("*", " ")
    base = re.sub(r"\b(const|volatile|restrict|static|register|extern|inline)\b", " ", base)
    base = re.sub(r"\bstruct\s+", "", base)
    base = re.sub(r"\benum\s+", "", base)
    base = re.sub(r"\s+", " ", base).strip()

    if pointer_depth:
        rust_base = _rust_scalar_type_from_c_base(base, pointer_base=True)
        for _ in range(pointer_depth):
            rust_base = f"*mut {rust_base}"
        return rust_base

    rust_type = _rust_scalar_type_from_c_base(base, pointer_base=False)
    if is_return and rust_type == "()":
        return "()"
    return rust_type


def _normalize_c_type(c_type: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", c_type, flags=re.DOTALL)
    text = re.sub(r"\b__attribute__\s*\(\(.*?\)\)", " ", text)
    return re.sub(r"\s+", " ", text.replace("*", " * ")).strip()


def _rust_scalar_type_from_c_base(base: str, *, pointer_base: bool) -> str:
    normalized = base.strip()
    normalized = re.sub(r"\s+", " ", normalized)
    if not normalized or normalized == "void":
        return "()" if not pointer_base else "()"

    unsigned = "unsigned" in normalized
    words = tuple(word for word in normalized.split() if word not in {"signed"})
    normalized = " ".join(words)
    mapping = {
        "bool": "bool",
        "_Bool": "bool",
        "char": "u8" if unsigned else "i8",
        "unsigned char": "u8",
        "short": "i16",
        "short int": "i16",
        "unsigned short": "u16",
        "unsigned short int": "u16",
        "int": "u32" if unsigned else "i32",
        "unsigned": "u32",
        "unsigned int": "u32",
        "long": "i64",
        "long int": "i64",
        "unsigned long": "u64",
        "unsigned long int": "u64",
        "long long": "i64",
        "long long int": "i64",
        "unsigned long long": "u64",
        "unsigned long long int": "u64",
        "float": "f32",
        "double": "f64",
        "size_t": "usize",
        "ssize_t": "isize",
    }
    if normalized in mapping:
        return mapping[normalized]
    return normalized.replace(" ", "_")


_C_TYPE_WORDS = {
    "void",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "const",
    "volatile",
    "restrict",
    "size_t",
    "ssize_t",
    "bool",
}


_RUST_KEYWORDS = {
    "as",
    "break",
    "const",
    "continue",
    "crate",
    "else",
    "enum",
    "extern",
    "false",
    "fn",
    "for",
    "if",
    "impl",
    "in",
    "let",
    "loop",
    "match",
    "mod",
    "move",
    "mut",
    "pub",
    "ref",
    "return",
    "self",
    "Self",
    "static",
    "struct",
    "super",
    "trait",
    "true",
    "type",
    "unsafe",
    "use",
    "where",
    "while",
}


def _has_pub_function_named(rust_code: str, name: str) -> bool:
    return _find_pub_function_named(rust_code, name) is not None


def _sanitize_translated_rust_code(translated: TranslatedEntity) -> TranslatedEntity:
    rust_code = _sanitize_rust_literal_newlines(translated.rust_code)
    if rust_code == translated.rust_code:
        return translated
    return replace(
        translated,
        rust_code=rust_code,
    )


def _sanitize_rust_literal_newlines(rust_code: str) -> str:
    return (
        rust_code
        .replace("b'\n'", "b'\\n'")
        .replace("b'\r'", "b'\\r'")
        .replace("'\n'", "'\\n'")
        .replace("'\r'", "'\\r'")
    )


def _find_pub_function_named(rust_code: str, name: str) -> re.Match[str] | None:
    return re.search(rf"\bpub\s+fn\s+{re.escape(name)}\b", rust_code)


def _find_signature_body_start(text: str, start: int) -> int | None:
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "{" and depth == 0:
            return index
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(depth - 1, 0)
    plain_index = text.find("{", start)
    return plain_index if plain_index >= 0 else None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Translation pipeline.")
    parser.add_argument(
        "-w",
        "--workspace",
        type=Path,
        default=Path("tests/c2rust_workspace"),
        help="workflow workspace directory",
    )
    parser.add_argument(
        "--max-repair-attempts",
        type=int,
        default=3,
        help="maximum repair attempts per entity",
    )
    parser.add_argument(
        "--translation-concurrency",
        type=int,
        default=3,
        help="maximum initial translation requests to run concurrently per batch",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress progress logs",
    )
    parser.add_argument(
        "--no-reset-generated",
        action="store_true",
        help="do not clear previous Translation-generated code before running",
    )
    parser.add_argument(
        "--resume-from-entity",
        type=int,
        default=None,
        help="resume translation from this entity id using translation-state.json",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        translator_client = OpenAICompatibleTranslationLLMClient(role="translator")
        checker_client = OpenAICompatibleTranslationLLMClient(role="checker")
        runtime = TranslationAgentRuntime(
            translator_client=translator_client,
            checker_client=checker_client,
            semantic_hint_tool=SemanticHintTool.from_workspace(args.workspace),
            project_inspection_tool=ProjectInspectionTool.from_workspace(args.workspace),
            debug_dir=args.workspace / "translation-debug",
        )
        report = TranslationPipeline(
            workspace=args.workspace,
            runtime=runtime,
            max_repair_attempts=args.max_repair_attempts,
            translation_concurrency=args.translation_concurrency,
            log=None if args.quiet else print,
            reset_generated=not args.no_reset_generated,
            resume_from_entity=args.resume_from_entity,
        ).run_sync()
    except Exception as exc:
        traceback.print_exc()
        print(f"error: translation failed: {exc}", file=sys.stderr)
        return 2

    passed = sum(1 for item in report["entities"] if item["status"] == "passed")
    fallback = sum(1 for item in report["entities"] if item["status"] == "fallback")
    failed = sum(1 for item in report["entities"] if item["status"] == "failed")
    print(f"translation entities: {len(report['entities'])}")
    print(f"passed: {passed}")
    print(f"fallback: {fallback}")
    print(f"failed: {failed}")
    print(f"report: {args.workspace / 'translation-report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
