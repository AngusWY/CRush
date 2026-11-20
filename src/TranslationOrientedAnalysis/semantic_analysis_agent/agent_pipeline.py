from __future__ import annotations

import asyncio
import dataclasses
import json
from pathlib import Path
from typing import Any

from ..analysis_context import AnalysisContext
from .config import SemanticAgentConfig
from .context_provider import SemanticAgentContextProvider
from .llm_client import OpenAICompatibleSemanticLLMClient, SemanticLLMClient
from .models import (
    DECLARATION_TASK_KIND,
    EntitySemanticPatch,
    SchedulerResult,
    SemanticAgentResult,
    SemanticAgentTask,
    SemanticMergeResult,
    TaskStatus,
    UNSAFE_STMT_TASK_KIND,
)
from .prompts import SemanticPromptBuilder
from .response_parser import AgentResponseParser
from .runtime import SemanticAgentRuntime
from .scheduler import SemanticAgentScheduler
from .semantic_merger import SemanticMerger
from .task_builder import SemanticAgentTaskBuilder, SemanticAgentTaskBuildError
from .tools import build_tool_registry


SEMANTIC_ANALYSIS_DIR_NAME = "semantic_analysis"
POINTER_SEMANTICS_FILE_NAME = "pointer-semantics.json"
VARIABLE_SEMANTICS_FILE_NAME = "variable-semantics.json"
UNSAFE_STMT_SEMANTICS_FILE_NAME = "unsafe-stmt-semantics.json"
AGENT_RUN_REPORT_FILE_NAME = "agent-run-report.json"
SEMANTIC_CONFLICTS_FILE_NAME = "semantic-conflicts.json"


class AgentPipelineError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class PerEntityReport:
    entity_id: int
    task_kind: str
    status: str
    model: str
    attempts: int
    turns: int
    tool_calls: int
    token_usage: dict[str, int]
    applied_fields: tuple[str, ...]
    confirmed_fields: tuple[str, ...]
    remaining_fields: tuple[str, ...]
    issues: tuple[str, ...]
    error: str | None = None


@dataclasses.dataclass(frozen=True)
class AgentPipelineResult:


    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    declaration_task_count: int
    unsafe_stmt_task_count: int
    declaration_completed: int
    unsafe_stmt_completed: int
    declaration_failed: int
    unsafe_stmt_failed: int
    merged_pointer_count: int
    merged_variable_count: int
    merged_unsafe_stmt_count: int
    fields_filled: int
    conflicts: int
    remaining_entity_ids: tuple[int, ...]
    pointer_semantics_path: Path
    variable_semantics_path: Path
    unsafe_stmt_semantics_path: Path
    report_path: Path
    per_entity: tuple[PerEntityReport, ...]


class SemanticAgentPipeline:


    def __init__(
        self,
        *,
        loader: Any,
        workspace: Path,
        config: SemanticAgentConfig | None = None,
    ) -> None:
        self._loader = loader
        self._workspace = workspace.resolve()
        self._config = (
            config
            if config is not None
            else SemanticAgentConfig.from_env()
        )
        self._semantic_analysis_dir = (
            self._workspace / SEMANTIC_ANALYSIS_DIR_NAME
        )
        self._pointer_semantics_path = (
            self._semantic_analysis_dir / POINTER_SEMANTICS_FILE_NAME
        )
        self._variable_semantics_path = (
            self._semantic_analysis_dir / VARIABLE_SEMANTICS_FILE_NAME
        )
        self._unsafe_stmt_semantics_path = (
            self._semantic_analysis_dir / UNSAFE_STMT_SEMANTICS_FILE_NAME
        )
        self._report_path = (
            self._semantic_analysis_dir / AGENT_RUN_REPORT_FILE_NAME
        )
        self._semantic_conflicts_path = (
            self._semantic_analysis_dir / SEMANTIC_CONFLICTS_FILE_NAME
        )

    async def run(self) -> AgentPipelineResult:


        context = AnalysisContext(self._loader)
        try:
            tasks = SemanticAgentTaskBuilder(
                workspace=self._workspace
            ).build()
        except SemanticAgentTaskBuildError as exc:
            raise AgentPipelineError(
                f"failed to build Agent tasks: {exc}"
            ) from exc

        if not tasks:
            return AgentPipelineResult(
                total_tasks=0,
                completed_tasks=0,
                failed_tasks=0,
                declaration_task_count=0,
                unsafe_stmt_task_count=0,
                declaration_completed=0,
                unsafe_stmt_completed=0,
                declaration_failed=0,
                unsafe_stmt_failed=0,
                merged_pointer_count=0,
                merged_variable_count=0,
                merged_unsafe_stmt_count=0,
                fields_filled=0,
                conflicts=0,
                remaining_entity_ids=(),
                pointer_semantics_path=self._pointer_semantics_path,
                variable_semantics_path=self._variable_semantics_path,
                unsafe_stmt_semantics_path=self._unsafe_stmt_semantics_path,
                report_path=self._report_path,
                per_entity=(),
            )


        context_provider = SemanticAgentContextProvider(
            context=context,
            workspace=self._workspace,
        )
        tool_registry = build_tool_registry(context, self._workspace)
        prompt_builder = SemanticPromptBuilder()
        llm_client: SemanticLLMClient = OpenAICompatibleSemanticLLMClient(
            config=self._config
        )
        parser = AgentResponseParser()

        runtime = SemanticAgentRuntime(
            config=self._config,
            context_provider=context_provider,
            prompt_builder=prompt_builder,
            llm_client=llm_client,
            tool_registry=tool_registry,
            parser=parser,
            log=print,
        )


        scheduler = SemanticAgentScheduler(
            executor=runtime,
            max_retries=self._config.max_retries,
            max_concurrency=self._config.max_concurrency,
            log=print,
        )
        scheduler_result = await scheduler.run(tasks)


        agent_results: dict[tuple[int, str], SemanticAgentResult] = {}
        for task_result in scheduler_result.task_results:
            if (
                task_result.status is TaskStatus.COMPLETED
                and isinstance(task_result.output, SemanticAgentResult)
            ):
                agent_results[
                    (task_result.entity_id, task_result.task_kind)
                ] = task_result.output


        original_data = self._read_pointer_semantics()
        original_variable_data = self._read_variable_semantics()
        original_unsafe_data = self._read_unsafe_stmt_semantics()
        entity_patches: list[EntitySemanticPatch] = [
            result.patch for result in agent_results.values()
        ]
        merge_result = SemanticMerger().merge(
            original_data,
            entity_patches,
            unsafe_stmt_semantics=original_unsafe_data,
            variable_semantics=original_variable_data,
        )


        self._write_pointer_semantics(merge_result)
        self._write_variable_semantics(merge_result)
        self._write_unsafe_stmt_semantics(merge_result)
        self._write_semantic_conflicts(merge_result)


        per_entity_reports = self._build_per_entity_reports(
            scheduler_result,
            agent_results,
            merge_result,
        )


        self._write_report(per_entity_reports, merge_result)

        total_fields_filled = sum(
            len(pointer_result.applied_fields)
            for pointer_result in merge_result.pointer_results
        ) + sum(
            len(variable_result.applied_fields)
            for variable_result in merge_result.variable_results
        ) + sum(
            len(unsafe_result.applied_fields)
            for unsafe_result in merge_result.unsafe_stmt_results
        )
        total_completed = len(
            [
                r
                for r in scheduler_result.task_results
                if r.status is TaskStatus.COMPLETED
            ]
        )
        total_failed = len(scheduler_result.task_results) - total_completed
        task_counts = self._task_kind_counts(scheduler_result)

        return AgentPipelineResult(
            total_tasks=len(tasks),
            completed_tasks=total_completed,
            failed_tasks=total_failed,
            declaration_task_count=task_counts["declaration_total"],
            unsafe_stmt_task_count=task_counts["unsafe_stmt_total"],
            declaration_completed=task_counts["declaration_completed"],
            unsafe_stmt_completed=task_counts["unsafe_stmt_completed"],
            declaration_failed=task_counts["declaration_failed"],
            unsafe_stmt_failed=task_counts["unsafe_stmt_failed"],
            merged_pointer_count=len(merge_result.pointer_results),
            merged_variable_count=len(merge_result.variable_results),
            merged_unsafe_stmt_count=len(merge_result.unsafe_stmt_results),
            fields_filled=total_fields_filled,
            conflicts=len(merge_result.issues),
            remaining_entity_ids=merge_result.remaining_entity_ids,
            pointer_semantics_path=self._pointer_semantics_path,
            variable_semantics_path=self._variable_semantics_path,
            unsafe_stmt_semantics_path=self._unsafe_stmt_semantics_path,
            report_path=self._report_path,
            per_entity=tuple(per_entity_reports),
        )

    def run_sync(self) -> AgentPipelineResult:

        return asyncio.run(self.run())



    def _read_pointer_semantics(self) -> dict[str, Any]:
        if not self._pointer_semantics_path.is_file():
            raise AgentPipelineError(
                "pointer semantics file does not exist: "
                f"{self._pointer_semantics_path}"
            )
        try:
            value = json.loads(
                self._pointer_semantics_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentPipelineError(
                f"failed to read pointer semantics "
                f"{self._pointer_semantics_path}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise AgentPipelineError(
                "pointer semantics file must be a JSON object"
            )
        return value

    def _read_variable_semantics(self) -> dict[str, Any] | None:
        if not self._variable_semantics_path.is_file():
            return None
        try:
            value = json.loads(
                self._variable_semantics_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentPipelineError(
                f"failed to read variable semantics "
                f"{self._variable_semantics_path}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise AgentPipelineError(
                "variable semantics file must be a JSON object"
            )
        return value

    def _read_unsafe_stmt_semantics(self) -> dict[str, Any] | None:
        if not self._unsafe_stmt_semantics_path.is_file():
            return None
        try:
            value = json.loads(
                self._unsafe_stmt_semantics_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentPipelineError(
                f"failed to read unsafe stmt semantics "
                f"{self._unsafe_stmt_semantics_path}: {exc}"
            ) from exc
        if not isinstance(value, dict):
            raise AgentPipelineError(
                "unsafe stmt semantics file must be a JSON object"
            )
        return value

    def _write_pointer_semantics(
        self,
        merge_result: SemanticMergeResult,
    ) -> None:
        temporary_path = self._pointer_semantics_path.with_suffix(
            self._pointer_semantics_path.suffix + ".tmp"
        )
        try:
            self._semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            payload = merge_result.pointer_semantics
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self._pointer_semantics_path)
        except OSError as exc:
            raise AgentPipelineError(
                "failed to write pointer semantics "
                f"{self._pointer_semantics_path}: {exc}"
            ) from exc

    def _write_variable_semantics(
        self,
        merge_result: SemanticMergeResult,
    ) -> None:
        if merge_result.variable_semantics is None:
            return
        temporary_path = self._variable_semantics_path.with_suffix(
            self._variable_semantics_path.suffix + ".tmp"
        )
        try:
            self._semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(
                    merge_result.variable_semantics,
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self._variable_semantics_path)
        except OSError as exc:
            raise AgentPipelineError(
                "failed to write variable semantics "
                f"{self._variable_semantics_path}: {exc}"
            ) from exc

    def _write_unsafe_stmt_semantics(
        self,
        merge_result: SemanticMergeResult,
    ) -> None:
        if merge_result.unsafe_stmt_semantics is None:
            return
        temporary_path = self._unsafe_stmt_semantics_path.with_suffix(
            self._unsafe_stmt_semantics_path.suffix + ".tmp"
        )
        try:
            self._semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(
                    merge_result.unsafe_stmt_semantics,
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self._unsafe_stmt_semantics_path)
        except OSError as exc:
            raise AgentPipelineError(
                "failed to write unsafe stmt semantics "
                f"{self._unsafe_stmt_semantics_path}: {exc}"
            ) from exc

    def _write_semantic_conflicts(
        self,
        merge_result: SemanticMergeResult,
    ) -> None:
        conflicts = self._semantic_conflict_records(merge_result)
        payload = {
            "version": 1,
            "kind": "semantic_conflicts",
            "conflicts": conflicts,
        }
        temporary_path = self._semantic_conflicts_path.with_suffix(
            self._semantic_conflicts_path.suffix + ".tmp"
        )
        try:
            self._semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self._semantic_conflicts_path)
        except OSError as exc:
            raise AgentPipelineError(
                "failed to write semantic conflicts "
                f"{self._semantic_conflicts_path}: {exc}"
            ) from exc

    @staticmethod
    def _semantic_conflict_records(
        merge_result: SemanticMergeResult,
    ) -> list[dict[str, Any]]:
        target_kind_by_stmt: dict[int, str] = {}
        for pointer_result in merge_result.pointer_results:
            target_kind_by_stmt[pointer_result.stmt_id] = "pointer"
        for variable_result in merge_result.variable_results:
            target_kind_by_stmt[variable_result.stmt_id] = "variable"
        for unsafe_result in merge_result.unsafe_stmt_results:
            target_kind_by_stmt[unsafe_result.stmt_id] = "unsafe_stmt"

        records: list[dict[str, Any]] = []
        seen_agent_conflict_keys = {
            (issue.entity_id, issue.stmt_id, issue.field)
            for issue in merge_result.issues
            if issue.kind == "agent_reported_conflict"
        }
        for issue in merge_result.issues:
            if issue.kind not in {
                "agent_reported_conflict",
                "programmatic_conflict",
            }:
                continue
            key = (issue.entity_id, issue.stmt_id, issue.field)
            if (
                issue.kind == "programmatic_conflict"
                and key in seen_agent_conflict_keys
            ):
                continue
            records.append(
                {
                    "entity_id": issue.entity_id,
                    "target_kind": target_kind_by_stmt.get(
                        issue.stmt_id or -1,
                        "unknown",
                    ),
                    "stmt_id": issue.stmt_id,
                    "field": issue.field,
                    "conflict_kind": issue.kind,
                    "programmatic_value": issue.existing_value,
                    "agent_suggested_value": issue.suggested_value,
                    "reason": issue.reason,
                    "evidence_refs": list(issue.evidence_refs),
                    "status": "pending",
                }
            )
        return records

    def _write_report(
        self,
        per_entity_reports: list[PerEntityReport],
        merge_result: SemanticMergeResult,
    ) -> None:
        total_fields_filled = sum(
            len(
                [
                    f
                    for pointer_result in merge_result.pointer_results
                    for f in pointer_result.applied_fields
                ]
            )
            for _ in (1,)
        )
        total_completed = sum(
            1 for r in per_entity_reports if r.status == "completed"
        )
        total_failed = len(per_entity_reports) - total_completed
        declaration_reports = [
            report
            for report in per_entity_reports
            if report.task_kind == DECLARATION_TASK_KIND
        ]
        unsafe_reports = [
            report
            for report in per_entity_reports
            if report.task_kind == UNSAFE_STMT_TASK_KIND
        ]

        payload = {
            "version": 1,
            "total_tasks": len(per_entity_reports),
            "completed_tasks": total_completed,
            "failed_tasks": total_failed,
            "task_counts": {
                "declaration": {
                    "total": len(declaration_reports),
                    "completed": sum(
                        1
                        for report in declaration_reports
                        if report.status == "completed"
                    ),
                    "failed": sum(
                        1
                        for report in declaration_reports
                        if report.status == "failed"
                    ),
                },
                "unsafe_stmt": {
                    "total": len(unsafe_reports),
                    "completed": sum(
                        1
                        for report in unsafe_reports
                        if report.status == "completed"
                    ),
                    "failed": sum(
                        1
                        for report in unsafe_reports
                        if report.status == "failed"
                    ),
                },
            },
            "merged_pointer_count": len(merge_result.pointer_results),
            "merged_variable_count": len(merge_result.variable_results),
            "merged_unsafe_stmt_count": len(merge_result.unsafe_stmt_results),
            "fields_filled": sum(
                len(r.applied_fields) for r in per_entity_reports
            ),
            "conflicts": len(merge_result.issues),
            "remaining_entity_ids": list(merge_result.remaining_entity_ids),
            "per_entity": [
                {
                    "entity_id": report.entity_id,
                    "task_kind": report.task_kind,
                    "status": report.status,
                    "model": report.model,
                    "attempts": report.attempts,
                    "turns": report.turns,
                    "tool_calls": report.tool_calls,
                    "token_usage": report.token_usage,
                    "applied_fields": list(report.applied_fields),
                    "confirmed_fields": list(report.confirmed_fields),
                    "remaining_fields": list(report.remaining_fields),
                    "issues": list(report.issues),
                    "error": report.error,
                }
                for report in per_entity_reports
            ],
        }
        temporary_path = self._report_path.with_suffix(
            self._report_path.suffix + ".tmp"
        )
        try:
            self._semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self._report_path)
        except OSError as exc:
            raise AgentPipelineError(
                f"failed to write Agent run report "
                f"{self._report_path}: {exc}"
            ) from exc

    @staticmethod
    def _build_per_entity_reports(
        scheduler_result: SchedulerResult,
        agent_results: dict[tuple[int, str], SemanticAgentResult],
        merge_result: SemanticMergeResult,
    ) -> list[PerEntityReport]:
        pointer_results_by_entity: dict[int, list[Any]] = {}
        for pointer_result in merge_result.pointer_results:
            pointer_results_by_entity.setdefault(
                pointer_result.entity_id, []
            ).append(pointer_result)
        variable_results_by_entity: dict[int, list[Any]] = {}
        for variable_result in merge_result.variable_results:
            variable_results_by_entity.setdefault(
                variable_result.entity_id, []
            ).append(variable_result)
        unsafe_results_by_entity: dict[int, list[Any]] = {}
        for unsafe_result in merge_result.unsafe_stmt_results:
            unsafe_results_by_entity.setdefault(
                unsafe_result.entity_id, []
            ).append(unsafe_result)

        reports: list[PerEntityReport] = []
        for task_result in scheduler_result.task_results:
            entity_id = task_result.entity_id
            task_kind = task_result.task_kind
            agent_result = agent_results.get((entity_id, task_kind))
            if task_kind == DECLARATION_TASK_KIND:
                pointer_results = pointer_results_by_entity.get(entity_id, [])
                variable_results = variable_results_by_entity.get(
                    entity_id, []
                )
                unsafe_results = []
            elif task_kind == UNSAFE_STMT_TASK_KIND:
                pointer_results = []
                variable_results = []
                unsafe_results = unsafe_results_by_entity.get(entity_id, [])
            else:
                pointer_results = []
                variable_results = []
                unsafe_results = []

            applied_fields: list[str] = []
            confirmed_fields: list[str] = []
            remaining_fields: list[str] = []
            issues: list[str] = []
            for pr in pointer_results:
                applied_fields.extend(
                    f"pointer:{pr.stmt_id}:{field}"
                    for field in pr.applied_fields
                )
                confirmed_fields.extend(
                    f"pointer:{pr.stmt_id}:{field}"
                    for field in pr.confirmed_fields
                )
                remaining_fields.extend(
                    f"pointer:{pr.stmt_id}:{field}"
                    for field in pr.remaining_fields
                )
                issues.extend(
                    issue.reason for issue in pr.issues
                )
            for vr in variable_results:
                applied_fields.extend(
                    f"variable:{vr.stmt_id}:{field}"
                    for field in vr.applied_fields
                )
                confirmed_fields.extend(
                    f"variable:{vr.stmt_id}:{field}"
                    for field in vr.confirmed_fields
                )
                remaining_fields.extend(
                    f"variable:{vr.stmt_id}:{field}"
                    for field in vr.remaining_fields
                )
                issues.extend(
                    issue.reason for issue in vr.issues
                )
            for ur in unsafe_results:
                applied_fields.extend(
                    f"unsafe_stmt:{ur.stmt_id}:{field}"
                    for field in ur.applied_fields
                )
                confirmed_fields.extend(
                    f"unsafe_stmt:{ur.stmt_id}:{field}"
                    for field in ur.confirmed_fields
                )
                remaining_fields.extend(
                    f"unsafe_stmt:{ur.stmt_id}:{field}"
                    for field in ur.remaining_fields
                )
                issues.extend(
                    issue.reason for issue in ur.issues
                )

            reports.append(
                PerEntityReport(
                    entity_id=entity_id,
                    task_kind=task_kind,
                    status=task_result.status.value,
                    model=(
                        agent_result.model
                        if agent_result is not None
                        else "unknown"
                    ),
                    attempts=task_result.attempts,
                    turns=(
                        agent_result.turn_count
                        if agent_result is not None
                        else 0
                    ),
                    tool_calls=(
                        len(agent_result.tool_calls)
                        if agent_result is not None
                        else 0
                    ),
                    token_usage=(
                        {
                            "prompt_tokens": (
                                agent_result.token_usage.prompt_tokens
                            ),
                            "completion_tokens": (
                                agent_result.token_usage.completion_tokens
                            ),
                            "total_tokens": (
                                agent_result.token_usage.total_tokens
                            ),
                        }
                        if agent_result is not None
                        else {
                            "prompt_tokens": 0,
                            "completion_tokens": 0,
                            "total_tokens": 0,
                        }
                    ),
                    applied_fields=tuple(applied_fields),
                    confirmed_fields=tuple(confirmed_fields),
                    remaining_fields=tuple(remaining_fields),
                    issues=tuple(issues),
                    error=task_result.error,
                )
            )
        return reports

    @staticmethod
    def _task_kind_counts(
        scheduler_result: SchedulerResult,
    ) -> dict[str, int]:
        counts = {
            "declaration_total": 0,
            "unsafe_stmt_total": 0,
            "declaration_completed": 0,
            "unsafe_stmt_completed": 0,
            "declaration_failed": 0,
            "unsafe_stmt_failed": 0,
        }
        for result in scheduler_result.task_results:
            if result.task_kind == DECLARATION_TASK_KIND:
                counts["declaration_total"] += 1
                if result.status is TaskStatus.COMPLETED:
                    counts["declaration_completed"] += 1
                elif result.status is TaskStatus.FAILED:
                    counts["declaration_failed"] += 1
            elif result.task_kind == UNSAFE_STMT_TASK_KIND:
                counts["unsafe_stmt_total"] += 1
                if result.status is TaskStatus.COMPLETED:
                    counts["unsafe_stmt_completed"] += 1
                elif result.status is TaskStatus.FAILED:
                    counts["unsafe_stmt_failed"] += 1
        return counts
