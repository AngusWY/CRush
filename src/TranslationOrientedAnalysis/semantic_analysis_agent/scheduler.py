from __future__ import annotations

import asyncio
from typing import Callable, Protocol

from .models import (
    DECLARATION_TASK_KIND,
    SchedulerResult,
    SemanticAgentTask,
    TASK_KINDS,
    UNSAFE_STMT_TASK_KIND,
    TaskExecutionResult,
    TaskStatus,
)


LogFn = Callable[[str], None]


class SemanticAgentSchedulerError(RuntimeError):
    pass


class SemanticTaskExecutor(Protocol):


    async def execute(self, task: SemanticAgentTask) -> object:
        pass


class SemanticAgentScheduler:


    def __init__(
        self,
        *,
        executor: SemanticTaskExecutor,
        max_retries: int = 0,
        max_concurrency: int = 1,
        log: LogFn | None = None,
    ) -> None:
        if executor is None:
            raise ValueError("executor must not be None")
        if max_retries < 0:
            raise ValueError("max_retries must be nonnegative")
        if max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        self.executor = executor
        self.max_retries = max_retries
        self.max_concurrency = max_concurrency
        self._log = log if log is not None else (lambda _: None)

    async def run(
        self,
        tasks: tuple[SemanticAgentTask, ...],
    ) -> SchedulerResult:
        ordered_tasks = self._validate_and_order_tasks(tasks)
        if not ordered_tasks:
            return SchedulerResult(task_results=())
        effective_concurrency = min(self.max_concurrency, len(ordered_tasks))
        self._log(
            f"scheduler: running {len(ordered_tasks)} task(s), "
            f"concurrency={effective_concurrency}"
        )
        semaphore = asyncio.Semaphore(effective_concurrency)

        async def _run_one(
            index: int,
            task: SemanticAgentTask,
        ) -> TaskExecutionResult:
            async with semaphore:
                self._log(
                    f"scheduler: task {index}/{len(ordered_tasks)} "
                    f"starting (entity {task.entity_id}, {task.task_kind})"
                )
                return await self._execute_task(task)

        results = list(
            await asyncio.gather(
                *(
                    _run_one(index, task)
                    for index, task in enumerate(ordered_tasks, start=1)
                )
            )
        )
        completed = sum(
            1 for r in results if r.status is TaskStatus.COMPLETED
        )
        self._log(
            f"scheduler: {completed}/{len(results)} completed, "
            f"{len(results) - completed} failed"
        )
        return SchedulerResult(task_results=tuple(results))

    async def _execute_task(
        self,
        task: SemanticAgentTask,
    ) -> TaskExecutionResult:
        max_attempts = self.max_retries + 1
        last_error: str | None = None

        for attempt in range(1, max_attempts + 1):
            try:
                output = await self.executor.execute(task)
            except Exception as exc:
                last_error = self._format_error(exc)
                self._log(
                    f"scheduler: entity {task.entity_id} "
                    f"{task.task_kind} attempt "
                    f"{attempt}/{max_attempts} failed: {last_error}"
                )
                continue

            return TaskExecutionResult(
                entity_id=task.entity_id,
                task_kind=task.task_kind,
                status=TaskStatus.COMPLETED,
                attempts=attempt,
                output=output,
            )

        self._log(
            f"scheduler: entity {task.entity_id} {task.task_kind} "
            f"failed after "
            f"{max_attempts} attempt(s): {last_error}"
        )
        return TaskExecutionResult(
            entity_id=task.entity_id,
            task_kind=task.task_kind,
            status=TaskStatus.FAILED,
            attempts=max_attempts,
            error=last_error or "task execution failed without an error",
        )

    @staticmethod
    def _validate_and_order_tasks(
        tasks: tuple[SemanticAgentTask, ...],
    ) -> tuple[SemanticAgentTask, ...]:
        tasks_by_key: dict[tuple[int, str], SemanticAgentTask] = {}
        for task in tasks:
            if task.entity_id <= 0:
                raise SemanticAgentSchedulerError(
                    f"task has invalid entity ID: {task.entity_id}"
                )
            if task.task_kind not in TASK_KINDS:
                raise SemanticAgentSchedulerError(
                    f"entity task {task.entity_id} has invalid task_kind: "
                    f"{task.task_kind!r}"
                )
            task_key = (task.entity_id, task.task_kind)
            if task_key in tasks_by_key:
                raise SemanticAgentSchedulerError(
                    "duplicate task key: "
                    f"entity {task.entity_id}, kind {task.task_kind}"
                )
            if (
                not task.pointer_gaps
                and not task.variable_gaps
                and not task.unsafe_stmt_gaps
            ):
                raise SemanticAgentSchedulerError(
                    f"entity task {task.entity_id} has no semantic gaps"
                )
            if (
                task.task_kind == DECLARATION_TASK_KIND
                and task.unsafe_stmt_gaps
            ):
                raise SemanticAgentSchedulerError(
                    f"declaration task {task.entity_id} contains unsafe gaps"
                )
            if (
                task.task_kind == UNSAFE_STMT_TASK_KIND
                and (task.pointer_gaps or task.variable_gaps)
            ):
                raise SemanticAgentSchedulerError(
                    f"unsafe_stmt task {task.entity_id} contains "
                    "declaration gaps"
                )
            tasks_by_key[task_key] = task

        return tuple(
            tasks_by_key[task_key]
            for task_key in sorted(tasks_by_key)
        )

    @staticmethod
    def _format_error(exc: Exception) -> str:
        message = str(exc).strip()
        if message:
            return f"{type(exc).__name__}: {message}"
        return type(exc).__name__
