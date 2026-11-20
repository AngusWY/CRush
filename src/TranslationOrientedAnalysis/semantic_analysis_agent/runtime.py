from __future__ import annotations

import asyncio
import json
from typing import Any, Callable, Sequence

from .config import SemanticAgentConfig
from .context_provider import SemanticAgentContextProvider
from .llm_client import SemanticLLMClient, SemanticLLMError
from .models import (
    ChatMessage,
    EntitySemanticPatch,
    SemanticAgentResult,
    SemanticAgentTask,
    TokenUsage,
    ToolCallRecord,
)
from .prompts import (
    SemanticPromptBuilder,
    build_correction_prompt,
)
from .response_parser import (
    AgentResponseParser,
    ParseKind,
    ResponseParseError,
    ToolCallRequest,
)
from .tools import ToolRegistry


LogFn = Callable[[str], None]


class SemanticAgentRuntimeError(RuntimeError):
    pass


def _noop_log(_message: str) -> None:
    pass


def _format_tools_description(tool_definitions: Sequence[dict[str, Any]]) -> str:

    if not tool_definitions:
        return ""
    compact_tools: list[dict[str, Any]] = []
    for definition in tool_definitions:
        func = definition.get("function", {})
        compact_tools.append(
            {
                "name": func.get("name", ""),
                "description": func.get("description", ""),
                "parameters": func.get("parameters", {}),
            }
        )
    return json.dumps(compact_tools, ensure_ascii=False, indent=2)


def _tool_record_dict(record: ToolCallRecord) -> dict[str, Any]:

    obj: dict[str, Any] = {"tool": record.tool_name}
    if record.result is not None:
        obj["result"] = record.result
    if record.error is not None:
        obj["error"] = record.error
    return obj


class SemanticAgentRuntime:


    def __init__(
        self,
        *,
        config: SemanticAgentConfig,
        context_provider: SemanticAgentContextProvider,
        prompt_builder: SemanticPromptBuilder,
        llm_client: SemanticLLMClient,
        tool_registry: ToolRegistry,
        parser: AgentResponseParser,
        log: LogFn | None = None,
    ) -> None:
        config.validate()
        if config.max_turns <= 0:
            raise SemanticAgentRuntimeError("max_turns must be greater than zero")
        self._config = config
        self._context_provider = context_provider
        self._prompt_builder = prompt_builder
        self._llm_client = llm_client
        self._tool_registry = tool_registry
        self._parser = parser
        self._log = log if log is not None else _noop_log

    async def execute(self, task: SemanticAgentTask) -> object:

        self._log(
            f"[entity {task.entity_id} ({task.entity_name}), "
            f"{task.task_kind}] "
            f"starting, {len(task.pointer_gaps)} pointer(s), "
            f"{len(task.variable_gaps)} variable(s), "
            f"{len(task.unsafe_stmt_gaps)} unsafe stmt(s) to resolve"
        )
        try:
            messages = self._build_initial_messages(task)
        except Exception as exc:
            raise SemanticAgentRuntimeError(
                "initial context/prompt construction failed: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        tool_call_records: list[ToolCallRecord] = []
        raw_outputs: list[str] = []
        total_usage = TokenUsage()

        for turn in range(1, self._config.max_turns + 1):
            self._log(
                f"[entity {task.entity_id} {task.task_kind}] "
                f"turn {turn}/{self._config.max_turns}"
            )
            try:
                response = await self._llm_client.chat(messages=messages)
            except SemanticLLMError:
                self._log(
                    f"[entity {task.entity_id} {task.task_kind}] "
                    "LLM call failed, "
                    "rethrowing for scheduler retry"
                )
                raise

            raw_outputs.append(response.content)
            total_usage = TokenUsage(
                prompt_tokens=total_usage.prompt_tokens
                + response.token_usage.prompt_tokens,
                completion_tokens=total_usage.completion_tokens
                + response.token_usage.completion_tokens,
                total_tokens=total_usage.total_tokens
                + response.token_usage.total_tokens,
            )
            self._log(
                f"[entity {task.entity_id} {task.task_kind}] "
                f"+{response.token_usage.completion_tokens} tokens"
            )

            try:
                parsed = self._parser.parse(response.content, task)
            except ResponseParseError as exc:
                self._log(
                    f"[entity {task.entity_id} {task.task_kind}] "
                    f"parse error: {exc}"
                )

                correction = build_correction_prompt(
                    str(exc), task_kind=task.task_kind
                )
                messages.append(
                    ChatMessage(role="assistant", content=response.content)
                )
                messages.append(ChatMessage(role="user", content=correction))
                continue

            if parsed.kind is ParseKind.TOOL_CALL:
                requests = parsed.tool_call_requests
                if not requests:
                    self._log(
                        f"[entity {task.entity_id} {task.task_kind}] "
                        "tool_calls with empty list"
                    )
                    messages.append(
                        ChatMessage(role="assistant", content=response.content)
                    )
                    messages.append(
                        ChatMessage(
                            role="user",
                            content=build_correction_prompt(
                                "tool_calls array is empty",
                                task_kind=task.task_kind,
                            ),
                        )
                    )
                    continue

                per_turn_limit = self._config.max_tool_calls_per_turn
                if len(requests) > per_turn_limit:
                    self._log(
                        f"[entity {task.entity_id} {task.task_kind}] "
                        "truncating tool_calls "
                        f"from {len(requests)} to {per_turn_limit} (per-turn limit)"
                    )
                    requests = requests[:per_turn_limit]

                for req in requests:
                    self._log(
                        f"[entity {task.entity_id} {task.task_kind}] "
                        "tool_call: "
                        f"{req.tool_name}"
                        f"{_format_args_summary(req.arguments)}"
                    )


                async def _execute_one(req: ToolCallRequest) -> ToolCallRecord:
                    result = await self._tool_registry.execute(
                        req.tool_name, req.arguments
                    )
                    if result.ok:
                        self._log(
                            f"[entity {task.entity_id}] {req.tool_name} → ok"
                        )
                    else:
                        self._log(
                            f"[entity {task.entity_id}] {req.tool_name} → "
                            f"error: {result.error}"
                        )
                    return ToolCallRecord(
                        tool_name=req.tool_name,
                        arguments=req.arguments,
                        result=result.data,
                        error=result.error,
                    )

                batch_results = await asyncio.gather(
                    *(_execute_one(req) for req in requests)
                )
                tool_call_records.extend(batch_results)



                combined_tool_text = json.dumps(
                    [
                        _tool_record_dict(record)
                        for record in batch_results
                    ],
                    ensure_ascii=False,
                    indent=2,
                )
                messages.append(
                    ChatMessage(role="assistant", content=response.content)
                )
                messages.append(
                    ChatMessage(role="user", content=combined_tool_text)
                )
                continue


            patch = parsed.entity_patch
            if patch is None:
                patch = EntitySemanticPatch(
                    entity_id=task.entity_id,
                    pointer_patches=(),
                    variable_patches=(),
                    unsafe_stmt_patches=(),
                )
            filled = _count_filled_fields(patch)
            unresolved = _count_unresolved_fields(patch)
            self._log(
                f"[entity {task.entity_id} {task.task_kind}] final: "
                f"{filled} field(s) filled, "
                f"{unresolved} unresolved, "
                f"{len(tool_call_records)} tool call(s), "
                f"{total_usage.total_tokens} total tokens"
            )
            return SemanticAgentResult(
                patch=patch,
                model=response.model,
                raw_model_outputs=tuple(raw_outputs),
                tool_calls=tuple(tool_call_records),
                token_usage=total_usage,
                turn_count=turn,
            )


        self._log(
            f"[entity {task.entity_id} {task.task_kind}] exhausted after "
            f"{self._config.max_turns} turns"
        )
        return SemanticAgentResult(
            patch=EntitySemanticPatch(
                entity_id=task.entity_id,
                pointer_patches=(),
                variable_patches=(),
                unsafe_stmt_patches=(),
            ),
            model=self._llm_client.model,
            raw_model_outputs=tuple(raw_outputs),
            tool_calls=tuple(tool_call_records),
            token_usage=total_usage,
            turn_count=self._config.max_turns,
        )

    def _build_initial_messages(
        self,
        task: SemanticAgentTask,
    ) -> list[ChatMessage]:

        context = self._context_provider.build(task)
        tool_defs = self._tool_registry.describe_tools()
        self._prompt_builder.tools_description = _format_tools_description(
            tool_defs
        )
        return list(
            self._prompt_builder.build(task=task, context=context)
        )


def _format_args_summary(arguments: dict[str, Any]) -> str:

    if not arguments:
        return ""
    parts = ", ".join(
        f"{k}={v}" for k, v in arguments.items()
    )
    return f"({parts})"


def _count_filled_fields(patch: EntitySemanticPatch) -> int:
    return (
        sum(len(p.updates) for p in patch.pointer_patches)
        + sum(len(p.updates) for p in patch.variable_patches)
        + sum(len(p.updates) for p in patch.unsafe_stmt_patches)
    )


def _count_unresolved_fields(patch: EntitySemanticPatch) -> int:
    return (
        sum(len(p.unresolved_fields) for p in patch.pointer_patches)
        + sum(len(p.unresolved_fields) for p in patch.variable_patches)
        + sum(len(p.unresolved_fields) for p in patch.unsafe_stmt_patches)
    )
