from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable, TypeVar

from SafeTranslation.models import (
    CheckerSummary,
    CompileResult,
    JsonDict,
    LLMResponse,
    RepairAttempt,
    TranslatedEntity,
    TranslatedSignature,
    TranslationTask,
    ToolCall,
)
from SafeTranslation.semantic_hint_tool import (
    GET_SEMANTIC_HINT_TOOL,
    SemanticHintTool,
)
from SafeTranslation.project_inspection_tool import (
    GET_PROJECT_CONTEXT_TOOL,
    INSPECT_RUST_CRATE_API_TOOL,
    INSPECT_POINTER_USAGE_TOOL,
    ProjectInspectionTool,
)

from .llm_client import TranslationLLMClient
from .prompts import (
    build_checker_summary_messages,
    build_entity_output_contract_repair_messages,
    build_global_export_repair_messages,
    build_initial_translation_messages,
    build_protocol_correction_message,
    build_repair_messages,
    build_signature_translation_messages,
    human_comment_context_text,
)
from .response_parser import (
    ResponseParseError,
    parse_checker_summary,
    parse_initial_translation,
    parse_repair_rewrite,
    parse_signature_translation,
)


_ParsedResponse = TypeVar("_ParsedResponse")


class TranslationAgentRuntime:


    def __init__(
        self,
        translator_client: TranslationLLMClient,
        checker_client: TranslationLLMClient | None = None,
        semantic_hint_tool: SemanticHintTool | None = None,
        project_inspection_tool: ProjectInspectionTool | None = None,
        max_tool_rounds: int | None = None,
        max_parse_retries: int = 2,
        debug_dir: Path | str | None = None,
    ) -> None:
        self.translator_client = translator_client
        self.checker_client = checker_client or translator_client
        self.semantic_hint_tool = semantic_hint_tool
        self.project_inspection_tool = project_inspection_tool
        if max_tool_rounds is not None and max_tool_rounds < 0:
            raise ValueError("max_tool_rounds must be non-negative")
        if max_parse_retries < 0:
            raise ValueError("max_parse_retries must be non-negative")
        self.max_tool_rounds = max_tool_rounds
        self.max_parse_retries = max_parse_retries
        self.debug_dir = Path(debug_dir) if debug_dir is not None else None
        self._tool_calls_by_entity: dict[int, int] = {}
        self._token_usage_records: list[JsonDict] = []
        self._llm_trace_counter = 0

    def get_semantic_hint_for_task(
        self,
        task: TranslationTask,
        anchor_id: str,
    ) -> JsonDict:


        if self.semantic_hint_tool is None:
            raise RuntimeError("semantic hint tool is not configured")
        return self.semantic_hint_tool.get_semantic_hint_for_task(
            task,
            anchor_id,
        )

    def tool_call_count_for_task(self, task: TranslationTask) -> int:


        return self._tool_calls_by_entity.get(task.entity_id, 0)

    def token_usage_summary(self, task: TranslationTask | None = None) -> JsonDict:


        records = self._token_usage_records
        if task is not None:
            records = [
                record
                for record in records
                if record["entity_id"] == task.entity_id
            ]
        return _summarize_token_usage(records, include_entities=task is None)

    async def translate_initial(
        self,
        task: TranslationTask,
        *,
        dependency_context: str = "",
        external_symbol_context: str = "",
    ) -> TranslatedEntity:
        messages = build_initial_translation_messages(
            task,
            dependency_context=dependency_context,
            external_symbol_context=external_symbol_context,
        )
        messages = self._with_critical_semantic_context(task, messages)
        response = await self._chat_translator_with_tools(
            task=task,
            messages=messages,
            phase="initial",
        )
        return await self._parse_with_protocol_retries(
            client=self.translator_client,
            task=task,
            phase="initial",
            messages=messages,
            response=response,
            parser=lambda content: parse_initial_translation(
                content,
                expected_entity_id=task.entity_id,
            ),
        )

    async def summarize_compile_error(
        self,
        task: TranslationTask,
        *,
        current_rust: str,
        compile_result: CompileResult,
    ) -> CheckerSummary:
        messages = build_checker_summary_messages(
            task,
            current_rust=current_rust,
            compile_result=compile_result,
        )
        response = await self._chat_with_trace(
            client=self.checker_client,
            task=task,
            phase="checker",
            round_label="0",
            messages=messages,
        )
        return await self._parse_with_protocol_retries(
            client=self.checker_client,
            task=task,
            phase="checker",
            messages=messages,
            response=response,
            parser=parse_checker_summary,
        )

    async def repair_global_export_names(
        self,
        task: TranslationTask,
        *,
        current_rust: str,
        missing_exports: tuple[str, ...],
        dependency_context: str = "",
        external_symbol_context: str = "",
    ) -> TranslatedEntity:
        messages = build_global_export_repair_messages(
            task,
            current_rust=current_rust,
            missing_exports=missing_exports,
            dependency_context=dependency_context,
            external_symbol_context=external_symbol_context,
        )
        messages = self._with_critical_semantic_context(task, messages)
        response = await self._chat_translator_with_tools(
            task=task,
            messages=messages,
            phase="global-name-repair",
        )
        return await self._parse_with_protocol_retries(
            client=self.translator_client,
            task=task,
            phase="global-name-repair",
            messages=messages,
            response=response,
            parser=lambda content: parse_repair_rewrite(
                content,
                expected_entity_id=task.entity_id,
            ),
        )

    async def repair_entity_output_contract(
        self,
        task: TranslationTask,
        *,
        current_rust: str,
        violations: tuple[str, ...],
        dependency_context: str = "",
        external_symbol_context: str = "",
    ) -> TranslatedEntity:
        messages = build_entity_output_contract_repair_messages(
            task,
            current_rust=current_rust,
            violations=violations,
            dependency_context=dependency_context,
            external_symbol_context=external_symbol_context,
        )
        messages = self._with_critical_semantic_context(task, messages)
        response = await self._chat_translator_with_tools(
            task=task,
            messages=messages,
            phase="entity-contract-repair",
        )
        return await self._parse_with_protocol_retries(
            client=self.translator_client,
            task=task,
            phase="entity-contract-repair",
            messages=messages,
            response=response,
            parser=lambda content: parse_repair_rewrite(
                content,
                expected_entity_id=task.entity_id,
            ),
        )

    async def translate_signature(
        self,
        task: TranslationTask,
        *,
        dependency_context: str = "",
        external_symbol_context: str = "",
    ) -> TranslatedSignature:
        messages = build_signature_translation_messages(
            task,
            dependency_context=dependency_context,
            external_symbol_context=external_symbol_context,
        )
        messages = self._with_critical_semantic_context(task, messages)
        response = await self._chat_translator_with_tools(
            task=task,
            messages=messages,
            phase="signature",
        )
        return await self._parse_with_protocol_retries(
            client=self.translator_client,
            task=task,
            phase="signature",
            messages=messages,
            response=response,
            parser=lambda content: parse_signature_translation(
                content,
                expected_entity_id=task.entity_id,
            ),
        )

    async def repair_compile_error(
        self,
        task: TranslationTask,
        *,
        current_rust: str,
        compile_result: CompileResult,
        checker_summary: CheckerSummary,
        repair_history: tuple[RepairAttempt, ...],
        dependency_context: str = "",
        external_symbol_context: str = "",
    ) -> TranslatedEntity:
        messages = build_repair_messages(
            task,
            current_rust=current_rust,
            compile_result=compile_result,
            checker_summary=checker_summary,
            repair_history=repair_history,
            dependency_context=dependency_context,
            external_symbol_context=external_symbol_context,
        )
        messages = self._with_critical_semantic_context(task, messages)
        response = await self._chat_translator_with_tools(
            task=task,
            messages=messages,
            phase="repair",
        )
        return await self._parse_with_protocol_retries(
            client=self.translator_client,
            task=task,
            phase="repair",
            messages=messages,
            response=response,
            parser=lambda content: parse_repair_rewrite(
                content,
                expected_entity_id=task.entity_id,
            ),
        )

    async def _parse_with_protocol_retries(
        self,
        *,
        client: TranslationLLMClient,
        task: TranslationTask,
        phase: str,
        messages: list[dict[str, object]],
        response: LLMResponse,
        parser: Callable[[str], _ParsedResponse],
    ) -> _ParsedResponse:
        conversation = list(messages)
        current_response = response
        parse_errors: list[str] = []
        dump_paths: list[Path] = []

        for parse_attempt in range(self.max_parse_retries + 1):
            try:
                return parser(current_response.content)
            except ResponseParseError as exc:
                parse_errors.append(str(exc))
                dump_path = self._dump_raw_response(
                    task=task,
                    phase=phase,
                    parse_attempt=parse_attempt,
                    raw_response=current_response.content,
                )
                if dump_path is not None:
                    dump_paths.append(dump_path)
                if parse_attempt >= self.max_parse_retries:
                    detail = (
                        f"entity {task.entity_id} phase {phase} response protocol "
                        f"failed after {len(parse_errors)} parse attempts; "
                        + " | ".join(
                            f"attempt {index}: {error}"
                            for index, error in enumerate(parse_errors, start=1)
                        )
                        + "; raw response excerpt: "
                        + _response_excerpt(current_response.content)
                    )
                    if dump_paths:
                        detail += "; raw responses dumped to " + ", ".join(
                            str(path) for path in dump_paths
                        )
                    raise ResponseParseError(detail) from exc

                conversation.extend(
                    [
                        {
                            "role": "assistant",
                            "content": current_response.content,
                        },
                        build_protocol_correction_message(str(exc)),
                    ]
                )
                current_response = await self._chat_with_trace(
                    client=client,
                    task=task,
                    phase=phase,
                    round_label=f"parse-retry-{parse_attempt + 1}",
                    messages=conversation,
                )

        raise AssertionError("protocol retry loop exited unexpectedly")

    async def _chat_translator_with_tools(
        self,
        *,
        task: TranslationTask,
        messages: list[dict[str, object]],
        phase: str,
    ) -> LLMResponse:
        tools = self._tools_for_task(task)
        if not tools:
            return await self._chat_with_trace(
                client=self.translator_client,
                task=task,
                phase=phase,
                round_label="0",
                messages=messages,
            )

        conversation = list(messages)
        round_idx = 0
        while self.max_tool_rounds is None or round_idx <= self.max_tool_rounds:
            response = await self._chat_with_trace(
                client=self.translator_client,
                task=task,
                phase=phase,
                round_label=str(round_idx),
                messages=conversation,
                tools=tools,
            )
            if not response.tool_calls:
                return response

            conversation.append(
                {
                    "role": "assistant",
                    "content": response.content,
                    "tool_calls": [
                        self._tool_call_message(tool_call)
                        for tool_call in response.tool_calls
                    ],
                }
            )
            for tool_call in response.tool_calls:
                conversation.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.call_id,
                        "content": self._execute_tool_call(task, tool_call),
                    }
                )
            round_idx += 1

        raise RuntimeError(
            f"translation agent exceeded tool round limit "
            f"for entity {task.entity_id}"
        )

    def _tools_for_task(self, task: TranslationTask) -> list[JsonDict]:
        tools: list[JsonDict] = []
        if self.semantic_hint_tool is not None and task.package.hint_anchor_ids:
            tools.append(GET_SEMANTIC_HINT_TOOL)
        if self.project_inspection_tool is not None:
            tools.append(GET_PROJECT_CONTEXT_TOOL)
            tools.append(INSPECT_POINTER_USAGE_TOOL)
            tools.append(INSPECT_RUST_CRATE_API_TOOL)
        return tools

    def _with_critical_semantic_context(
        self,
        task: TranslationTask,
        messages: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        if self.semantic_hint_tool is None:
            return messages
        context = self.semantic_hint_tool.critical_context_for_task(task)
        if not context:
            return messages

        result = [dict(message) for message in messages]
        system_message = result[0]
        system_message["content"] = (
            f"{system_message.get('content', '')}\n\n{context}"
        )
        return result

    @staticmethod
    def _tool_call_message(tool_call: ToolCall) -> JsonDict:
        return {
            "id": tool_call.call_id,
            "type": "function",
            "function": {
                "name": tool_call.name,
                "arguments": tool_call.arguments,
            },
        }

    async def _chat_with_trace(
        self,
        *,
        client: TranslationLLMClient,
        task: TranslationTask,
        phase: str,
        round_label: str,
        messages: list[dict[str, object]],
        tools: list[JsonDict] | None = None,
    ) -> LLMResponse:
        tool_list = tools or []
        response = await client.chat(messages=messages, tools=tool_list)
        self._record_token_usage(task=task, phase=phase, response=response)
        self._dump_llm_call_trace(
            task=task,
            phase=phase,
            round_label=round_label,
            messages=messages,
            tools=tool_list,
            response=response,
        )
        return response

    def _record_token_usage(
        self,
        *,
        task: TranslationTask,
        phase: str,
        response: LLMResponse,
    ) -> None:
        usage = response.token_usage
        reported = any(
            value > 0
            for value in (
                usage.prompt_tokens,
                usage.completion_tokens,
                usage.total_tokens,
            )
        )
        total_tokens = usage.total_tokens or (
            usage.prompt_tokens + usage.completion_tokens
        )
        self._token_usage_records.append(
            {
                "entity_id": task.entity_id,
                "phase": phase,
                "model": response.model,
                "reported": reported,
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": total_tokens,
            }
        )

    def _dump_llm_call_trace(
        self,
        *,
        task: TranslationTask,
        phase: str,
        round_label: str,
        messages: list[dict[str, object]],
        tools: list[JsonDict],
        response: LLMResponse,
    ) -> Path | None:
        if self.debug_dir is None:
            return None
        context_ref, replacements = self._ensure_trace_context(task)
        trace_dir = self.debug_dir / "llm-calls"
        trace_dir.mkdir(parents=True, exist_ok=True)
        self._llm_trace_counter += 1
        path = trace_dir / f"entity_{task.entity_id}.txt"
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                "\n\n" if path.stat().st_size > 0 else ""
            )
            handle.write(
                _llm_call_trace_text(
                    entity_id=task.entity_id,
                    call_index=self._llm_trace_counter,
                    phase=phase,
                    round_label=round_label,
                    messages=messages,
                    tools=tools,
                    response=response,
                    context_ref=context_ref,
                    replacements=replacements,
                )
            )
        return path

    def _ensure_trace_context(
        self,
        task: TranslationTask,
    ) -> tuple[str, tuple[tuple[str, str], ...]]:
        if self.debug_dir is None:
            return "", ()
        source = task.package.annotated_c_source.rstrip()
        comments = human_comment_context_text(task)
        if comments == "(none)":
            comments = ""
        identity = json.dumps(
            [task.entity_id, source, comments],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        source_token = f"<<C2SAFETY_ENTITY_{task.entity_id}_SOURCE_{digest}>>"
        comments_token = (
            f"<<C2SAFETY_ENTITY_{task.entity_id}_COMMENTS_{digest}>>"
        )
        context_dir = self.debug_dir / "contexts"
        context_dir.mkdir(parents=True, exist_ok=True)
        path = context_dir / f"entity_{task.entity_id}_{digest}.txt"
        if not path.exists():
            parts = [
                f"source_token: {source_token}",
                "",
                source,
            ]
            if comments:
                parts.extend(
                    [
                        "",
                        f"comments_token: {comments_token}",
                        "",
                        comments,
                    ]
                )
            path.write_text("\n".join(parts).rstrip() + "\n", encoding="utf-8")
        replacements: list[tuple[str, str]] = []
        if source:
            replacements.append((source, source_token))
        if comments:
            replacements.append((comments, comments_token))
        return path.relative_to(self.debug_dir).as_posix(), tuple(replacements)

    def _dump_raw_response(
        self,
        *,
        task: TranslationTask,
        phase: str,
        parse_attempt: int,
        raw_response: str,
    ) -> Path | None:
        if self.debug_dir is None:
            return None
        self.debug_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        path = self.debug_dir / (
            f"entity_{task.entity_id}_{_safe_trace_name(phase)}_parse_error_"
            f"attempt_{parse_attempt}_{timestamp}.txt"
        )
        path.write_text(raw_response, encoding="utf-8")
        return path

    def _execute_tool_call(
        self,
        task: TranslationTask,
        tool_call: ToolCall,
    ) -> str:
        if tool_call.name == "get_semantic_hint":
            self._tool_calls_by_entity[task.entity_id] = (
                self._tool_calls_by_entity.get(task.entity_id, 0) + 1
            )
            if self.semantic_hint_tool is None:
                return json.dumps(
                    {
                        "ok": False,
                        "error": "semantic hint tool is not configured",
                    },
                    ensure_ascii=False,
                )
            return self.semantic_hint_tool.execute_for_task(
                task,
                tool_call.arguments,
            )
        if tool_call.name in {
            "get_project_context",
            "inspect_pointer_usage",
            "inspect_rust_crate_api",
        }:
            self._tool_calls_by_entity[task.entity_id] = (
                self._tool_calls_by_entity.get(task.entity_id, 0) + 1
            )
            if self.project_inspection_tool is None:
                return json.dumps(
                    {
                        "ok": False,
                        "error": "project inspection tool is not configured",
                    },
                    ensure_ascii=False,
                )
            return self.project_inspection_tool.execute_for_task(
                task,
                tool_call.name,
                tool_call.arguments,
            )
        return json.dumps(
            {
                "ok": False,
                "error": f"unsupported tool: {tool_call.name}",
            },
            ensure_ascii=False,
        )


def _summarize_token_usage(
    records: list[JsonDict],
    *,
    include_entities: bool,
) -> JsonDict:
    summary = _token_usage_bucket(records)
    summary["by_phase"] = _group_token_usage(records, "phase")
    summary["by_model"] = _group_token_usage(records, "model")
    if include_entities:
        summary["by_entity"] = _group_token_usage(records, "entity_id")
    return summary


def _group_token_usage(records: list[JsonDict], key: str) -> JsonDict:
    groups: dict[str, list[JsonDict]] = {}
    for record in records:
        groups.setdefault(str(record[key]), []).append(record)
    return {
        name: _token_usage_bucket(group)
        for name, group in sorted(groups.items())
    }


def _token_usage_bucket(records: list[JsonDict]) -> JsonDict:
    reported_calls = sum(bool(record["reported"]) for record in records)
    return {
        "calls": len(records),
        "reported_calls": reported_calls,
        "unreported_calls": len(records) - reported_calls,
        "prompt_tokens": sum(int(record["prompt_tokens"]) for record in records),
        "completion_tokens": sum(
            int(record["completion_tokens"]) for record in records
        ),
        "total_tokens": sum(int(record["total_tokens"]) for record in records),
    }


def _response_excerpt(raw_response: str, *, limit: int = 500) -> str:
    if not raw_response:
        return "<empty>"
    text = raw_response.replace("\r", "\\r").replace("\n", "\\n")
    if len(text) > limit:
        text = f"{text[:limit]}..."
    return repr(text)


def _llm_call_trace_text(
    *,
    entity_id: int,
    call_index: int,
    phase: str,
    round_label: str,
    messages: list[dict[str, object]],
    tools: list[JsonDict],
    response: LLMResponse,
    context_ref: str = "",
    replacements: tuple[tuple[str, str], ...] = (),
) -> str:
    parts: list[str] = [
        f"===== LLM CALL {call_index} phase={phase} round={round_label} =====",
        f"entity_id: {entity_id}",
        f"context_ref: {context_ref or '(none)'}",
        "",
        "===== REQUEST =====",
        _messages_text(messages, replacements=replacements),
    ]
    if tools:
        parts.extend(("", "tools:", json.dumps(tools, ensure_ascii=False, indent=2)))
    parts.extend(
        [
            "",
            "===== RESPONSE =====",
            response.content or "",
        ]
    )
    if response.tool_calls:
        parts.extend(("", "tool_calls:", _tool_calls_text(response.tool_calls)))
    return "\n".join(parts).rstrip() + "\n"


def _messages_text(
    messages: list[dict[str, object]],
    *,
    replacements: tuple[tuple[str, str], ...] = (),
) -> str:
    chunks: list[str] = []
    for index, message in enumerate(messages, start=1):
        role = message.get("role", "<unknown>")
        chunks.append(f"--- message {index} role={role} ---")
        content = message.get("content", "")
        if isinstance(content, str):
            for original, token in replacements:
                content = content.replace(original, token)
            chunks.append(content)
        else:
            chunks.append(repr(content))
        if "tool_calls" in message:
            chunks.append("tool_calls:")
            chunks.append(
                json.dumps(message["tool_calls"], ensure_ascii=False, indent=2)
            )
        if "tool_call_id" in message:
            chunks.append(f"tool_call_id: {message['tool_call_id']}")
    return "\n".join(chunks)


def _tool_calls_text(tool_calls: tuple[ToolCall, ...]) -> str:
    chunks: list[str] = []
    for index, tool_call in enumerate(tool_calls, start=1):
        chunks.extend(
            [
                f"--- tool_call {index} ---",
                f"name: {tool_call.name}",
                f"arguments: {tool_call.arguments}",
            ]
        )
    return "\n".join(chunks)


def _safe_trace_name(value: str) -> str:
    safe = "".join(
        char if char.isalnum() or char in {"-", "_"} else "_"
        for char in str(value)
    )
    return safe or "unknown"
