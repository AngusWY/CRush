from __future__ import annotations

import dataclasses
import json
import math
import re
import time
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from .analysis_context import AnalysisContext, AnalysisContextError
from .models import (
    PointerAnalysisResult,
    PointerTarget,
    UnsafeStmtAnalysisResult,
    UnsafeStmtTarget,
    VariableAnalysisResult,
    VariableTarget,
)
from .declaration_analysis import (
    DeclarationAnalyzer,
    PointerAnalysisError,
    VariableAnalysisError,
)
from .declaration_target_collector import (
    DeclarationTargetCollector,
    PointerTargetCollectionError,
    VariableTargetCollectionError,
)
from .unsafe_stmt_analysis import (
    UnsafeStmtAnalysisError,
    UnsafeStmtProgrammaticAnalyzer,
)
from .unsafe_stmt_target_collector import (
    UnsafeStmtTargetCollectionError,
    UnsafeStmtTargetCollector,
)
from .function_return_analysis import (
    FunctionReturnAnalysisError,
    FunctionReturnAnalysisResult,
    FunctionReturnAnalyzer,
)
from .external_type_analysis import (
    ExternalTypeAnalysisError,
    ExternalTypeAnalysisResult,
    ExternalTypeAnalyzer,
)
from .callback_interface_analysis import (
    CallbackInterfaceAnalysisError,
    CallbackInterfaceAnalysisResult,
    CallbackInterfaceAnalyzer,
)


SEMANTIC_ANALYSIS_DIR_NAME = "semantic_analysis"
POINTER_SEMANTICS_FILE_NAME = "pointer-semantics.json"
VARIABLE_SEMANTICS_FILE_NAME = "variable-semantics.json"
UNSAFE_STMT_SEMANTICS_FILE_NAME = "unsafe-stmt-semantics.json"
FUNCTION_RETURN_SEMANTICS_FILE_NAME = "function-return-semantics.json"
EXTERNAL_TYPE_SEMANTICS_FILE_NAME = "external-type-semantics.json"
CALLBACK_INTERFACE_SEMANTICS_FILE_NAME = "callback-interface-semantics.json"
AGENT_REQUIRED_ENTITIES_FILE_NAME = "agent-required-entities.json"
TRANSLATION_ENTITIES_FILE_NAME = "translation-entities.json"
_ANALYZING_PROGRESS_RE = re.compile(r"\banalyzing .+? (\d+)/(\d+):")


class SemanticAnalysisPipelineError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class SemanticAnalysisPipelineResult:


    pointer_target_count: int
    pointer_result_count: int
    pointer_semantics_path: Path
    variable_target_count: int
    variable_result_count: int
    variable_semantics_path: Path
    unsafe_stmt_target_count: int
    unsafe_stmt_result_count: int
    unsafe_stmt_semantics_path: Path
    function_return_result_count: int
    function_return_semantics_path: Path
    external_type_count: int
    external_type_semantics_path: Path
    callback_interface_count: int
    callback_interface_semantics_path: Path
    agent_required_entity_count: int
    agent_required_entities_path: Path


@dataclasses.dataclass(frozen=True)
class _DeclarationAnalysisResult:
    pointer_targets: tuple[PointerTarget, ...]
    pointer_results: tuple[PointerAnalysisResult, ...]
    variable_targets: tuple[VariableTarget, ...]
    variable_results: tuple[VariableAnalysisResult, ...]


class SemanticAnalysisPipeline:


    def __init__(
        self,
        *,
        loader: Any,
        workspace: Path,
        debug: bool = False,
        emit: Callable[[str], None] | None = None,
    ) -> None:
        self.loader = loader
        self.workspace = workspace.resolve()
        self.debug = debug
        self._emit = (
            emit
            if emit is not None
            else lambda message: print(message, flush=True)
        )
        self._progress_emit_interval_seconds = 1.0
        self._last_progress_emit_at = 0.0
        self.translation_entities_path = (
            self.workspace / TRANSLATION_ENTITIES_FILE_NAME
        )
        self.semantic_analysis_dir = (
            self.workspace / SEMANTIC_ANALYSIS_DIR_NAME
        )
        self.pointer_semantics_path = (
            self.semantic_analysis_dir / POINTER_SEMANTICS_FILE_NAME
        )
        self.variable_semantics_path = (
            self.semantic_analysis_dir / VARIABLE_SEMANTICS_FILE_NAME
        )
        self.unsafe_stmt_semantics_path = (
            self.semantic_analysis_dir / UNSAFE_STMT_SEMANTICS_FILE_NAME
        )
        self.function_return_semantics_path = (
            self.semantic_analysis_dir / FUNCTION_RETURN_SEMANTICS_FILE_NAME
        )
        self.external_type_semantics_path = (
            self.semantic_analysis_dir / EXTERNAL_TYPE_SEMANTICS_FILE_NAME
        )
        self.callback_interface_semantics_path = (
            self.semantic_analysis_dir / CALLBACK_INTERFACE_SEMANTICS_FILE_NAME
        )
        self.agent_required_entities_path = (
            self.semantic_analysis_dir / AGENT_REQUIRED_ENTITIES_FILE_NAME
        )

    def run(self) -> SemanticAnalysisPipelineResult:


        started_at = time.perf_counter()
        self._debug("starting programmatic semantic analysis")
        self._debug(f"workspace: {self.workspace}")
        self._validate_inputs()
        context = AnalysisContext(self.loader)

        try:
            stage_started_at = time.perf_counter()
            declaration_result = self._run_declaration_analysis(
                context
            )
            self._debug(
                "declaration analysis collected "
                f"{len(declaration_result.pointer_targets)} pointer targets "
                f"and {len(declaration_result.variable_targets)} variable targets "
                f"in {self._elapsed(stage_started_at)}"
            )
            self._debug_counter(
                "pointer targets by location",
                Counter(
                    target.location.value
                    for target in declaration_result.pointer_targets
                ),
            )
            self._debug_counter(
                "variable targets by location",
                Counter(
                    target.location.value
                    for target in declaration_result.variable_targets
                ),
            )
            ordered_pointer_results = self._validate_pointer_results(
                declaration_result.pointer_targets,
                declaration_result.pointer_results,
            )
            ordered_variable_results = self._validate_variable_results(
                declaration_result.variable_targets,
                declaration_result.variable_results,
            )
            self._debug_missing_fields(
                "pointer missing fields",
                (
                    field
                    for result in ordered_pointer_results
                    for field in result.semantics.missing_fields()
                ),
            )
            self._debug_missing_fields(
                "variable missing fields",
                (
                    field
                    for result in ordered_variable_results
                    for field in result.semantics.missing_fields()
                ),
            )
            stage_started_at = time.perf_counter()
            unsafe_stmt_targets, unsafe_stmt_results = (
                self._run_unsafe_stmt_analysis(
                    context,
                    ordered_pointer_results,
                )
            )
            self._debug(
                "unsafe stmt analysis collected "
                f"{len(unsafe_stmt_targets)} targets in "
                f"{self._elapsed(stage_started_at)}"
            )
            self._debug_counter(
                "unsafe stmt targets by operation",
                Counter(target.operation.value for target in unsafe_stmt_targets),
            )
            ordered_unsafe_stmt_results = self._validate_unsafe_stmt_results(
                unsafe_stmt_targets, unsafe_stmt_results
            )
            self._debug_counter(
                "unsafe stmt results by semantic kind",
                Counter(
                    result.semantics.semantic_kind.value
                    for result in ordered_unsafe_stmt_results
                ),
            )
            self._debug_missing_fields(
                "unsafe stmt missing fields",
                (
                    field
                    for result in ordered_unsafe_stmt_results
                    for field in result.semantics.missing_fields()
                ),
            )
            stage_started_at = time.perf_counter()
            function_return_results = FunctionReturnAnalyzer(
                context,
                translation_entities_path=self.translation_entities_path,
            ).analyze_all()
            external_type_result = ExternalTypeAnalyzer(
                context,
                translation_entities_path=self.translation_entities_path,
            ).analyze()
            callback_interface_result = CallbackInterfaceAnalyzer(
                context,
                translation_entities_path=self.translation_entities_path,
            ).analyze()
            self._debug(
                "function return analysis collected "
                f"{len(function_return_results)} pointer-returning functions "
                f"in {self._elapsed(stage_started_at)}"
            )
            agent_required_entity_ids = (
                self._collect_pointer_agent_required_entity_ids(
                    ordered_pointer_results
                )
                | self._collect_variable_agent_required_entity_ids(
                    ordered_variable_results
                )
                | self._collect_unsafe_stmt_agent_required_entity_ids(
                    ordered_unsafe_stmt_results
                )
            )
            self._debug(
                "agent-required entities: "
                f"{len(agent_required_entity_ids)} "
                f"{sorted(agent_required_entity_ids)}"
            )
            self._write_pointer_results(ordered_pointer_results)
            self._debug(f"wrote pointer semantics: {self.pointer_semantics_path}")
            self._write_variable_results(ordered_variable_results)
            self._debug(f"wrote variable semantics: {self.variable_semantics_path}")
            self._write_unsafe_stmt_results(ordered_unsafe_stmt_results)
            self._debug(
                "wrote unsafe stmt semantics: "
                f"{self.unsafe_stmt_semantics_path}"
            )
            self._write_function_return_results(function_return_results)
            self._debug(
                "wrote function return semantics: "
                f"{self.function_return_semantics_path}"
            )
            self._write_external_type_results(external_type_result)
            self._debug(
                "wrote external type semantics: "
                f"{self.external_type_semantics_path}"
            )
            self._write_callback_interface_results(callback_interface_result)
            self._debug(
                "wrote callback interface semantics: "
                f"{self.callback_interface_semantics_path}"
            )
            self._write_agent_required_entities(
                agent_required_entity_ids
            )
            self._debug(
                "wrote agent-required entities: "
                f"{self.agent_required_entities_path}"
            )
        except (
            AnalysisContextError,
            PointerTargetCollectionError,
            PointerAnalysisError,
            VariableTargetCollectionError,
            VariableAnalysisError,
            UnsafeStmtTargetCollectionError,
            UnsafeStmtAnalysisError,
            FunctionReturnAnalysisError,
            ExternalTypeAnalysisError,
            CallbackInterfaceAnalysisError,
        ) as exc:
            raise SemanticAnalysisPipelineError(
                f"semantic analysis failed: {exc}"
            ) from exc

        self._debug(
            "programmatic semantic analysis completed in "
            f"{self._elapsed(started_at)}"
        )
        return SemanticAnalysisPipelineResult(
            pointer_target_count=len(declaration_result.pointer_targets),
            pointer_result_count=len(ordered_pointer_results),
            pointer_semantics_path=self.pointer_semantics_path,
            variable_target_count=len(declaration_result.variable_targets),
            variable_result_count=len(ordered_variable_results),
            variable_semantics_path=self.variable_semantics_path,
            unsafe_stmt_target_count=len(unsafe_stmt_targets),
            unsafe_stmt_result_count=len(ordered_unsafe_stmt_results),
            unsafe_stmt_semantics_path=self.unsafe_stmt_semantics_path,
            function_return_result_count=len(function_return_results),
            function_return_semantics_path=self.function_return_semantics_path,
            external_type_count=len(external_type_result.external_types),
            external_type_semantics_path=self.external_type_semantics_path,
            callback_interface_count=len(callback_interface_result.interfaces),
            callback_interface_semantics_path=self.callback_interface_semantics_path,
            agent_required_entity_count=len(agent_required_entity_ids),
            agent_required_entities_path=self.agent_required_entities_path,
        )

    def _validate_inputs(self) -> None:
        if self.loader is None:
            raise SemanticAnalysisPipelineError(
                "Lian loader must not be None"
            )
        if not self.workspace.is_dir():
            raise SemanticAnalysisPipelineError(
                f"workspace directory does not exist: {self.workspace}"
            )
        if not self.translation_entities_path.is_file():
            raise SemanticAnalysisPipelineError(
                "translation entities file does not exist: "
                f"{self.translation_entities_path}"
            )

    def _run_declaration_analysis(
        self,
        context: AnalysisContext,
    ) -> _DeclarationAnalysisResult:
        collector = DeclarationTargetCollector(
            context=context,
            translation_entities_path=self.translation_entities_path,
        )
        analyzer = DeclarationAnalyzer(context, progress=self._debug)
        pointer_targets = collector.collect_pointer_targets()
        variable_targets = collector.collect_variable_targets()
        return _DeclarationAnalysisResult(
            pointer_targets=pointer_targets,
            pointer_results=analyzer.analyze_pointers(pointer_targets),
            variable_targets=variable_targets,
            variable_results=analyzer.analyze_variables(variable_targets),
        )

    def _run_unsafe_stmt_analysis(
        self,
        context: AnalysisContext,
        pointer_results: tuple[PointerAnalysisResult, ...],
    ) -> tuple[
        tuple[UnsafeStmtTarget, ...],
        tuple[UnsafeStmtAnalysisResult, ...],
    ]:
        collector = UnsafeStmtTargetCollector(
            context=context,
            translation_entities_path=self.translation_entities_path,
        )
        targets = collector.collect()
        results = UnsafeStmtProgrammaticAnalyzer(
            context,
            pointer_results=pointer_results,
            progress=self._debug,
        ).analyze_all(targets)
        return targets, results

    def _validate_pointer_results(
        self,
        targets: tuple[PointerTarget, ...],
        results: tuple[PointerAnalysisResult, ...],
    ) -> tuple[PointerAnalysisResult, ...]:
        if len(targets) != len(results):
            raise SemanticAnalysisPipelineError(
                "pointer target/result count mismatch: "
                f"{len(targets)} targets, {len(results)} results"
            )

        targets_by_id: dict[int, PointerTarget] = {}
        for target in targets:
            if target.stmt_id in targets_by_id:
                raise SemanticAnalysisPipelineError(
                    f"duplicate pointer target stmt_id: {target.stmt_id}"
                )
            targets_by_id[target.stmt_id] = target

        results_by_id: dict[int, PointerAnalysisResult] = {}
        for result in results:
            result_id = result.semantics.stmt_id
            if result_id in results_by_id:
                raise SemanticAnalysisPipelineError(
                    f"duplicate pointer result stmt_id: {result_id}"
                )

            matching_target = targets_by_id.get(result_id)
            if matching_target is None:
                raise SemanticAnalysisPipelineError(
                    f"pointer result {result_id} has no matching target"
                )
            self._validate_pointer_result(matching_target, result)
            results_by_id[result_id] = result

        missing_ids = sorted(set(targets_by_id) - set(results_by_id))
        if missing_ids:
            raise SemanticAnalysisPipelineError(
                f"pointer targets have no analysis result: {missing_ids}"
            )

        return tuple(
            sorted(
                results,
                key=lambda result: (
                    result.target.unit_id,
                    result.target.stmt_id,
                ),
            )
        )

    @staticmethod
    def _validate_pointer_result(
        target: PointerTarget,
        result: PointerAnalysisResult,
    ) -> None:
        semantics = result.semantics
        if result.target != target:
            raise SemanticAnalysisPipelineError(
                f"pointer result target mismatch for stmt {target.stmt_id}"
            )
        if semantics.stmt_id != target.stmt_id:
            raise SemanticAnalysisPipelineError(
                f"pointer result stmt_id mismatch for {target.stmt_id}"
            )
        if semantics.name != target.name:
            raise SemanticAnalysisPipelineError(
                f"pointer result name mismatch for stmt {target.stmt_id}: "
                f"{semantics.name!r} != {target.name!r}"
            )
        if semantics.operation is not target.operation:
            raise SemanticAnalysisPipelineError(
                f"pointer result operation mismatch for stmt {target.stmt_id}"
            )
        if semantics.is_struct_member != target.is_aggregate_member:
            raise SemanticAnalysisPipelineError(
                "pointer result aggregate-member flag mismatch for stmt "
                f"{target.stmt_id}"
            )
        if target.source is None:
            raise SemanticAnalysisPipelineError(
                f"pointer target {target.stmt_id} has no original source range"
            )

    def _validate_variable_results(
        self,
        targets: tuple[VariableTarget, ...],
        results: tuple[VariableAnalysisResult, ...],
    ) -> tuple[VariableAnalysisResult, ...]:
        if len(targets) != len(results):
            raise SemanticAnalysisPipelineError(
                "variable target/result count mismatch: "
                f"{len(targets)} targets, {len(results)} results"
            )

        targets_by_id: dict[int, VariableTarget] = {}
        for target in targets:
            if target.stmt_id in targets_by_id:
                raise SemanticAnalysisPipelineError(
                    f"duplicate variable target stmt_id: {target.stmt_id}"
                )
            targets_by_id[target.stmt_id] = target

        results_by_id: dict[int, VariableAnalysisResult] = {}
        for result in results:
            result_id = result.semantics.stmt_id
            if result_id in results_by_id:
                raise SemanticAnalysisPipelineError(
                    f"duplicate variable result stmt_id: {result_id}"
                )

            matching_target = targets_by_id.get(result_id)
            if matching_target is None:
                raise SemanticAnalysisPipelineError(
                    f"variable result {result_id} has no matching target"
                )
            self._validate_variable_result(matching_target, result)
            results_by_id[result_id] = result

        missing_ids = sorted(set(targets_by_id) - set(results_by_id))
        if missing_ids:
            raise SemanticAnalysisPipelineError(
                f"variable targets have no analysis result: {missing_ids}"
            )

        return tuple(
            sorted(
                results,
                key=lambda result: (
                    result.target.unit_id,
                    result.target.stmt_id,
                ),
            )
        )

    @staticmethod
    def _validate_variable_result(
        target: VariableTarget,
        result: VariableAnalysisResult,
    ) -> None:
        semantics = result.semantics
        if result.target != target:
            raise SemanticAnalysisPipelineError(
                f"variable result target mismatch for stmt {target.stmt_id}"
            )
        if semantics.stmt_id != target.stmt_id:
            raise SemanticAnalysisPipelineError(
                f"variable result stmt_id mismatch for {target.stmt_id}"
            )
        if semantics.name != target.name:
            raise SemanticAnalysisPipelineError(
                f"variable result name mismatch for stmt {target.stmt_id}: "
                f"{semantics.name!r} != {target.name!r}"
            )
        if semantics.operation is not target.operation:
            raise SemanticAnalysisPipelineError(
                f"variable result operation mismatch for stmt {target.stmt_id}"
            )
        if semantics.is_struct_member != target.is_aggregate_member:
            raise SemanticAnalysisPipelineError(
                "variable result aggregate-member flag mismatch for stmt "
                f"{target.stmt_id}"
            )
        if target.source is None:
            raise SemanticAnalysisPipelineError(
                f"variable target {target.stmt_id} has no original source range"
            )

    def _validate_unsafe_stmt_results(
        self,
        targets: tuple[UnsafeStmtTarget, ...],
        results: tuple[UnsafeStmtAnalysisResult, ...],
    ) -> tuple[UnsafeStmtAnalysisResult, ...]:
        if len(targets) != len(results):
            raise SemanticAnalysisPipelineError(
                "unsafe stmt target/result count mismatch: "
                f"{len(targets)} targets, {len(results)} results"
            )

        targets_by_id: dict[int, UnsafeStmtTarget] = {}
        for target in targets:
            if target.stmt_id in targets_by_id:
                raise SemanticAnalysisPipelineError(
                    f"duplicate unsafe stmt target stmt_id: {target.stmt_id}"
                )
            targets_by_id[target.stmt_id] = target

        results_by_id: dict[int, UnsafeStmtAnalysisResult] = {}
        for result in results:
            result_id = result.semantics.stmt_id
            if result_id in results_by_id:
                raise SemanticAnalysisPipelineError(
                    f"duplicate unsafe stmt result stmt_id: {result_id}"
                )

            matching_target = targets_by_id.get(result_id)
            if matching_target is None:
                raise SemanticAnalysisPipelineError(
                    f"unsafe stmt result {result_id} has no matching target"
                )
            self._validate_unsafe_stmt_result(matching_target, result)
            results_by_id[result_id] = result

        missing_ids = sorted(set(targets_by_id) - set(results_by_id))
        if missing_ids:
            raise SemanticAnalysisPipelineError(
                f"unsafe stmt targets have no analysis result: {missing_ids}"
            )

        return tuple(
            sorted(
                results,
                key=lambda result: (
                    result.target.unit_id,
                    result.target.stmt_id,
                ),
            )
        )

    @staticmethod
    def _validate_unsafe_stmt_result(
        target: UnsafeStmtTarget,
        result: UnsafeStmtAnalysisResult,
    ) -> None:
        semantics = result.semantics
        if result.target != target:
            raise SemanticAnalysisPipelineError(
                f"unsafe stmt result target mismatch for stmt {target.stmt_id}"
            )
        if semantics.stmt_id != target.stmt_id:
            raise SemanticAnalysisPipelineError(
                f"unsafe stmt result stmt_id mismatch for {target.stmt_id}"
            )
        if semantics.entity_id != target.entity_id:
            raise SemanticAnalysisPipelineError(
                f"unsafe stmt result entity_id mismatch for {target.stmt_id}"
            )
        if semantics.operation is not target.operation:
            raise SemanticAnalysisPipelineError(
                f"unsafe stmt result operation mismatch for {target.stmt_id}"
            )

    def _write_pointer_results(
        self,
        results: tuple[PointerAnalysisResult, ...],
    ) -> None:
        payload = self._pointer_results_payload(results)
        self._debug(
            "pointer semantic records written: "
            f"{len(payload.get('pointers', []))}/{len(results)}"
        )
        temporary_path = self.pointer_semantics_path.with_suffix(
            self.pointer_semantics_path.suffix + ".tmp"
        )

        try:
            self.semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.pointer_semantics_path)
        except OSError as exc:
            raise SemanticAnalysisPipelineError(
                "failed to write pointer semantics "
                f"{self.pointer_semantics_path}: {exc}"
            ) from exc

    @staticmethod
    def _pointer_results_payload(
        results: tuple[PointerAnalysisResult, ...],
    ) -> dict[str, Any]:
        return {
            "version": 4,
            "kind": "pointer_declarations",
            "pointers": [
                {
                    "entity_id": result.target.entity_id,
                    "target": result.target.to_dict(),
                    **result.semantics.to_dict(),
                }
                for result in results
            ],
        }

    def _write_variable_results(
        self,
        results: tuple[VariableAnalysisResult, ...],
    ) -> None:
        payload = self._variable_results_payload(results)
        self._debug(
            "variable semantic records written: "
            f"{len(payload.get('variables', []))}/{len(results)}"
        )
        temporary_path = self.variable_semantics_path.with_suffix(
            self.variable_semantics_path.suffix + ".tmp"
        )

        try:
            self.semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.variable_semantics_path)
        except OSError as exc:
            raise SemanticAnalysisPipelineError(
                "failed to write variable semantics "
                f"{self.variable_semantics_path}: {exc}"
            ) from exc

    @staticmethod
    def _variable_results_payload(
        results: tuple[VariableAnalysisResult, ...],
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "kind": "variable_declarations",
            "variables": [
                {
                    "entity_id": result.target.entity_id,
                    "target": result.target.to_dict(),
                    **result.semantics.to_dict(),
                }
                for result in results
            ],
        }

    def _write_unsafe_stmt_results(
        self,
        results: tuple[UnsafeStmtAnalysisResult, ...],
    ) -> None:
        payload = self._unsafe_stmt_results_payload(results)
        self._debug(
            "unsafe stmt semantic records written: "
            f"{len(payload.get('unsafe_stmts', []))}/{len(results)}"
        )
        temporary_path = self.unsafe_stmt_semantics_path.with_suffix(
            self.unsafe_stmt_semantics_path.suffix + ".tmp"
        )

        try:
            self.semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.unsafe_stmt_semantics_path)
        except OSError as exc:
            raise SemanticAnalysisPipelineError(
                "failed to write unsafe stmt semantics "
                f"{self.unsafe_stmt_semantics_path}: {exc}"
            ) from exc

    def _write_function_return_results(
        self,
        results: tuple[FunctionReturnAnalysisResult, ...],
    ) -> None:
        payload = {
            "version": 1,
            "kind": "function_return_semantics",
            "functions": [result.to_dict() for result in results],
        }
        temporary_path = self.function_return_semantics_path.with_suffix(
            self.function_return_semantics_path.suffix + ".tmp"
        )
        try:
            self.semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.function_return_semantics_path)
        except OSError as exc:
            raise SemanticAnalysisPipelineError(
                "failed to write function return semantics "
                f"{self.function_return_semantics_path}: {exc}"
            ) from exc

    def _write_external_type_results(
        self,
        result: ExternalTypeAnalysisResult,
    ) -> None:
        payload = result.to_payload()
        temporary_path = self.external_type_semantics_path.with_suffix(
            self.external_type_semantics_path.suffix + ".tmp"
        )
        try:
            self.semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.external_type_semantics_path)
        except OSError as exc:
            raise SemanticAnalysisPipelineError(
                "failed to write external type semantics "
                f"{self.external_type_semantics_path}: {exc}"
            ) from exc

    def _write_callback_interface_results(
        self,
        result: CallbackInterfaceAnalysisResult,
    ) -> None:
        payload = result.to_payload()
        temporary_path = self.callback_interface_semantics_path.with_suffix(
            self.callback_interface_semantics_path.suffix + ".tmp"
        )
        try:
            self.semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.callback_interface_semantics_path)
        except OSError as exc:
            raise SemanticAnalysisPipelineError(
                "failed to write callback interface semantics "
                f"{self.callback_interface_semantics_path}: {exc}"
            ) from exc

    @staticmethod
    def _unsafe_stmt_results_payload(
        results: tuple[UnsafeStmtAnalysisResult, ...],
    ) -> dict[str, Any]:
        records = [
            record
            for result in results
            if (record := SemanticAnalysisPipeline._unsafe_stmt_result_record(result))
            is not None
        ]
        return {
            "version": 3,
            "kind": "unsafe_stmts",
            "unsafe_stmts": records,
        }

    @staticmethod
    def _unsafe_stmt_result_record(
        result: UnsafeStmtAnalysisResult,
    ) -> dict[str, Any] | None:
        semantics = result.semantics.to_dict()
        target = result.target.to_dict()
        target["semantic_kind"] = semantics["semantic_kind"]
        semantic_hints = SemanticAnalysisPipeline._compact_semantic_hints(
            semantics.get("semantic_hints", {})
        )
        agent_missing_fields = [
            str(field)
            for field in semantics.get("agent_missing_fields", [])
            if isinstance(field, str) and field
        ]
        if not semantic_hints and not agent_missing_fields:
            return None
        return {
            "entity_id": result.target.entity_id,
            "target": target,
            "stmt_id": result.target.stmt_id,
            "operation": semantics["operation"],
            "semantic_kind": semantics["semantic_kind"],
            "semantic_hints": semantic_hints,
            "agent_missing_fields": agent_missing_fields,
        }

    @staticmethod
    def _compact_semantic_hints(value: dict[str, Any]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in value.items():
            if item is None or item == [] or item == {}:
                continue
            if item == "unknown":
                continue
            if isinstance(item, float) and math.isnan(item):
                continue
            result[key] = item
        return result

    @staticmethod
    def _collect_pointer_agent_required_entity_ids(
        results: tuple[PointerAnalysisResult, ...],
    ) -> set[int]:
        return {
            result.target.entity_id
            for result in results
            if result.semantics.missing_fields()
        }

    @staticmethod
    def _collect_variable_agent_required_entity_ids(
        results: tuple[VariableAnalysisResult, ...],
    ) -> set[int]:
        return {
            result.target.entity_id
            for result in results
            if result.semantics.missing_fields()
        }

    @staticmethod
    def _collect_unsafe_stmt_agent_required_entity_ids(
        results: tuple[UnsafeStmtAnalysisResult, ...],
    ) -> set[int]:
        return {
            result.target.entity_id
            for result in results
            if result.semantics.missing_fields()
        }

    def _write_agent_required_entities(
        self,
        entity_ids: set[int],
    ) -> None:
        payload = {
            "version": 1,
            "entity_ids": sorted(entity_ids),
        }
        temporary_path = self.agent_required_entities_path.with_suffix(
            self.agent_required_entities_path.suffix + ".tmp"
        )

        try:
            self.semantic_analysis_dir.mkdir(parents=True, exist_ok=True)
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.agent_required_entities_path)
        except OSError as exc:
            raise SemanticAnalysisPipelineError(
                "failed to write Agent-required entity IDs "
                f"{self.agent_required_entities_path}: {exc}"
            ) from exc

    def _debug(self, message: str) -> None:
        if not self.debug:
            return
        if self._is_throttled_progress_message(message):
            return
        self._emit(f"[semantic] {message}")

    def _is_throttled_progress_message(self, message: str) -> bool:
        match = _ANALYZING_PROGRESS_RE.search(message)
        if match is None:
            return False
        index = int(match.group(1))
        total = int(match.group(2))
        if index <= 1 or index >= total:
            self._last_progress_emit_at = time.perf_counter()
            return False
        now = time.perf_counter()
        if now - self._last_progress_emit_at >= self._progress_emit_interval_seconds:
            self._last_progress_emit_at = now
            return False
        return True

    def _debug_counter(self, title: str, counter: Counter[str]) -> None:
        if not self.debug:
            return
        if not counter:
            self._debug(f"{title}: none")
            return
        items = ", ".join(
            f"{key}={count}" for key, count in sorted(counter.items())
        )
        self._debug(f"{title}: {items}")

    def _debug_missing_fields(self, title: str, fields: Any) -> None:
        counter = Counter(str(field) for field in fields)
        self._debug_counter(title, counter)

    @staticmethod
    def _elapsed(started_at: float) -> str:
        return f"{time.perf_counter() - started_at:.2f}s"
