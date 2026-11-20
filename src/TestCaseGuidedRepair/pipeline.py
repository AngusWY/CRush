from __future__ import annotations

import asyncio
import json
import re
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Callable

from .agent import (
    CorrectnessRepairAgent,
    build_agent_context,
    build_c_bridge_generation_context,
    build_c_interface_pairing_context,
    build_c_test_analysis_context,
)
from .cargo_runner import CargoExecutor, CargoRunner
from .models import (
    JsonDict,
    CTestInterface,
    CTestResult,
    InterfacePairing,
    RepairConfig,
    RepairRecord,
    RepairStatus,
    TestResult,
)
from .patch_manager import PatchManager
from .safety import SafetyChecker
from .state_store import StateStore
from .workspace import RepairWorkspace
from .source_tools import AgentRequestTimeout, AgentRuntimeError
from .c_diagnostics import c_failure_diagnostics
from .interface_catalog import load_entity_catalog


def _normalize_c_project_source(source: str) -> str:
    normalized = PurePosixPath(source.replace("\\", "/")).as_posix()
    for prefix in ("harness/c_project/", "c_project/"):
        if normalized.startswith(prefix):
            return normalized.removeprefix(prefix)
    return normalized


class CorrectnessRepairPipeline:


    def __init__(
        self,
        config: RepairConfig,
        *,
        agent: CorrectnessRepairAgent | None = None,
        cargo: CargoExecutor | None = None,
        safety: SafetyChecker | None = None,
        log: Callable[[str], None] | None = print,
    ) -> None:
        config.validate()
        self.config = config
        self.agent = agent
        self.cargo = cargo
        self.safety = safety or SafetyChecker()
        self._log = log
        self.records: list[RepairRecord] = []
        self._c_validation: JsonDict = {}
        self._c_attempts: list[JsonDict] = []
        self._c_interfaces: tuple[CTestInterface, ...] = ()
        self._c_pairings: tuple[InterfacePairing, ...] = ()
        self._c_bridge_stage = "interface_analysis"

    async def run(self) -> JsonDict:
        try:
            repair_workspace = RepairWorkspace.prepare(self.config)
        except Exception as exc:
            return self._preparation_failure(exc)
        store = StateStore(repair_workspace.root)
        patcher = PatchManager(repair_workspace)
        self._emit(f"prepared isolated run: {repair_workspace.root}")
        self._write_state(store, "prepared", repair_workspace)

        if self.config.prepare_only:
            return self._finish(
                store,
                repair_workspace,
                RepairStatus.PREPARED,
                "isolated projects prepared",
            )

        try:
            self.cargo = self.cargo or CargoRunner()
        except OSError as exc:
            return self._finish(store, repair_workspace, RepairStatus.ENVIRONMENT_ERROR,
                                str(exc), validation={"environment_error": str(exc)})

        if self.config.test_mode == "c":
            return await self._run_c_test(repair_workspace, patcher, store)

        validation = self._validate_compile_and_discovery(repair_workspace)
        if not _bridge_ready(validation):
            if self.agent is None:
                return self._finish(
                    store,
                    repair_workspace,
                    RepairStatus.BRIDGE_FAILED,
                    "bridge is not ready and no repair agent was configured",
                    validation=validation,
                )
            validation = await self._bridge_loop(
                repair_workspace, patcher, store, validation
            )
            if not _bridge_ready(validation):
                if validation.get("terminal_agent_error"):
                    return self._finish(
                        store,
                        repair_workspace,
                        (
                            RepairStatus.TIMEOUT
                            if validation.get("llm_timeout")
                            else RepairStatus.AGENT_ERROR
                        ),
                        validation["agent_error"],
                        validation=validation,
                    )
                status = _failure_status(validation, RepairStatus.BRIDGE_FAILED)
                return self._finish(
                    store,
                    repair_workspace,
                    status,
                    "bridge repair budget exhausted",
                    validation=validation,
                )

        test_results = self._run_tests(repair_workspace)
        if _tests_pass(test_results):
            final_validation = {**validation, "tests": _test_json(test_results)}
            return self._finish(
                store,
                repair_workspace,
                RepairStatus.PASSED,
                "all selected tests passed",
                validation=final_validation,
            )
        if self.agent is None:
            return self._finish(
                store,
                repair_workspace,
                RepairStatus.REPAIR_EXHAUSTED,
                "tests failed and no repair agent was configured",
                validation={**validation, "tests": _test_json(test_results)},
            )

        last_validation = {**validation, "tests": _test_json(test_results)}
        for attempt in range(1, self.config.max_test_repairs + 1):
            self._emit(f"behavior repair attempt {attempt}")
            context = build_agent_context(
                repair_workspace,
                test_targets=self.config.test_targets,
                diagnostics=last_validation,
                phase="behavior",
            )
            context["recent_repairs"] = [
                _record_json(item) for item in self.records[-3:]
            ]

            context["recent_repairs"] = [
                {
                    key: item[key]
                    for key in ("phase", "attempt", "proposal_summary", "changed_files")
                }
                for item in context["recent_repairs"]
            ]
            try:
                self._write_state(store, "behavior_agent", repair_workspace)
                proposal = await self.agent.propose_repair(context)
                changed = patcher.apply(proposal, phase="behavior", attempt=attempt)
            except (asyncio.CancelledError, AgentRuntimeError) as exc:
                return self._finish(
                    store,
                    repair_workspace,
                    (
                        RepairStatus.TIMEOUT
                        if isinstance(exc, AgentRequestTimeout)
                        else RepairStatus.AGENT_ERROR
                    ),
                    str(exc) or "agent interrupted",
                    validation=last_validation,
                )
            except Exception as exc:
                return self._finish(
                    store,
                    repair_workspace,
                    RepairStatus.AGENT_ERROR,
                    f"behavior repair proposal failed: {exc}",
                    validation=last_validation,
                )
            compile_validation = self._validate_compile_and_discovery(repair_workspace)
            current_tests: list[TestResult] = []
            if _bridge_ready(compile_validation):
                current_tests = self._run_tests(repair_workspace)
            last_validation = {
                **compile_validation,
                "tests": _test_json(current_tests),
            }
            record = RepairRecord(
                phase="behavior",
                attempt=attempt,
                proposal_summary=proposal.summary,
                changed_files=changed,
                changed_entities=[
                    replacement.entity_id
                    for replacement in proposal.entity_replacements
                ],
                safety=compile_validation["safety"],
                compile_results=compile_validation["compile"],
                test_results=_test_json(current_tests),
            )
            self.records.append(record)
            self._write_state(store, "behavior_repair", repair_workspace)
            if _bridge_ready(compile_validation) and _tests_pass(current_tests):
                return self._finish(
                    store,
                    repair_workspace,
                    RepairStatus.PASSED,
                    "all selected tests passed after repair",
                    validation=last_validation,
                )

        status = _failure_status(last_validation, RepairStatus.REPAIR_EXHAUSTED)
        return self._finish(
            store,
            repair_workspace,
            status,
            "behavior repair budget exhausted",
            validation=last_validation,
        )

    async def _run_c_test(self, workspace: RepairWorkspace, patcher: PatchManager,
                            store: StateStore) -> JsonDict:
        from .c_runner import CRunner

        runner = CRunner()
        if self._uses_staged_c_bridge():
            result = CTestResult(
                target=self.config.test_targets[0],
                error="bridge has not been generated yet",
                failure_kind="bridge_missing",
            )
        else:
            result = runner.run(workspace, check_timeout=self.config.check_timeout,
                                test_timeout=self.config.test_timeout)
        used = {"bridge": 0, "implementation": 0}
        limits = {"bridge": self.config.max_bridge_repairs,
                  "implementation": self.config.max_test_repairs}
        diagnosing = False
        proposal_error = None

        def validation() -> JsonDict:
            return {**result.to_json(), "proposal_error": proposal_error,
                    "repair_budgets": {key: {"used": used[key], "limit": limits[key],
                        "remaining": limits[key] - used[key]} for key in used}}

        def finish(status: RepairStatus, message: str) -> JsonDict:
            self._c_validation = validation()
            return self._finish(store, workspace, status, message, validation=self._c_validation)

        def persist(phase: str) -> None:
            self._c_validation = validation()
            self._write_state(store, phase, workspace)

        persist("c_validation")

        while True:
            if result.passed:
                return finish(RepairStatus.PASSED, "original C test passed through Rust FFI")
            if result.failure_kind == "timeout":
                return finish(RepairStatus.TIMEOUT, result.error or "C validation timed out")
            if result.failure_kind == "safety":
                return finish(RepairStatus.SAFETY_FAILED, result.error or "implementation safety failed")
            if result.failure_kind == "protection":
                return finish(RepairStatus.ENVIRONMENT_ERROR, result.error or "protected inputs changed")
            if any(command.get("exit_code") == 127 and command.get("stage") != "execution"
                   for command in result.stages):
                return finish(RepairStatus.ENVIRONMENT_ERROR, result.error or "required tool unavailable")
            diagnosing = diagnosing or result.execution is not None or result.failure_kind == "implementation_check"
            fallback = RepairStatus.REPAIR_EXHAUSTED if diagnosing else RepairStatus.BRIDGE_FAILED
            if self.agent is None:
                return finish(fallback, "C validation failed and no repair agent was configured")
            if (all(used[key] >= limits[key] for key in used)
                    or (not diagnosing and used["bridge"] >= limits["bridge"])):
                return finish(fallback, "C repair budget exhausted")

            phase = "behavior" if diagnosing else "bridge"
            if phase == "bridge" and self._uses_staged_c_bridge():
                try:
                    await self._ensure_c_bridge_pairings(workspace, store)
                except (asyncio.CancelledError, AgentRuntimeError, ValueError) as exc:
                    event = {"sequence": len(self._c_attempts) + 1,
                        "phase": self._c_bridge_stage, "repair_kind": "bridge",
                        "status": "agent_error", "budget_charged": False,
                        "changed_files": [], "changed_entities": [], "error": str(exc)}
                    self._c_attempts.append(event)
                    return finish(RepairStatus.TIMEOUT if isinstance(exc, AgentRequestTimeout)
                                  else RepairStatus.AGENT_ERROR, str(exc))
                context = build_c_bridge_generation_context(
                    workspace,
                    interfaces=self._c_interfaces,
                    pairings=self._c_pairings,
                    test_targets=self.config.test_targets,
                    diagnostics=validation(),
                )
            else:
                context = build_agent_context(workspace, test_targets=self.config.test_targets,
                                              diagnostics=validation(), phase=phase)
            context["repair_budgets"] = validation()["repair_budgets"]
            context["recent_repairs"] = [{"phase": item.phase, "attempt": item.attempt,
                "summary": item.proposal_summary, "changed_files": item.changed_files,
                "changed_entities": item.changed_entities, "failure_evidence": item.failure_evidence}
                for item in self.records[-3:]]
            self._emit(f"C {phase} proposal; budgets: {context['repair_budgets']}")
            charged = False
            kind = "implementation" if diagnosing else "bridge"
            event: JsonDict = {"sequence": len(self._c_attempts) + 1, "phase": phase,
                "repair_kind": kind, "status": "agent_running", "budget_charged": False,
                "changed_files": [], "changed_entities": []}
            self._c_attempts.append(event)
            persist(f"{phase}_agent")
            try:
                proposal = await (self.agent.propose_repair(context) if diagnosing
                                  else self.agent.propose_bridge(context))
                if not diagnosing and self._c_pairings:
                    proposal = self._attach_confirmed_mappings(proposal)
                event.update({"summary": proposal.summary, "failure_evidence": proposal.failure_evidence,
                              "repair_kind": proposal.repair_kind or kind})
                if proposal.repair_kind == "environment":
                    if proposal.edits or proposal.entity_replacements:
                        raise ValueError("environment diagnosis must not modify code")
                    if not proposal.failure_evidence.strip():
                        raise ValueError("environment diagnosis requires concrete failure_evidence")
                    event["status"] = "environment"
                    persist(f"{phase}_environment_blocked")
                    return finish(
                        RepairStatus.ENVIRONMENT_ERROR,
                        f"{proposal.summary}: {proposal.failure_evidence}",
                    )
                if diagnosing:
                    if proposal.repair_kind not in {"bridge", "implementation"}:
                        raise ValueError("C repair requires repair_kind")
                    kind = proposal.repair_kind
                    if not proposal.failure_evidence.strip():
                        raise ValueError("C repair requires concrete failure_evidence")
                    if kind == "bridge" and self._c_pairings:
                        proposal = self._attach_confirmed_mappings(proposal)
                elif proposal.repair_kind not in {None, "bridge"}:
                    raise ValueError("C bridge generation requires bridge or environment repair_kind")
                if used[kind] >= limits[kind]:
                    event["status"] = "budget_exhausted"
                    return finish(RepairStatus.BRIDGE_FAILED if kind == "bridge"
                                  else RepairStatus.REPAIR_EXHAUSTED,
                                  f"C {kind} repair budget exhausted")
                used[kind] += 1
                charged = True
                event.update({"attempt": used[kind], "repair_kind": kind,
                              "budget_charged": True, "status": "applying"})
                persist(f"{phase}_applying")
                patch_phase = "bridge" if kind == "bridge" else "behavior"
                changed = patcher.apply(proposal, phase=patch_phase, attempt=used[kind])
            except (asyncio.CancelledError, AgentRuntimeError) as exc:
                event.update({"status": "agent_error", "error": str(exc) or "agent interrupted"})
                return finish(RepairStatus.TIMEOUT if isinstance(exc, AgentRequestTimeout)
                              else RepairStatus.AGENT_ERROR, str(exc) or "agent interrupted")
            except Exception as exc:

                if not charged:
                    if kind not in used:
                        kind = "implementation"
                    if used[kind] >= limits[kind]:
                        event.update({"status": "budget_exhausted", "error": str(exc)})
                        return finish(fallback, f"C {kind} repair budget exhausted: {exc}")
                    used[kind] += 1
                proposal_error = f"{kind} proposal rejected: {exc}"
                event.update({"status": "rejected", "repair_kind": kind,
                    "attempt": used[kind], "budget_charged": True, "error": proposal_error})
                self._emit(proposal_error)
                persist(f"{phase}_repair_rejected")
                continue

            proposal_error = None
            event.update({"status": "validating", "changed_files": changed,
                          "changed_entities": [item.entity_id for item in proposal.entity_replacements]})
            persist(f"{patch_phase}_validation")
            result = runner.run(workspace, check_timeout=self.config.check_timeout,
                                test_timeout=self.config.test_timeout)
            event.update({"status": "applied", "passed": result.passed,
                          "failure_kind": result.failure_kind,
                          "validation_path": ((Path(result.link_evidence["output_dir"]) / "result.json").relative_to(workspace.root).as_posix()
                              if result.link_evidence.get("output_dir") else "logs/c-test-result.json")})
            self.records.append(RepairRecord(phase=patch_phase, attempt=used[kind],
                proposal_summary=proposal.summary, changed_files=changed,
                changed_entities=[item.entity_id for item in proposal.entity_replacements],
                failure_evidence=proposal.failure_evidence,
                compile_results=result.stages, test_results=[result.to_json()]))
            persist(f"{patch_phase}_repair")

    def _uses_staged_c_bridge(self) -> bool:
        return (
            self.agent is not None
            and "propose_bridge" not in vars(self.agent)
            and callable(getattr(self.agent, "analyze_c_test", None))
            and callable(getattr(self.agent, "pair_c_rust_interfaces", None))
        )

    async def _ensure_c_bridge_pairings(
        self, workspace: RepairWorkspace, store: StateStore
    ) -> None:
        assert self.agent is not None
        if not self._c_interfaces:
            self._c_bridge_stage = "interface_analysis"
            self._write_state(store, "c_test_interface_analysis", workspace)
            context = build_c_test_analysis_context(
                workspace, test_targets=self.config.test_targets
            )
            interfaces = await self.agent.analyze_c_test(context)
            self._c_interfaces = self._validate_c_interfaces(workspace, interfaces)
            StateStore._write(
                workspace.context / "test-interfaces.json",
                {"version": 1, "interfaces": [asdict(item) for item in self._c_interfaces]},
            )
        if not self._c_pairings:
            self._c_bridge_stage = "interface_pairing"
            self._write_state(store, "c_interface_pairing", workspace)
            context = build_c_interface_pairing_context(
                workspace,
                interfaces=self._pairing_interfaces(),
                test_targets=self.config.test_targets,
            )
            pairings = await self.agent.pair_c_rust_interfaces(context)
            self._c_pairings = self._validate_c_pairings(workspace, pairings)
            StateStore._write(
                workspace.context / "interface-pairings.json",
                {"version": 1, "pairings": [asdict(item) for item in self._c_pairings]},
            )
            build_path = workspace.harness / "build.json"
            build = json.loads(build_path.read_text())
            build["symbols"] = sorted({item.c_symbol for item in self._c_pairings})
            StateStore._write(build_path, build)
        self._c_bridge_stage = "bridge_generation"

    def _validate_c_interfaces(
        self, workspace: RepairWorkspace, interfaces: tuple[CTestInterface, ...]
    ) -> tuple[CTestInterface, ...]:
        if not interfaces:
            raise ValueError("C test interface analysis returned no calls")
        build = json.loads((workspace.harness / "build.json").read_text())
        entry = workspace.harness / "c_project" / build["entry"]
        helper_paths = [entry, *(workspace.harness / "c_project" / path
                                  for path in (*build.get("sources", []),
                                               *build.get("helpers", [])))]
        source_contents = {
            path.relative_to(workspace.harness / "c_project").as_posix():
                path.read_text(encoding="utf-8", errors="replace").splitlines()
            for path in helper_paths
        }
        source_lines = {path: len(lines) for path, lines in source_contents.items()}
        helper_definitions: set[str] = set()
        function_pointer_names: set[str] = set()
        definition_pattern = re.compile(
            r"(?m)^\s*(?:[A-Za-z_]\w*[\s\*]+)+([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{"
        )
        for path in helper_paths:
            text = path.read_text(encoding="utf-8", errors="replace")
            helper_definitions.update(definition_pattern.findall(text))
            callback_types = set(re.findall(
                r"\btypedef\b[^;{}]*\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\([^;{}]*\)\s*;",
                text, flags=re.DOTALL,
            ))
            for callback_type in callback_types:
                function_pointer_names.update(re.findall(
                    rf"\b{re.escape(callback_type)}\s+([A-Za-z_]\w*)\b", text
                ))
            function_pointer_names.update(re.findall(
                r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\([^;{}]*\)", text
            ))
        external = {
            "assert", "abort", "calloc", "exit", "fclose", "fopen", "fprintf",
            "free", "fread", "fwrite", "malloc", "memcmp", "memcpy", "memmove",
            "memset", "printf", "puts", "realloc", "snprintf", "sprintf", "strcmp",
            "strcpy", "strlen", "strncmp", "strncpy",
        }
        configured = {value for value in build.get("symbols", []) if isinstance(value, str)}
        translated: set[str] = set()
        if (workspace.context / "entity-catalog.json").is_file():
            catalog = load_entity_catalog(workspace.root)
            translated = {
                value
                for entity in catalog["entities"]
                if isinstance(entity, dict)
                for value in (entity.get("source_name"), entity.get("rust_name"))
                if isinstance(value, str) and value
            }
        seen: set[str] = set()
        normalized: list[CTestInterface] = []
        for item in interfaces:
            if item.c_symbol in seen:
                raise ValueError(f"duplicate C test interface: {item.c_symbol}")
            seen.add(item.c_symbol)
            call_sources = item.call_sources
            if (len(call_sources) != len(item.call_locations)
                    or any(not source for source in call_sources)):
                call_pattern = re.compile(rf"\b{re.escape(item.c_symbol)}\s*\(")
                candidates: list[list[str]] = []
                inferred_sources: list[str | None] = []
                for line in item.call_locations:
                    matching = [
                        source for source, lines in source_contents.items()
                        if line <= len(lines) and call_pattern.search(lines[line - 1])
                    ]
                    in_range = [
                        source for source, lines in source_contents.items()
                        if line <= len(lines)
                    ]
                    possible = matching or in_range
                    candidates.append(possible)
                    inferred_sources.append(possible[0] if len(possible) == 1 else None)
                for index, source in enumerate(inferred_sources):
                    if source is not None:
                        continue
                    left = next((value for value in reversed(inferred_sources[:index])
                                 if value is not None), None)
                    right = next((value for value in inferred_sources[index + 1:]
                                  if value is not None), None)
                    neighboring = left if left == right else (left or right)
                    if neighboring in candidates[index] and (left is None or right is None
                                                               or left == right):
                        inferred_sources[index] = neighboring
                        continue
                    supplied = call_sources[index] if index < len(call_sources) else ""
                    if supplied in candidates[index]:
                        inferred_sources[index] = supplied
                        continue
                    raise ValueError(
                        f"C test interface {item.c_symbol} call at line "
                        f"{item.call_locations[index]} "
                        "has no unique configured source"
                    )
                call_sources = tuple(source for source in inferred_sources if source is not None)
            call_sources = tuple(
                _normalize_c_project_source(source) for source in call_sources
            )
            if any(source not in source_lines for source in call_sources):
                raise ValueError(
                    f"C test interface {item.c_symbol} references an unconfigured source"
                )
            if any(line < 1 or line > source_lines[source]
                   for source, line in zip(call_sources, item.call_locations)):
                raise ValueError(f"C test interface {item.c_symbol} has an invalid call location")
            if item.c_symbol in configured:
                classification = "project_api"
                call_kind = "direct"
            elif item.c_symbol in helper_definitions:
                classification = "test_helper"
                call_kind = "direct"
            elif item.c_symbol in translated:
                classification = "project_api"
                call_kind = "direct"
            elif item.c_symbol in external:
                classification = "external_api"
                call_kind = "direct"
            elif item.c_symbol in function_pointer_names:
                classification = "indirect_call"
                call_kind = "indirect"
            else:
                classification = item.classification
                call_kind = item.call_kind
            normalized.append(replace(
                item, classification=classification, call_kind=call_kind,
                call_sources=tuple(call_sources),
            ))
        unresolved = sorted(item.c_symbol for item in normalized
                            if item.classification == "unresolved")
        if unresolved:
            raise ValueError(
                f"C test interface analysis left unresolved calls: {unresolved}"
            )
        required = self._required_c_symbols(tuple(normalized))
        if not required:
            raise ValueError("C test analysis found no project interface to bridge")
        return tuple(normalized)

    @staticmethod
    def _required_c_symbols(interfaces: tuple[CTestInterface, ...]) -> set[str]:
        required = {item.c_symbol for item in interfaces
                    if item.classification == "project_api"}
        required.update(target for item in interfaces
                        if item.classification == "indirect_call"
                        for target in item.indirect_targets)
        return required

    def _pairing_interfaces(self) -> tuple[CTestInterface, ...]:
        required = self._required_c_symbols(self._c_interfaces)
        by_symbol = {item.c_symbol: item for item in self._c_interfaces}
        result: list[CTestInterface] = []
        for symbol in sorted(required):
            item = by_symbol.get(symbol)
            if item is not None:
                result.append(replace(
                    item, classification="project_api", call_kind="direct",
                    indirect_targets=(),
                ))
                continue
            callers = [item for item in self._c_interfaces
                       if symbol in item.indirect_targets]
            sites = tuple(dict.fromkeys(
                (source, line)
                for item in callers
                for source, line in zip(item.call_sources, item.call_locations)
            ))
            result.append(CTestInterface(
                c_symbol=symbol,
                call_locations=tuple(line for _, line in sites),
                argument_usage=("Passed as a function-pointer callback in the selected test",),
                return_usage="Used through an indirect test-helper call",
                classification="project_api",
                call_sources=tuple(source for source, _ in sites),
            ))
        return tuple(result)

    def _validate_c_pairings(
        self, workspace: RepairWorkspace, pairings: tuple[InterfacePairing, ...]
    ) -> tuple[InterfacePairing, ...]:
        required = self._required_c_symbols(self._c_interfaces)
        supplied = {item.c_symbol for item in pairings}
        if supplied != required:
            missing = sorted(required - supplied)
            extra = sorted(supplied - required)
            raise ValueError(f"interface pairing mismatch; missing={missing}, extra={extra}")
        catalog = load_entity_catalog(workspace.root)
        by_id = {item.get("entity_id"): item for item in catalog["entities"]
                 if isinstance(item, dict)}
        normalized: list[InterfacePairing] = []
        for pairing in pairings:
            entity = by_id.get(pairing.rust_entity_id)
            if entity is None:
                raise ValueError(
                    f"interface {pairing.c_symbol} references an unknown Rust entity"
                )
            if entity.get("visibility") != "public" or entity.get("module_visibility") != "public":
                raise ValueError(
                    f"interface {pairing.c_symbol} maps to Rust entity "
                    f"{pairing.rust_entity_id}, which is not publicly callable"
                )
            for type_id in pairing.required_type_entities:
                if type_id not in by_id:
                    raise ValueError(
                        f"interface {pairing.c_symbol} references unknown type entity {type_id}"
                    )
            normalized.append(replace(
                pairing,
                rust_path=str(entity.get("rust_path", "")),
                rust_module_path=str(entity.get("module_path", "")),
                rust_symbol=str(entity.get("rust_name", "")),
                rust_signature=str(entity.get("signature", "")),
            ))
        return tuple(normalized)

    def _attach_confirmed_mappings(self, proposal):
        mappings = tuple({
            "c_symbol": item.c_symbol,
            "ffi_symbol": item.c_symbol,
            "rust_symbol": item.rust_symbol,
            "entity_id": item.rust_entity_id,
        } for item in self._c_pairings)
        return replace(proposal, interface_mappings=mappings)

    async def _bridge_loop(
        self,
        repair_workspace: RepairWorkspace,
        patcher: PatchManager,
        store: StateStore,
        initial_validation: JsonDict,
    ) -> JsonDict:
        validation = initial_validation
        assert self.agent is not None
        for attempt in range(1, self.config.max_bridge_repairs + 1):
            self._emit(f"bridge repair attempt {attempt}")
            context = build_agent_context(
                repair_workspace,
                test_targets=self.config.test_targets,
                diagnostics=validation,
            )
            try:
                self._write_state(store, "bridge_agent", repair_workspace)
                proposal = await self.agent.propose_bridge(context)
                changed = patcher.apply(proposal, phase="bridge", attempt=attempt)
            except (asyncio.CancelledError, AgentRuntimeError) as exc:
                return {
                    **validation,
                    "terminal_agent_error": True,
                    "llm_timeout": isinstance(exc, AgentRequestTimeout),
                    "agent_error": str(exc) or "agent interrupted",
                }
            except Exception as exc:
                validation = {**validation, "agent_error": str(exc)}
                self._emit(f"bridge repair proposal rejected: {exc}")
                self._write_state(store, "bridge_repair_rejected", repair_workspace)
                continue
            validation = self._validate_compile_and_discovery(repair_workspace)
            self.records.append(
                RepairRecord(
                    phase="bridge",
                    attempt=attempt,
                    proposal_summary=proposal.summary,
                    changed_files=changed,
                    safety=validation["safety"],
                    compile_results=validation["compile"],
                )
            )
            self._write_state(store, "bridge_repair", repair_workspace)
            if _bridge_ready(validation):
                break
        return validation

    def _validate_compile_and_discovery(
        self, repair_workspace: RepairWorkspace
    ) -> JsonDict:
        assert self.cargo is not None
        self._emit("Cargo validation: safety, compile and discovery")
        try:
            repair_workspace.assert_protected_unchanged()
        except ValueError as exc:
            return {
                "protected_files_ok": False,
                "error": str(exc),
                "safety": {"passed": False},
                "compile": [],
                "discovery": [],
            }
        safety = self.safety.check(
            (repair_workspace.implementation,), repair_workspace.unsafe_baseline
        )
        if not safety.passed:
            return {
                "protected_files_ok": True,
                "safety": safety.to_json(),
                "compile": [],
                "discovery": [],
            }
        implementation_check = self.cargo.check(
            repair_workspace.implementation, timeout=self.config.check_timeout
        )
        compile_results = [implementation_check]
        discoveries: list[TestResult] = []
        if implementation_check.passed:
            for target in self.config.test_targets:
                checked = self.cargo.check_test_target(
                    repair_workspace.harness,
                    target,
                    timeout=self.config.check_timeout,
                )
                compile_results.append(checked)
                if not checked.passed:
                    break
                discovery_result, names = self.cargo.discover(
                    repair_workspace.harness,
                    target,
                    timeout=self.config.test_timeout,
                )
                discoveries.append(
                    TestResult(
                        target=target,
                        discovery=discovery_result,
                        execution=None,
                        discovered_tests=names,
                    )
                )
        return {
            "protected_files_ok": True,
            "safety": safety.to_json(),
            "compile": [item.to_json() for item in compile_results],
            "discovery": _test_json(discoveries),
        }

    def _run_tests(self, repair_workspace: RepairWorkspace) -> list[TestResult]:
        assert self.cargo is not None
        self._emit("Cargo validation: running selected tests")
        repair_workspace.assert_protected_unchanged()
        return [
            self.cargo.test(
                repair_workspace.harness,
                target,
                timeout=self.config.test_timeout,
            )
            for target in self.config.test_targets
        ]

    def _write_state(
        self, store: StateStore, phase: str, repair_workspace: RepairWorkspace,
        *, stop_reason: JsonDict | None = None,
    ) -> None:
        state = {
                "version": 1,
                "phase": phase,
                "run_root": str(repair_workspace.root),
                "test_targets": list(self.config.test_targets),
                "test_mode": self.config.test_mode,
                "unsafe_baseline": "unsafe-baseline.json",
                "records": [_record_json(item) for item in self.records],
                "agent_config": {
                    "max_rounds": self.config.max_agent_rounds,
                    "llm_timeout": self.config.llm_timeout,
                    "max_tool_bytes": self.config.max_tool_bytes,
                    "max_history_bytes": self.config.max_history_bytes,
                },
            }
        if self.config.test_mode == "c":
            state["c_test"] = self._c_run_details(repair_workspace, self._c_validation)
        if stop_reason is not None:
            state["stop_reason"] = stop_reason
        store.write_state(state)

    def _c_run_details(self, workspace: RepairWorkspace, validation: JsonDict) -> JsonDict:

        errors: list[str] = []

        def artifact(relative: str) -> JsonDict | None:
            try:
                value = json.loads((workspace.root / relative).read_text())
                if not isinstance(value, dict):
                    raise ValueError("expected a JSON object")
                return value
            except (OSError, ValueError) as exc:
                errors.append(f"{relative}: {exc}")
                return None

        build = artifact("harness/build.json")
        mappings = artifact("interface-map.json")
        execution = validation.get("execution")
        budgets = validation.get("repair_budgets") or {
            key: {"used": 0, "limit": limit, "remaining": limit}
            for key, limit in (("bridge", self.config.max_bridge_repairs),
                               ("implementation", self.config.max_test_repairs))}
        latest_result = None
        latest_path = workspace.logs / "c-test-result.json"
        if latest_path.is_file():
            try:
                latest = json.loads(latest_path.read_text())
                latest_result = latest.get("result") or "logs/c-test-result.json"
            except (OSError, ValueError):
                latest_result = "logs/c-test-result.json"
        return {
            "entry": (build or {}).get("entry", str(self.config.c_test.entry) if self.config.c_test else None),
            "build_config": build, "interface_map": mappings,
            "artifact_errors": errors, "link_evidence": validation.get("link_evidence", {}),
            "test_executed": execution is not None,
            "execution": {key: value for key, value in execution.items()
                          if key not in {"stdout", "stderr"}} if execution else None,
            "diagnostics": c_failure_diagnostics(validation, workspace.root),
            "last_result": latest_result,
            "test_interfaces": ("context/test-interfaces.json"
                if (workspace.context / "test-interfaces.json").is_file() else None),
            "interface_pairings": ("context/interface-pairings.json"
                if (workspace.context / "interface-pairings.json").is_file() else None),
            "repair_budgets": budgets, "repair_attempts": self._c_attempts,
        }

    def _finish(
        self,
        store: StateStore,
        repair_workspace: RepairWorkspace,
        status: RepairStatus,
        message: str,
        *,
        validation: JsonDict | None = None,
    ) -> JsonDict:
        report = {
            "version": 1,
            "status": status.value,
            "message": message,
            "run_root": str(repair_workspace.root),
            "implementation": str(repair_workspace.implementation),
            "harness": str(repair_workspace.harness),
            "test_targets": list(self.config.test_targets),
            "test_mode": self.config.test_mode,
            "unsafe_baseline": "unsafe-baseline.json",
            "records": [_record_json(item) for item in self.records],
            "validation": validation or {},
            "agent_traces": "agent-traces/",
            "stop_reason": {"status": status.value, "message": message,
                "failure_kind": (validation or {}).get("failure_kind")},
        }
        if self.config.test_mode == "c":
            self._c_validation = validation or {}
            report["interface_map"] = "interface-map.json"
            report["test_interfaces"] = (
                "context/test-interfaces.json"
                if (repair_workspace.context / "test-interfaces.json").is_file() else None
            )
            report["interface_pairings"] = (
                "context/interface-pairings.json"
                if (repair_workspace.context / "interface-pairings.json").is_file() else None
            )
            report["build_config"] = "harness/build.json"
            report["c_test"] = self._c_run_details(repair_workspace, self._c_validation)
            report["stop_reason"]["source"] = (
                "agent" if self._c_attempts and self._c_attempts[-1]["status"] == "agent_error"
                else "preparation" if status == RepairStatus.PREPARED
                else "environment" if status == RepairStatus.ENVIRONMENT_ERROR
                else "validation")
        store.write_report(report)
        self._write_state(store, status.value, repair_workspace, stop_reason=report["stop_reason"])
        self._emit(f"correctness repair finished status={status.value}")
        return report

    def run_sync(self) -> JsonDict:
        return asyncio.run(self.run())

    def _preparation_failure(self, error: Exception) -> JsonDict:
        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ-preparation-failed")
        root = self.config.workspace / "test_case_repair" / "runs" / run_id
        root.mkdir(parents=True, exist_ok=False)
        report = {
            "version": 1,
            "status": RepairStatus.ENVIRONMENT_ERROR.value,
            "message": f"correctness repair preparation failed: {error}",
            "run_root": str(root),
            "test_targets": list(self.config.test_targets),
            "test_mode": self.config.test_mode,
            "records": [],
            "validation": {"preparation_error": str(error)},
            "stop_reason": {"status": RepairStatus.ENVIRONMENT_ERROR.value,
                            "source": "preparation", "message": str(error)},
        }
        store = StateStore(root)
        store.write_report(report)
        store.write_state({**report, "phase": RepairStatus.ENVIRONMENT_ERROR.value})
        self._emit(f"correctness repair preparation failed: {error}")
        return report

    def _emit(self, message: str) -> None:
        if self._log is not None:
            self._log(f"[correctness-repair] {message}")


def _bridge_ready(validation: JsonDict) -> bool:
    if not validation.get("protected_files_ok"):
        return False
    safety = validation.get("safety", {})
    compile_results = validation.get("compile", [])
    discovery = validation.get("discovery", [])
    return (
        isinstance(safety, dict)
        and safety.get("passed") is True
        and bool(compile_results)
        and all(
            item.get("exit_code") == 0 and not item.get("timed_out")
            for item in compile_results
        )
        and bool(discovery)
        and all(item.get("discovered_tests") for item in discovery)
    )


def _tests_pass(results: list[TestResult]) -> bool:
    return bool(results) and all(result.passed for result in results)


def _failure_status(validation: JsonDict, default: RepairStatus) -> RepairStatus:
    safety = validation.get("safety")
    if isinstance(safety, dict) and safety.get("passed") is False:
        return RepairStatus.SAFETY_FAILED
    commands = [*validation.get("compile", [])]
    for test in validation.get("tests", []):
        if isinstance(test, dict):
            commands.extend(
                item for item in (test.get("discovery"), test.get("execution")) if item
            )
    if any(item.get("timed_out") for item in commands if isinstance(item, dict)):
        return RepairStatus.TIMEOUT
    return default


def _test_json(results: list[TestResult]) -> list[JsonDict]:
    return [item.to_json() for item in results]


def _record_json(record: RepairRecord) -> JsonDict:
    return {
        "phase": record.phase,
        "repair_kind": "implementation" if record.phase == "behavior" else record.phase,
        "attempt": record.attempt,
        "proposal_summary": record.proposal_summary,
        "changed_files": record.changed_files,
        "changed_entities": record.changed_entities,
        "safety": record.safety,
        "compile_results": record.compile_results,
        "test_results": record.test_results,
        "failure_evidence": record.failure_evidence,
    }


