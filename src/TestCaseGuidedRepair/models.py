from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import math
from pathlib import Path
from typing import Any


JsonDict = dict[str, Any]


class RepairStatus(StrEnum):
    PREPARED = "prepared"
    PASSED = "passed"
    BRIDGE_FAILED = "bridge_failed"
    REPAIR_EXHAUSTED = "repair_exhausted"
    SAFETY_FAILED = "safety_failed"
    ENVIRONMENT_ERROR = "environment_error"
    TIMEOUT = "timeout"
    AGENT_ERROR = "agent_error"


@dataclass(frozen=True)
class CTestConfig:


    entry: Path
    sources: tuple[Path, ...] = ()
    helpers: tuple[Path, ...] = ()
    include_dirs: tuple[Path, ...] = ()
    defines: tuple[str, ...] = ()
    cflags: tuple[str, ...] = ()
    ldflags: tuple[str, ...] = ()
    libraries: tuple[str, ...] = ()
    args: tuple[str, ...] = ()
    cwd: Path = Path(".")
    resources: tuple[Path, ...] = ()
    compiler: str = "cc"
    symbols: tuple[str, ...] = ()

    def validate(self, project: Path) -> None:
        root = project.resolve()
        if not root.is_dir():
            raise ValueError(f"C project directory does not exist: {project}")
        for path in (self.entry, *self.sources, *self.helpers, *self.include_dirs,
                     self.cwd, *self.resources):
            if path.is_absolute() or ".." in path.parts or "interfaces" in path.parts:
                raise ValueError(f"C input path must be inside the project: {path}")
            resolved = (root / path).resolve()
            if not resolved.is_relative_to(root) or not resolved.exists():
                raise ValueError(f"C input is missing or outside the project: {path}")
        for path in (self.entry, *self.sources):
            if path.suffix != ".c" or not (root / path).is_file():
                raise ValueError(f"test source must be a .c file: {path}")
        for path in self.helpers:
            if path.suffix not in {".c", ".h"} or not (root / path).is_file():
                raise ValueError(f"test helper must be a .c or .h file: {path}")
        for path in (*self.include_dirs, self.cwd):
            if not (root / path).is_dir():
                raise ValueError(f"C input must be a directory: {path}")
        if not self.compiler.strip():
            raise ValueError("C compiler must not be empty")


@dataclass(frozen=True)
class RepairConfig:
    workspace: Path
    test_project: Path
    test_targets: tuple[str, ...]
    max_bridge_repairs: int = 3
    max_test_repairs: int = 3
    check_timeout: int = 120
    test_timeout: int = 300
    prepare_only: bool = False
    max_agent_rounds: int = 24
    llm_timeout: float = 300
    max_tool_bytes: int = 400_000
    max_history_bytes: int = 800_000
    test_mode: str = "c"
    c_test: CTestConfig | None = None

    def validate(self) -> None:
        if self.test_mode != "c":
            raise ValueError("TestCaseGuidedRepair supports only C tests")
        if self.c_test is None:
            raise ValueError("C mode requires a C test configuration")
        self.c_test.validate(self.test_project)
        if not math.isfinite(self.llm_timeout) or (
            min(
                self.max_agent_rounds,
                self.llm_timeout,
                self.max_tool_bytes,
                self.max_history_bytes,
            )
            <= 0
        ):
            raise ValueError("agent budgets must be positive")
        if len(self.test_targets) != 1:
            raise ValueError("exactly one --test-target is required per run")
        if self.max_bridge_repairs < 0 or self.max_test_repairs < 0:
            raise ValueError("repair limits must be non-negative")
        if self.check_timeout <= 0 or self.test_timeout <= 0:
            raise ValueError("timeouts must be positive")


@dataclass(frozen=True)
class CommandResult:
    command: tuple[str, ...]
    cwd: str
    exit_code: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False

    @property
    def passed(self) -> bool:
        return not self.timed_out and self.exit_code == 0

    def to_json(self) -> JsonDict:
        return asdict(self)


@dataclass(frozen=True)
class SafetyResult:
    passed: bool
    violations: tuple[JsonDict, ...] = ()

    def to_json(self) -> JsonDict:
        return {"passed": self.passed, "violations": list(self.violations)}


@dataclass(frozen=True)
class TestResult:
    target: str
    discovery: CommandResult
    execution: CommandResult | None
    discovered_tests: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return (
            bool(self.discovered_tests)
            and self.execution is not None
            and self.execution.passed
        )

    def to_json(self) -> JsonDict:
        return {
            "target": self.target,
            "passed": self.passed,
            "discovered_tests": list(self.discovered_tests),
            "discovery": self.discovery.to_json(),
            "execution": self.execution.to_json() if self.execution else None,
        }


@dataclass
class CTestResult:
    target: str
    stages: list[JsonDict] = field(default_factory=list)
    execution: CommandResult | None = None
    error: str | None = None
    failure_kind: str | None = None
    link_evidence: JsonDict = field(default_factory=dict)
    diagnostics: JsonDict = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.error is None and self.execution is not None and self.execution.passed

    def to_json(self) -> JsonDict:
        return {"test_mode": "c", "target": self.target, "passed": self.passed,
                "stages": self.stages, "execution": self.execution.to_json() if self.execution else None,
                "signal": -self.execution.exit_code if self.execution and self.execution.exit_code < 0 else None,
                "error": self.error, "failure_kind": self.failure_kind,
                "link_evidence": self.link_evidence, "diagnostics": self.diagnostics}


@dataclass(frozen=True)
class FileEdit:
    path: str
    content: str


@dataclass(frozen=True)
class EntityReplacement:
    entity_id: int
    expected_sha256: str
    rust_code: str


@dataclass(frozen=True)
class ChangeProposal:
    summary: str
    edits: tuple[FileEdit, ...] = ()
    related_entities: tuple[int, ...] = ()
    entity_replacements: tuple[EntityReplacement, ...] = ()
    interface_mappings: tuple[JsonDict, ...] = ()
    repair_kind: str | None = None
    failure_evidence: str = ""


@dataclass(frozen=True)
class CTestInterface:
    c_symbol: str
    call_locations: tuple[int, ...] = ()
    argument_usage: tuple[str, ...] = ()
    return_usage: str = ""
    classification: str = "unresolved"
    call_kind: str = "direct"
    indirect_targets: tuple[str, ...] = ()
    call_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class InterfacePairing:
    c_symbol: str
    c_declaration: str
    rust_entity_id: int
    rust_path: str
    rust_module_path: str
    rust_symbol: str
    rust_signature: str
    required_type_entities: tuple[int, ...] = ()
    type_definitions: tuple[str, ...] = ()
    adaptations: tuple[str, ...] = ()


@dataclass
class RepairRecord:
    phase: str
    attempt: int
    proposal_summary: str
    changed_files: list[str] = field(default_factory=list)
    changed_entities: list[int] = field(default_factory=list)
    safety: JsonDict | None = None
    compile_results: list[JsonDict] = field(default_factory=list)
    test_results: list[JsonDict] = field(default_factory=list)
    failure_evidence: str = ""
