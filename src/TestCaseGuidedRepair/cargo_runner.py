from __future__ import annotations

import os
import re
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from .models import CommandResult, TestResult
from .workspace import resolve_cargo_target_kind
from .process_runner import run_command


_TEST_LIST_RE = re.compile(r"^(?P<name>.+): test$", re.MULTILINE)


class CargoExecutor(Protocol):
    def check(self, project: Path, *, timeout: int) -> CommandResult: ...

    def check_test_target(
        self, project: Path, target: str, *, timeout: int
    ) -> CommandResult: ...

    def discover(
        self, project: Path, target: str, *, timeout: int
    ) -> tuple[CommandResult, tuple[str, ...]]: ...

    def test(self, project: Path, target: str, *, timeout: int) -> TestResult: ...


class CargoRunner:
    def __init__(self, *, cargo_bin: str = "cargo") -> None:
        self.cargo_bin = cargo_bin
        if shutil.which(cargo_bin) is None:
            raise FileNotFoundError(f"Cargo executable not found: {cargo_bin}")

    def check(self, project: Path, *, timeout: int) -> CommandResult:
        return self._run(
            (self.cargo_bin, "check", "--all-targets"), project, timeout=timeout
        )

    def check_test_target(
        self, project: Path, target: str, *, timeout: int
    ) -> CommandResult:
        kind = resolve_cargo_target_kind(project, target)
        return self._run(
            (self.cargo_bin, "check", f"--{kind}", target), project, timeout=timeout
        )

    def test(self, project: Path, target: str, *, timeout: int) -> TestResult:
        discovery, names = self.discover(project, target, timeout=timeout)
        execution = None
        if discovery.passed and names:
            kind = resolve_cargo_target_kind(project, target)
            execution = self._run(
                (self.cargo_bin, "test", f"--{kind}", target, "--", "--nocapture"),
                project,
                timeout=timeout,
            )
        return TestResult(target, discovery, execution, names)

    def discover(
        self, project: Path, target: str, *, timeout: int
    ) -> tuple[CommandResult, tuple[str, ...]]:
        kind = resolve_cargo_target_kind(project, target)
        result = self._run(
            (self.cargo_bin, "test", f"--{kind}", target, "--", "--list"),
            project,
            timeout=timeout,
        )
        names = tuple(
            match.group("name").strip()
            for match in _TEST_LIST_RE.finditer(result.stdout)
        )
        return result, names

    @staticmethod
    def _run(command: tuple[str, ...], cwd: Path, *, timeout: int) -> CommandResult:
        result = CargoRunner._run_once(command, cwd, timeout=timeout, env=os.environ.copy())
        if (
            not result.passed
            and not result.timed_out
            and "CARGO_NET_OFFLINE" not in os.environ
            and _looks_like_registry_network_failure(result.stderr)
        ):
            offline_env = os.environ.copy()
            offline_env["CARGO_NET_OFFLINE"] = "true"
            offline = CargoRunner._run_once(
                command, cwd, timeout=timeout, env=offline_env
            )

            return replace(
                offline,
                stderr=(
                    "[c2safety] retried with CARGO_NET_OFFLINE=true after registry/network failure\n"
                    + offline.stderr
                ),
            )
        return result

    @staticmethod
    def _run_once(
        command: tuple[str, ...],
        cwd: Path,
        *,
        timeout: int,
        env: dict[str, str],
    ) -> CommandResult:
        return run_command(command, cwd, timeout=timeout, env=env)


def _looks_like_registry_network_failure(stderr: str) -> bool:
    lowered = stderr.lower()
    return any(
        marker in lowered
        for marker in (
            "failed to download",
            "failed to fetch",
            "could not connect",
            "network failure",
            "spurious network error",
            "failed to get `",
        )
    )
