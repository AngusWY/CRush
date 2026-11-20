from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .models import CompileResult


class RustCompiler:


    def __init__(
        self,
        rust_project: Path | str,
        *,
        cargo_bin: str = "cargo",
        timeout_seconds: int = 120,
    ) -> None:
        self.rust_project = Path(rust_project)
        self.cargo_bin = cargo_bin
        self.timeout_seconds = timeout_seconds

    def check(self) -> CompileResult:
        self._validate_environment()
        try:
            proc = subprocess.run(
                [self.cargo_bin, "check", "--all-targets"],
                cwd=self.rust_project,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            timeout_message = (
                f"cargo check timed out after {self.timeout_seconds} seconds"
            )
            return CompileResult(
                passed=False,
                exit_code=124,
                stdout=stdout,
                stderr=f"{stderr}\n{timeout_message}".strip(),
            )

        return CompileResult(
            passed=proc.returncode == 0,
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )

    def _validate_environment(self) -> None:
        if shutil.which(self.cargo_bin) is None:
            raise FileNotFoundError(f"Cargo executable not found: {self.cargo_bin}")
        if not self.rust_project.is_dir():
            raise FileNotFoundError(f"Rust project directory not found: {self.rust_project}")
        cargo_toml = self.rust_project / "Cargo.toml"
        if not cargo_toml.is_file():
            raise FileNotFoundError(f"Cargo.toml not found: {cargo_toml}")
