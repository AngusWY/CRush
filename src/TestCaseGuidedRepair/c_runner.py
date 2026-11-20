
from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
from pathlib import Path

from .cargo_runner import CargoRunner
from .models import CTestConfig, CTestResult, CommandResult
from .process_runner import run_command
from .safety import SafetyChecker
from .state_store import StateStore
from .workspace import RepairWorkspace
from .c_diagnostics import c_failure_diagnostics


def load_prepared_workspace(root: Path) -> RepairWorkspace:
    root = root.resolve()
    hashes = json.loads((root / "protected-files.json").read_text())
    for relative in hashes:
        path = Path(relative)
        if path.is_absolute() or ".." in path.parts or not (root / path).resolve().is_relative_to(root):
            raise ValueError(f"invalid protected path: {relative}")
    return RepairWorkspace(root, root / "implementation", root / "harness",
        root / "context", root / "logs", root / "snapshots", hashes,
        json.loads((root / "unsafe-baseline.json").read_text()), "c")


def read_build_config(workspace: RepairWorkspace) -> tuple[CTestConfig, str]:
    data = json.loads((workspace.harness / "build.json").read_text())
    if (data.get("version") != 1 or data.get("test_mode") != "c"
            or data.get("project_root") != "c_project" or data.get("ffi_project") != "ffi"):
        raise ValueError("unsupported C build configuration")
    if "cxxflags" in data or "cxx_compiler" in data:
        raise ValueError("C++ test configuration is not supported")
    options: dict = {}
    for name in (
        "sources", "helpers", "include_dirs", "resources", "defines", "cflags",
        "ldflags", "libraries", "args", "symbols",
    ):
        values = data.get(name, [])
        if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
            raise ValueError(f"{name} must be an array of strings")
        options[name] = tuple(Path(item) for item in values) if name in {
            "sources", "helpers", "include_dirs", "resources"
        } else tuple(values)
    for name, default in (
        ("entry", None), ("cwd", "."), ("compiler", "cc"),
    ):
        value = data.get(name, default)
        if not isinstance(value, str) or not value or "\0" in value:
            raise ValueError(f"invalid {name}")
        options[name] = Path(value) if name in {"entry", "cwd"} else value
    config = CTestConfig(**options)
    config.validate(workspace.harness / "c_project")
    for source in (config.entry, *config.sources):
        key = (workspace.harness / "c_project" / source).relative_to(workspace.root).as_posix()
        if key not in workspace.protected_hashes:
            raise ValueError(f"C source is not an original protected input: {source}")
    target = data.get("target")
    if not isinstance(target, str) or not target:
        raise ValueError("missing C test target")
    _validate_flags(config)
    return config, target


def _validate_flags(config: CTestConfig) -> None:


    for define in config.defines:
        if not re.fullmatch(r"[A-Za-z_]\w*(?:=[^\r\n\0]*)?", define) or define.split("=", 1)[0] == "NDEBUG":
            raise ValueError(f"invalid or assertion-disabling macro: {define}")
    allowed_c_flag = re.compile(
        r"(?:-O[0-3sg]|-g[0-3]?|-W(?:all|extra|error|pedantic|no-[a-z-]+)|"
        r"-std=(?:c|gnu)(?:89|90|99|11|17|18|2x|23)|-pedantic|-pthread|-fPIC)"
    )

    def validate_compile_flags(
        flags: tuple[str, ...], allowed: re.Pattern[str], language: str
    ) -> None:
        index = 0
        while index < len(flags):
            flag = flags[index]
            if flag == "-include":
                if index + 1 >= len(flags):
                    raise ValueError(f"-include requires a header name in {language} flags")
                header = flags[index + 1]
                header_path = Path(header)
                if (not re.fullmatch(r"[A-Za-z0-9_./+-]+", header)
                        or header.startswith("-") or ".." in header_path.parts):
                    raise ValueError(f"invalid -include header in {language} flags: {header}")
                index += 2
                continue
            if not allowed.fullmatch(flag):
                raise ValueError(f"unsupported {language} flag (use structured fields): {flag}")
            index += 1

    validate_compile_flags(config.cflags, allowed_c_flag, "C")
    for flag in config.ldflags:
        if flag not in {"-pthread", "-Wl,--as-needed", "-Wl,--no-as-needed"}:
            raise ValueError(f"unsupported linker flag: {flag}")
    for library in config.libraries:
        if not re.fullmatch(r"[A-Za-z0-9_+-]+", library):
            raise ValueError(f"invalid library name: {library}")
    for symbol in config.symbols:
        if not re.fullmatch(r"[A-Za-z_]\w*", symbol):
            raise ValueError(f"invalid tested symbol: {symbol}")


class CRunner:


    def __init__(self, *, cargo: CargoRunner | None = None, nm_bin: str = "nm") -> None:
        self.cargo = cargo or CargoRunner()
        self.nm_bin = nm_bin

    def run(self, workspace: RepairWorkspace, *, check_timeout: int = 120,
            test_timeout: int = 300) -> CTestResult:
        result = CTestResult("unknown")
        stage = "configuration"
        output: Path | None = None
        try:
            if workspace.test_mode != "c" or not sys.platform.startswith("linux"):
                raise ValueError("C runner currently requires a prepared FFI workspace on Linux")
            if min(check_timeout, test_timeout) <= 0:
                raise ValueError("timeouts must be positive")
            workspace.assert_protected_unchanged()
            config, result.target = read_build_config(workspace)
            safety = SafetyChecker().check((workspace.implementation,), workspace.unsafe_baseline)
            result.link_evidence["safety"] = safety.to_json()
            if not safety.passed:
                result.failure_kind = "safety"
                raise ValueError("implementation safety check failed")
            build_root = workspace.root / "build"
            build_root.mkdir(exist_ok=True)
            output = Path(tempfile.mkdtemp(prefix="c-test-", dir=build_root))
            result.link_evidence["output_dir"] = str(output)

            def record(name: str, command: CommandResult) -> CommandResult:
                result.stages.append({"stage": name, **command.to_json()})
                if not command.passed:
                    result.failure_kind = "timeout" if command.timed_out else name
                    raise ValueError(f"{name} failed (exit {command.exit_code})")
                return command

            stage = "implementation_check"
            record(stage, self.cargo.check(workspace.implementation, timeout=check_timeout))
            stage = "rust_build"
            ffi = workspace.harness / "ffi"
            built = record(stage, self.cargo._run((self.cargo.cargo_bin, "build", "--lib",
                "--message-format=json", "--target-dir", str(build_root / "cargo")), ffi, timeout=check_timeout))
            archives = []
            for line in built.stdout.splitlines():
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if (item.get("reason") == "compiler-artifact"
                        and Path(item.get("manifest_path", "")).resolve() == (ffi / "Cargo.toml").resolve()
                        and "staticlib" in item.get("target", {}).get("crate_types", [])):
                    archives.extend(Path(name) for name in item.get("filenames", []) if name.endswith(".a"))
            if len(archives) != 1 or not archives[0].is_file() or not archives[0].resolve().is_relative_to(build_root.resolve()):
                raise ValueError("expected one Rust staticlib artifact in the isolated build directory")
            archive = archives[0]
            project = workspace.harness / "c_project"
            objects = []
            stage = "c_compile"
            sources = tuple(dict.fromkeys((config.entry, *config.sources)))
            for index, source in enumerate(sources):
                obj = output / f"source-{index}.o"
                command = (config.compiler, *config.cflags,
                    *(f"-D{define}" for define in config.defines),
                    *(f"-I{project / path}" for path in config.include_dirs),
                    "-UNDEBUG", "-c", str(project / source), "-o", str(obj))
                record(stage, run_command(command, project, timeout=check_timeout))
                objects.append(obj)

            stage = "symbol_audit"
            def symbols(path: Path, defined: bool) -> set[str]:
                command = record(stage, run_command((self.nm_bin, "-g",
                    "--defined-only" if defined else "--undefined-only", str(path)), output, timeout=check_timeout))
                return {parts[-1] for line in command.stdout.splitlines()
                        if len(parts := line.split()) >= 2 and len(parts[-2]) == 1}

            exports = symbols(archive, True)
            defined: set[str] = set()
            undefined: set[str] = set()
            for obj in objects:
                defined.update(symbols(obj, True))
                undefined.update(symbols(obj, False))

            duplicates = defined & exports
            candidates = undefined & exports
            result.link_evidence.update({
                "c_sources": [str(project / source) for source in sources],
                "objects": [str(obj) for obj in objects], "rust_archive": str(archive),
                "rust_referenced_symbols": sorted(candidates), "requested_symbols": list(config.symbols),
                "duplicate_c_rust_symbols": sorted(duplicates),
                "unmatched_requested_symbols": sorted(set(config.symbols) - candidates)})
            if duplicates:
                raise ValueError(f"C input defines Rust-exported symbols: {sorted(duplicates)}")
            if not candidates or (set(config.symbols) - candidates):
                raise ValueError("no matching Rust test symbols, or requested symbols are not referenced by C")
            stage = "c_link"
            executable = output / "test"
            link_map = output / "link.map"
            record(stage, run_command((config.compiler, *(str(obj) for obj in objects),
                str(archive), *config.ldflags, *(f"-l{name}" for name in config.libraries),
                "-ldl", "-lpthread", "-lm", "-lrt", "-lutil",
                f"-Wl,-Map,{link_map}", "-o", str(executable)), project, timeout=check_timeout))
            result.link_evidence.update({"link_map": str(link_map), "executable": str(executable)})
            workspace.assert_protected_unchanged()
            stage = "execution"
            result.execution = run_command((str(executable), *config.args), project / config.cwd, timeout=test_timeout)
            record(stage, result.execution)
            workspace.assert_protected_unchanged()
        except (ValueError, OSError, TypeError, KeyError) as exc:
            result.error = str(exc)
            result.failure_kind = result.failure_kind or stage


        try:
            workspace.assert_protected_unchanged()
        except (ValueError, OSError) as exc:
            result.error = f"{result.error + '; ' if result.error else ''}{exc}"
            result.failure_kind = "protection"
        result.diagnostics = c_failure_diagnostics(result.to_json(), workspace.root)
        full_result = result.to_json()
        if output is not None:
            result_path = output / "result.json"
            StateStore._write(result_path, full_result)
            StateStore._write(workspace.logs / "c-test-result.json", {
                "version": 1,
                "target": result.target,
                "passed": result.passed,
                "failure_kind": result.failure_kind,
                "error": result.error,
                "result": result_path.relative_to(workspace.root).as_posix(),
            })
        else:
            StateStore._write(workspace.logs / "c-test-result.json", full_result)
        return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an existing isolated C test and FFI bridge, without an LLM")
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--check-timeout", type=int, default=120)
    parser.add_argument("--test-timeout", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        workspace = load_prepared_workspace(args.run_dir)
        result = CRunner().run(workspace, check_timeout=args.check_timeout, test_timeout=args.test_timeout)
    except (ValueError, OSError) as exc:
        print(f"C test setup failed: {exc}", file=sys.stderr)
        return 2
    print(f"status: {'passed' if result.passed else 'failed'}")
    print(f"report: {workspace.logs / 'c-test-result.json'}")
    if result.error:
        print(result.error)
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
