from __future__ import annotations

import hashlib
import json
import re
import shutil
import tomllib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from .models import RepairConfig


_IGNORED_NAMES = {".git", "target", "__pycache__", ".pytest_cache", "interfaces"}


def is_ignored_project_path(path: Path, root: Path) -> bool:

    return any(part in _IGNORED_NAMES for part in path.relative_to(root).parts[:-1])


@dataclass(frozen=True)
class RepairWorkspace:
    root: Path
    implementation: Path
    harness: Path
    context: Path
    logs: Path
    snapshots: Path
    protected_hashes: dict[str, str]
    unsafe_baseline: dict[str, object]
    test_mode: str = "c"

    @classmethod
    def prepare(cls, config: RepairConfig) -> "RepairWorkspace":
        config.validate()
        rust_project = read_rust_project(config.workspace)
        _require_cargo_project(rust_project, "translated Rust project")
        if config.test_mode == "rust":
            _require_cargo_project(config.test_project, "test project")
            for target in config.test_targets:
                resolve_cargo_target_kind(config.test_project, target)

        run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        root = config.workspace / "test_case_repair" / "runs" / run_id
        implementation = root / "implementation"
        harness = root / "harness"
        from .safety import collect_unsafe_baseline

        unsafe_baseline = collect_unsafe_baseline(rust_project)
        _copy_project(rust_project, implementation)
        if config.test_mode == "c":
            _prepare_c_harness(config, harness, implementation)
            (root / "build").mkdir()
        else:
            _copy_project(config.test_project, harness)
            _seed_missing_module_bridges(harness, implementation)
        _configure_implementation_unsafe_lint(implementation)
        context = root / "context"
        _copy_translation_context(config.workspace, context)
        from .interface_catalog import build_entity_catalog
        build_entity_catalog(root)
        logs = root / "logs"
        snapshots = root / "snapshots"
        logs.mkdir(parents=True)
        snapshots.mkdir(parents=True)

        if config.test_mode == "c":
            protected = tuple(path for path in (harness / "c_project").rglob("*") if path.is_file())
        else:
            _add_implementation_dependency(harness, implementation)
            protected = _protected_test_files(harness, config.test_targets)
        protected = (*protected, implementation / "Cargo.toml")
        hashes = {_relative_key(root, path): _sha256(path) for path in protected}
        (root / "protected-files.json").write_text(
            json.dumps(hashes, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        (root / "interface-map.json").write_text(
            json.dumps({"version": 1, "mappings": []}, indent=2) + "\n",
            encoding="utf-8",
        )
        (root / "unsafe-baseline.json").write_text(
            json.dumps(unsafe_baseline, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return cls(root, implementation, harness, context, logs, snapshots, hashes, unsafe_baseline, config.test_mode)

    def assert_protected_unchanged(self) -> None:
        for relative, expected in self.protected_hashes.items():
            path = self.root / relative
            if not path.is_file() or _sha256(path) != expected:
                raise ValueError(f"protected test file was modified: {relative}")


def read_rust_project(workspace: Path) -> Path:
    layout_path = workspace / "rust-module-layout.json"
    if not layout_path.is_file():
        raise FileNotFoundError(f"missing Rust module layout: {layout_path}")
    data = json.loads(layout_path.read_text(encoding="utf-8"))
    value = data.get("rust_project") if isinstance(data, dict) else None
    if not isinstance(value, str) or not value:
        raise ValueError(f"{layout_path}: missing rust_project")
    path = Path(value)
    return path.resolve() if path.is_absolute() else (workspace / path).resolve()


def _prepare_c_harness(config: RepairConfig, harness: Path, implementation: Path) -> None:

    assert config.c_test is not None
    _copy_c_project(config.test_project.resolve(), harness / "c_project")
    config.c_test.validate(harness / "c_project")
    ffi = harness / "ffi"
    (ffi / "src").mkdir(parents=True)
    package_name = _cargo_package_name(implementation)
    (ffi / "Cargo.toml").write_text(
        '[package]\nname = "c2safety-test-ffi"\nversion = "0.1.0"\nedition = "2024"\n'
        '\n[lib]\ncrate-type = ["staticlib"]\n'
        '\n[dependencies.c2safety_impl]\n'
        f'package = {json.dumps(package_name)}\npath = "../../implementation"\n'
        '\n[workspace]\n', encoding="utf-8",
    )
    (ffi / "src" / "lib.rs").write_text(
        '// FFI exports will be generated for the selected C test.\n'
        '// This skeleton does not provide a tested interface yet.\n', encoding="utf-8",
    )
    build = {"version": 1, "test_mode": "c", "target": config.test_targets[0],
             "project_root": "c_project", "ffi_project": "ffi", "status": "prepared",
             **asdict(config.c_test)}
    (harness / "build.json").write_text(
        json.dumps(build, default=lambda value: value.as_posix(), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _copy_c_project(source: Path, destination: Path) -> None:

    def ignored(directory: str, names: list[str]) -> set[str]:
        excluded = set(names) & _IGNORED_NAMES
        for name in names:
            if name in excluded:
                continue
            path = Path(directory) / name
            if path.is_symlink():
                resolved = path.resolve()
                if not resolved.is_relative_to(source) or not resolved.exists():
                    raise ValueError(f"C project symlink is missing or escapes the project: {path}")
                if path.is_dir() or "interfaces" in resolved.relative_to(source).parts:
                    raise ValueError(f"unsupported C project symlink: {path}")
        return excluded

    shutil.copytree(source, destination, ignore=ignored, symlinks=False)


def _copy_project(source: Path, destination: Path) -> None:
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(*sorted(_IGNORED_NAMES)),
        symlinks=False,
    )


def _configure_implementation_unsafe_lint(project: Path) -> None:

    manifest = project / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8")
    data = tomllib.loads(text)
    lints = data.get("lints", {})
    if lints.get("workspace"):
        raise ValueError("implementation workspace-inherited lints are not supported")
    rust_lints = lints.get("rust", {})
    if "unsafe_code" in rust_lints:
        value = rust_lints["unsafe_code"]
        level = value.get("level") if isinstance(value, dict) else value
        if level in {"forbid", "deny"}:
            text = text.replace('unsafe_code = "forbid"', 'unsafe_code = "warn"', 1)
            text = text.replace('unsafe_code = "deny"', 'unsafe_code = "warn"', 1)
            text = text.replace('level = "forbid"', 'level = "warn"', 1)
            text = text.replace('level = "deny"', 'level = "warn"', 1)
            manifest.write_text(text, encoding="utf-8")
        return
    if "[lints.rust]" in text:
        text = text.replace("[lints.rust]", '[lints.rust]\nunsafe_code = "warn"', 1)
    else:
        text += '\n[lints.rust]\nunsafe_code = "warn"\n'
    manifest.write_text(text, encoding="utf-8")


def _copy_translation_context(workspace: Path, destination: Path) -> None:
    destination.mkdir(parents=True)
    for name in (
        "entity-index.json",
        "translation-entities.json",
        "entity-dependencies.json",
        "translation-plan.json",
        "translation-state.json",
        "translation-report.json",
    ):
        source = workspace / name
        if source.is_file():
            shutil.copy2(source, destination / name)
    hints = workspace / "semantic_hints"
    if hints.is_dir():
        shutil.copytree(hints, destination / "semantic_hints")


def _require_cargo_project(path: Path, label: str) -> None:
    if not path.is_dir() or not (path / "Cargo.toml").is_file():
        raise FileNotFoundError(f"{label} is not a Cargo project: {path}")


def _cargo_package_name(project: Path) -> str:
    data = tomllib.loads((project / "Cargo.toml").read_text(encoding="utf-8"))
    package = data.get("package")
    name = package.get("name") if isinstance(package, dict) else None
    if not isinstance(name, str) or not name.strip():
        raise ValueError(f"{project / 'Cargo.toml'}: missing package.name")
    return name


def _add_implementation_dependency(harness: Path, implementation: Path) -> None:
    manifest = harness / "Cargo.toml"
    text = manifest.read_text(encoding="utf-8")
    marker = "# @C2SAFETY:CORRECTNESS_REPAIR_DEPENDENCY"
    if marker in text:
        return
    package_name = _cargo_package_name(implementation)
    relative_path = Path("..") / implementation.name
    block = (
        f"\n{marker}\n[dependencies.c2safety_impl]\n"
        f"package = {json.dumps(package_name)}\n"
        f"path = {json.dumps(relative_path.as_posix())}\n"
    )
    manifest.write_text(text.rstrip() + "\n" + block, encoding="utf-8")


def _seed_missing_module_bridges(harness: Path, implementation: Path) -> None:

    lib_rs = harness / "src" / "lib.rs"
    if not lib_rs.is_file():
        return
    declarations = re.findall(
        r"^\s*pub\s+mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
        lib_rs.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if not declarations:
        return
    source_root = implementation / "src"
    candidates: dict[str, list[Path]] = {}
    for source in source_root.rglob("*.rs"):
        if source.name == "lib.rs" or source.name == "mod.rs":
            continue
        candidates.setdefault(source.stem, []).append(source)
    for name in declarations:
        target = harness / "src" / f"{name}.rs"
        if target.exists():
            continue
        matches = sorted(candidates.get(name, ()), key=lambda p: (len(p.relative_to(source_root).parts), str(p)))
        if not matches:
            continue
        source = matches[0]
        module_path = "::".join(source.relative_to(source_root).with_suffix("").parts)
        target.write_text(
            "// @C2SAFETY:GENERATED_BRIDGE seed; adapt only the public interface.\n"
            f"pub use c2safety_impl::{module_path}::*;\n",
            encoding="utf-8",
        )


def _protected_test_files(harness: Path, targets: tuple[str, ...]) -> tuple[Path, ...]:
    manifest_data = tomllib.loads((harness / "Cargo.toml").read_text(encoding="utf-8"))
    selected: set[Path] = set()
    found_targets: set[str] = set()
    for entry in manifest_data.get("test", []):
        if not isinstance(entry, dict) or entry.get("name") not in targets:
            continue
        found_targets.add(str(entry["name"]))
        value = entry.get("path")
        if isinstance(value, str):
            selected.add((harness / value).resolve())
    for target in targets:
        conventional = harness / "tests" / f"{target}.rs"
        if conventional.is_file():
            selected.add(conventional.resolve())
            found_targets.add(target)
        binary = harness / "src" / "bin" / f"{target}.rs"
        binary_main = harness / "src" / "bin" / target / "main.rs"
        if binary.is_file():
            selected.add(binary.resolve())
            found_targets.add(target)
        elif binary_main.is_file():
            selected.add(binary_main.resolve())
            found_targets.add(target)
    missing = [target for target in targets if target not in found_targets]
    if missing:
        raise ValueError(f"unknown Cargo test target(s): {', '.join(missing)}")




    selected.update(
        path.resolve()
        for path in harness.rglob("*.rs")
        if not is_ignored_project_path(path, harness)
        and not _is_generated_bridge(path)
    )
    selected.add((harness / "Cargo.toml").resolve())
    return tuple(sorted(selected))


def _relative_key(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _is_generated_bridge(path: Path) -> bool:

    try:
        with path.open(encoding="utf-8") as source:
            first_line = source.readline()
    except (OSError, UnicodeError):
        return False
    return first_line.startswith("// @C2SAFETY:GENERATED_BRIDGE seed")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_cargo_target_kind(project: Path, target: str) -> str:

    manifest = project / "Cargo.toml"
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    if any(
        isinstance(entry, dict) and entry.get("name") == target
        for entry in data.get("test", [])
    ):
        return "test"
    if any(
        isinstance(entry, dict) and entry.get("name") == target
        for entry in data.get("bin", [])
    ):
        return "bin"

    kinds: set[str] = set()
    if (project / "tests" / f"{target}.rs").is_file():
        kinds.add("test")
    if (project / "src" / "bin" / f"{target}.rs").is_file() or (
        project / "src" / "bin" / target / "main.rs"
    ).is_file():
        kinds.add("bin")
    package = data.get("package")
    package_name = package.get("name") if isinstance(package, dict) else None
    if target == package_name and (project / "src" / "main.rs").is_file():
        kinds.add("bin")
    if not kinds:
        raise ValueError(f"unknown Cargo test or binary target: {target}")
    if len(kinds) > 1:
        raise ValueError(
            f"ambiguous Cargo target {target!r}; it exists as both test and binary"
        )
    return kinds.pop()


