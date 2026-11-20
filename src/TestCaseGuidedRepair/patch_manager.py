from __future__ import annotations

import json
import re
from pathlib import Path

from .entities import EntityBlock, find_entity
from .models import ChangeProposal
from .safety import _mask_comments_and_literals
from .workspace import RepairWorkspace, is_ignored_project_path


class PatchManager:


    def __init__(self, workspace: RepairWorkspace) -> None:
        self.workspace = workspace
        self.allowed_roots = (
            workspace.implementation.resolve(),
            workspace.harness.resolve(),
        )

    def apply(self, proposal: ChangeProposal, *, phase: str, attempt: int) -> list[str]:
        resolved: list[tuple[Path, str]] = []
        if phase == "bridge":
            if proposal.entity_replacements or not proposal.edits:
                raise ValueError("bridge phase requires harness file edits only")
            seen: set[Path] = set()
            for edit in proposal.edits:
                target = self._resolve_target(edit.path)
                self._validate_phase_root(target, phase)
                self._reject_protected(target)
                if target in seen:
                    raise ValueError(
                        f"proposal edits the same file more than once: {edit.path}"
                    )
                seen.add(target)
                content = edit.content
                if (self.workspace.test_mode == "c" and target.suffix == ".rs"
                        and self.workspace.harness / "ffi" in target.parents):
                    content = self._normalize_c_bridge_rust(content)
                resolved.append((target, content))
            self._validate_bridge_reference(resolved)
            if self.workspace.test_mode == "c":
                if not proposal.interface_mappings:
                    raise ValueError("C bridge requires interface_mappings")
                for mapping in proposal.interface_mappings:
                    find_entity(self.workspace.implementation, mapping["entity_id"])
                resolved.append((self.workspace.root / "interface-map.json", json.dumps(
                    {"version": 1, "mappings": list(proposal.interface_mappings)}, indent=2)))
        elif phase == "behavior":
            if proposal.edits or not proposal.entity_replacements:
                raise ValueError(
                    "behavior phase requires one or more entity replacements"
                )
            replacements: list[tuple[Path, EntityBlock, str]] = []
            seen_entities: set[int] = set()
            for replacement in proposal.entity_replacements:
                if replacement.entity_id in seen_entities:
                    raise ValueError(
                        f"entity {replacement.entity_id} is replaced more than once"
                    )
                seen_entities.add(replacement.entity_id)
                target, block = find_entity(
                    self.workspace.implementation.resolve(), replacement.entity_id
                )
                self._validate_phase_root(target, phase)
                self._reject_protected(target)
                if block.code_sha256 != replacement.expected_sha256:
                    raise ValueError(
                        f"entity {replacement.entity_id} changed since it was read"
                    )
                code = replacement.rust_code.strip()
                if (
                    "@C2SAFETY:ENTITY_START" in code
                    or "@C2SAFETY:ENTITY_END" in code
                ):
                    raise ValueError(
                        "entity replacement must not contain entity markers"
                    )
                replacements.append((target, block, code))



            by_file: dict[Path, list[tuple[EntityBlock, str]]] = {}
            for target, block, code in replacements:
                by_file.setdefault(target, []).append((block, code))
            for target, items in by_file.items():
                text = target.read_text(encoding="utf-8")
                for block, code in sorted(
                    items, key=lambda item: item[0].code_start, reverse=True
                ):
                    text = text[: block.code_start] + code + text[block.code_end :]
                resolved.append((target, text))
        else:
            raise ValueError(f"unknown repair phase: {phase}")

        original_build = None
        if phase == "bridge" and self.workspace.test_mode == "c":
            original_build = json.loads((self.workspace.harness / "build.json").read_text())
        snapshot_dir = self.workspace.snapshots / f"{phase}-{attempt:03d}"
        snapshot_dir.mkdir(parents=True, exist_ok=False)
        manifest: list[dict[str, str | bool]] = []
        try:
            for target, _ in resolved:
                existed = target.is_file()
                relative = target.relative_to(self.workspace.root).as_posix()
                manifest.append({"path": relative, "existed": existed})
                if existed:
                    backup = snapshot_dir / relative
                    backup.parent.mkdir(parents=True, exist_ok=True)
                    backup.write_bytes(target.read_bytes())
            for target, content in resolved:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content.rstrip() + "\n", encoding="utf-8")
            self.workspace.assert_protected_unchanged()
            if original_build is not None:
                from .c_runner import read_build_config
                read_build_config(self.workspace)
                candidate = json.loads((self.workspace.harness / "build.json").read_text())
                if any(candidate.get(key) != original_build.get(key) for key in
                       ("entry", "target", "project_root", "ffi_project", "version",
                        "test_mode", "sources", "helpers", "compiler")):
                    raise ValueError("C bridge must preserve the selected test and project roots")
        except Exception:
            self._restore(snapshot_dir, manifest)
            raise
        (snapshot_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        return [
            target.relative_to(self.workspace.root).as_posix() for target, _ in resolved
        ]

    def _normalize_c_bridge_rust(self, content: str) -> str:
        manifest = self.workspace.harness / "ffi" / "Cargo.toml"
        edition = "2021"
        if manifest.is_file():
            match = re.search(
                r'(?m)^\s*edition\s*=\s*["\'](?P<edition>\d{4})["\']\s*$',
                manifest.read_text(encoding="utf-8"),
            )
            if match:
                edition = match["edition"]
        if int(edition) >= 2024:
            content = re.sub(r"#\[\s*no_mangle\s*\]", "#[unsafe(no_mangle)]", content)
        return content

    def _validate_phase_root(self, target: Path, phase: str) -> None:
        if phase == "bridge":
            required = self.workspace.harness.resolve()
            label = "harness"
            if self.workspace.test_mode == "c":
                ffi = required / "ffi"
                if ffi not in target.parents and target != required / "build.json":
                    raise ValueError("C bridge phase may only edit harness/ffi/ or harness/build.json")
        elif phase == "behavior":
            required = self.workspace.implementation.resolve()
            label = "implementation"
        else:
            raise ValueError(f"unknown repair phase: {phase}")
        if required not in target.parents:
            raise ValueError(f"{phase} phase may only edit {label}/ files")

    def _resolve_target(self, value: str) -> Path:
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"invalid edit path: {value}")
        target = (self.workspace.root / relative).resolve()
        if not any(
            target == root or root in target.parents for root in self.allowed_roots
        ):
            raise ValueError(f"edit path is outside approved roots: {value}")
        for root in self.allowed_roots:
            if root in target.parents and is_ignored_project_path(target, root):
                raise ValueError(f"edit path is out of repair scope: {value}")
        if target.exists() and target.is_symlink():
            raise ValueError(f"refusing to edit symlink: {value}")
        return target

    def _reject_protected(self, target: Path) -> None:
        key = target.relative_to(self.workspace.root).as_posix()
        if key in self.workspace.protected_hashes:
            raise ValueError(f"agent cannot modify protected test file: {key}")

    def _validate_bridge_reference(self, edits: list[tuple[Path, str]]) -> None:

        harness = self.workspace.harness.resolve()
        candidates = {
            path: content
            for path, content in edits
            if harness in path.parents and path.suffix == ".rs"
        }
        if not candidates:
            return
        for path in harness.rglob("*.rs"):
            if is_ignored_project_path(path, harness):
                continue
            key = path.relative_to(self.workspace.root).as_posix()
            if key not in self.workspace.protected_hashes and path not in candidates:
                candidates[path] = path.read_text(encoding="utf-8")
        if not any(
            re.search(
                r"\bc2safety_impl\s*(?:::|;|\bas\b)",
                _mask_comments_and_literals(content),
            )
            for content in candidates.values()
        ):
            raise ValueError("bridge modules must reference the real c2safety_impl")

    @staticmethod
    def _restore(snapshot_dir: Path, manifest: list[dict[str, str | bool]]) -> None:
        for entry in manifest:
            target = snapshot_dir.parent.parent / str(entry["path"])
            backup = snapshot_dir / str(entry["path"])
            if bool(entry["existed"]):
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(backup.read_bytes())
            elif target.exists():
                target.unlink()
