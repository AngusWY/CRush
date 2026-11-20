from __future__ import annotations

import json
import re
import shutil
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

from .config import (
    ENTITY_DEPENDENCIES_NAME,
    RUST_MODULE_LAYOUT_NAME,
    RUST_PROJECT_DIR_NAME,
    TRANSLATION_ENTITIES_NAME,
)
from .models import PreprocessManifest


_RUST_KEYWORDS = frozenset(
    {
        "Self",
        "abstract",
        "as",
        "async",
        "await",
        "become",
        "box",
        "break",
        "const",
        "continue",
        "crate",
        "do",
        "dyn",
        "else",
        "enum",
        "extern",
        "false",
        "final",
        "fn",
        "for",
        "gen",
        "if",
        "impl",
        "in",
        "let",
        "loop",
        "macro",
        "match",
        "mod",
        "move",
        "mut",
        "override",
        "priv",
        "pub",
        "ref",
        "return",
        "static",
        "struct",
        "super",
        "trait",
        "true",
        "try",
        "type",
        "typeof",
        "union",
        "unsafe",
        "unsized",
        "use",
        "virtual",
        "where",
        "while",
        "yield",
    }
)


class RustModuleLayoutError(RuntimeError):
    pass


class RustModuleLayoutBuilder:


    def __init__(self, *, manifest: PreprocessManifest) -> None:
        self.manifest = manifest
        self.translation_entities_path = (
            manifest.workspace / TRANSLATION_ENTITIES_NAME
        )
        self.dependencies_path = (
            manifest.workspace / ENTITY_DEPENDENCIES_NAME
        )
        self.output_path = (
            manifest.workspace / RUST_MODULE_LAYOUT_NAME
        )
        self.rust_project = (
            manifest.workspace / RUST_PROJECT_DIR_NAME
        )

    def run(self) -> Path:
        entities = self._read_translation_entities()
        entity_ids = {self._entity_id(entity) for entity in entities}
        dependencies, co_location_owners = self._read_dependencies(
            entity_ids
        )
        modules: dict[str, dict[str, Any]] = {}
        placements: dict[str, dict[str, str]] = {}
        logical_sources_by_rust_file: dict[str, set[str]] = defaultdict(
            set
        )

        base_placements: dict[int, dict[str, str]] = {}
        for entity in entities:
            entity_id = self._entity_id(entity)
            source = entity.get("origin") or entity.get("source")
            if not isinstance(source, dict):
                raise RustModuleLayoutError(
                    f"translation entity {entity_id} has no source"
                )
            source_rel_path = self._source_rel_path(
                entity_id, source.get("rel_path")
            )
            placement_rel_path = source_rel_path
            module_rel_path = source.get("module_rel_path")
            if module_rel_path is not None:
                placement_rel_path = self._module_rel_path(
                    entity_id,
                    module_rel_path,
                )
            elif source_rel_path.suffix.lower() == ".inc":
                raise RustModuleLayoutError(
                    f"translation entity {entity_id} with .inc source has no "
                    "module_rel_path"
                )
            base_placements[entity_id] = self._placement(placement_rel_path)

        resolved_placements: dict[int, dict[str, str]] = {}
        for entity_id in sorted(base_placements):
            owner_id = co_location_owners.get(entity_id, entity_id)
            placement = base_placements[owner_id]
            resolved_placements[entity_id] = placement
            rust_file = placement["rust_file"]
            logical_source = placement["logical_source"]
            logical_sources_by_rust_file[rust_file].add(logical_source)
            if len(logical_sources_by_rust_file[rust_file]) > 1:
                sources = sorted(logical_sources_by_rust_file[rust_file])
                raise RustModuleLayoutError(
                    "multiple unrelated C paths map to the same Rust file "
                    f"{rust_file}: {sources}"
                )

            modules.setdefault(
                rust_file,
                {
                    "module": placement["module"],
                    "rust_file": rust_file,
                    "entity_ids": [],
                },
            )["entity_ids"].append(entity_id)
            placements[str(entity_id)] = {
                "module": placement["module"],
                "rust_file": rust_file,
            }

        self._validate_dependency_directions(
            dependencies,
            resolved_placements,
        )

        module_list = sorted(
            modules.values(), key=lambda item: item["rust_file"]
        )
        for module in module_list:
            module["entity_ids"].sort()

        result = {
            "version": 1,
            "rust_project": str(self.rust_project),
            "modules": module_list,
            "entity_placements": placements,
        }
        self._reset_rust_project()
        self._write_crate_scaffold(module_list)
        self._write_result(result)
        return self.output_path

    def _read_dependencies(
        self,
        entity_ids: set[int],
    ) -> tuple[dict[int, set[int]], dict[int, int]]:
        try:
            data = json.loads(
                self.dependencies_path.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise RustModuleLayoutError(
                f"failed to read entity dependencies "
                f"{self.dependencies_path}: {exc}"
            ) from exc

        rows = data.get("entities")
        if not isinstance(rows, list):
            raise RustModuleLayoutError(
                "entity dependencies file has no entities array: "
                f"{self.dependencies_path}"
            )
        dependencies: dict[int, set[int]] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise RustModuleLayoutError(
                    "entity dependency row must be an object"
                )
            try:
                entity_id = int(row["entity_id"])
                dependency_ids = {int(item) for item in row["dependencies"]}
            except (KeyError, TypeError, ValueError) as exc:
                raise RustModuleLayoutError(
                    f"invalid entity dependency row: {row!r}"
                ) from exc
            if entity_id not in entity_ids or not dependency_ids <= entity_ids:
                raise RustModuleLayoutError(
                    f"entity dependency row references unknown entities: {row!r}"
                )
            dependencies[entity_id] = dependency_ids
        missing_rows = entity_ids - set(dependencies)
        if missing_rows:
            raise RustModuleLayoutError(
                f"missing dependency rows for entities: {sorted(missing_rows)}"
            )

        owners: dict[int, int] = {}
        raw_groups = data.get("co_location_groups", [])
        if not isinstance(raw_groups, list):
            raise RustModuleLayoutError(
                "entity dependencies co_location_groups must be a list"
            )
        for group in raw_groups:
            if not isinstance(group, dict):
                raise RustModuleLayoutError(
                    "co-location group must be an object"
                )
            try:
                owner_id = int(group["owner_entity_id"])
                member_ids = [
                    int(item) for item in group["member_entity_ids"]
                ]
            except (KeyError, TypeError, ValueError) as exc:
                raise RustModuleLayoutError(
                    f"invalid co-location group: {group!r}"
                ) from exc
            if owner_id not in entity_ids or not set(member_ids) <= entity_ids:
                raise RustModuleLayoutError(
                    f"co-location group references unknown entities: {group!r}"
                )
            for member_id in member_ids:
                previous_owner = owners.get(member_id)
                if previous_owner is not None and previous_owner != owner_id:
                    raise RustModuleLayoutError(
                        f"entity {member_id} has conflicting co-location owners "
                        f"{previous_owner} and {owner_id}"
                    )
                owners[member_id] = owner_id
        return dependencies, owners

    @staticmethod
    def _validate_dependency_directions(
        dependencies: dict[int, set[int]],
        placements: dict[int, dict[str, str]],
    ) -> None:
        for entity_id, dependency_ids in dependencies.items():
            rust_file = placements[entity_id]["rust_file"]
            if not rust_file.startswith("src/"):
                continue
            for dependency_id in sorted(dependency_ids):
                dependency_file = placements[dependency_id]["rust_file"]
                if dependency_file.startswith("tests/"):
                    raise RustModuleLayoutError(
                        f"library entity {entity_id} in {rust_file} depends on "
                        f"test entity {dependency_id} in {dependency_file}"
                    )

    def _placement(
        self, source_rel_path: PurePosixPath
    ) -> dict[str, str]:
        logical_source = source_rel_path.with_suffix("")
        if source_rel_path.suffix.lower() == ".h":
            c_candidate = (
                self.manifest.project_root
                / Path(*source_rel_path.with_suffix(".c").parts)
            )
            if c_candidate.is_file():
                logical_source = source_rel_path.with_suffix("")

        parts = list(logical_source.parts)
        if not parts:
            raise RustModuleLayoutError(
                f"cannot map empty source path {source_rel_path}"
            )

        if parts[0] == "tests":
            module_parts = [
                self._sanitize_module_part(part)
                for part in parts[1:]
            ]
            if not module_parts:
                module_parts = ["test"]
            rust_parts = ["tests", *module_parts]
            module = "::".join(module_parts)
        else:
            if parts[0] == "src":
                parts = parts[1:]
            module_parts = [
                self._sanitize_module_part(part) for part in parts
            ]
            if not module_parts:
                module_parts = ["root"]
            rust_parts = ["src", *module_parts]
            module = "crate::" + "::".join(module_parts)

        rust_file = PurePosixPath(*rust_parts).with_suffix(".rs")
        return {
            "module": module,
            "rust_file": rust_file.as_posix(),
            "logical_source": logical_source.as_posix(),
        }

    def _write_crate_scaffold(
        self, modules: list[dict[str, Any]]
    ) -> None:
        package_name = self._package_name(
            self.manifest.project_root.name
        )
        self._write_text(
            self.rust_project / "Cargo.toml",
            "\n".join(
                [
                    "[package]",
                    f'name = "{package_name}"',
                    'version = "0.1.0"',
                    'edition = "2021"',
                    "",
                    "[lib]",
                    'path = "src/lib.rs"',
                    "",
                    "[dependencies]",
                    "",
                ]
            ),
        )

        crate_modules = [
            str(module["module"]).removeprefix("crate::")
            for module in modules
            if str(module["module"]).startswith("crate::")
        ]
        module_tree = self._module_tree(crate_modules)
        self._write_module_tree(
            self.rust_project / "src", module_tree, is_root=True
        )
        test_modules = [
            str(module["module"])
            for module in modules
            if not str(module["module"]).startswith("crate::")
        ]
        self._write_test_module_trees(test_modules)

        for module in modules:
            rust_file = self.rust_project / str(module["rust_file"])
            if not rust_file.exists():
                self._write_text(rust_file, "")

    def _write_module_tree(
        self,
        directory: Path,
        tree: dict[str, dict[str, Any]],
        *,
        is_root: bool,
    ) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        declarations = [
            f"pub mod {name};" for name in sorted(tree)
        ]
        if is_root:
            module_file = directory / "lib.rs"
        else:
            module_file = directory.with_suffix(".rs")

        existing_content = ""
        if module_file.is_file():
            existing_content = module_file.read_text(encoding="utf-8")
        content = "\n".join(declarations)
        if content:
            content += "\n"
        if existing_content and not content:
            content = existing_content
        self._write_text(module_file, content)

        for name, subtree in tree.items():
            if not subtree:
                continue
            self._write_module_tree(
                directory / name, subtree, is_root=False
            )

    def _write_test_module_trees(self, module_names: list[str]) -> None:
        tree = self._module_tree(
            [
                module_name
                for module_name in module_names
                if "::" in module_name
            ]
        )
        for name, subtree in tree.items():
            if subtree:
                self._write_module_tree_mod_rs(
                    self.rust_project / "tests" / name,
                    subtree,
                )

    def _write_module_tree_mod_rs(
        self,
        directory: Path,
        tree: dict[str, dict[str, Any]],
    ) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        declarations = [
            f"pub mod {name};" for name in sorted(tree)
        ]
        content = "\n".join(declarations)
        if content:
            content += "\n"
        self._write_text(directory / "mod.rs", content)

        for name, subtree in tree.items():
            if not subtree:
                continue
            self._write_module_tree_mod_rs(directory / name, subtree)

    @staticmethod
    def _module_tree(
        module_names: list[str],
    ) -> dict[str, dict[str, Any]]:
        tree: dict[str, dict[str, Any]] = {}
        for module_name in sorted(set(module_names)):
            cursor = tree
            for part in module_name.split("::"):
                if part:
                    cursor = cursor.setdefault(part, {})
        return tree

    def _reset_rust_project(self) -> None:
        if self.rust_project.exists() and not self.rust_project.is_dir():
            raise RustModuleLayoutError(
                f"Rust project path is not a directory: "
                f"{self.rust_project}"
            )
        try:
            if self.rust_project.exists():
                shutil.rmtree(self.rust_project)
            self.rust_project.mkdir(parents=True)
        except OSError as exc:
            raise RustModuleLayoutError(
                f"failed to reset Rust project {self.rust_project}: {exc}"
            ) from exc

    def _read_translation_entities(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(
                self.translation_entities_path.read_text(
                    encoding="utf-8"
                )
            )
        except (OSError, json.JSONDecodeError) as exc:
            raise RustModuleLayoutError(
                "failed to read translation entities "
                f"{self.translation_entities_path}: {exc}"
            ) from exc
        entities = data.get("entities")
        if not isinstance(entities, list):
            raise RustModuleLayoutError(
                "translation entities file has no entities array: "
                f"{self.translation_entities_path}"
            )
        return entities

    def _module_rel_path(
        self,
        entity_id: int,
        value: Any,
    ) -> PurePosixPath:
        if not isinstance(value, str) or not value:
            raise RustModuleLayoutError(
                f"translation entity {entity_id} has no module_rel_path"
            )
        path = PurePosixPath(value)
        if (
            path.is_absolute()
            or ".." in path.parts
            or path.suffix.lower() != ".c"
        ):
            raise RustModuleLayoutError(
                f"translation entity {entity_id} has invalid "
                f"module_rel_path: {value}"
            )
        compile_unit_paths = {
            PurePosixPath(unit.source_rel_path.as_posix())
            for unit in self.manifest.units
        }
        if path not in compile_unit_paths:
            raise RustModuleLayoutError(
                f"translation entity {entity_id} module_rel_path is not a "
                f"compile unit: {value}"
            )
        return path

    @staticmethod
    def _source_rel_path(
        entity_id: int, value: Any
    ) -> PurePosixPath:
        if not isinstance(value, str) or not value:
            raise RustModuleLayoutError(
                f"translation entity {entity_id} has no source rel_path"
            )
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts:
            raise RustModuleLayoutError(
                f"translation entity {entity_id} has invalid source "
                f"rel_path: {value}"
            )
        if path.suffix.lower() not in {".c", ".h", ".inc"}:
            raise RustModuleLayoutError(
                f"translation entity {entity_id} uses unsupported "
                f"source file: {value}"
            )
        return path

    @staticmethod
    def _entity_id(entity: dict[str, Any]) -> int:
        try:
            return int(entity["id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RustModuleLayoutError(
                f"translation entity has invalid id: {entity!r}"
            ) from exc

    @staticmethod
    def _sanitize_module_part(value: str) -> str:
        part = re.sub(r"[^A-Za-z0-9_]", "_", value)
        part = re.sub(r"_+", "_", part).strip("_").lower()
        if not part:
            part = "module"
        if part[0].isdigit():
            part = f"m_{part}"
        if part in _RUST_KEYWORDS:
            part += "_"
        return part

    @classmethod
    def _package_name(cls, value: str) -> str:
        name = cls._sanitize_module_part(value).replace("_", "-")
        return f"{name}-translated"

    def _write_result(self, result: dict[str, Any]) -> None:
        temporary_path = self.output_path.with_suffix(
            self.output_path.suffix + ".tmp"
        )
        try:
            temporary_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.output_path)
        except OSError as exc:
            raise RustModuleLayoutError(
                f"failed to write Rust module layout "
                f"{self.output_path}: {exc}"
            ) from exc

    @staticmethod
    def _write_text(path: Path, content: str) -> None:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        except OSError as exc:
            raise RustModuleLayoutError(
                f"failed to write Rust scaffold file {path}: {exc}"
            ) from exc
