from __future__ import annotations

import re
from pathlib import Path

from .models import EntityPlacement, TranslationTask


class ImportManager:


    def __init__(
        self,
        *,
        placements: dict[int, EntityPlacement],
        exports_by_entity: dict[int, tuple[str, ...]],
        support_exports_by_entity: dict[int, tuple[str, ...]] | None = None,
        rust_by_entity: dict[int, str] | None = None,
        skip_dependency_ids: set[int] | frozenset[int] = frozenset(),
        rust_project: Path | str | None = None,
        package_name: str | None = None,
    ) -> None:
        if package_name is None and rust_project is not None:
            package_name = read_package_name(Path(rust_project) / "Cargo.toml")
        self.placements = dict(placements)
        self.exports_by_entity = dict(exports_by_entity)
        self.support_exports_by_entity = dict(support_exports_by_entity or {})
        self.rust_by_entity = dict(rust_by_entity or {})
        self.skip_dependency_ids = frozenset(skip_dependency_ids)
        self.package_name = package_name

    def imports_for_task(
        self,
        task: TranslationTask,
        *,
        dependency_ids: tuple[int, ...] | None = None,
    ) -> tuple[str, ...]:
        imports: set[str] = set()
        imported_names: set[str] = set()
        local_export_names = set(task.expected_exports)
        for dependency_id in dependency_ids or task.dependency_ids:
            if dependency_id in self.skip_dependency_ids:
                continue
            dependency_placement = self._dependency_placement(dependency_id)
            if _same_module(task.placement, dependency_placement):
                continue
            exports = self._dependency_exports(dependency_id)
            for exported_name in exports:
                if exported_name in local_export_names:
                    continue
                if exported_name in imported_names:
                    continue
                imported_names.add(exported_name)
                imports.update(
                    use_lines_for_dependency(
                        current=task.placement,
                        dependency=dependency_placement,
                        exported_name=exported_name,
                        package_name=self.package_name,
                    )
                )
        return tuple(sorted(imports))

    def _dependency_placement(self, dependency_id: int) -> EntityPlacement:
        try:
            return self.placements[dependency_id]
        except KeyError as exc:
            raise ValueError(
                f"Missing placement for dependency entity {dependency_id}"
            ) from exc

    def _dependency_exports(self, dependency_id: int) -> tuple[str, ...]:
        try:
            exports = (
                *self.exports_by_entity[dependency_id],
                *self.support_exports_by_entity.get(dependency_id, ()),
                *_public_items_from_rust_code(self.rust_by_entity.get(dependency_id, "")),
            )
        except KeyError as exc:
            raise ValueError(
                f"Missing exported Rust items for dependency entity {dependency_id}"
            ) from exc
        normalized = tuple(name.strip() for name in exports if name.strip())
        if not normalized:
            raise ValueError(
                f"Dependency entity {dependency_id} has no exported Rust items"
            )
        merged = tuple(dict.fromkeys(normalized))
        for name in merged:
            _validate_exported_name(name, dependency_id)
        return merged


def read_package_name(cargo_toml: Path) -> str:
    if not cargo_toml.is_file():
        raise FileNotFoundError(cargo_toml)

    in_package_section = False
    for raw_line in cargo_toml.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            in_package_section = line == "[package]"
            continue
        if not in_package_section or not line.startswith("name"):
            continue
        match = re.match(r'name\s*=\s*"([^"]+)"\s*$', line)
        if match:
            return _crate_identifier(match.group(1))

    raise ValueError(f"Failed to read package.name from {cargo_toml}")


def use_lines_for_dependency(
    *,
    current: EntityPlacement,
    dependency: EntityPlacement,
    exported_name: str,
    package_name: str | None = None,
) -> tuple[str, ...]:
    _validate_exported_name(exported_name, dependency.entity_id)

    if _same_module(current, dependency):
        raise ValueError("same-module dependencies do not require use lines")

    dependency_module = dependency.module_path
    if _is_crate_module(dependency_module):
        if _is_crate_module(current.module_path):
            prefix = "::".join(dependency_module)
        else:
            if package_name is None:
                raise ValueError(
                    "package_name is required when importing crate modules "
                    "from non-crate modules"
                )
            prefix = "::".join((package_name, *dependency_module[1:]))
        return (f"use {prefix}::{exported_name};",)

    relative_prefix = _relative_non_crate_module_prefix(
        current.module_path,
        dependency_module,
    )
    if relative_prefix is not None:
        return (f"use {relative_prefix}::{exported_name};",)

    if _is_top_level_non_crate_module(current.module_path) and dependency_module:
        root_module = dependency_module[0]
        prefix = "::".join(dependency_module)
        return (
            f"mod {root_module};",
            f"use {prefix}::{exported_name};",
        )

    raise ValueError(
        "Cannot import dependency from non-crate module "
        f"{'::'.join(dependency_module)!r}"
    )


def _same_module(current: EntityPlacement, dependency: EntityPlacement) -> bool:
    return (
        current.rust_file == dependency.rust_file
        or current.module_path == dependency.module_path
    )


def _is_crate_module(module_path: tuple[str, ...]) -> bool:
    return bool(module_path) and module_path[0] == "crate"


def _is_top_level_non_crate_module(module_path: tuple[str, ...]) -> bool:
    return len(module_path) == 1 and not _is_crate_module(module_path)


def _relative_non_crate_module_prefix(
    current: tuple[str, ...],
    dependency: tuple[str, ...],
) -> str | None:
    if _is_crate_module(current) or _is_crate_module(dependency):
        return None

    common_len = 0
    for current_part, dependency_part in zip(current, dependency):
        if current_part != dependency_part:
            break
        common_len += 1
    if common_len == 0:
        return None

    upward = ("super",) * (len(current) - common_len)
    downward = dependency[common_len:]
    parts = (*upward, *downward)
    if not parts:
        return None
    return "::".join(parts)


def _crate_identifier(package_name: str) -> str:
    return package_name.replace("-", "_")


def _validate_exported_name(name: str, entity_id: int) -> None:
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        raise ValueError(
            f"Invalid exported Rust item name for entity {entity_id}: {name!r}"
        )


def _public_items_from_rust_code(rust_code: str) -> tuple[str, ...]:
    if not rust_code.strip():
        return ()
    names: list[str] = []
    identifier = r"(?:r#)?([A-Za-z_][A-Za-z0-9_]*)\b"
    for line in _top_level_lines(rust_code):
        stripped = line.strip()
        match = re.match(
            r"pub\s+"
            r"(?:unsafe\s+)?"
            r"(?:struct|enum|type|fn|trait)\s+"
            + identifier,
            stripped,
        )
        if match:
            names.append(match.group(1))
            continue
        match = re.match(
            r"pub\s+"
            r"(?:static|const)\s+"
            r"(?:mut\s+)?"
            + identifier,
            stripped,
        )
        if match:
            names.append(match.group(1))
    return tuple(dict.fromkeys(names))


def _top_level_lines(rust_code: str) -> tuple[str, ...]:
    lines: list[str] = []
    depth = 0
    for raw_line in rust_code.splitlines():
        stripped = raw_line.lstrip()
        if depth == 0 and stripped.startswith("pub "):
            lines.append(raw_line)
        depth += raw_line.count("{")
        depth -= raw_line.count("}")
        if depth < 0:
            depth = 0
    return tuple(lines)
