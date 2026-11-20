from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .models import EntityPackage, EntityPlacement, HumanComment, JsonDict

_ANCHOR_ID_PATTERN = re.compile(r"^SH_E[1-9][0-9]*_S[1-9][0-9]*$")
_LIAN_TEMPORARY_NAME_PATTERN = re.compile(r"^%vv[0-9]+$")


def load_entity_packages(workspace: Path | str) -> dict[int, EntityPackage]:


    workspace_path = Path(workspace)
    manifest_path = workspace_path / "semantic_hints" / "manifest.json"
    manifest = _load_json_object(manifest_path)
    manifest_version = _require_manifest_version(manifest, manifest_path)
    _require_str(manifest, "hint_store_file", manifest_path)
    human_comments = (
        _load_human_comment_store(manifest, manifest_path)
        if manifest_version >= 3
        else {}
    )
    entries = _require_list(manifest, "entities", manifest_path)

    packages: dict[int, EntityPackage] = {}
    for index, entry_value in enumerate(entries):
        entry = _as_object(entry_value, f"{manifest_path}: entities[{index}]")
        entity_id = _require_int(entry, "entity_id", manifest_path)
        kind = _require_str(entry, "kind", manifest_path)
        package_file = _require_str(entry, "package_file", manifest_path)
        hint_count = _require_int(entry, "hint_count", manifest_path)
        human_comment_count = _optional_int(
            entry, "human_comment_count", manifest_path, default=0
        )
        package_path = _resolve_path(manifest_path.parent, package_file)

        if entity_id in packages:
            raise ValueError(f"Duplicate entity package in manifest: {entity_id}")

        package_json = _load_json_object(package_path)
        entity = _require_object(package_json, "entity", package_path)
        package_entity_id = _require_int(entity, "id", package_path)
        package_kind = _require_str(entity, "kind", package_path)
        if package_entity_id != entity_id:
            raise ValueError(
                f"{package_path} entity id {package_entity_id} does not match "
                f"manifest entity id {entity_id}"
            )
        if package_kind != kind:
            raise ValueError(
                f"{package_path} kind {package_kind!r} does not match "
                f"manifest kind {kind!r}"
            )

        package_version = _require_int(package_json, "version", package_path)
        if package_version != 4:
            raise ValueError(
                f"{package_path}: unsupported entity package version "
                f"{package_version!r}; expected 4; regenerate semantic hints"
            )
        hint_anchor_ids = _read_anchor_ids(
            package_json,
            key="hint_anchor_ids",
            path=package_path,
        )
        if len(hint_anchor_ids) != hint_count:
            raise ValueError(
                f"{package_path}: hint_anchor_ids count {len(hint_anchor_ids)} "
                f"does not match manifest hint_count {hint_count}"
            )
        human_comment_ids = (
            _read_string_ids(
                package_json,
                key="human_comment_ids",
                path=package_path,
            )
            if package_version >= 3
            else []
        )
        if len(human_comment_ids) != human_comment_count:
            raise ValueError(
                f"{package_path}: human_comment_ids count "
                f"{len(human_comment_ids)} does not match manifest "
                f"human_comment_count {human_comment_count}"
            )
        missing_comments = [
            comment_id
            for comment_id in human_comment_ids
            if comment_id not in human_comments
        ]
        if missing_comments:
            raise ValueError(
                f"{package_path}: unknown human comment IDs: "
                f"{', '.join(missing_comments)}"
            )
        original_c_source = _require_str(
            package_json, "original_c_source", package_path
        )
        raw_declaration_facts = entity.get("declaration_facts")
        declaration_facts = (
            _as_object(
                raw_declaration_facts,
                f"{package_path}: entity.declaration_facts",
            )
            if raw_declaration_facts is not None
            else None
        )
        is_static = (
            _require_bool(declaration_facts, "is_static", package_path)
            if declaration_facts is not None
            else bool(re.match(r"^\s*static\b", original_c_source))
        )
        is_extern = (
            _require_bool(declaration_facts, "is_extern", package_path)
            if declaration_facts is not None
            else bool(re.match(r"^\s*extern\b", original_c_source))
        )
        raw_export_names = entity.get("export_names", [])
        if not isinstance(raw_export_names, list) or any(
            not isinstance(item, str) or not item.strip()
            for item in raw_export_names
        ):
            raise ValueError(
                f"{package_path}: entity.export_names must be a list of "
                "non-empty strings"
            )
        raw_macro_context = package_json.get("macro_context", [])
        if not isinstance(raw_macro_context, list) or any(
            not isinstance(item, dict) for item in raw_macro_context
        ):
            raise ValueError(
                f"{package_path}: macro_context must be a list of objects"
            )
        packages[entity_id] = EntityPackage(
            entity_id=entity_id,
            kind=kind,
            name=_require_str(entity, "name", package_path),
            original_c_source=original_c_source,
            annotated_c_source=_require_str(
                package_json, "annotated_c_source", package_path
            ),
            hint_anchor_ids=tuple(hint_anchor_ids),
            package_file=package_path,
            human_comments=tuple(
                human_comments[comment_id]
                for comment_id in human_comment_ids
            ),
            is_static=is_static,
            is_extern=is_extern,
            export_names=tuple(dict.fromkeys(raw_export_names)),
            macro_context=tuple(
                dict(item) for item in raw_macro_context
            ),
        )

    return packages


def load_hint_store(workspace: Path | str) -> dict[str, JsonDict]:


    workspace_path = Path(workspace)
    manifest_path = workspace_path / "semantic_hints" / "manifest.json"
    manifest = _load_json_object(manifest_path)
    _require_manifest_version(manifest, manifest_path)
    hint_store_file = _require_str(manifest, "hint_store_file", manifest_path)
    store_path = _resolve_path(manifest_path.parent, hint_store_file)
    store = _load_json_object(store_path)
    version = _require_int(store, "version", store_path)
    if version != 1:
        raise ValueError(
            f"{store_path}: unsupported hint store version {version!r}; expected 1"
        )
    raw_hints = _require_object(store, "hints", store_path)

    hints: dict[str, JsonDict] = {}
    for anchor_id, value in raw_hints.items():
        if not isinstance(anchor_id, str):
            raise ValueError(f"{store_path}: hint store keys must be strings")
        _validate_anchor_id(anchor_id, store_path)
        hint = _as_object(value, f"{store_path}: hints[{anchor_id}]")
        hint_anchor_id = _require_str(hint, "anchor_id", store_path)
        if hint_anchor_id != anchor_id:
            raise ValueError(
                f"{store_path}: hint key {anchor_id!r} does not match "
                f"anchor_id {hint_anchor_id!r}"
            )
        hints[anchor_id] = hint
    return hints


def _load_human_comment_store(
    manifest: JsonDict,
    manifest_path: Path,
) -> dict[str, HumanComment]:
    store_file = _require_str(
        manifest, "human_comment_store_file", manifest_path
    )
    store_path = _resolve_path(manifest_path.parent, store_file)
    store = _load_json_object(store_path)
    version = _require_int(store, "version", store_path)
    if version != 1:
        raise ValueError(
            f"{store_path}: unsupported human comment store version "
            f"{version!r}; expected 1"
        )
    raw_comments = _require_object(store, "comments", store_path)
    comments: dict[str, HumanComment] = {}
    for comment_id, raw_value in raw_comments.items():
        value = _as_object(raw_value, f"{store_path}: comments[{comment_id}]")
        stored_id = _require_str(value, "id", store_path)
        if stored_id != comment_id:
            raise ValueError(
                f"{store_path}: comment key {comment_id!r} does not match "
                f"stored ID {stored_id!r}"
            )
        source = _require_object(value, "source", store_path)
        comments[comment_id] = HumanComment(
            comment_id=comment_id,
            kind=_require_str(value, "kind", store_path),
            path=_require_str(source, "path", store_path),
            rel_path=_require_str(source, "rel_path", store_path),
            start_line=_require_int(source, "start_line", store_path),
            end_line=_require_int(source, "end_line", store_path),
            text=_require_str(value, "text", store_path),
        )
    return comments


def load_entity_placements(workspace: Path | str) -> dict[int, EntityPlacement]:


    workspace_path = Path(workspace)
    layout_path = workspace_path / "rust-module-layout.json"
    layout = _load_json_object(layout_path)
    rust_project_value = _require_str(layout, "rust_project", layout_path)
    rust_project = _resolve_path(workspace_path, rust_project_value)
    placement_json = _require_object(layout, "entity_placements", layout_path)

    placements: dict[int, EntityPlacement] = {}
    for entity_id_text, value in placement_json.items():
        try:
            entity_id = int(entity_id_text)
        except ValueError as exc:
            raise ValueError(
                f"{layout_path}: invalid entity_placements key {entity_id_text!r}"
            ) from exc
        item = _as_object(value, f"{layout_path}: entity_placements[{entity_id_text}]")
        module = _require_str(item, "module", layout_path)
        rust_file_value = _require_str(item, "rust_file", layout_path)
        rust_file = _resolve_path(rust_project, rust_file_value)
        placements[entity_id] = EntityPlacement(
            entity_id=entity_id,
            rust_file=rust_file,
            module_path=_parse_module_path(module, layout_path),
        )

    return placements


def load_entity_dependencies(workspace: Path | str) -> dict[int, tuple[int, ...]]:


    workspace_path = Path(workspace)
    dependency_path = workspace_path / "entity-dependencies.json"
    dependency_json = _load_json_object(dependency_path)
    entries = _require_list(dependency_json, "entities", dependency_path)

    dependencies: dict[int, tuple[int, ...]] = {}
    for index, entry_value in enumerate(entries):
        entry = _as_object(entry_value, f"{dependency_path}: entities[{index}]")
        entity_id = _require_int(entry, "entity_id", dependency_path)
        if entity_id in dependencies:
            raise ValueError(f"Duplicate dependency entry for entity {entity_id}")
        deps_value = _require_list(entry, "dependencies", dependency_path)
        deps: list[int] = []
        seen: set[int] = set()
        for dep_index, dep_value in enumerate(deps_value):
            if not isinstance(dep_value, int):
                raise ValueError(
                    f"{dependency_path}: dependencies[{dep_index}] for entity "
                    f"{entity_id} must be an int"
                )
            if dep_value not in seen:
                seen.add(dep_value)
                deps.append(dep_value)
        dependencies[entity_id] = tuple(deps)

    return dependencies


def load_expected_exports(workspace: Path | str) -> dict[int, tuple[str, ...]]:


    workspace_path = Path(workspace)
    translation_path = workspace_path / "translation-entities.json"
    entity_index_path = workspace_path / "entity-index.json"
    translation_data = _load_json_object(translation_path)
    entity_index_data = _load_json_object(entity_index_path)

    raw_index_entities = _require_list(entity_index_data, "entities", entity_index_path)
    names_by_id: dict[int, str] = {}
    for index, value in enumerate(raw_index_entities):
        entity = _as_object(value, f"{entity_index_path}: entities[{index}]")
        entity_id = _require_int(entity, "canonical_stmt_id", entity_index_path)
        names_by_id[entity_id] = _rust_export_name(
            _require_str(entity, "name", entity_index_path)
        )

    raw_translation_entities = _require_list(
        translation_data, "entities", translation_path
    )
    expected: dict[int, tuple[str, ...]] = {}
    for index, value in enumerate(raw_translation_entities):
        entity = _as_object(value, f"{translation_path}: entities[{index}]")
        entity_id = _require_int(entity, "id", translation_path)
        kind = _require_str(entity, "kind", translation_path)
        primary_name = _rust_export_name(
            _require_str(entity, "name", translation_path)
        )
        raw_export_names = entity.get("export_names")
        if raw_export_names is not None:
            if not isinstance(raw_export_names, list):
                raise ValueError(
                    f"{translation_path}: entities[{index}].export_names "
                    "must be a list"
                )
            explicit_names: list[str] = []
            seen_explicit: set[str] = set()
            for export_index, raw_name in enumerate(raw_export_names):
                if not isinstance(raw_name, str) or not raw_name.strip():
                    raise ValueError(
                        f"{translation_path}: entities[{index}].export_names"
                        f"[{export_index}] must be a non-empty string"
                    )
                name = _rust_export_name(raw_name.strip())
                if name not in seen_explicit:
                    seen_explicit.add(name)
                    explicit_names.append(name)
            if not explicit_names:
                raise ValueError(
                    f"{translation_path}: entities[{index}].export_names "
                    "must not be empty"
                )
            expected[entity_id] = tuple(explicit_names)
            continue
        if kind != "global":
            expected[entity_id] = (primary_name,)
            continue

        raw_members = _require_list(entity, "member_entity_ids", translation_path)
        names: list[str] = []
        seen: set[str] = set()
        for member_index, member_value in enumerate(raw_members):
            if not isinstance(member_value, int):
                raise ValueError(
                    f"{translation_path}: entities[{index}].member_entity_ids"
                    f"[{member_index}] must be an int"
                )
            name = names_by_id.get(member_value)
            if name is None:
                raise ValueError(
                    f"{translation_path}: entity {entity_id} references "
                    f"unknown member entity {member_value}"
                )
            if name and name not in seen:
                seen.add(name)
                names.append(name)
        expected[entity_id] = tuple(names or (primary_name,))

    return expected


def _rust_export_name(source_name: str) -> str:
    if not _LIAN_TEMPORARY_NAME_PATTERN.fullmatch(source_name):
        return source_name
    digest = hashlib.sha256(source_name.encode("utf-8")).hexdigest()[:8]
    return f"{source_name[1:]}_{digest}"


def _load_json_object(path: Path) -> JsonDict:
    if not path.is_file():
        raise FileNotFoundError(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return _as_object(data, str(path))


def _resolve_path(base: Path, value: str) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path.resolve()
    return (base / path).resolve()


def _parse_module_path(module: str, path: Path) -> tuple[str, ...]:
    parts = tuple(part for part in module.split("::") if part)
    if not parts:
        raise ValueError(f"{path}: empty Rust module path")
    return parts


def _require_manifest_version(data: JsonDict, path: Path) -> int:
    version = _require_int(data, "version", path)
    if version != 4:
        raise ValueError(
            f"{path}: unsupported semantic hints manifest version "
            f"{version!r}; expected 4; regenerate semantic hints"
        )
    return version


def _read_anchor_ids(data: JsonDict, *, key: str, path: Path) -> list[str]:
    raw_ids = _require_list(data, key, path)
    anchor_ids: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(raw_ids):
        if not isinstance(value, str):
            raise ValueError(f"{path}: {key}[{index}] must be a string")
        _validate_anchor_id(value, path)
        if value in seen:
            raise ValueError(f"{path}: duplicate semantic hint anchor ID {value!r}")
        seen.add(value)
        anchor_ids.append(value)
    return anchor_ids


def _read_string_ids(data: JsonDict, *, key: str, path: Path) -> list[str]:
    raw_ids = _require_list(data, key, path)
    result: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(raw_ids):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{path}: {key}[{index}] must be a non-empty string")
        if value in seen:
            raise ValueError(f"{path}: duplicate ID in {key}: {value!r}")
        seen.add(value)
        result.append(value)
    return result


def _validate_anchor_id(anchor_id: str, path: Path) -> None:
    if not _ANCHOR_ID_PATTERN.fullmatch(anchor_id):
        raise ValueError(
            f"{path}: invalid semantic hint anchor ID {anchor_id!r}; "
            "expected SH_E<entity_id>_S<stmt_id>"
        )


def _require_object(data: JsonDict, key: str, path: Path) -> JsonDict:
    if key not in data:
        raise ValueError(f"{path}: missing required field {key!r}")
    return _as_object(data[key], f"{path}: {key}")


def _require_list(data: JsonDict, key: str, path: Path) -> list[Any]:
    if key not in data:
        raise ValueError(f"{path}: missing required field {key!r}")
    value = data[key]
    if not isinstance(value, list):
        raise ValueError(f"{path}: field {key!r} must be a list")
    return value


def _require_int(data: JsonDict, key: str, path: Path) -> int:
    if key not in data:
        raise ValueError(f"{path}: missing required field {key!r}")
    value = data[key]
    if not isinstance(value, int):
        raise ValueError(f"{path}: field {key!r} must be an int")
    return value


def _optional_int(
    data: JsonDict,
    key: str,
    path: Path,
    *,
    default: int,
) -> int:
    if key not in data:
        return default
    return _require_int(data, key, path)


def _require_bool(data: JsonDict, key: str, path: Path) -> bool:
    if key not in data:
        raise ValueError(f"{path}: missing required field {key!r}")
    value = data[key]
    if not isinstance(value, bool):
        raise ValueError(f"{path}: field {key!r} must be a bool")
    return value


def _require_str(data: JsonDict, key: str, path: Path) -> str:
    if key not in data:
        raise ValueError(f"{path}: missing required field {key!r}")
    value = data[key]
    if not isinstance(value, str):
        raise ValueError(f"{path}: field {key!r} must be a string")
    return value


def _as_object(value: Any, label: str) -> JsonDict:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return value
