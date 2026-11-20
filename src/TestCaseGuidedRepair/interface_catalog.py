from __future__ import annotations

import json
import re
from pathlib import Path

from .entities import entity_blocks
from .models import JsonDict


CATALOG_NAME = "entity-catalog.json"


def build_entity_catalog(run_root: Path) -> JsonDict:

    implementation = run_root / "implementation"
    context = run_root / "context"
    metadata = _translation_metadata(context / "translation-entities.json")
    dependencies = _dependencies(context / "entity-dependencies.json")
    entries: list[JsonDict] = []

    for path in sorted(implementation.rglob("*.rs")):
        if path.is_symlink() or "target" in path.relative_to(implementation).parts:
            continue
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(run_root).as_posix()
        module_path = _module_path(path.relative_to(implementation))
        module_visibility = (
            "public" if _module_is_public(implementation, module_path) else "private"
        )
        for block in entity_blocks(text):
            item = metadata.get(block.entity_id, {})
            rust_name = _rust_name(block.code, item.get("name"))
            signature = _rust_signature(block.code)
            source = item.get("source") if isinstance(item.get("source"), dict) else {}
            visibility = _item_visibility(signature)
            entries.append({
                "entity_id": block.entity_id,
                "kind": block.kind,
                "rust_name": rust_name,
                "source_name": item.get("name") or rust_name,
                "rust_path": relative,
                "module_path": module_path,
                "call_path": "::".join(part for part in (module_path, rust_name) if part),
                "signature": signature,
                "visibility": visibility,
                "module_visibility": module_visibility,
                "start_line": block.code_start_line,
                "end_line": block.code_end_line,
                "current_sha256": block.code_sha256,
                "source": {
                    key: source[key]
                    for key in ("rel_path", "start_line", "end_line")
                    if key in source
                },
                "dependencies": dependencies.get(block.entity_id, []),
            })

    catalog = {"version": 1, "entities": entries}
    (context / CATALOG_NAME).write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return catalog


def load_entity_catalog(run_root: Path) -> JsonDict:
    path = run_root / "context" / CATALOG_NAME
    if not path.is_file():
        return build_entity_catalog(run_root)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("entities"), list):
        raise ValueError("invalid entity catalog")
    return data


def _translation_metadata(path: Path) -> dict[int, JsonDict]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("entities", []) if isinstance(data, dict) else []
    return {
        item["id"]: item
        for item in items
        if isinstance(item, dict) and type(item.get("id")) is int
    }


def _dependencies(path: Path) -> dict[int, list[int]]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    items = data.get("entities", []) if isinstance(data, dict) else []
    result: dict[int, list[int]] = {}
    for item in items:
        if not isinstance(item, dict) or type(item.get("entity_id")) is not int:
            continue
        values = item.get("dependencies", [])
        result[item["entity_id"]] = [value for value in values if type(value) is int]
    return result


def _module_path(relative: Path) -> str:
    parts = list(relative.with_suffix("").parts)
    if parts and parts[0] == "src":
        parts.pop(0)
    if parts and parts[-1] in {"lib", "main", "mod"}:
        parts.pop()
    return "::".join(parts)


def _module_is_public(implementation: Path, module_path: str) -> bool:
    if not module_path:
        return True
    declaration_file = implementation / "src" / "lib.rs"
    module_dir = implementation / "src"
    for part in module_path.split("::"):
        if not declaration_file.is_file():
            return False
        text = declaration_file.read_text(encoding="utf-8")
        if re.search(rf"(?m)^\s*pub\s+mod\s+{re.escape(part)}\s*;", text) is None:
            return False
        flat = module_dir / f"{part}.rs"
        nested = module_dir / part / "mod.rs"
        declaration_file = flat if flat.is_file() else nested
        module_dir = module_dir / part
    return True


def _item_visibility(signature: str) -> str:
    stripped = signature.lstrip()
    if re.match(r"pub\s+", stripped):
        return "public"
    if re.match(r"pub\s*\(", stripped):
        return "restricted"
    return "private"


def _rust_name(code: str, fallback: object) -> str:
    patterns = (
        r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\b(?:struct|enum|union|type|trait)\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\b(?:const|static)\s+([A-Za-z_][A-Za-z0-9_]*)",
    )
    for pattern in patterns:
        match = re.search(pattern, code)
        if match:
            return match.group(1)
    return str(fallback) if isinstance(fallback, str) else ""


def _rust_signature(code: str) -> str:
    lines: list[str] = []
    depth = 0
    started = False
    for raw in code.splitlines():
        line = raw.strip()
        if not started:
            if not line or line.startswith("//") or line.startswith("#"):
                continue
            started = True
        lines.append(line)
        depth += line.count("(") + line.count("[") - line.count(")") - line.count("]")
        if depth <= 0 and ("{" in line or line.endswith(";") or "=" in line):
            break
    signature = " ".join(lines)
    if "{" in signature:
        signature = signature.split("{", 1)[0].rstrip()
    return signature[:4000]
