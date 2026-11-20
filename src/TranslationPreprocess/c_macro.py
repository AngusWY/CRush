from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Mapping

from .c_source_lex import mask_c_non_code
from .config import PROJECT_MACROS_NAME
from .models import PreprocessManifest


_DEFINE_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P<parameters>\([^\r\n]*?\))?"
    r"(?P<replacement>.*)$",
    re.DOTALL,
)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PROJECT_SOURCE_SUFFIXES = frozenset({".c", ".h", ".inc"})
_SKIPPED_DIRECTORY_NAMES = frozenset(
    {".git", ".hg", ".svn", "build", "generated", "target", "node_modules"}
)


class MacroCollectionError(RuntimeError):
    pass


class ProjectMacroCollector:


    def __init__(self, *, manifest: PreprocessManifest) -> None:
        self.manifest = manifest
        self.output_path = manifest.workspace / PROJECT_MACROS_NAME

    def run(self) -> Path:
        source_files = self._project_source_files()
        definitions = [
            definition
            for path in source_files
            for definition in self._definitions_in_file(path)
        ]
        invocations = self._collect_invocations(source_files, definitions)
        payload = {
            "version": 1,
            "project_root": str(self.manifest.project_root),
            "definitions": definitions,
            "invocations": invocations,
        }
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.output_path.with_suffix(
            self.output_path.suffix + ".tmp"
        )
        try:
            temporary_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(self.output_path)
        except OSError as exc:
            raise MacroCollectionError(
                f"failed to write project macro catalog {self.output_path}: {exc}"
            ) from exc
        return self.output_path

    def _project_source_files(self) -> tuple[Path, ...]:
        files: list[Path] = []
        for path in self.manifest.project_root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _PROJECT_SOURCE_SUFFIXES:
                continue
            try:
                relative = path.relative_to(self.manifest.project_root)
            except ValueError:
                continue
            if any(part in _SKIPPED_DIRECTORY_NAMES for part in relative.parts):
                continue
            files.append(path.resolve())
        return tuple(sorted(files, key=lambda item: item.as_posix()))

    def _definitions_in_file(self, path: Path) -> list[dict[str, Any]]:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise MacroCollectionError(f"failed to read project source {path}: {exc}") from exc

        lines = source.splitlines(keepends=True)
        definitions: list[dict[str, Any]] = []
        index = 0
        while index < len(lines):
            if not re.match(r"^[ \t]*#[ \t]*define\b", lines[index]):
                index += 1
                continue
            start_index = index
            while self._continues(lines[index]) and index + 1 < len(lines):
                index += 1
            end_index = index
            definition_source = "".join(lines[start_index : end_index + 1])
            logical_source = re.sub(r"\\\r?\n", "", definition_source).rstrip()
            match = _DEFINE_RE.match(logical_source)
            index += 1
            if match is None:
                continue

            raw_parameters = match.group("parameters")
            parameters = self._parse_parameters(raw_parameters)
            name = match.group("name")
            rel_path = path.relative_to(self.manifest.project_root).as_posix()
            definition_id = self._stable_id(
                "definition", rel_path, start_index + 1, name
            )
            definitions.append(
                {
                    "id": definition_id,
                    "name": name,
                    "function_like": raw_parameters is not None,
                    "parameters": parameters,
                    "replacement": match.group("replacement").strip(),
                    "path": str(path),
                    "rel_path": rel_path,
                    "start_line": start_index + 1,
                    "end_line": end_index + 1,
                    "source": definition_source.rstrip(),
                }
            )
        return definitions

    def _collect_invocations(
        self,
        source_files: tuple[Path, ...],
        definitions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        definitions_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for definition in definitions:
            if definition["function_like"]:
                definitions_by_name[str(definition["name"])].append(definition)
        if not definitions_by_name:
            return []

        names_pattern = re.compile(
            r"\b(" + "|".join(
                re.escape(name)
                for name in sorted(definitions_by_name, key=len, reverse=True)
            ) + r")\s*\("
        )
        invocations: list[dict[str, Any]] = []
        for path in source_files:
            try:
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            masked = mask_c_non_code(source, mask_literals=True)
            masked = self._mask_preprocessor_directives(masked)
            rel_path = path.relative_to(self.manifest.project_root).as_posix()
            for match in names_pattern.finditer(masked):
                open_index = masked.find("(", match.start(1) + len(match.group(1)))
                close_index = self._matching_parenthesis(masked, open_index)
                if close_index is None:
                    continue
                arguments = self._split_arguments(
                    source[open_index + 1 : close_index],
                    masked[open_index + 1 : close_index],
                )
                start_line = source.count("\n", 0, match.start(1)) + 1
                end_line = source.count("\n", 0, close_index) + 1
                name = match.group(1)
                invocations.append(
                    {
                        "id": self._stable_id(
                            "invocation", rel_path, start_line, name, match.start(1)
                        ),
                        "name": name,
                        "arguments": arguments,
                        "path": str(path),
                        "rel_path": rel_path,
                        "start_line": start_line,
                        "end_line": end_line,
                        "definition_ids": [
                            definition["id"]
                            for definition in definitions_by_name[name]
                        ],
                    }
                )
        return sorted(
            invocations,
            key=lambda item: (
                item["rel_path"],
                item["start_line"],
                item["end_line"],
                item["name"],
                item["id"],
            ),
        )

    @staticmethod
    def _continues(line: str) -> bool:
        return line.rstrip("\r\n").endswith("\\")

    @staticmethod
    def _parse_parameters(raw: str | None) -> list[str]:
        if raw is None:
            return []
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [item.strip() for item in inner.split(",")]

    @staticmethod
    def _mask_preprocessor_directives(source: str) -> str:
        result = list(source)
        lines = source.splitlines(keepends=True)
        offset = 0
        in_directive = False
        for line in lines:
            stripped = line.lstrip(" \t")
            if not in_directive:
                in_directive = stripped.startswith("#")
            if in_directive:
                for index in range(offset, offset + len(line)):
                    if result[index] not in "\r\n":
                        result[index] = " "
                in_directive = ProjectMacroCollector._continues(line)
            offset += len(line)
        return "".join(result)

    @staticmethod
    def _matching_parenthesis(source: str, open_index: int) -> int | None:
        if open_index < 0 or open_index >= len(source) or source[open_index] != "(":
            return None
        depth = 0
        for index in range(open_index, len(source)):
            if source[index] == "(":
                depth += 1
            elif source[index] == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    @staticmethod
    def _split_arguments(source: str, masked: str) -> list[str]:
        if not source.strip():
            return []
        arguments: list[str] = []
        start = 0
        depths = {"(": 0, "[": 0, "{": 0}
        closing = {")": "(", "]": "[", "}": "{"}
        for index, char in enumerate(masked):
            if char in depths:
                depths[char] += 1
            elif char in closing:
                opener = closing[char]
                depths[opener] = max(0, depths[opener] - 1)
            elif char == "," and not any(depths.values()):
                arguments.append(source[start:index].strip())
                start = index + 1
        arguments.append(source[start:].strip())
        return arguments

    @staticmethod
    def _stable_id(*parts: object) -> str:
        value = "\0".join(str(part) for part in parts)
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


def load_project_macro_catalog(path_or_workspace: Path | str) -> dict[str, Any]:
    path = Path(path_or_workspace)
    if path.is_dir():
        path = path / PROJECT_MACROS_NAME
    if not path.is_file():
        return {"version": 1, "definitions": [], "invocations": []}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MacroCollectionError(f"failed to read project macro catalog {path}: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("version") != 1:
        raise MacroCollectionError(f"unsupported project macro catalog: {path}")
    definitions = payload.get("definitions")
    invocations = payload.get("invocations")
    if not isinstance(definitions, list) or not isinstance(invocations, list):
        raise MacroCollectionError(f"invalid project macro catalog: {path}")
    return payload


def select_macro_context(
    source: str,
    catalog: Mapping[str, Any],
    *,
    max_definitions: int = 96,
    max_source_bytes: int = 65536,
) -> tuple[dict[str, Any], ...]:


    raw_definitions = catalog.get("definitions", [])
    definitions = [item for item in raw_definitions if isinstance(item, dict)]
    definitions_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for definition in definitions:
        name = definition.get("name")
        if isinstance(name, str) and name:
            definitions_by_name[name].append(definition)

    masked_source = mask_c_non_code(source, mask_literals=True)
    initial_names = [
        name
        for name in definitions_by_name
        if _macro_is_referenced(masked_source, name, definitions_by_name[name])
    ]
    queue = deque(sorted(initial_names))
    visited_names: set[str] = set()
    selected: list[dict[str, Any]] = []
    source_bytes = 0
    while queue and len(selected) < max_definitions:
        name = queue.popleft()
        if name in visited_names:
            continue
        visited_names.add(name)
        for definition in sorted(
            definitions_by_name[name],
            key=lambda item: (
                str(item.get("rel_path", "")),
                int(item.get("start_line", 0)),
            ),
        ):
            definition_bytes = len(
                str(definition.get("source", "")).encode("utf-8")
            )
            if selected and source_bytes + definition_bytes > max_source_bytes:
                return tuple(selected)
            selected.append(dict(definition))
            source_bytes += definition_bytes
            replacement = str(definition.get("replacement", ""))
            for dependency_name in _IDENTIFIER_RE.findall(replacement):
                if (
                    dependency_name in definitions_by_name
                    and dependency_name not in visited_names
                ):
                    queue.append(dependency_name)
    return tuple(selected)


def macro_family_specs(catalog: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:


    definitions = [
        item
        for item in catalog.get("definitions", [])
        if isinstance(item, dict)
    ]
    invocations = [
        item
        for item in catalog.get("invocations", [])
        if isinstance(item, dict)
    ]
    definitions_by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for definition in definitions:
        name = str(definition.get("name", ""))
        if name:
            definitions_by_name[name].append(definition)

    directly_invoked = {
        str(invocation.get("name", "")) for invocation in invocations
    }
    type_roots = [
        definition
        for definition in definitions
        if definition.get("function_like") is True
        and str(definition.get("name", "")) in directly_invoked
        and re.search(r"\btypedef\b", str(definition.get("replacement", "")))
        and re.search(
            r"\b(struct|union|enum)\b",
            str(definition.get("replacement", "")),
        )
        and Path(str(definition.get("rel_path", ""))).suffix.lower() == ".h"
    ]
    roots_by_path: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for root in type_roots:
        roots_by_path[str(root["rel_path"])].append(root)

    specs: list[dict[str, Any]] = []
    for rel_path, roots in sorted(roots_by_path.items()):
        root_groups: list[list[dict[str, Any]]] = []
        for root in sorted(
            roots,
            key=lambda item: (
                len(str(item.get("name", ""))),
                str(item.get("name", "")).lower(),
            ),
        ):
            root_name = str(root.get("name", ""))
            for group in root_groups:
                primary_name = str(group[0].get("name", ""))
                if _belongs_to_macro_family(root_name, primary_name):
                    group.append(root)
                    break
            else:
                root_groups.append([root])

        for roots_in_family in root_groups:
            specs.append(
                _macro_family_spec(
                    rel_path=rel_path,
                    roots=roots_in_family,
                    definitions=definitions,
                    definitions_by_name=definitions_by_name,
                )
            )
    return tuple(specs)


def _macro_family_spec(
    *,
    rel_path: str,
    roots: list[dict[str, Any]],
    definitions: list[dict[str, Any]],
    definitions_by_name: Mapping[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    primary_name = str(roots[0]["name"])
    selected_names = {
        str(definition.get("name", ""))
        for definition in definitions
        if str(definition.get("rel_path", "")) == rel_path
        and _belongs_to_macro_family(
            str(definition.get("name", "")),
            primary_name,
        )
    }
    queue = deque(selected_names)
    while queue:
        name = queue.popleft()
        for definition in definitions_by_name.get(name, ()):
            if str(definition.get("rel_path", "")) != rel_path:
                continue
            for dependency_name in _IDENTIFIER_RE.findall(
                str(definition.get("replacement", ""))
            ):
                if dependency_name in selected_names:
                    continue
                if any(
                    str(candidate.get("rel_path", "")) == rel_path
                    for candidate in definitions_by_name.get(
                        dependency_name, ()
                    )
                ):
                    selected_names.add(dependency_name)
                    queue.append(dependency_name)

    selected_definitions = [
        definition
        for definition in definitions
        if str(definition.get("rel_path", "")) == rel_path
        and str(definition.get("name", "")) in selected_names
    ]
    ordered_roots = sorted(roots, key=lambda item: int(item["start_line"]))
    exports = list(dict.fromkeys(str(root["name"]) for root in ordered_roots))
    return {
        "name": exports[0],
        "export_names": exports,
        "path": str(ordered_roots[0]["path"]),
        "rel_path": rel_path,
        "start_line": min(
            int(item["start_line"]) for item in selected_definitions
        ),
        "end_line": max(
            int(item["end_line"]) for item in selected_definitions
        ),
        "macro_names": sorted(selected_names),
        "caller_macro_names": sorted(
            name
            for name in selected_names
            if any(
                definition.get("function_like") is True
                for definition in definitions_by_name.get(name, ())
            )
        ),
        "macro_definition_ids": [
            str(item["id"])
            for item in sorted(
                selected_definitions,
                key=lambda item: int(item["start_line"]),
            )
        ],
    }


def _belongs_to_macro_family(name: str, root_name: str) -> bool:
    name_lower = name.lower()
    root_lower = root_name.lower()
    return name_lower == root_lower or name_lower.startswith(root_lower + "_")


def _macro_is_referenced(
    source: str,
    name: str,
    definitions: list[dict[str, Any]],
) -> bool:
    if any(definition.get("function_like") is True for definition in definitions):
        return re.search(r"\b" + re.escape(name) + r"\s*\(", source) is not None
    return re.search(r"\b" + re.escape(name) + r"\b", source) is not None
