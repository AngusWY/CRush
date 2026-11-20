from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Iterator

from .entities import entity_blocks, find_entity
from .interface_catalog import load_entity_catalog
from .models import JsonDict


class AgentRuntimeError(RuntimeError):
    pass


class AgentRequestTimeout(AgentRuntimeError):
    pass


class SourceTools:
    ROOTS = {"implementation", "harness", "context", "logs"}
    IGNORED = {"interfaces", "target", ".git", "__pycache__", ".pytest_cache"}
    SUFFIXES = {
        ".rs", ".toml", ".json", ".c", ".h", ".txt", ".log", ".cmake",
    }

    @classmethod
    def readable(cls, path: Path) -> bool:
        return path.suffix in cls.SUFFIXES or path.name in {"Makefile", "makefile", "GNUmakefile"}

    def __init__(
        self,
        root: Path,
        *,
        max_return_bytes: int = 16_000,
        total_bytes: int = 400_000,
        phase: str = "bridge",
    ) -> None:
        self.root = root.resolve()
        self.max_return_bytes = max_return_bytes
        self.remaining = total_bytes
        self.phase = phase
        self._read_cache: dict[str, JsonDict] = {}

    def resolve(self, relative: str) -> Path:
        path = Path(relative)
        if (
            path.is_absolute()
            or not path.parts
            or path.parts[0] not in self.ROOTS
            or any(
                part in self.IGNORED or part == ".." or part.startswith(".")
                for part in path.parts
            )
        ):
            raise ValueError("path is outside readable scope")
        candidate = self.root
        for part in path.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise ValueError("symbolic links are not readable")
        candidate.resolve().relative_to(self.root)
        return candidate

    def files(self, relative: str) -> Iterator[Path]:
        start = self.resolve(relative)
        if start.is_file():
            if self.readable(start):
                yield start
            return
        if not start.is_dir():
            raise ValueError("path does not exist")
        for directory, dirs, names in os.walk(start, followlinks=False):
            dirs[:] = sorted(
                d
                for d in dirs
                if d not in self.IGNORED
                and not d.startswith(".")
                and not (Path(directory) / d).is_symlink()
            )
            for name in sorted(names):
                path = Path(directory) / name
                if (
                    not name.startswith(".")
                    and not path.is_symlink()
                    and self.readable(path)
                ):
                    yield path

    def execute(self, name: str, arguments: JsonDict) -> JsonDict:
        if self.remaining <= 0:
            raise AgentRuntimeError("cumulative tool output budget exhausted")
        try:
            result = self._execute(name, arguments)
        except (ValueError, OSError, TypeError) as exc:

            result = {
                "error": str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            }
        cache_arguments = (
            {"entity_id": result["entity_id"]}
            if name == "read_entity" and "rust_code" in result
            else arguments
        )
        cache_key = json.dumps([name, cache_arguments], sort_keys=True)
        cacheable = {
            "read_file", "read_entity", "find_rust_entities",
            "read_entity_signature", "read_related_type", "find_c_declaration",
            "inspect_interface_symbols", "read_entity_signatures",
        }
        if (
            self.phase in {"behavior", "c_test_analysis", "c_interface_pairing"}
            and name in cacheable
            and "error" not in result
        ):
            previous = self._read_cache.get(cache_key)
            if previous == result:
                result = {
                    "already_read": True,
                    "message": "Unchanged content is already present in this conversation.",
                    **{
                        key: result[key]
                        for key in ("entity_id", "path", "current_sha256")
                        if key in result
                    },
                }
            else:
                self._read_cache[cache_key] = result
        size = len(json.dumps(result, ensure_ascii=False).encode())
        if size > self.remaining:
            raise AgentRuntimeError("cumulative tool output budget exhausted")
        self.remaining -= size
        return result

    def _execute(self, name: str, args: JsonDict) -> JsonDict:
        if name in {
            "find_rust_entities",
            "read_entity_signature",
            "read_entity_signatures",
            "read_related_type",
            "find_c_declaration",
            "inspect_interface_symbols",
        }:
            if self.phase != "c_interface_pairing":
                raise ValueError("interface pairing tools are only available during C interface pairing")
            return self._execute_pairing_tool(name, args)
        if self.phase == "c_interface_pairing":
            raise ValueError("interface pairing may only use catalog and declaration tools")
        if self.phase == "c_bridge_generation":
            raise ValueError("bridge generation uses the confirmed pairing and cannot browse source")
        if name == "read_entity":
            if "entity_id" not in args:
                path_arg = args.get("path")
                if not isinstance(path_arg, str):
                    raise ValueError("provide entity_id or an implementation path with line/query")
                path = self.resolve(path_arg)
                if not path.is_file() or path.suffix != ".rs" or Path(path_arg).parts[0] != "implementation":
                    raise ValueError("entity reading requires an implementation Rust file")
                if ("line" in args) == ("query" in args):
                    raise ValueError("provide exactly one of line or query with path")
                if "line" in args:
                    located = self._execute("locate_entity", args)
                    entity_id = located["entity_id"]
                else:
                    query = args["query"]
                    if not isinstance(query, str) or not query or len(query) > 500:
                        raise ValueError("query must be a non-empty literal (at most 500 characters)")
                    matching_entities = [
                        block for block in entity_blocks(path.read_text(encoding="utf-8"))
                        if query in block.code
                    ]
                    if len(matching_entities) != 1:
                        return {
                            "error": "query must match exactly one entity; refine the query or use entity_id",
                            "candidates": [
                                {"entity_id": block.entity_id, "line": block.code_start_line}
                                for block in matching_entities[:20]
                            ],
                            "match_count": len(matching_entities),
                        }
                    entity_id = matching_entities[0].entity_id
                args = {"entity_id": entity_id}
            entity_id = _integer(args, "entity_id", -1, 0, 2**63 - 1)
            path, block = find_entity(self.root / "implementation", entity_id)
            result: JsonDict = {
                "entity_id": entity_id,
                "kind": block.kind,
                "path": path.relative_to(self.root).as_posix(),
                "start_line": block.start_line,
                "code_start_line": block.code_start_line,
                "code_end_line": block.code_end_line,
                "end_line": block.end_line,
                "current_sha256": block.code_sha256,
                "rust_code": block.code,
            }
            metadata = self._entity_metadata(entity_id)
            if metadata:
                result["translation_entity"] = metadata
            return result
        path_arg = args.get("path")
        if not isinstance(path_arg, str):
            raise ValueError("path must be a relative string")
        if self.phase == "behavior":
            path_parts = Path(path_arg).parts
            if path_parts and path_parts[0] == "logs":
                raise ValueError(
                    "behavior phase uses structured failures in context; raw logs are not readable"
                )
            if name == "read_file" and (
                not path_parts or path_parts[0] != "harness"
            ):
                raise ValueError(
                    "behavior read_file is for harness only; use read_entity "
                    "with entity_id or implementation path and line/query"
                )
        if self.phase == "c_test_analysis":
            if name != "read_file":
                raise ValueError("C test analysis may only read the selected test and configured helpers")
            allowed = self._c_analysis_paths()
            if path_arg not in allowed:
                raise ValueError("C test analysis may only read the selected test and configured helpers")
        if name == "list_files":
            offset = _integer(args, "offset", 0, 0, 1_000_000)
            limit = _integer(args, "limit", 50, 1, 100)
            items: list[JsonDict] = []
            used = 0
            more = False
            for index, path in enumerate(self.files(path_arg)):
                if index < offset:
                    continue
                item = {
                    "path": path.relative_to(self.root).as_posix(),
                    "bytes": path.stat().st_size,
                }
                size = len(json.dumps(item).encode())
                if len(items) >= limit or used + size > self.max_return_bytes - 1024:
                    more = True
                    break
                items.append(item)
                used += size
            return {
                "files": items,
                "next_offset": offset + len(items) if more else None,
            }
        if name == "read_file":
            path = self.resolve(path_arg)
            if not self.readable(path) or not path.is_file():
                raise ValueError("not a readable source or log file")
            start = _integer(args, "start_line", 1, 1, 10_000_000)
            end = _integer(args, "end_line", start + 199, start, 10_000_000)
            if self.phase == "behavior":
                end = min(end, start + 149)
            column = _integer(args, "start_column", 0, 0, 100_000_000)
            lines: list[JsonDict] = []
            used = 0
            total = 0
            stopped = False
            with path.open(encoding="utf-8", errors="replace") as stream:
                for total, line in enumerate(stream, 1):
                    if total < start or total > end or stopped:
                        continue

                    text = line.rstrip("\n")
                    if total == start:
                        text = text[column:]
                    entry = {"line": total, "text": text}
                    size = len(json.dumps(entry, ensure_ascii=False).encode())
                    if used + size > self.max_return_bytes - 1024:
                        stopped = True
                        if not lines:
                            entry["text"] = text[:500]
                            lines.append(entry)
                        continue
                    lines.append(entry)
                    used += size
            partial = stopped and len(lines) == 1 and used == 0
            return {
                "path": path_arg,
                "lines": lines,
                "total_lines": total,
                "truncated": stopped or end < total,
                "partial_line": partial,
                "next_column": column + len(lines[0]["text"]) if partial else None,
                "next_line": (
                    start
                    if partial
                    else (
                        (lines[-1]["line"] + 1)
                        if partial or (lines and lines[-1]["line"] < total)
                        else None
                    )
                ),
            }
        if name == "locate_entity":
            path = self.resolve(path_arg)
            if not path.is_file() or path.suffix != ".rs" or not str(
                path.relative_to(self.root)
            ).startswith("implementation/"):
                raise ValueError("entity location requires an implementation Rust file")
            diagnostic_line = _integer(args, "line", -1, 1, 10_000_000)
            entity_matches = [
                block
                for block in entity_blocks(path.read_text(encoding="utf-8"))
                if block.contains_line(diagnostic_line)
            ]
            if len(entity_matches) != 1:
                raise ValueError("line is not inside exactly one translated entity")
            block = entity_matches[0]
            return {
                "entity_id": block.entity_id,
                "kind": block.kind,
                "path": path_arg,
                "start_line": block.start_line,
                "code_start_line": block.code_start_line,
                "code_end_line": block.code_end_line,
                "end_line": block.end_line,
                "current_sha256": block.code_sha256,
            }
        if name == "search_code":
            query = args.get("query")
            if not isinstance(query, str) or not query or len(query) > 500:
                raise ValueError(
                    "query must be a non-empty literal (at most 500 characters)"
                )
            limit = _integer(args, "limit", 20, 1, 100)
            matches: list[JsonDict] = []
            used = 0
            scanned = 0
            for path in self.files(path_arg):
                with path.open(encoding="utf-8", errors="replace") as stream:
                    for number, line in enumerate(stream, 1):
                        scanned += len(line.encode())
                        if scanned > 4_000_000:
                            return {
                                "matches": matches,
                                "truncated": True,
                                "reason": "search scan limit",
                            }
                        if query not in line:
                            continue
                        pos = line.index(query)
                        item = {
                            "path": path.relative_to(self.root).as_posix(),
                            "line": number,
                            "text": line[
                                max(0, pos - 100) : pos + len(query) + 200
                            ].rstrip(),
                        }
                        size = len(json.dumps(item, ensure_ascii=False).encode())
                        if (
                            len(matches) >= limit
                            or used + size > self.max_return_bytes - 1024
                        ):
                            return {"matches": matches, "truncated": True}
                        matches.append(item)
                        used += size
            return {"matches": matches, "truncated": False}
        raise ValueError("unknown reading tool")

    def _c_analysis_paths(self) -> set[str]:
        path = self.root / "harness" / "build.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        values = [
            data.get("entry"),
            *(data.get("sources") or []),
            *(data.get("helpers") or []),
        ]
        return {
            f"harness/c_project/{value}"
            for value in values
            if isinstance(value, str) and value
        }

    def _execute_pairing_tool(self, name: str, args: JsonDict) -> JsonDict:
        catalog = load_entity_catalog(self.root)
        entities = [item for item in catalog["entities"] if isinstance(item, dict)]
        if name == "inspect_interface_symbols":
            symbols = args.get("c_symbols")
            if (not isinstance(symbols, list) or not 1 <= len(symbols) <= 12
                    or any(not isinstance(symbol, str) or not symbol or len(symbol) > 500
                           for symbol in symbols)):
                raise ValueError("c_symbols must contain 1 to 12 non-empty strings")
            return {"interfaces": [
                {
                    "c_symbol": symbol,
                    "declarations": self._find_c_declarations(symbol)["declarations"],
                    "rust_candidates": self._find_rust_candidates(symbol, entities),
                }
                for symbol in symbols
            ]}
        if name == "find_rust_entities":
            symbol = args.get("c_symbol")
            if not isinstance(symbol, str) or not symbol or len(symbol) > 500:
                raise ValueError("c_symbol must be a non-empty string")
            return {"c_symbol": symbol,
                    "candidates": self._find_rust_candidates(symbol, entities)}
        if name == "read_entity_signatures":
            entity_ids = args.get("entity_ids")
            if (not isinstance(entity_ids, list) or not 1 <= len(entity_ids) <= 24
                    or any(type(entity_id) is not int or entity_id < 0
                           for entity_id in entity_ids)):
                raise ValueError("entity_ids must contain 1 to 24 non-negative integers")
            results: list[JsonDict] = []
            for entity_id in dict.fromkeys(entity_ids):
                matches = [item for item in entities if item.get("entity_id") == entity_id]
                if len(matches) != 1:
                    raise ValueError("entity_id is not unique in the catalog")
                results.append(self._catalog_summary(matches[0]))
            return {"entities": results}
        if name in {"read_entity_signature", "read_related_type"}:
            entity_id = _integer(args, "entity_id", -1, 0, 2**63 - 1)
            matches = [item for item in entities if item.get("entity_id") == entity_id]
            if len(matches) != 1:
                raise ValueError("entity_id is not unique in the catalog")
            item = matches[0]
            result = self._catalog_summary(item)
            if name == "read_related_type":
                path = self.root / str(item["rust_path"])
                blocks = [block for block in entity_blocks(path.read_text(encoding="utf-8"))
                          if block.entity_id == entity_id]
                if len(blocks) != 1:
                    raise ValueError("catalog entity does not resolve to one source block")
                result["rust_code"] = blocks[0].code
            return result
        symbol = args.get("c_symbol")
        if not isinstance(symbol, str) or not symbol or len(symbol) > 500:
            raise ValueError("c_symbol must be a non-empty string")
        return self._find_c_declarations(symbol)

    def _find_rust_candidates(
        self, symbol: str, entities: list[JsonDict]
    ) -> list[JsonDict]:
        lowered = symbol.lower()
        ranked: list[tuple[int, JsonDict]] = []
        for item in entities:
            rust_name = str(item.get("rust_name", ""))
            source_name = str(item.get("source_name", ""))
            module_path = str(item.get("module_path", ""))
            qualified_name = "_".join(
                part for part in (*module_path.split("::"), rust_name) if part
            )
            score = 0
            if symbol == source_name:
                score = 4
            elif symbol == rust_name:
                score = 3
            elif lowered == qualified_name.lower():
                score = 3
            elif lowered in {source_name.lower(), rust_name.lower()}:
                score = 2
            elif lowered in source_name.lower() or lowered in rust_name.lower():
                score = 1
            if score:
                ranked.append((score, self._catalog_summary(item)))
        ranked.sort(key=lambda pair: (-pair[0], pair[1]["entity_id"]))
        return [item for _, item in ranked[:12]]

    @staticmethod
    def _catalog_summary(item: JsonDict) -> JsonDict:
        return {
            key: item.get(key)
            for key in (
                "entity_id", "kind", "rust_name", "source_name", "rust_path",
                "module_path", "call_path", "signature", "visibility",
                "module_visibility", "current_sha256", "source", "dependencies",
            )
        }

    def _find_c_declarations(self, symbol: str) -> JsonDict:
        pattern = re.compile(rf"\b{re.escape(symbol)}\s*\(")
        declarations: list[JsonDict] = []
        for path in self.files("harness/c_project"):
            if path.suffix not in {".h", ".c"}:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            for index, line in enumerate(lines):
                if not pattern.search(line):
                    continue
                start = index
                while start > 0:
                    previous = lines[start - 1].strip()
                    if (not previous or previous.startswith("#") or ";" in previous
                            or "}" in previous or "{" in previous):
                        break
                    start -= 1
                    if index - start >= 8:
                        break
                end = index
                while end + 1 < len(lines) and ";" not in lines[end] and "{" not in lines[end]:
                    end += 1
                    if end - start >= 12:
                        break
                snippet = "\n".join(lines[start:end + 1]).strip()
                declarations.append({
                    "path": path.relative_to(self.root).as_posix(),
                    "start_line": start + 1,
                    "end_line": end + 1,
                    "declaration": snippet[:4000],
                })
                if len(declarations) >= 12:
                    return {"c_symbol": symbol, "declarations": declarations, "truncated": True}
        return {"c_symbol": symbol, "declarations": declarations, "truncated": False}

    def _entity_metadata(self, entity_id: int) -> JsonDict | None:
        path = self.root / "context" / "translation-entities.json"
        if not path.is_file():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        entities = data.get("entities", []) if isinstance(data, dict) else []
        for item in entities:
            if isinstance(item, dict) and item.get("id") == entity_id:
                return {
                    key: item[key]
                    for key in ("id", "kind", "name", "source")
                    if key in item
                }
        return None


def _integer(args: JsonDict, key: str, default: int, low: int, high: int) -> int:
    value = args.get(key, default)
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{key} must be an integer between {low} and {high}")
    return value


def _tool(
    name: str, description: str, properties: JsonDict, required: list[str]
) -> JsonDict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


TOOLS = (
    _tool(
        "list_files",
        "List readable files with pagination (no contents).",
        {
            "path": {"type": "string"},
            "offset": {"type": "integer"},
            "limit": {"type": "integer"},
        },
        ["path"],
    ),
    _tool(
        "read_file",
        "Read numbered source/log lines; use ranges and inspect truncation.",
        {
            "path": {"type": "string"},
            "start_line": {"type": "integer"},
            "end_line": {"type": "integer"},
            "start_column": {
                "type": "integer",
                "description": "Optional character offset on start_line; continue partial lines using next_column.",
            },
        },
        ["path"],
    ),
    _tool(
        "search_code",
        "Search literal text in readable files and return matching locations.",
        {
            "path": {"type": "string"},
            "query": {"type": "string"},
            "limit": {"type": "integer"},
        },
        ["path", "query"],
    ),
    _tool(
        "locate_entity",
        "Locate the translated entity containing a diagnostic line.",
        {"path": {"type": "string"}, "line": {"type": "integer"}},
        ["path", "line"],
    ),
    _tool(
        "read_entity",
        "Read one complete translated entity and its replacement hash in one call. "
        "Provide entity_id, OR an implementation Rust file path with line, OR path "
        "with a unique literal query such as 'fn update_tm('. Ambiguous queries "
        "return candidate IDs without source; refine the query. Prefer this over "
        "separate search/locate/read calls when the file is known.",
        {
            "entity_id": {"type": "integer"},
            "path": {"type": "string"},
            "line": {"type": "integer"},
            "query": {"type": "string"},
        },
        [],
    ),
    _tool(
        "submit_changes",
        "Submit bridge file edits or all behavior entity replacements and finish.",
        {
            "summary": {"type": "string"},
            "repair_kind": {"type": "string", "enum": ["bridge", "implementation", "environment"]},
            "failure_evidence": {"type": "string"},
            "related_entities": {"type": "array", "items": {"type": "integer"}},
            "interface_mappings": {"type": "array", "items": {
                "type": "object", "properties": {
                    "c_symbol": {"type": "string"}, "ffi_symbol": {"type": "string"},
                    "rust_symbol": {"type": "string"}, "entity_id": {"type": "integer"}},
                "required": ["c_symbol", "ffi_symbol", "rust_symbol", "entity_id"],
                "additionalProperties": False}},
            "edits": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["path", "content"],
                    "additionalProperties": False,
                },
            },
            "entity_replacements": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "entity_id": {"type": "integer"},
                        "expected_sha256": {"type": "string"},
                        "rust_code": {"type": "string"},
                    },
                    "required": ["entity_id", "expected_sha256", "rust_code"],
                    "additionalProperties": False,
                },
                "minItems": 1,
            },
        },
        ["summary"],
    ),
)


def _named_tool(name: str) -> JsonDict:
    return next(tool for tool in TOOLS if tool["function"]["name"] == name)


_FIND_RUST_ENTITIES_TOOL = _tool(
    "find_rust_entities",
    "Find compact translated Rust entity candidates for one C symbol.",
    {"c_symbol": {"type": "string"}},
    ["c_symbol"],
)
_READ_ENTITY_SIGNATURE_TOOL = _tool(
    "read_entity_signature",
    "Read one cataloged Rust entity signature, module path, source mapping and dependencies.",
    {"entity_id": {"type": "integer"}},
    ["entity_id"],
)
_READ_RELATED_TYPE_TOOL = _tool(
    "read_related_type",
    "Read one already identified Rust type entity needed for ABI adaptation.",
    {"entity_id": {"type": "integer"}},
    ["entity_id"],
)
_FIND_C_DECLARATION_TOOL = _tool(
    "find_c_declaration",
    "Find declarations or definitions for one known C symbol without returning whole headers.",
    {"c_symbol": {"type": "string"}},
    ["c_symbol"],
)
_INSPECT_INTERFACE_SYMBOLS_TOOL = _tool(
    "inspect_interface_symbols",
    "Find C declarations and compact Rust entity candidates for up to 12 interfaces.",
    {
        "c_symbols": {
            "type": "array", "minItems": 1, "maxItems": 12,
            "items": {"type": "string"},
        },
    },
    ["c_symbols"],
)
_READ_ENTITY_SIGNATURES_TOOL = _tool(
    "read_entity_signatures",
    "Confirm catalog signatures and module metadata for up to 24 selected entities.",
    {
        "entity_ids": {
            "type": "array", "minItems": 1, "maxItems": 24,
            "items": {"type": "integer"},
        },
    },
    ["entity_ids"],
)
_SUBMIT_TEST_INTERFACES_TOOL = _tool(
    "submit_test_interfaces",
    "Submit the classified function interfaces actually called by the selected C test.",
    {"interfaces": {"type": "array", "minItems": 1, "items": {
        "type": "object", "properties": {
            "c_symbol": {"type": "string"},
            "call_locations": {"type": "array", "items": {"type": "integer"}},
            "call_sources": {"type": "array", "items": {"type": "string"}},
            "argument_usage": {"type": "array", "items": {"type": "string"}},
            "return_usage": {"type": "string"},
            "classification": {"type": "string", "enum": [
                "project_api", "test_helper", "external_api", "indirect_call", "unresolved"]},
            "call_kind": {"type": "string", "enum": ["direct", "indirect"]},
            "indirect_targets": {"type": "array", "items": {"type": "string"}},
        }, "required": ["c_symbol", "call_locations", "argument_usage",
                          "return_usage", "classification", "call_kind", "indirect_targets",
                          "call_sources"],
        "additionalProperties": False}},
    },
    ["interfaces"],
)
_SUBMIT_INTERFACE_PAIRINGS_TOOL = _tool(
    "submit_interface_pairings",
    "Submit one unique translated Rust entity pairing for every supplied project C interface.",
    {"pairings": {"type": "array", "minItems": 1, "items": {
        "type": "object", "properties": {
            "c_symbol": {"type": "string"},
            "c_declaration": {"type": "string"},
            "rust_entity_id": {"type": "integer"},
            "rust_path": {"type": "string"},
            "rust_module_path": {"type": "string"},
            "rust_symbol": {"type": "string"},
            "rust_signature": {"type": "string"},
            "required_type_entities": {"type": "array", "items": {"type": "integer"}},
            "type_definitions": {"type": "array", "items": {"type": "string"}},
            "adaptations": {"type": "array", "items": {"type": "string"}},
        }, "required": ["c_symbol", "c_declaration", "rust_entity_id", "rust_path",
                          "rust_module_path", "rust_symbol", "rust_signature",
                          "required_type_entities", "type_definitions", "adaptations"],
        "additionalProperties": False}},
    },
    ["pairings"],
)

C_TEST_ANALYSIS_TOOLS = (_named_tool("read_file"), _SUBMIT_TEST_INTERFACES_TOOL)
C_INTERFACE_PAIRING_TOOLS = (
    _INSPECT_INTERFACE_SYMBOLS_TOOL,
    _READ_ENTITY_SIGNATURES_TOOL,
    _FIND_RUST_ENTITIES_TOOL,
    _READ_ENTITY_SIGNATURE_TOOL,
    _READ_RELATED_TYPE_TOOL,
    _FIND_C_DECLARATION_TOOL,
    _SUBMIT_INTERFACE_PAIRINGS_TOOL,
)
C_BRIDGE_GENERATION_TOOLS = (_named_tool("submit_changes"),)
