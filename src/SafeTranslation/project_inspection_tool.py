from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Any

from .cargo_manifest import read_dependency_specs
from .models import JsonDict, TranslationTask


GET_PROJECT_CONTEXT_TOOL: JsonDict = {
    "type": "function",
    "function": {
        "name": "get_project_context",
        "description": (
            "Return compact project-wide C and Cargo context for translation "
            "decisions. Use this single tool for unfamiliar C symbols, library "
            "types/functions/macros/globals, pointer-like C values, and crate "
            "dependency checks."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "symbols": {
                    "type": "array",
                    "description": (
                        "C symbols to inspect, such as regex_t, sigaction, "
                        "stdscr, editor, or strcasestr."
                    ),
                    "items": {
                        "type": "object",
                        "properties": {
                            "symbol": {
                                "type": "string",
                                "description": "C symbol name.",
                            },
                            "kind": {
                                "type": "string",
                                "description": (
                                    "Optional expected kind: function, type, "
                                    "struct, macro, constant, global, pointer, "
                                    "or unknown."
                                ),
                            },
                            "pointer": {
                                "type": "boolean",
                                "description": (
                                    "Set true when the symbol is a C pointer "
                                    "variable/global/field or may be translated "
                                    "as pointer-like Rust."
                                ),
                            },
                        },
                        "required": ["symbol"],
                        "additionalProperties": False,
                    },
                },
                "crates": {
                    "type": "array",
                    "description": (
                        "Optional Rust crate names to check in Cargo.toml, "
                        "such as regex or nix."
                    ),
                    "items": {"type": "string"},
                },
            },
            "required": [],
            "additionalProperties": False,
        },
    },
}


INSPECT_POINTER_USAGE_TOOL: JsonDict = {
    "type": "function",
    "function": {
        "name": "inspect_pointer_usage",
        "description": (
            "Inspect project-wide C usage of a pointer variable, global, or "
            "field before choosing a Rust representation. Use this before "
            "emitting raw pointers, unsafe, FFI, CStr/CString, c_void, or "
            "pointer-like placeholders."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "symbol": {
                    "type": "string",
                    "description": "Pointer variable/global/field name, for example initpath.",
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of source matches to return.",
                },
            },
            "required": ["symbol"],
            "additionalProperties": False,
        },
    },
}


INSPECT_RUST_CRATE_API_TOOL: JsonDict = {
    "type": "function",
    "function": {
        "name": "inspect_rust_crate_api",
        "description": (
            "Inspect the locally available Rust crate source for exact public "
            "API item names, enum variants, modules, feature-gated functions, "
            "and signatures before emitting or repairing third-party crate paths."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "crate": {
                    "type": "string",
                    "description": "Cargo crate name, for example nix, ncurses, regex, or signal-hook.",
                },
                "query": {
                    "type": "string",
                    "description": (
                        "Space-separated API names or concepts to search for, "
                        "such as 'SysconfVar PHYS_PAGES PAGE_SIZE sysconf'."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "description": "Maximum number of source matches to return.",
                },
            },
            "required": ["crate", "query"],
            "additionalProperties": False,
        },
    },
}


_COMMON_C_HEADERS = (
    "sys/types.h",
    "stddef.h",
    "stdint.h",
    "stdbool.h",
    "stdio.h",
    "stdlib.h",
    "string.h",
    "strings.h",
    "regex.h",
    "signal.h",
    "dirent.h",
    "unistd.h",
    "errno.h",
    "fcntl.h",
    "sys/stat.h",
    "sys/inotify.h",
    "time.h",
    "pthread.h",
    "curses.h",
    "ncurses.h",
)


@dataclass(frozen=True)
class ProjectInspectionTool:


    workspace: Path
    rust_project: Path | None = None
    clang: str = "clang"
    cargo: str = "cargo"
    conda_env_name: str = "c2safety"

    @classmethod
    def from_workspace(
        cls,
        workspace: Path | str,
        *,
        rust_project: Path | str | None = None,
    ) -> "ProjectInspectionTool":
        workspace_path = Path(workspace)
        return cls(
            workspace=workspace_path,
            rust_project=Path(rust_project) if rust_project is not None else _rust_project_from_workspace(workspace_path),
        )

    def execute_for_task(
        self,
        task: TranslationTask,
        tool_name: str,
        arguments_json: str,
    ) -> str:
        try:
            arguments = json.loads(arguments_json or "{}")
            if not isinstance(arguments, dict):
                raise ValueError("tool arguments must be an object")
            if tool_name == "get_project_context":
                result = self.get_project_context(task, arguments)
            elif tool_name == "resolve_c_symbol":
                result = self.resolve_c_symbol(
                    _required_symbol(arguments),
                    kind=_optional_string(arguments.get("kind")) or "unknown",
                    task=task,
                )
            elif tool_name == "inspect_c_usage":
                result = self.inspect_c_usage(
                    _required_symbol(arguments),
                    limit=_optional_positive_int(arguments.get("limit"), default=20),
                )
            elif tool_name == "inspect_cargo_dependencies":
                result = self.inspect_cargo_dependencies(
                    crate_name=_optional_string(arguments.get("crate")),
                )
            elif tool_name == "inspect_rust_crate_api":
                result = self.inspect_rust_crate_api(
                    crate_name=_required_crate_name(arguments),
                    query=_required_query(arguments),
                    limit=_optional_positive_int(arguments.get("limit"), default=30),
                )
            elif tool_name == "inspect_pointer_usage":
                result = self.inspect_pointer_usage(
                    _required_symbol(arguments),
                    limit=_optional_positive_int(arguments.get("limit"), default=40),
                )
            else:
                result = {
                    "ok": False,
                    "error": f"unsupported project inspection tool: {tool_name}",
                }
            return json.dumps(result, ensure_ascii=False, indent=2)
        except Exception as exc:
            return json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                },
                ensure_ascii=False,
                indent=2,
            )

    def get_project_context(
        self,
        task: TranslationTask,
        arguments: JsonDict,
    ) -> JsonDict:
        symbols = _symbol_requests(arguments.get("symbols"))
        crates = _string_list(arguments.get("crates"), limit=12)
        symbol_context: list[JsonDict] = []
        for request in symbols:
            symbol = request["symbol"]
            kind = request.get("kind") or "unknown"
            resolved = self.resolve_c_symbol(symbol, kind=kind, task=task)
            context: JsonDict = {
                "symbol": symbol,
                "requested_kind": kind,
                "resolution": _compact_resolution(resolved),
                "usage": self.inspect_c_usage(symbol, limit=12),
            }
            if request.get("pointer") or kind == "pointer":
                context["pointer_usage"] = self.inspect_pointer_usage(symbol, limit=20)
            symbol_context.append(context)
        family_strategies = _external_api_family_strategies(
            symbol["symbol"] for symbol in symbols
        )

        cargo_context: JsonDict | list[JsonDict]
        if crates:
            cargo_context = [
                self.inspect_cargo_dependencies(crate_name=crate_name)
                for crate_name in crates
            ]
        else:
            cargo_context = self.inspect_cargo_dependencies()

        return {
            "ok": True,
            "tool": "get_project_context",
            "current_entity": {
                "entity_id": task.entity_id,
                "name": task.package.name,
                "kind": task.kind,
            },
            "symbols": symbol_context,
            "cargo": cargo_context,
            "external_api_family_strategies": family_strategies,
            "guidance": (
                "Choose a direct safe Rust std/crate/project abstraction from "
                "this context. Preserve consistent Rust representations for "
                "symbols with the same C type and usage role. Do not use "
                "crate::external, placeholder types, dyn Any, raw pointer "
                "aliases, or FFI shims."
            ),
        }

    def build_cargo_dependency_context(self) -> str:

        lines = [
            "Cargo Dependency Context (manually configured, read-only):",
            "Use these external crates when their APIs preserve the C behavior. "
            "Use only the configured versions and enabled features; verify exact "
            "APIs with inspect_rust_crate_api when needed. Do not edit Cargo.toml, "
            "run cargo add, or request new crates/features. cargo_dependencies "
            "must be empty. Optional, target-specific, or workspace-inherited "
            "dependencies require verification that they are available to this crate.",
        ]
        if self.rust_project is None:
            return "\n".join(lines + ["Dependency availability is unknown: rust_project is not configured."])
        manifest = self.rust_project / "Cargo.toml"
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return "\n".join(lines + [f"Dependency availability is unknown: cannot read {manifest}: {exc}"])
        dependencies = data.get("dependencies", {})
        lines.append(f"Source: {manifest} [dependencies]")
        if not dependencies:
            lines.append("No external crates are configured in [dependencies].")
        for name, spec in sorted(dependencies.items()):
            lines.append(
                f"- {name} (Rust crate path: {name.replace('-', '_')}): "
                + json.dumps(spec, ensure_ascii=False, sort_keys=True)
            )
        lines.append("Do not assume dev-dependencies, build-dependencies, or transitive crates are directly usable.")
        return "\n".join(lines)

    def build_external_symbol_context(
        self,
        task: TranslationTask,
        *,
        limit: int = 12,
    ) -> str:
        collected = self.collect_entity_symbols(task)
        symbols = _candidate_symbol_requests(collected, limit=limit)
        if not symbols:
            return ""

        lines = [
            "External Symbol Context:",
            (
                "These C symbols are referenced by the current entity or by "
                "macros it uses. Treat unresolved header/library symbols as "
                "external C APIs: do not copy their C names into Rust unless "
                "you intentionally preserve FFI, and do not invent helpers or "
                "erase observable side effects."
            ),
            "",
        ]
        for request in symbols:
            resolved = self._resolve_c_symbol_lightweight(request["symbol"])
            lines.extend(_external_symbol_lines(request, resolved))
        family_strategies = _external_api_family_strategies(
            request["symbol"] for request in symbols
        )
        if family_strategies:
            lines.extend(["", "External API Family Strategy:"])
            for strategy in family_strategies:
                lines.extend(_external_api_family_strategy_lines(strategy))
        return "\n".join(lines).strip()

    def collect_entity_symbols(self, task: TranslationTask) -> JsonDict:
        return _collect_entity_symbols_with_tree_sitter(task)

    def _resolve_c_symbol_lightweight(self, symbol: str) -> JsonDict:
        return {
            "ok": True,
            "symbol": symbol,
            "project_matches": self.inspect_c_usage(symbol, limit=3).get("matches", []),
            "macro_matches": self._macro_matches(symbol),
            "clang_probe": {"ok": False, "skipped": True},
        }

    def resolve_c_symbol(
        self,
        symbol: str,
        *,
        kind: str,
        task: TranslationTask,
    ) -> JsonDict:
        project_matches = self.inspect_c_usage(symbol, limit=12)
        clang_result = self._clang_probe_symbol(symbol, kind=kind)
        macro_matches = self._macro_matches(symbol)
        return {
            "ok": True,
            "tool": "resolve_c_symbol",
            "symbol": symbol,
            "requested_kind": kind,
            "project_matches": project_matches.get("matches", []),
            "macro_matches": macro_matches,
            "clang_probe": clang_result,
            "current_entity": {
                "entity_id": task.entity_id,
                "name": task.package.name,
                "kind": task.kind,
            },
            "guidance": (
                "Use these facts to choose a direct Rust std/crate/project "
                "abstraction. Do not generate crate::external or placeholder "
                "types."
            ),
        }

    def inspect_c_usage(self, symbol: str, *, limit: int = 20) -> JsonDict:
        matches: list[JsonDict] = []
        for path, lineno, line in self._c_identifier_line_index.get(symbol, ()):
            matches.append(
                {
                    "path": str(path),
                    "line": lineno,
                    "kind": _classify_c_line(line, symbol),
                    "text": line.strip()[:500],
                }
            )
            if len(matches) >= limit:
                return {
                        "ok": True,
                        "tool": "inspect_c_usage",
                        "symbol": symbol,
                        "backend": self._cached_tree_sitter_backend_status,
                        "matches": matches,
                        "truncated": True,
                    }
        return {
            "ok": True,
            "tool": "inspect_c_usage",
            "symbol": symbol,
            "backend": self._cached_tree_sitter_backend_status,
            "matches": matches,
            "truncated": False,
        }

    def inspect_pointer_usage(self, symbol: str, *, limit: int = 40) -> JsonDict:
        pattern = re.compile(rf"\b{re.escape(symbol)}\b")
        matches: list[JsonDict] = []
        categories: dict[str, int] = {}
        for path, lines in self._c_source_file_lines:
            for lineno, line in enumerate(lines, start=1):
                if not pattern.search(line):
                    continue
                category = _classify_pointer_line(line, symbol)
                categories[category] = categories.get(category, 0) + 1
                matches.append(
                    {
                        "path": str(path),
                        "line": lineno,
                        "category": category,
                        "text": line.strip()[:500],
                    }
                )
                if len(matches) >= limit:
                    return {
                        "ok": True,
                        "tool": "inspect_pointer_usage",
                        "symbol": symbol,
                        "backend": self._cached_tree_sitter_backend_status,
                        "categories": categories,
                        "matches": matches,
                        "recommendation_hints": _pointer_recommendation_hints(categories),
                        "truncated": True,
                    }
        return {
            "ok": True,
            "tool": "inspect_pointer_usage",
            "symbol": symbol,
            "backend": self._cached_tree_sitter_backend_status,
            "categories": categories,
            "matches": matches,
            "recommendation_hints": _pointer_recommendation_hints(categories),
            "truncated": False,
        }

    def inspect_cargo_dependencies(self, *, crate_name: str | None = None) -> JsonDict:
        rust_project = self.rust_project
        if rust_project is None:
            return {
                "ok": False,
                "error": "rust_project is not configured",
            }
        cargo_toml = rust_project / "Cargo.toml"
        dependencies: dict[str, JsonDict] = {}
        backend = "Cargo.toml"
        cargo_path = shutil.which(self.cargo)
        if cargo_path is not None:
            result = subprocess.run(
                [cargo_path, "metadata", "--format-version", "1", "--no-deps"],
                cwd=rust_project,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            if result.returncode == 0:
                backend = "cargo metadata"
                metadata = json.loads(result.stdout)
                root = metadata.get("root_package")
                packages = metadata.get("packages", [])
                root_package = next(
                    (
                        package
                        for package in packages
                        if isinstance(package, dict) and package.get("id") == root
                    ),
                    None,
                )
                if root_package is None and len(packages) == 1 and isinstance(packages[0], dict):
                    root_package = packages[0]
                if isinstance(root_package, dict):
                    for dependency in root_package.get("dependencies", []):
                        if not isinstance(dependency, dict):
                            continue
                        name = dependency.get("name")
                        if isinstance(name, str):
                            dependencies[name] = {
                                "version": dependency.get("req", ""),
                                "features": dependency.get("features", []),
                                "source": "cargo metadata",
                            }
            elif cargo_toml.is_file():
                dependencies = _dependency_specs_json(cargo_toml)
        elif cargo_toml.is_file():
            dependencies = _dependency_specs_json(cargo_toml)

        if crate_name:
            dependencies = {
                name: spec
                for name, spec in dependencies.items()
                if name == crate_name
            }
        return {
            "ok": True,
            "tool": "inspect_cargo_dependencies",
            "backend": backend,
            "rust_project": str(rust_project),
            "dependencies": dependencies,
        }

    def inspect_rust_crate_api(
        self,
        *,
        crate_name: str,
        query: str,
        limit: int = 30,
    ) -> JsonDict:
        if self.rust_project is None:
            return {
                "ok": False,
                "tool": "inspect_rust_crate_api",
                "error": "rust_project is not configured",
            }
        dependency = self.inspect_cargo_dependencies(crate_name=crate_name)
        dependency_specs = dependency.get("dependencies", {})
        if not isinstance(dependency_specs, dict) or crate_name not in dependency_specs:
            return {
                "ok": False,
                "tool": "inspect_rust_crate_api",
                "crate": crate_name,
                "query": query,
                "error": f"crate {crate_name!r} is not declared in Cargo.toml",
                "cargo": dependency,
            }

        versions = self._crate_version_candidates(crate_name)
        roots = self._crate_source_roots(crate_name, versions=versions)
        tokens = _query_tokens(query)
        matches = _crate_source_matches(roots, tokens=tokens, limit=limit)
        return {
            "ok": bool(roots),
            "tool": "inspect_rust_crate_api",
            "crate": crate_name,
            "query": query,
            "versions": versions,
            "source_roots": [str(root) for root in roots],
            "matches": matches,
            "truncated": len(matches) >= limit,
            "guidance": (
                "Use exact item, module, function, type, and enum variant "
                "names from these matches. Do not infer renamed crate APIs. "
                "If matches contradict a guessed Rust path, rewrite the code "
                "to the exact available API or choose a different verified API."
            ),
            "cargo": dependency,
        }

    def _crate_version_candidates(self, crate_name: str) -> list[str]:
        versions: list[str] = []
        for version in self._cargo_lock_versions(crate_name):
            if version not in versions:
                versions.append(version)
        dependency = self.inspect_cargo_dependencies(crate_name=crate_name)
        specs = dependency.get("dependencies", {})
        if isinstance(specs, dict):
            spec = specs.get(crate_name)
            if isinstance(spec, dict):
                raw_version = spec.get("version")
                if isinstance(raw_version, str):
                    cleaned = _clean_cargo_version_req(raw_version)
                    if cleaned and cleaned not in versions:
                        versions.append(cleaned)
        return versions

    def _cargo_lock_versions(self, crate_name: str) -> tuple[str, ...]:
        if self.rust_project is None:
            return ()
        lock_path = self.rust_project / "Cargo.lock"
        if not lock_path.is_file():
            return ()
        try:
            text = lock_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ()
        versions: list[str] = []
        current_name: str | None = None
        for line in text.splitlines():
            stripped = line.strip()
            if stripped == "[[package]]":
                current_name = None
                continue
            name_match = re.fullmatch(r'name\s*=\s*"([^"]+)"', stripped)
            if name_match:
                current_name = name_match.group(1)
                continue
            version_match = re.fullmatch(r'version\s*=\s*"([^"]+)"', stripped)
            if current_name == crate_name and version_match:
                versions.append(version_match.group(1))
        return tuple(dict.fromkeys(versions))

    def _crate_source_roots(
        self,
        crate_name: str,
        *,
        versions: list[str],
    ) -> tuple[Path, ...]:
        candidates: list[Path] = []
        crate_prefix = f"{crate_name}-"
        for registry_root in _cargo_registry_src_roots():
            if not registry_root.is_dir():
                continue
            for source_root in registry_root.iterdir():
                if not source_root.is_dir() or not source_root.name.startswith(crate_prefix):
                    continue
                version = source_root.name[len(crate_prefix):]
                if versions and not any(
                    version == candidate or version.startswith(f"{candidate}.")
                    for candidate in versions
                ):
                    continue
                candidates.append(source_root)
        if not candidates and versions:
            return self._crate_source_roots(crate_name, versions=[])
        return tuple(sorted(candidates, key=lambda path: path.name, reverse=True)[:4])

    def _clang_probe_symbol(self, symbol: str, *, kind: str) -> JsonDict:
        clang_path = shutil.which(self.clang)
        if clang_path is None:
            return {
                "ok": False,
                "backend": "clang",
                "error": f"clang executable not found: {self.clang}",
            }
        candidates = _clang_probe_candidates(symbol, kind=kind)
        include_lines = "\n".join(f"#include <{header}>" for header in _COMMON_C_HEADERS)
        args = self._preprocess_args()
        for candidate in candidates:
            source = f"{include_lines}\n\n{candidate}\n"
            with tempfile.NamedTemporaryFile(
                "w",
                suffix=".c",
                encoding="utf-8",
                delete=False,
            ) as handle:
                handle.write(source)
                temp_path = Path(handle.name)
            try:
                command = [
                    clang_path,
                    "-fsyntax-only",
                    "-Wno-everything",
                    *args,
                    str(temp_path),
                ]
                result = subprocess.run(
                    command,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=20,
                    check=False,
                )
            finally:
                try:
                    temp_path.unlink()
                except OSError:
                    pass
            if result.returncode == 0:
                return {
                    "ok": True,
                    "backend": "clang -fsyntax-only",
                    "probe": candidate,
                    "headers": list(_COMMON_C_HEADERS),
                    "preprocess_args": args,
                    "meaning": (
                        "clang accepted this symbol with common/project headers; "
                        "it is likely provided by included system or project C APIs."
                    ),
                }
        return {
            "ok": False,
            "backend": "clang -fsyntax-only",
            "error": "symbol was not accepted by clang probes",
            "probes": candidates,
            "preprocess_args": args,
        }

    def _preprocess_args(self) -> list[str]:
        manifest = self._preprocess_manifest()
        units = manifest.get("units", []) if isinstance(manifest, dict) else []
        for unit in units:
            if not isinstance(unit, dict):
                continue
            args = unit.get("preprocess_args", [])
            if isinstance(args, list):
                return [item for item in args if isinstance(item, str)]
        return []

    def _macro_matches(self, symbol: str) -> list[JsonDict]:
        matches: list[JsonDict] = []
        for macro in self._macro_catalog:
            if not isinstance(macro, dict) or macro.get("name") != symbol:
                continue
            matches.append(
                {
                    "name": macro.get("name"),
                    "path": macro.get("path"),
                    "line": macro.get("start_line"),
                    "source": macro.get("source"),
                }
            )
            if len(matches) >= 10:
                break
        return matches

    @cached_property
    def _macro_catalog(self) -> tuple[JsonDict, ...]:
        macro_file = self.workspace / "project-macros.json"
        if not macro_file.is_file():
            return ()
        try:
            data = json.loads(macro_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return ()
        raw_macros = data.get("macros") if isinstance(data, dict) else data
        if not isinstance(raw_macros, list):
            return ()
        return tuple(item for item in raw_macros if isinstance(item, dict))

    @cached_property
    def _c_source_file_lines(self) -> tuple[tuple[Path, tuple[str, ...]], ...]:
        result: list[tuple[Path, tuple[str, ...]]] = []
        for path in self._c_source_files():
            try:
                lines = tuple(path.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError:
                continue
            result.append((path, lines))
        return tuple(result)

    @cached_property
    def _c_identifier_line_index(self) -> dict[str, tuple[tuple[Path, int, str], ...]]:
        indexed: dict[str, list[tuple[Path, int, str]]] = {}
        for path, lines in self._c_source_file_lines:
            for lineno, line in enumerate(lines, start=1):
                for symbol in set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", line)):
                    indexed.setdefault(symbol, []).append((path, lineno, line))
        return {symbol: tuple(matches) for symbol, matches in indexed.items()}

    def _c_source_files(self) -> tuple[Path, ...]:
        files: list[Path] = []
        manifest = self._preprocess_manifest()
        units = manifest.get("units", []) if isinstance(manifest, dict) else []
        for unit in units:
            if not isinstance(unit, dict):
                continue
            for key in (
                "source_path",
                "preprocessed_path",
                "commented_preprocessed_path",
            ):
                value = unit.get(key)
                if not isinstance(value, str) or not value:
                    continue
                path = Path(value)
                if not path.is_absolute():
                    path = self.workspace / path
                if path.is_file() and path not in files:
                    files.append(path)
        if files:
            return tuple(files)
        return tuple(
            sorted(
                path
                for root in (self.workspace / "preprocessed", self.workspace / "preprocessed_with_comments")
                if root.is_dir()
                for path in root.rglob("*.c")
            )
        )

    def _preprocess_manifest(self) -> JsonDict:
        path = self.workspace / "preprocess-manifest.json"
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _tree_sitter_backend_status(self) -> JsonDict:
        return self._cached_tree_sitter_backend_status

    @cached_property
    def _cached_tree_sitter_backend_status(self) -> JsonDict:
        return {
            "name": "tree-sitter-c",
            "status": _tree_sitter_status(self.conda_env_name),
            "note": (
                "This tool uses source scanning as a stable fallback; install "
                "tree_sitter_c in the c2safety env to enable AST classification."
            ),
        }


def _required_symbol(arguments: JsonDict) -> str:
    value = arguments.get("symbol")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("symbol must be a non-empty string")
    symbol = value.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
        raise ValueError(f"invalid C symbol name: {symbol!r}")
    return symbol


def _required_crate_name(arguments: JsonDict) -> str:
    value = arguments.get("crate")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("crate must be a non-empty string")
    crate_name = value.strip()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", crate_name):
        raise ValueError(f"invalid Cargo crate name: {crate_name!r}")
    return crate_name


def _required_query(arguments: JsonDict) -> str:
    value = arguments.get("query")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("query must be a non-empty string")
    return value.strip()


def _symbol_requests(value: Any) -> list[JsonDict]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("symbols must be an array")
    requests: list[JsonDict] = []
    for item in value[:20]:
        if isinstance(item, str):
            item = {"symbol": item}
        if not isinstance(item, dict):
            raise ValueError("each symbol request must be an object or string")
        symbol = _required_symbol(item)
        kind = _optional_string(item.get("kind")) or "unknown"
        if kind not in {
            "function",
            "type",
            "struct",
            "macro",
            "constant",
            "global",
            "pointer",
            "unknown",
        }:
            kind = "unknown"
        requests.append(
            {
                "symbol": symbol,
                "kind": kind,
                "pointer": bool(item.get("pointer")),
            }
        )
    return requests


_C_KEYWORDS_AND_BUILTINS = {
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "_Bool",
    "bool",
    "NULL",
}

_RUST_QUERY_NOISE = {
    "as",
    "const",
    "crate",
    "enum",
    "fn",
    "impl",
    "mod",
    "pub",
    "self",
    "struct",
    "trait",
    "type",
    "use",
    "where",
}


def _collect_entity_symbols_with_tree_sitter(task: TranslationTask) -> JsonDict:
    macro_context = [
        item
        for item in task.package.macro_context
        if isinstance(item, dict)
    ]
    sources = [task.package.original_c_source or task.package.annotated_c_source]
    for macro in macro_context:
        for key in ("replacement", "source"):
            value = macro.get(key)
            if isinstance(value, str) and value.strip():
                sources.append(value)

    merged: JsonDict = {
        "backend": "tree-sitter-c",
        "function_calls": [],
        "types": [],
        "macros_or_constants": [],
        "macro_names": [],
    }
    seen: set[tuple[str, str]] = set()
    macro_params: set[str] = set()
    for macro in macro_context:
        name = macro.get("name")
        if isinstance(name, str) and _is_c_identifier(name):
            _append_symbol(merged, seen, "macro_names", name)
        params = macro.get("parameters")
        if isinstance(params, list):
            macro_params.update(item for item in params if isinstance(item, str))

    for source in sources:
        parsed = _tree_sitter_c_symbols(source)
        for key in ("function_calls", "types", "macros_or_constants"):
            for symbol in parsed.get(key, []):
                if not isinstance(symbol, str):
                    continue
                if symbol == task.package.name or symbol in macro_params:
                    continue
                if symbol in _C_KEYWORDS_AND_BUILTINS:
                    continue
                _append_symbol(merged, seen, key, symbol)

    if not any(merged[key] for key in ("function_calls", "types", "macros_or_constants")):
        merged["backend"] = "regex-fallback"
        _collect_entity_symbols_regex(task, macro_context, merged, seen, macro_params)

    return merged


def _tree_sitter_c_symbols(source: str) -> JsonDict:
    if not source.strip():
        return {"function_calls": [], "types": [], "macros_or_constants": []}
    try:
        return _tree_sitter_c_symbols_in_process(source)
    except Exception:
        result = _tree_sitter_c_symbols_conda(source)
        if result:
            return result
    return {"function_calls": [], "types": [], "macros_or_constants": []}


def _tree_sitter_c_symbols_in_process(source: str) -> JsonDict:
    from pathlib import Path as _Path

    import tree_sitter_c
    from tree_sitter import Language, Parser

    language_fn = tree_sitter_c.language()
    try:
        language = Language(language_fn)
        parser = Parser(language)
    except TypeError:
        binding_path = _Path(tree_sitter_c.__file__).parent / "_binding.abi3.so"
        language = Language(str(binding_path), "c")
        parser = Parser()
        parser.set_language(language)
    tree = parser.parse(source.encode("utf-8"))
    return _symbols_from_tree(source.encode("utf-8"), tree.root_node)


def _tree_sitter_c_symbols_conda(source: str) -> JsonDict | None:
    conda_path = shutil.which("conda")
    if conda_path is None:
        return None
    script = r'''
import json
import sys

payload = json.loads(sys.stdin.read())
source = payload.get("source", "")
import tree_sitter_c
from tree_sitter import Language, Parser

language_fn = tree_sitter_c.language()
try:
    language = Language(language_fn)
    parser = Parser(language)
except TypeError:
    language = Language(language_fn, "c")
    parser = Parser()
    parser.set_language(language)
source_bytes = source.encode("utf-8")
tree = parser.parse(source_bytes)

def text(node):
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", "replace")

def first_identifier(node):
    if node.type == "identifier":
        return text(node)
    for child in node.children:
        value = first_identifier(child)
        if value:
            return value
    return None

out = {"function_calls": [], "types": [], "macros_or_constants": []}
seen = set()

def add(key, value):
    if not value:
        return
    pair = (key, value)
    if pair not in seen:
        seen.add(pair)
        out[key].append(value)

def walk(node):
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        add("function_calls", first_identifier(fn) if fn is not None else None)
    elif node.type == "type_identifier":
        add("types", text(node))
    elif node.type == "identifier":
        value = text(node)
        if value.isupper() and len(value) > 1:
            add("macros_or_constants", value)
    for child in node.children:
        walk(child)

walk(tree.root_node)
print(json.dumps(out))
'''
    result = subprocess.run(
        [conda_path, "run", "-n", "c2safety", "python", "-c", script],
        input=json.dumps({"source": source}),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
    )
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _symbols_from_tree(source_bytes: bytes, root: Any) -> JsonDict:
    out: JsonDict = {
        "function_calls": [],
        "types": [],
        "macros_or_constants": [],
    }
    seen: set[tuple[str, str]] = set()

    def node_text(node: Any) -> str:
        return source_bytes[node.start_byte : node.end_byte].decode(
            "utf-8",
            "replace",
        )

    def first_identifier(node: Any | None) -> str | None:
        if node is None:
            return None
        if node.type == "identifier":
            return node_text(node)
        for child in getattr(node, "children", []):
            value = first_identifier(child)
            if value:
                return value
        return None

    def add(key: str, value: str | None) -> None:
        if not value:
            return
        pair = (key, value)
        if pair not in seen:
            seen.add(pair)
            out[key].append(value)

    def walk(node: Any) -> None:
        if node.type == "call_expression":
            add("function_calls", first_identifier(node.child_by_field_name("function")))
        elif node.type == "type_identifier":
            add("types", node_text(node))
        elif node.type == "identifier":
            value = node_text(node)
            if value.isupper() and len(value) > 1:
                add("macros_or_constants", value)
        for child in getattr(node, "children", []):
            walk(child)

    walk(root)
    return out


def _collect_entity_symbols_regex(
    task: TranslationTask,
    macro_context: list[JsonDict],
    merged: JsonDict,
    seen: set[tuple[str, str]],
    macro_params: set[str],
) -> None:
    sources = [task.package.original_c_source or task.package.annotated_c_source]
    for macro in macro_context:
        for key in ("replacement", "source"):
            value = macro.get(key)
            if isinstance(value, str) and value.strip():
                sources.append(value)
    for source in sources:
        masked = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", source)
        for symbol in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", masked):
            if (
                symbol not in _C_KEYWORDS_AND_BUILTINS
                and symbol not in macro_params
                and symbol != task.package.name
                and not symbol.isupper()
            ):
                _append_symbol(merged, seen, "function_calls", symbol)
        for symbol in re.findall(r"\b[A-Z][A-Z0-9_]{1,}\b", masked):
            if symbol not in macro_params:
                _append_symbol(merged, seen, "macros_or_constants", symbol)


def _append_symbol(
    data: JsonDict,
    seen: set[tuple[str, str]],
    key: str,
    symbol: str,
) -> None:
    if not _is_c_identifier(symbol):
        return
    pair = (key, symbol)
    if pair in seen:
        return
    seen.add(pair)
    data.setdefault(key, []).append(symbol)


def _candidate_symbol_requests(collected: JsonDict, *, limit: int) -> list[JsonDict]:
    requests: list[JsonDict] = []
    seen: set[str] = set()
    for key, kind in (
        ("macro_names", "macro"),
        ("function_calls", "function"),
        ("types", "type"),
        ("macros_or_constants", "macro"),
    ):
        values = collected.get(key, [])
        if not isinstance(values, list):
            continue
        for symbol in values:
            if not isinstance(symbol, str) or symbol in seen:
                continue
            if symbol in _C_KEYWORDS_AND_BUILTINS:
                continue
            seen.add(symbol)
            requests.append({"symbol": symbol, "kind": kind, "source": key})
            if len(requests) >= limit:
                return requests
    return requests


def _external_symbol_lines(request: JsonDict, resolved: JsonDict) -> list[str]:
    symbol = request["symbol"]
    kind = request.get("kind", "unknown")
    lines = [f"- {symbol} ({kind}, from {request.get('source', 'entity')})"]
    for macro in resolved.get("macro_matches", [])[:2]:
        if not isinstance(macro, dict):
            continue
        source = macro.get("source") or macro.get("text")
        path = macro.get("path")
        line = macro.get("line")
        location = f"{path}:{line}" if path and line else path
        if location:
            lines.append(f"  macro: {location}")
        if source:
            lines.append(f"  macro source: {str(source).strip()[:240]}")
    for match in resolved.get("project_matches", [])[:3]:
        if not isinstance(match, dict):
            continue
        path = match.get("path")
        line = match.get("line")
        match_kind = match.get("kind")
        text = match.get("text")
        location = f"{path}:{line}" if path and line else path
        if location or text:
            prefix = f"  usage: {location}" if location else "  usage:"
            if match_kind:
                prefix += f" [{match_kind}]"
            lines.append(prefix)
            if text:
                lines.append(f"    {str(text).strip()[:240]}")
    clang_probe = resolved.get("clang_probe", {})
    if isinstance(clang_probe, dict) and clang_probe.get("ok"):
        lines.append("  clang: accepted with project/common headers")
    return lines


def _external_api_family_strategies(symbols: Any) -> list[JsonDict]:
    return []


def _external_api_family_strategy_lines(strategy: JsonDict) -> list[str]:
    family = strategy.get("family", "external API")
    lines = [f"- {family}"]
    triggers = strategy.get("trigger_symbols")
    if isinstance(triggers, list) and triggers:
        lines.append(f"  triggers: {', '.join(str(item) for item in triggers[:16])}")
    crate = strategy.get("preferred_rust_crate")
    if isinstance(crate, str) and crate:
        lines.append(f"  preferred Rust crate: {crate}")
    dependency = strategy.get("cargo_dependency")
    if isinstance(dependency, dict):
        name = dependency.get("name")
        version = dependency.get("version")
        features = dependency.get("features")
        if name and version:
            suffix = f" features={features}" if isinstance(features, list) and features else ""
            lines.append(f"  cargo: {name} {version}{suffix}")
    guidance = strategy.get("guidance")
    if isinstance(guidance, str) and guidance:
        lines.append(f"  guidance: {guidance}")
    mappings = strategy.get("common_mappings")
    if isinstance(mappings, dict) and mappings:
        lines.append("  common mappings:")
        for key, value in mappings.items():
            lines.append(f"    {key} -> {value}")
    return lines


def _query_tokens(query: str) -> tuple[str, ...]:
    tokens = [
        token
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", query)
        if token not in _C_KEYWORDS_AND_BUILTINS and token not in _RUST_QUERY_NOISE
    ]
    return tuple(dict.fromkeys(tokens))


def _clean_cargo_version_req(version_req: str) -> str:
    cleaned = version_req.strip()
    cleaned = re.sub(r"^[~^=<> ]+", "", cleaned)
    cleaned = cleaned.split(",", 1)[0].strip()
    return cleaned


def _cargo_registry_src_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    cargo_home = Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")
    src_root = cargo_home / "registry" / "src"
    if src_root.is_dir():
        roots.extend(path for path in src_root.iterdir() if path.is_dir())
    return tuple(roots)


def _crate_source_matches(
    roots: tuple[Path, ...],
    *,
    tokens: tuple[str, ...],
    limit: int,
) -> list[JsonDict]:
    if not tokens:
        return []
    candidates: list[tuple[int, JsonDict]] = []
    lowered_tokens = tuple(token.lower() for token in tokens)
    for root in roots:
        for path in sorted(root.rglob("*.rs")):
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, start=1):
                lowered = line.lower()
                token_hits = sum(
                    1
                    for token, lowered_token in zip(tokens, lowered_tokens, strict=True)
                    if token in line or lowered_token in lowered
                )
                if token_hits == 0:
                    continue
                stripped = line.strip()
                declaration_bonus = 0
                if re.match(
                    r"^(pub\s+)?(fn|enum|struct|type|trait|mod|const)\b",
                    stripped,
                ):
                    declaration_bonus += 5
                if re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
                    declaration_bonus += 4
                if re.match(r"^_[A-Za-z_][A-Za-z0-9_]*\s*=", stripped):
                    declaration_bonus += 4
                score = token_hits * 10 + declaration_bonus
                candidates.append(
                    (
                        score,
                        {
                            "path": str(path),
                            "line": lineno,
                            "text": stripped[:500],
                        },
                    )
                )
    candidates.sort(
        key=lambda item: (
            -item[0],
            item[1]["path"],
            item[1]["line"],
        )
    )
    return [match for _, match in candidates[:limit]]


def _is_c_identifier(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value))


def _string_list(value: Any, *, limit: int) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError("crates must be an array")
    result: list[str] = []
    for item in value[:limit]:
        if isinstance(item, str) and item.strip():
            result.append(item.strip())
    return result


def _compact_resolution(result: JsonDict) -> JsonDict:
    return {
        "ok": result.get("ok"),
        "macro_matches": result.get("macro_matches", []),
        "clang_probe": result.get("clang_probe", {}),
        "project_matches": result.get("project_matches", []),
    }


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _optional_positive_int(value: Any, *, default: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return min(value, 100)
    return default


def _classify_c_line(line: str, symbol: str) -> str:
    stripped = line.strip()
    if re.match(rf"^\s*#\s*define\s+{re.escape(symbol)}\b", line):
        return "macro_definition"
    if re.search(rf"\b(struct|enum|union)\s+{re.escape(symbol)}\b", line):
        return "tag_reference_or_definition"
    if re.search(rf"\btypedef\b.*\b{re.escape(symbol)}\b", line):
        return "typedef"
    if re.search(rf"\b{re.escape(symbol)}\s*\(", line):
        return "call_or_function_declaration"
    if stripped.startswith("#include"):
        return "include"
    return "reference"


def _classify_pointer_line(line: str, symbol: str) -> str:
    stripped = line.strip()
    escaped = re.escape(symbol)
    if re.search(rf"\b(char|const\s+char)\s*\*+\s*{escaped}\b", line):
        return "char_pointer_declaration"
    if re.search(rf"\b[A-Za-z_][A-Za-z0-9_\s]*\*+\s*{escaped}\b", line):
        return "pointer_declaration"
    if re.search(rf"\b{escaped}\s*==\s*NULL\b|\bNULL\s*==\s*{escaped}\b|!{escaped}\b", line):
        return "null_check"
    if re.search(rf"\b{escaped}\s*=\s*(NULL|nullptr|0)\b", line):
        return "assigned_null"
    if re.search(rf"\b(malloc|calloc|realloc|strdup|xstrdup|realpath|getenv)\s*\(", line) and re.search(rf"\b{escaped}\b", line):
        return "allocation_or_borrow_source"
    if re.search(rf"\b{escaped}\s*=", line):
        return "assignment"
    if re.search(rf"\*\s*{escaped}\b|\b{escaped}\s*\[", line):
        return "dereference_or_index"
    if re.search(rf"&\s*{escaped}\b", line):
        return "address_taken_or_out_parameter"
    if re.search(rf"\b(free|cfree)\s*\(\s*{escaped}\s*\)", line):
        return "freed"
    if re.search(rf"\b(strlen|xstrlen|strcpy|strncpy|xstrsncpy|strcmp|strncmp|strchr|strrchr|strstr|strcasestr|snprintf)\s*\(", line) and re.search(rf"\b{escaped}\b", line):
        return "c_string_operation"
    if re.search(rf"\b{escaped}\s*\(", line):
        return "function_pointer_call_or_function"
    if stripped.startswith("#define"):
        return "macro_reference"
    return "reference"


def _pointer_recommendation_hints(categories: dict[str, int]) -> list[str]:
    hints: list[str] = []
    if categories.get("char_pointer_declaration") or categories.get("c_string_operation"):
        hints.append(
            "C char* usage detected; consider String, Option<String>, PathBuf, "
            "&str, or Vec<u8> depending on ownership and mutability."
        )
    if categories.get("allocation_or_borrow_source") or categories.get("freed"):
        hints.append(
            "Allocation/free evidence detected; model ownership explicitly with "
            "String/Vec/Box/Option rather than raw pointers when possible."
        )
    if categories.get("address_taken_or_out_parameter"):
        hints.append(
            "Address is taken or passed as out parameter; consider mutable state "
            "containers such as &mut Option<T>, Mutex<Option<T>>, or Vec<T>."
        )
    if categories.get("dereference_or_index"):
        hints.append(
            "Dereference/index evidence detected; inspect element type and bounds "
            "before choosing slice, Vec, String, or a structured type."
        )
    if not hints:
        hints.append(
            "No strong pointer-specific evidence found; avoid raw pointers unless "
            "ABI or aliasing requirements are proven by context."
        )
    return hints


def _clang_probe_candidates(symbol: str, *, kind: str) -> list[str]:
    candidates: list[str] = []
    if kind in {"struct", "unknown", ""}:
        candidates.append(f"void c2safety_probe(void) {{ (void)sizeof(struct {symbol}); }}")
    if kind in {"type", "unknown", ""}:
        candidates.append(f"void c2safety_probe(void) {{ (void)sizeof({symbol}); }}")
    if kind in {"function", "unknown", ""}:
        candidates.append(f"void *c2safety_probe(void) {{ return (void *){symbol}; }}")
    if kind in {"macro", "constant", "unknown", ""}:
        candidates.append(f"long c2safety_probe(void) {{ return (long)({symbol}); }}")
    return candidates or [f"void c2safety_probe(void) {{ (void){symbol}; }}"]


def _dependency_specs_json(cargo_toml: Path) -> dict[str, JsonDict]:
    try:
        specs = read_dependency_specs(cargo_toml)
    except Exception:
        return {}
    return {
        name: {
            "version": dependency.version,
            "features": list(dependency.features),
            "source": "Cargo.toml",
        }
        for name, dependency in sorted(specs.items())
    }


def _rust_project_from_workspace(workspace: Path) -> Path | None:
    layout = workspace / "rust-module-layout.json"
    if layout.is_file():
        try:
            data = json.loads(layout.read_text(encoding="utf-8"))
            value = data.get("rust_project")
            if isinstance(value, str) and value:
                path = Path(value)
                return path if path.is_absolute() else workspace / path
        except (OSError, json.JSONDecodeError):
            pass
    candidate = workspace / "rust_project"
    return candidate if candidate.exists() else None


def _tree_sitter_status(conda_env_name: str) -> str:
    code = (
        "import tree_sitter, tree_sitter_c; "
        "print('ok')"
    )
    conda_path = shutil.which("conda")
    if conda_path is not None:
        result = subprocess.run(
            [conda_path, "run", "-n", conda_env_name, "python", "-c", code],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return f"available in conda env {conda_env_name}"
    try:
        import tree_sitter
        import tree_sitter_c
    except Exception as exc:
        return f"unavailable ({type(exc).__name__}: {exc})"
    return "available in current Python process"
