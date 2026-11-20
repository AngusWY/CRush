from __future__ import annotations

import hashlib
import json
import os
import shlex
from pathlib import Path
from typing import Any

from .config import (
    COMMENTED_PREPROCESSED_DIR_NAME,
    COMMENTED_PREPROCESSED_ORIGIN_DIR_NAME,
    PREPROCESSED_DIR_NAME,
    PREPROCESSED_ORIGIN_DIR_NAME,
    PREPROCESS_MANIFEST_NAME,
    SUPPORTED_C_EXTENSIONS,
)
from .models import CompileUnit, PreprocessManifest


class ProjectLoadError(RuntimeError):
    pass


class ProjectLoader:


    _PATH_FLAGS = frozenset(
        {
            "-I",
            "-isystem",
            "-iquote",
            "-idirafter",
            "-include",
            "-imacros",
            "-isysroot",
            "--sysroot",
        }
    )
    _VALUE_FLAGS = frozenset(
        {
            "-D",
            "-U",
            "-x",
            "-std",
            "-target",
            "--target",
            "-arch",
            "-march",
            "-mcpu",
            "-mabi",
            "-mfpu",
            "-mfloat-abi",
        }
    )
    _STANDALONE_FLAGS = frozenset(
        {
            "-nostdinc",
            "-nostdinc++",
            "-undef",
            "-pthread",
            "-fms-extensions",
            "-fdeclspec",
            "-fshort-wchar",
            "-funsigned-char",
            "-fsigned-char",
            "-m32",
            "-m64",
        }
    )
    _DROP_WITH_VALUE = frozenset(
        {
            "-o",
            "-MF",
            "-MT",
            "-MQ",
            "-MJ",
            "-Xlinker",
        }
    )
    _DROP_STANDALONE = frozenset(
        {
            "-C",
            "-CC",
            "-c",
            "-S",
            "-M",
            "-MM",
            "-MD",
            "-MMD",
            "-MP",
            "-MG",
            "-pipe",
        }
    )

    def __init__(
        self,
        *,
        project_root: Path,
        workspace: Path,
        compile_commands_path: Path | None = None,
    ) -> None:
        self.project_root = project_root.resolve()
        self.workspace = workspace.resolve()
        self.compile_commands_path = (
            compile_commands_path.resolve()
            if compile_commands_path is not None
            else self._find_compile_commands()
        )

    def build_manifest(self) -> PreprocessManifest:
        self._validate_paths()
        entries = self._read_compile_commands()
        units_by_signature: dict[tuple[Any, ...], CompileUnit] = {}

        for index, entry in enumerate(entries):
            unit = self._parse_entry(entry, index=index)
            if unit is None:
                continue
            signature = self._compile_signature(unit)
            units_by_signature.setdefault(signature, unit)

        if not units_by_signature:
            raise ProjectLoadError(
                f"no existing C source entries found in {self.compile_commands_path}"
            )

        units = tuple(
            sorted(
                units_by_signature.values(),
                key=lambda unit: (
                    unit.source_rel_path.as_posix(),
                    unit.unit_id,
                ),
            )
        )
        return PreprocessManifest(
            version=1,
            project_root=self.project_root,
            compile_commands_path=self.compile_commands_path,
            workspace=self.workspace,
            units=units,
        )

    def write_manifest(self, manifest: PreprocessManifest) -> Path:
        self.workspace.mkdir(parents=True, exist_ok=True)
        output_path = self.workspace / PREPROCESS_MANIFEST_NAME
        temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")
        temporary_path.write_text(
            json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary_path.replace(output_path)
        return output_path

    def _find_compile_commands(self) -> Path:
        candidates = (
            self.project_root / "compile_commands.json",
            self.project_root / "build" / "compile_commands.json",
        )
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        return candidates[0].resolve()

    def _validate_paths(self) -> None:
        if not self.project_root.is_dir():
            raise ProjectLoadError(
                f"C project directory does not exist: {self.project_root}"
            )
        if not self.compile_commands_path.is_file():
            raise ProjectLoadError(
                "compile_commands.json not found; expected "
                f"{self.compile_commands_path} or pass --compile-commands"
            )

    def _read_compile_commands(self) -> list[dict[str, Any]]:
        try:
            raw = json.loads(
                self.compile_commands_path.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError as exc:
            raise ProjectLoadError(
                f"invalid JSON in {self.compile_commands_path}: {exc}"
            ) from exc
        except OSError as exc:
            raise ProjectLoadError(
                f"failed to read {self.compile_commands_path}: {exc}"
            ) from exc

        if not isinstance(raw, list):
            raise ProjectLoadError(
                f"{self.compile_commands_path} must contain a JSON array"
            )
        entries: list[dict[str, Any]] = []
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ProjectLoadError(
                    f"compile command entry {index} must be a JSON object"
                )
            entries.append(item)
        return entries

    def _parse_entry(
        self, entry: dict[str, Any], *, index: int
    ) -> CompileUnit | None:
        raw_directory = entry.get("directory")
        raw_file = entry.get("file")
        if not isinstance(raw_directory, str) or not raw_directory.strip():
            raise ProjectLoadError(
                f"compile command entry {index} has no valid directory"
            )
        if not isinstance(raw_file, str) or not raw_file.strip():
            raise ProjectLoadError(f"compile command entry {index} has no valid file")

        directory = Path(raw_directory)
        if not directory.is_absolute():
            directory = self.project_root / directory
        directory = directory.resolve()

        source_path = self._resolve_path(raw_file, directory)
        if source_path.suffix.lower() not in SUPPORTED_C_EXTENSIONS:
            return None
        if not source_path.is_file():
            raise ProjectLoadError(
                f"compile command entry {index} references missing source: {source_path}"
            )

        arguments = self._entry_arguments(entry, index=index)
        if not arguments:
            raise ProjectLoadError(
                f"compile command entry {index} has an empty command"
            )

        compiler = arguments[0]
        preprocess_args = tuple(
            self._extract_preprocess_args(
                arguments[1:],
                directory=directory,
                source_path=source_path,
            )
        )
        source_rel_path = self._source_relative_path(source_path)
        unit_id = self._stable_unit_id(
            source_rel_path=source_rel_path,
            source_path=source_path,
            directory=directory,
            compiler=compiler,
            preprocess_args=preprocess_args,
        )
        preprocessed_rel_path = (
            Path(PREPROCESSED_DIR_NAME)
            / "__units__"
            / f"{unit_id}{source_path.suffix.lower()}"
        )
        origin_map_rel_path = (
            Path(PREPROCESSED_ORIGIN_DIR_NAME)
            / "__units__"
            / f"{unit_id}.json"
        )
        commented_preprocessed_rel_path = (
            Path(COMMENTED_PREPROCESSED_DIR_NAME)
            / "__units__"
            / f"{unit_id}{source_path.suffix.lower()}"
        )
        commented_origin_map_rel_path = (
            Path(COMMENTED_PREPROCESSED_ORIGIN_DIR_NAME)
            / "__units__"
            / f"{unit_id}.json"
        )

        return CompileUnit(
            unit_id=unit_id,
            source_path=source_path,
            source_rel_path=source_rel_path,
            directory=directory,
            compiler=compiler,
            preprocess_args=preprocess_args,
            preprocessed_rel_path=preprocessed_rel_path,
            origin_map_rel_path=origin_map_rel_path,
            commented_preprocessed_rel_path=commented_preprocessed_rel_path,
            commented_origin_map_rel_path=commented_origin_map_rel_path,
        )

    @staticmethod
    def _entry_arguments(entry: dict[str, Any], *, index: int) -> list[str]:
        raw_arguments = entry.get("arguments")
        if isinstance(raw_arguments, list):
            if not all(isinstance(arg, str) for arg in raw_arguments):
                raise ProjectLoadError(
                    f"compile command entry {index} contains non-string arguments"
                )
            return list(raw_arguments)

        raw_command = entry.get("command")
        if isinstance(raw_command, str) and raw_command.strip():
            try:
                return shlex.split(raw_command)
            except ValueError as exc:
                raise ProjectLoadError(
                    f"failed to parse command in entry {index}: {exc}"
                ) from exc

        raise ProjectLoadError(
            f"compile command entry {index} needs arguments or command"
        )

    def _extract_preprocess_args(
        self,
        arguments: list[str],
        *,
        directory: Path,
        source_path: Path,
    ) -> list[str]:
        result: list[str] = []
        index = 0
        while index < len(arguments):
            arg = arguments[index]

            if arg in self._DROP_WITH_VALUE:
                index += 2
                continue
            if arg in self._DROP_STANDALONE:
                index += 1
                continue
            if self._is_source_argument(arg, directory, source_path):
                index += 1
                continue

            if arg in self._PATH_FLAGS:
                if index + 1 >= len(arguments):
                    raise ProjectLoadError(f"missing value after compile flag {arg}")
                value = arguments[index + 1]
                resolved = self._resolve_flag_path(value, directory)
                if arg == "--sysroot":
                    result.append(f"--sysroot={resolved}")
                else:
                    result.extend((arg, resolved))
                index += 2
                continue

            combined_path_flag = self._combined_path_flag(arg)
            if combined_path_flag is not None:
                flag, value = combined_path_flag
                result.append(f"{flag}{self._resolve_flag_path(value, directory)}")
                index += 1
                continue

            if arg in self._VALUE_FLAGS:
                if index + 1 >= len(arguments):
                    raise ProjectLoadError(f"missing value after compile flag {arg}")
                result.extend((arg, arguments[index + 1]))
                index += 2
                continue

            if self._is_supported_combined_value_flag(arg):
                result.append(arg)
                index += 1
                continue

            if arg in self._STANDALONE_FLAGS:
                result.append(arg)
                index += 1
                continue

            index += 1

        return result

    def _combined_path_flag(self, arg: str) -> tuple[str, str] | None:
        for flag in ("-isystem", "-iquote", "-idirafter", "-include", "-imacros", "-I"):
            if arg.startswith(flag) and arg != flag:
                value = arg[len(flag) :]
                if value:
                    return flag, value
        if arg.startswith("--sysroot="):
            return "--sysroot=", arg.split("=", 1)[1]
        return None

    @staticmethod
    def _is_supported_combined_value_flag(arg: str) -> bool:
        return (
            (arg.startswith("-D") and arg != "-D")
            or (arg.startswith("-U") and arg != "-U")
            or arg.startswith("-std=")
            or (arg.startswith("-x") and arg != "-x")
            or any(
                arg.startswith(prefix)
                for prefix in (
                    "-target=",
                    "--target=",
                    "-arch=",
                    "-march=",
                    "-mcpu=",
                    "-mabi=",
                    "-mfpu=",
                    "-mfloat-abi=",
                )
            )
        )

    @staticmethod
    def _resolve_path(raw_path: str, directory: Path) -> Path:
        path = Path(raw_path)
        if not path.is_absolute():
            path = directory / path
        return path.resolve()

    @staticmethod
    def _resolve_flag_path(raw_path: str, directory: Path) -> str:
        path = Path(raw_path)
        if not path.is_absolute():
            path = directory / path
        return str(path.resolve())

    @staticmethod
    def _is_source_argument(
        arg: str, directory: Path, source_path: Path
    ) -> bool:
        if not arg or arg.startswith("-"):
            return False
        return ProjectLoader._resolve_path(arg, directory) == source_path

    def _source_relative_path(self, source_path: Path) -> Path:
        try:
            return source_path.relative_to(self.project_root)
        except ValueError:
            digest = hashlib.sha256(str(source_path).encode("utf-8")).hexdigest()[:12]
            return Path("_external") / digest / source_path.name

    @classmethod
    def _stable_unit_id(
        cls,
        *,
        source_rel_path: Path,
        source_path: Path,
        directory: Path,
        compiler: str,
        preprocess_args: tuple[str, ...],
    ) -> str:
        digest = cls._compile_signature_digest(
            source_path=source_path,
            directory=directory,
            compiler=compiler,
            preprocess_args=preprocess_args,
        )
        readable = "_".join(source_rel_path.parts).replace(".", "_")
        return f"{readable}-{digest}"

    @staticmethod
    def _compile_signature(unit: CompileUnit) -> tuple[Any, ...]:
        return (
            unit.source_path,
            unit.directory,
            unit.compiler,
            unit.preprocess_args,
        )

    @staticmethod
    def _compile_signature_digest(
        *,
        source_path: Path,
        directory: Path,
        compiler: str,
        preprocess_args: tuple[str, ...],
    ) -> str:
        signature = {
            "source_path": str(source_path),
            "directory": str(directory),
            "compiler": compiler,
            "preprocess_args": list(preprocess_args),
        }
        normalized = json.dumps(
            signature,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
