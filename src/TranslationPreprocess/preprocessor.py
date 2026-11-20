from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .config import (
    COMMENTED_PREPROCESSED_DIR_NAME,
    COMMENTED_PREPROCESSED_ORIGIN_DIR_NAME,
    PREPROCESSED_DIR_NAME,
    PREPROCESSED_ORIGIN_DIR_NAME,
)
from .models import CompileUnit, PreprocessManifest
from .c_macro import MacroCollectionError, ProjectMacroCollector


_LINE_MARKER_RE = re.compile(r'^#\s+(\d+)\s+"((?:\\.|[^"])*)"(?:\s+.*)?$')


class PreprocessError(RuntimeError):
    pass


class CPreprocessor:


    def __init__(self, *, clang: str = "clang") -> None:
        self.clang = clang

    def run(self, manifest: PreprocessManifest) -> list[Path]:
        self._reset_output_directories(manifest)
        outputs: list[Path] = []
        for unit in manifest.units:
            outputs.append(self._preprocess_unit(manifest, unit))
        try:
            ProjectMacroCollector(manifest=manifest).run()
        except MacroCollectionError as exc:
            raise PreprocessError(str(exc)) from exc
        return outputs

    def _preprocess_unit(
        self,
        manifest: PreprocessManifest,
        unit: CompileUnit,
    ) -> Path:
        output_path = manifest.workspace / unit.preprocessed_rel_path
        origin_map_path = manifest.workspace / unit.origin_map_rel_path
        self._preprocess_variant(
            manifest=manifest,
            unit=unit,
            output_path=output_path,
            origin_map_path=origin_map_path,
            preserve_comments=False,
        )

        self._preprocess_variant(
            manifest=manifest,
            unit=unit,
            output_path=(
                manifest.workspace / unit.commented_preprocessed_rel_path
            ),
            origin_map_path=(
                manifest.workspace / unit.commented_origin_map_rel_path
            ),
            preserve_comments=True,
        )
        return output_path

    def _preprocess_variant(
        self,
        *,
        manifest: PreprocessManifest,
        unit: CompileUnit,
        output_path: Path,
        origin_map_path: Path,
        preserve_comments: bool,
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        origin_map_path.parent.mkdir(parents=True, exist_ok=True)

        command = [self.clang, "-E"]
        if preserve_comments:
            command.append("-CC")
        command.extend((*unit.preprocess_args, str(unit.source_path)))
        result = self._run_clang(command, unit)

        if preserve_comments and result.returncode != 0:
            cc_detail = self._error_detail(result.stderr, result.stdout)
            fallback_command = [self.clang, "-E", "-C"]
            fallback_command.extend(
                (*unit.preprocess_args, str(unit.source_path))
            )
            fallback_result = self._run_clang(fallback_command, unit)
            if fallback_result.returncode != 0:
                fallback_detail = self._error_detail(
                    fallback_result.stderr,
                    fallback_result.stdout,
                )
                raise PreprocessError(
                    f"clang -E -CC failed for {unit.source_path} "
                    f"(exit {result.returncode}): {cc_detail}; "
                    f"fallback clang -E -C failed "
                    f"(exit {fallback_result.returncode}): {fallback_detail}"
                )
            print(
                f"warning: clang -E -CC failed for {unit.source_path}; "
                f"using -C fallback: {cc_detail}",
                file=sys.stderr,
            )
            result = fallback_result

        if result.returncode != 0:
            detail = self._error_detail(result.stderr, result.stdout)
            raise PreprocessError(
                f"clang -E failed for {unit.source_path} "
                f"(exit {result.returncode}): {detail}"
            )

        clean_text, origin_map = self._filter_project_code(
            manifest=manifest,
            unit=unit,
            preprocessed_text=result.stdout,
            output_path=output_path,
        )
        temporary_path = output_path.with_suffix(output_path.suffix + ".tmp")
        temporary_origin_path = origin_map_path.with_suffix(
            origin_map_path.suffix + ".tmp"
        )
        try:
            temporary_path.write_text(clean_text, encoding="utf-8")
            temporary_origin_path.write_text(
                json.dumps(origin_map, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            temporary_path.replace(output_path)
            temporary_origin_path.replace(origin_map_path)
        except OSError as exc:
            raise PreprocessError(
                f"failed to write preprocessing artifacts for "
                f"{unit.source_path}: {exc}"
            ) from exc

    def _run_clang(
        self,
        command: list[str],
        unit: CompileUnit,
    ) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                command,
                cwd=unit.directory,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except FileNotFoundError as exc:
            raise PreprocessError(
                f"clang executable not found: {self.clang}"
            ) from exc
        except OSError as exc:
            raise PreprocessError(
                f"failed to start clang for {unit.source_path}: {exc}"
            ) from exc

    @staticmethod
    def _reset_output_directories(manifest: PreprocessManifest) -> None:
        for directory_name in (
            PREPROCESSED_DIR_NAME,
            PREPROCESSED_ORIGIN_DIR_NAME,
            COMMENTED_PREPROCESSED_DIR_NAME,
            COMMENTED_PREPROCESSED_ORIGIN_DIR_NAME,
        ):
            output_root = manifest.workspace / directory_name
            if output_root.exists() and not output_root.is_dir():
                raise PreprocessError(
                    f"preprocessing output path is not a directory: "
                    f"{output_root}"
                )
            if output_root.exists():
                try:
                    shutil.rmtree(output_root)
                except OSError as exc:
                    raise PreprocessError(
                        f"failed to clear preprocessing output directory "
                        f"{output_root}: {exc}"
                    ) from exc
            try:
                output_root.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise PreprocessError(
                    f"failed to create preprocessing output directory "
                    f"{output_root}: {exc}"
                ) from exc

    def _filter_project_code(
        self,
        *,
        manifest: PreprocessManifest,
        unit: CompileUnit,
        preprocessed_text: str,
        output_path: Path,
    ) -> tuple[str, dict[str, Any]]:
        current_file = ""
        current_line = 1
        current_origin: tuple[Path, str] | None = None
        origin_by_marker: dict[str, tuple[Path, str] | None] = {}
        project_root = manifest.project_root.resolve()
        clean_lines: list[str] = []
        ranges: list[dict[str, Any]] = []

        for line in preprocessed_text.splitlines():
            marker = _LINE_MARKER_RE.match(line)
            if marker is not None:
                current_line = int(marker.group(1))
                current_file = self._decode_marker_path(marker.group(2))
                if current_file not in origin_by_marker:
                    origin_by_marker[current_file] = self._project_origin(
                        project_root=project_root,
                        unit=unit,
                        marker_path=current_file,
                    )
                current_origin = origin_by_marker[current_file]
                continue

            if current_origin is not None:
                origin_path, origin_rel_path = current_origin
                clean_lines.append(line)
                self._append_origin_range(
                    ranges=ranges,
                    clean_line=len(clean_lines),
                    origin_path=origin_path,
                    origin_rel_path=origin_rel_path,
                    origin_line=current_line,
                )
            current_line += 1

        clean_text = "\n".join(clean_lines)
        if clean_lines:
            clean_text += "\n"

        origin_map = {
            "version": 1,
            "unit_id": unit.unit_id,
            "clean_path": str(output_path),
            "clean_rel_path": unit.preprocessed_rel_path.as_posix(),
            "original_unit": str(unit.source_path),
            "original_unit_rel_path": unit.source_rel_path.as_posix(),
            "ranges": ranges,
        }
        return clean_text, origin_map

    def _project_origin(
        self,
        *,
        project_root: Path,
        unit: CompileUnit,
        marker_path: str,
    ) -> tuple[Path, str] | None:
        if not marker_path or self._is_virtual_marker(marker_path):
            return None

        origin_path = self._resolve_marker_path(marker_path, unit.directory)
        try:
            origin_rel_path = origin_path.relative_to(project_root).as_posix()
        except ValueError:
            return None
        return origin_path, origin_rel_path

    @staticmethod
    def _append_origin_range(
        *,
        ranges: list[dict[str, Any]],
        clean_line: int,
        origin_path: Path,
        origin_rel_path: str,
        origin_line: int,
    ) -> None:
        origin_path_text = str(origin_path)
        if ranges:
            current = ranges[-1]
            can_extend = (
                current["origin_path"] == origin_path_text
                and int(current["clean_end"]) + 1 == clean_line
                and int(current["origin_end"]) + 1 == origin_line
            )
            if can_extend:
                current["clean_end"] = clean_line
                current["origin_end"] = origin_line
                return

        ranges.append(
            {
                "clean_start": clean_line,
                "clean_end": clean_line,
                "origin_path": origin_path_text,
                "origin_rel_path": origin_rel_path,
                "origin_start": origin_line,
                "origin_end": origin_line,
            }
        )

    @staticmethod
    def _decode_marker_path(value: str) -> str:
        try:
            return bytes(value, "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            return value

    @staticmethod
    def _is_virtual_marker(path: str) -> bool:
        return path.startswith("<") and path.endswith(">")

    @staticmethod
    def _resolve_marker_path(marker_path: str, directory: Path) -> Path:
        path = Path(marker_path)
        if not path.is_absolute():
            path = directory / path
        return path.resolve()

    @staticmethod
    def _error_detail(stderr: str, stdout: str) -> str:
        text = (stderr or stdout or "").strip()
        if not text:
            return "no diagnostic output"
        for line in text.splitlines():
            if "error:" in line:
                return line.strip()
        return text.splitlines()[0].strip()
