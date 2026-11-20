from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any


@dataclasses.dataclass(frozen=True)
class CompileUnit:


    unit_id: str
    source_path: Path
    source_rel_path: Path
    directory: Path
    compiler: str
    preprocess_args: tuple[str, ...]
    preprocessed_rel_path: Path
    origin_map_rel_path: Path
    commented_preprocessed_rel_path: Path
    commented_origin_map_rel_path: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.unit_id,
            "source_path": str(self.source_path),
            "source_rel_path": self.source_rel_path.as_posix(),
            "directory": str(self.directory),
            "compiler": self.compiler,
            "preprocess_args": list(self.preprocess_args),
            "preprocessed_path": self.preprocessed_rel_path.as_posix(),
            "origin_map_path": self.origin_map_rel_path.as_posix(),
            "commented_preprocessed_path": (
                self.commented_preprocessed_rel_path.as_posix()
            ),
            "commented_origin_map_path": (
                self.commented_origin_map_rel_path.as_posix()
            ),
        }


@dataclasses.dataclass(frozen=True)
class PreprocessManifest:
    version: int
    project_root: Path
    compile_commands_path: Path
    workspace: Path
    units: tuple[CompileUnit, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "project_root": str(self.project_root),
            "compile_commands_path": str(self.compile_commands_path),
            "workspace": str(self.workspace),
            "units": [unit.to_dict() for unit in self.units],
        }
