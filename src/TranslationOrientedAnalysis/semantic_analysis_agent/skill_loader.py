from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
import re


SKILL_DIR = Path(__file__).resolve().parent / "skill"
UNSAFE_ANALYSIS_SKILL_PATH = SKILL_DIR / "unsafe_analysis_skill.md"
RESOURCE_IO_ANALYSIS_SKILL_PATH = SKILL_DIR / "resource_io_analysis_skill.md"
C_STRING_ANALYSIS_SKILL_PATH = SKILL_DIR / "c_string_analysis_skill.md"

UNSAFE_OPERATION_ORDER = (
    "array_read",
    "array_write",
    "mem_read",
    "mem_write",
    "addr_of",
    "field_read",
    "field_write",
    "type_cast_stmt",
    "return_stmt",
)

_SECTION_HEADING_PATTERN = re.compile(r"^##\s+([A-Za-z0-9_]+)\s*$")


class SkillLoadError(RuntimeError):
    pass


def select_unsafe_analysis_skill_sections(
    operations: Iterable[str],
) -> str:


    requested = {str(operation) for operation in operations}
    if not requested:
        return ""

    sections = _unsafe_analysis_skill_sections()
    selected: list[str] = []
    for operation in UNSAFE_OPERATION_ORDER:
        if operation not in requested:
            continue
        section = sections.get(operation)
        if section:
            selected.append(section)
    return "\n\n".join(selected)


@lru_cache(maxsize=1)
def load_resource_io_analysis_skill() -> str:


    try:
        return RESOURCE_IO_ANALYSIS_SKILL_PATH.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SkillLoadError(
            f"failed to read skill file {RESOURCE_IO_ANALYSIS_SKILL_PATH}: {exc}"
        ) from exc


@lru_cache(maxsize=1)
def load_c_string_analysis_skill() -> str:


    try:
        return C_STRING_ANALYSIS_SKILL_PATH.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SkillLoadError(
            f"failed to read skill file {C_STRING_ANALYSIS_SKILL_PATH}: {exc}"
        ) from exc


@lru_cache(maxsize=1)
def _unsafe_analysis_skill_sections() -> dict[str, str]:
    return _read_markdown_sections(UNSAFE_ANALYSIS_SKILL_PATH)


def _read_markdown_sections(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SkillLoadError(f"failed to read skill file {path}: {exc}") from exc

    sections: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []

    for line in text.splitlines():
        match = _SECTION_HEADING_PATTERN.match(line)
        if match:
            if current_name is not None:
                sections[current_name] = "\n".join(current_lines).strip()
            current_name = match.group(1)
            current_lines = [line]
            continue
        if current_name is not None:
            current_lines.append(line)

    if current_name is not None:
        sections[current_name] = "\n".join(current_lines).strip()

    return sections
