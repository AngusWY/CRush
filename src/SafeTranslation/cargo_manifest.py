from __future__ import annotations

import re
from pathlib import Path

from .library_profiles import CargoDependency


MANAGED_DEPENDENCIES_START = "# @C2SAFETY:DEPENDENCIES_START"
MANAGED_DEPENDENCIES_END = "# @C2SAFETY:DEPENDENCIES_END"


class CargoManifestError(ValueError):
    pass


def read_dependency_specs(
    cargo_toml: Path,
    *,
    section: str = "dependencies",
) -> dict[str, CargoDependency]:
    if not cargo_toml.is_file():
        raise FileNotFoundError(cargo_toml)
    return _dependency_specs_in_section(cargo_toml.read_text(encoding="utf-8"), section)


def _dependency_specs_in_section(
    text: str,
    section_name: str,
) -> dict[str, CargoDependency]:
    section_match = _section_pattern(section_name).search(text)
    if section_match is None:
        return {}
    following = text[section_match.end() :]
    next_section = re.search(
        r"^[ \t]*\[[^\n]+\][ \t]*$",
        following,
        re.MULTILINE,
    )
    section = following[: next_section.start()] if next_section else following
    specs: dict[str, CargoDependency] = {}
    for raw_line in section.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        name_part, value_part = line.split("=", 1)
        name = name_part.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            continue
        value = value_part.strip()
        version = _dependency_version_from_value(value)
        features = _dependency_features_from_value(value)
        if version is None:
            continue
        specs[name] = CargoDependency(
            name=name,
            version=version,
            features=features,
        )
    return specs


def _dependency_version_from_value(value: str) -> str | None:
    string_match = re.fullmatch(r'"([^"]+)"', value)
    if string_match:
        return string_match.group(1)
    table_match = re.search(r'\bversion\s*=\s*"([^"]+)"', value)
    if table_match:
        return table_match.group(1)
    return None


def _dependency_features_from_value(value: str) -> tuple[str, ...]:
    match = re.search(r"\bfeatures\s*=\s*\[([^\]]*)\]", value)
    if not match:
        return ()
    return tuple(
        dict.fromkeys(
            feature_match.group(1)
            for feature_match in re.finditer(r'"([^"]+)"', match.group(1))
        )
    )


def _section_pattern(section_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"^[ \t]*\[{re.escape(section_name)}\][ \t]*$",
        re.MULTILINE,
    )


