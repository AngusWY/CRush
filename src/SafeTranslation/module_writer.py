from __future__ import annotations

import re
from pathlib import Path

from .models import TranslationTask


IMPORTS_START = "// @C2SAFETY:IMPORTS_START"
IMPORTS_END = "// @C2SAFETY:IMPORTS_END"
ENTITY_START_PREFIX = "// @C2SAFETY:ENTITY_START"
ENTITY_END_PREFIX = "// @C2SAFETY:ENTITY_END"


class ModuleWriter:


    def clear_generated_content(self, rust_files: tuple[Path, ...]) -> None:


        for rust_file in sorted(set(rust_files)):
            if not rust_file.is_file():
                raise FileNotFoundError(
                    f"Rust target file does not exist: {rust_file}. "
                    "Run TranslationPreprocess rust module layout before SafeTranslation."
                )
            text = rust_file.read_text(encoding="utf-8")
            cleaned = clear_generated_content(text)
            rust_file.write_text(_normalize_file_text(cleaned), encoding="utf-8")

    def write_imports(self, rust_file: Path, imports: tuple[str, ...]) -> None:
        if not rust_file.is_file():
            raise FileNotFoundError(
                f"Rust target file does not exist: {rust_file}. "
                "Run TranslationPreprocess rust module layout before SafeTranslation."
            )
        text = rust_file.read_text(encoding="utf-8")
        text = update_generated_imports(text, imports)
        rust_file.write_text(_normalize_file_text(text), encoding="utf-8")

    def write_entity(
        self,
        task: TranslationTask,
        rust_code: str,
        imports: tuple[str, ...] = (),
    ) -> None:
        rust_file = task.placement.rust_file
        if not rust_file.is_file():
            raise FileNotFoundError(
                f"Rust target file does not exist: {rust_file}. "
                "Run TranslationPreprocess rust module layout before SafeTranslation."
            )
        text = rust_file.read_text(encoding="utf-8")

        text = update_generated_imports(text, imports)
        block = make_entity_block(task, rust_code)
        text = replace_or_append_entity_block(text, task.entity_id, block)

        rust_file.write_text(_normalize_file_text(text), encoding="utf-8")


def make_entity_block(task: TranslationTask, rust_code: str) -> str:
    code = rust_code.strip()
    return (
        f"{ENTITY_START_PREFIX} id={task.entity_id} kind={task.kind}\n"
        f"{code}\n"
        f"{ENTITY_END_PREFIX} id={task.entity_id}"
    )


def replace_or_append_entity_block(text: str, entity_id: int, block: str) -> str:
    pattern = _entity_block_pattern(entity_id)
    if pattern.search(text):
        return pattern.sub(lambda _: block, text, count=1)

    stripped = text.rstrip()
    if not stripped:
        return block
    return f"{stripped}\n\n{block}"


def update_generated_imports(text: str, imports: tuple[str, ...]) -> str:
    existing_imports = _extract_generated_imports(text)
    merged_imports = _normalize_imports((*existing_imports, *imports))
    imports_block = _make_imports_block(merged_imports)
    pattern = _imports_block_pattern()

    if pattern.search(text):
        return pattern.sub(lambda _: imports_block, text, count=1)

    stripped = text.lstrip()
    if not stripped:
        return imports_block

    leading_len = len(text) - len(stripped)
    leading = text[:leading_len]
    rest = text[leading_len:]
    return f"{leading}{imports_block}\n\n{rest.rstrip()}"


def clear_generated_content(text: str) -> str:
    text = _imports_block_pattern().sub("", text)
    text = _any_entity_block_pattern().sub("", text)
    return _collapse_blank_lines(text).strip()


def _entity_block_pattern(entity_id: int) -> re.Pattern[str]:
    return re.compile(
        rf"^// @C2SAFETY:ENTITY_START id={entity_id}\b[^\n]*\n"
        rf".*?"
        rf"^// @C2SAFETY:ENTITY_END id={entity_id}\b[^\n]*",
        re.MULTILINE | re.DOTALL,
    )


def _any_entity_block_pattern() -> re.Pattern[str]:
    return re.compile(
        rf"^// @C2SAFETY:ENTITY_START id=\d+\b[^\n]*\n"
        rf".*?"
        rf"^// @C2SAFETY:ENTITY_END id=\d+\b[^\n]*",
        re.MULTILINE | re.DOTALL,
    )


def _imports_block_pattern() -> re.Pattern[str]:
    return re.compile(
        rf"^{re.escape(IMPORTS_START)}\n.*?^{re.escape(IMPORTS_END)}",
        re.MULTILINE | re.DOTALL,
    )


def _extract_generated_imports(text: str) -> tuple[str, ...]:
    match = _imports_block_pattern().search(text)
    if match is None:
        return ()

    lines = match.group(0).splitlines()
    if len(lines) <= 2:
        return ()
    return tuple(line.strip() for line in lines[1:-1] if line.strip())


def _normalize_imports(imports: tuple[str, ...]) -> tuple[str, ...]:
    normalized: set[str] = set()
    for item in imports:
        line = item.strip()
        if not line:
            continue
        if not line.startswith(("use ", "mod ")):
            raise ValueError(
                "generated import must be a full Rust use or mod line: "
                f"{item!r}"
            )
        if not line.endswith(";"):
            line = f"{line};"
        normalized.add(line)
    return tuple(sorted(normalized))


def _make_imports_block(imports: tuple[str, ...]) -> str:
    if not imports:
        return f"{IMPORTS_START}\n{IMPORTS_END}"
    return "\n".join((IMPORTS_START, *imports, IMPORTS_END))


def _normalize_file_text(text: str) -> str:
    return f"{text.rstrip()}\n"


def _collapse_blank_lines(text: str) -> str:
    return re.sub(r"\n{3,}", "\n\n", text)
