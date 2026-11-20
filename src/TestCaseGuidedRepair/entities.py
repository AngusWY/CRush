from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path


_ENTITY_BLOCK = re.compile(
    r"^// @C2SAFETY:ENTITY_START id=(?P<id>\d+) kind=(?P<kind>[^\n]+)\n"
    r"(?P<code>.*?)\n"
    r"^// @C2SAFETY:ENTITY_END id=(?P=id)[^\n]*",
    re.MULTILINE | re.DOTALL,
)


@dataclass(frozen=True)
class EntityBlock:
    entity_id: int
    kind: str
    start_line: int
    code_start_line: int
    code_end_line: int
    end_line: int
    code: str
    code_sha256: str
    code_start: int
    code_end: int

    def contains_line(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


def entity_blocks(text: str) -> tuple[EntityBlock, ...]:
    blocks: list[EntityBlock] = []
    for match in _ENTITY_BLOCK.finditer(text):
        code = match.group("code")
        start_line = text.count("\n", 0, match.start()) + 1
        code_start_line = text.count("\n", 0, match.start("code")) + 1
        code_end_line = code_start_line + code.count("\n")
        end_line = text.count("\n", 0, match.end()) + 1
        blocks.append(
            EntityBlock(
                entity_id=int(match.group("id")),
                kind=match.group("kind").strip(),
                start_line=start_line,
                code_start_line=code_start_line,
                code_end_line=code_end_line,
                end_line=end_line,
                code=code,
                code_sha256=hashlib.sha256(code.encode()).hexdigest(),
                code_start=match.start("code"),
                code_end=match.end("code"),
            )
        )
    return tuple(blocks)


def find_entity(root: Path, entity_id: int) -> tuple[Path, EntityBlock]:
    matches: list[tuple[Path, EntityBlock]] = []
    for path in sorted(root.rglob("*.rs")):
        if path.is_symlink() or "target" in path.relative_to(root).parts:
            continue
        text = path.read_text(encoding="utf-8")
        matches.extend(
            (path, block)
            for block in entity_blocks(text)
            if block.entity_id == entity_id
        )
    if not matches:
        raise ValueError(f"unknown implementation entity: {entity_id}")
    if len(matches) != 1:
        raise ValueError(f"implementation entity {entity_id} is not unique")
    return matches[0]

