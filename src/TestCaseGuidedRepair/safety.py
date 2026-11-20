from __future__ import annotations

import re
from pathlib import Path

from .models import SafetyResult
from .workspace import is_ignored_project_path


_UNSAFE_PATTERNS = (
    ("unsafe_block", re.compile(r"\bunsafe\s*\{")),
    ("unsafe_fn", re.compile(r'\bunsafe\s+(?:extern\s+"[^"]+"\s+)?fn\b')),
    ("unsafe_impl", re.compile(r"\bunsafe\s+impl\b")),
    ("unsafe_trait", re.compile(r"\bunsafe\s+trait\b")),
    ("extern_block", re.compile(r'\bextern\s+"[^"]+"\s*\{')),
    ("unimplemented", re.compile(r"\bunimplemented\s*!\s*\(")),
    ("todo", re.compile(r"\btodo\s*!\s*\(")),
)


class SafetyChecker:


    def check(
        self,
        roots: tuple[Path, ...],
        baseline: dict[str, object] | None = None,
    ) -> SafetyResult:
        violations: list[dict[str, object]] = []
        allowed = _baseline_counts(baseline)
        for root in roots:
            for path in sorted(root.rglob("*.rs")):
                if is_ignored_project_path(path, root):
                    continue
                text = path.read_text(encoding="utf-8")
                masked = _mask_comments_and_literals(text)
                for kind, pattern in _UNSAFE_PATTERNS:
                    for match in pattern.finditer(masked):
                        relative = path.relative_to(root).as_posix()
                        line_start = masked.rfind("\n", 0, match.start()) + 1
                        line = masked.count("\n", 0, match.start()) + 1
                        fingerprint = _fingerprint(kind, relative, masked[line_start:masked.find("\n", match.start()) if masked.find("\n", match.start()) >= 0 else len(masked)])
                        if kind.startswith("unsafe_") and allowed.get(fingerprint, 0):
                            allowed[fingerprint] -= 1
                            continue
                        violations.append(
                            {
                                "kind": kind,
                                "path": str(path),
                                "line": line,
                            }
                        )
        return SafetyResult(passed=not violations, violations=tuple(violations))


def collect_unsafe_baseline(root: Path) -> dict[str, object]:

    entries: list[dict[str, str]] = []
    for path in sorted(root.rglob("*.rs")):
        if is_ignored_project_path(path, root):
            continue
        text = path.read_text(encoding="utf-8")
        masked = _mask_comments_and_literals(text)
        relative = path.relative_to(root).as_posix()
        for kind, pattern in _UNSAFE_PATTERNS:
            if not kind.startswith("unsafe_"):
                continue
            for match in pattern.finditer(masked):
                line_start = masked.rfind("\n", 0, match.start()) + 1
                line_end = masked.find("\n", match.start())
                if line_end < 0:
                    line_end = len(masked)
                entries.append({"kind": kind, "path": relative, "line": masked[line_start:line_end]})
    return {"version": 1, "entries": entries}


def _fingerprint(kind: str, path: str, line: str) -> str:
    return f"{kind}\0{path}\0{' '.join(line.split())}"


def _baseline_counts(baseline: dict[str, object] | None) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not baseline:
        return counts
    entries = baseline.get("entries")
    if not isinstance(entries, list):
        return counts
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        kind, path, line = entry.get("kind"), entry.get("path"), entry.get("line")
        if all(isinstance(value, str) for value in (kind, path, line)):
            key = _fingerprint(kind, path, line)
            counts[key] = counts.get(key, 0) + 1
    return counts


def _mask_comments_and_literals(text: str) -> str:

    chars = list(text)
    index = 0
    block_depth = 0
    state = "code"
    while index < len(chars):
        current = chars[index]
        next_char = chars[index + 1] if index + 1 < len(chars) else ""
        if state == "code":
            if current == "/" and next_char == "/":
                chars[index] = chars[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if current == "/" and next_char == "*":
                chars[index] = chars[index + 1] = " "
                state = "block_comment"
                block_depth = 1
                index += 2
                continue
            if current == '"':
                chars[index] = " "
                state = "string"
            elif current == "'" and _looks_like_char_literal(text, index):
                chars[index] = " "
                state = "char"
        elif state == "line_comment":
            if current == "\n":
                state = "code"
            else:
                chars[index] = " "
        elif state == "block_comment":
            if current == "/" and next_char == "*":
                chars[index] = chars[index + 1] = " "
                block_depth += 1
                index += 2
                continue
            if current == "*" and next_char == "/":
                chars[index] = chars[index + 1] = " "
                block_depth -= 1
                index += 2
                if block_depth == 0:
                    state = "code"
                continue
            if current != "\n":
                chars[index] = " "
        elif state in {"string", "char"}:
            quote = '"' if state == "string" else "'"
            if current == "\\":
                chars[index] = " "
                if index + 1 < len(chars):
                    if chars[index + 1] != "\n":
                        chars[index + 1] = " "
                    index += 2
                    continue
            if current == quote:
                chars[index] = " "
                state = "code"
            elif current != "\n":
                chars[index] = " "
        index += 1
    return "".join(chars)


def _looks_like_char_literal(text: str, index: int) -> bool:
    tail = text[index + 1 : index + 8]
    return bool(re.match(r"(?:\\.|[^'\\\n])'", tail))
