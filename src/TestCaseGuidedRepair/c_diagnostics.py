
from __future__ import annotations

import json
import re
import signal
from pathlib import Path

from .models import JsonDict


_LOCATION = re.compile(r"(?P<path>/[^\n:`\"<>]+?\.(?:c|h|rs)|(?:[\w.-]+/)*[\w.-]+\.(?:c|h|rs)):(?P<line>\d+)(?::(?P<column>\d+))?")
_ASSERT = re.compile(r"Assertion\s+[`'\"](?P<expression>.*?)[`'\"]\s+failed", re.IGNORECASE)
_DARWIN_ASSERT = re.compile(r"Assertion failed:\s*\((.*?)\),.*?file (.*?), line (\d+)")
_SYMBOL = re.compile(r"(?P<kind>undefined reference to|undefined symbol:|multiple definition of|duplicate symbol:)\s*[`'\"]?(?P<symbol>[^`'\"\s;]+)")


def c_failure_diagnostics(raw: JsonDict, root: Path, *, max_bytes: int = 8000) -> JsonDict:

    if max_bytes < 2048:
        raise ValueError("C diagnostic budget must be at least 2048 bytes")
    truncated = False

    def clip(text: str, limit: int = 1800) -> str:
        nonlocal truncated
        text = text.replace(str(root) + "/", "")
        if len(text) > limit:
            truncated = True
            return text[:limit // 2] + "\n...[truncated]...\n" + text[-limit // 2:]
        return text

    def source_path(value: str, cwd: str) -> str:
        path = Path(value)
        if not path.is_absolute():
            path = Path(cwd) / path
        try:
            return path.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return str(path)

    result: JsonDict = {
        "failure_kind": raw.get("failure_kind"), "error": clip(raw.get("error") or "", 800),
        "proposal_error": clip(raw.get("proposal_error") or "", 800),
        "locations": [], "messages": [], "assertions": [],
        "symbols": {"undefined": [], "duplicate": [], "unmatched_requested": []}, "failed_commands": [],
        "execution": None, "signal": None, "signal_name": None, "truncated": False,
    }

    def append(items: list, item: object, limit: int = 12) -> None:
        nonlocal truncated
        if item not in items:
            if len(items) < limit:
                items.append(item)
            else:
                truncated = True

    def location(path: str, line: int, column: int, cwd: str, stage: str) -> JsonDict:
        normalized = source_path(path, cwd)
        item = {"path": clip(normalized, 400), "line": line, "column": column,
                "source": "rust" if path.endswith(".rs") else "c", "stage": stage}
        append(result["locations"], item)
        return item

    def extract(text: str, cwd: str, stage: str) -> str:


        rendered: list[str] = []
        for line in text.splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                rendered.append(line)
                continue
            if not isinstance(value, dict) or "reason" not in value:
                rendered.append(line)
                continue
            message = value.get("message", {})
            if not isinstance(message, dict) or message.get("level") != "error":
                continue
            rendered.append(message.get("rendered") or message.get("message", ""))
            for span in message.get("spans", []):
                if span.get("is_primary"):
                    location(span["file_name"], span["line_start"], span["column_start"], cwd, stage)
        text = "\n".join(rendered)
        excerpts: list[str] = []
        lines = text.splitlines()
        warning_block = False
        for index, line in enumerate(lines):

            warning = re.search(r"\bwarning(?:\[.*?\])?:", line)
            if warning:
                warning_block = True
                continue
            if re.search(r"\berror(?:\[|:)|panicked at|^thread |Assertion", line):
                warning_block = False
            if warning_block:
                continue
            loc = None
            has_location = (stage == "execution" or re.search(r"\b(?:fatal )?error:|-->", line))
            match = (_LOCATION.search(line) if has_location and re.search(r"\.(?:c|h|rs):\d+", line)
                     else None)
            if match:
                loc = location(match["path"], int(match["line"]), int(match["column"] or 1), cwd, stage)
            assertion = _ASSERT.search(line)
            if assertion:
                append(result["assertions"], {"expression": clip(assertion["expression"], 600),
                    "location": loc})
            darwin = _DARWIN_ASSERT.search(line)
            if darwin:
                loc = location(darwin[2], int(darwin[3]), 1, cwd, stage)
                append(result["assertions"], {"expression": clip(darwin[1], 600), "location": loc})
            for symbol in _SYMBOL.finditer(line):
                kind = "undefined" if symbol["kind"].startswith("undefined") else "duplicate"
                append(result["symbols"][kind], clip(symbol["symbol"], 200))
            if (assertion or darwin or re.search(
                    r"\berror(?:\[|:)|undefined reference|undefined symbol|multiple definition|duplicate symbol|"
                    r"panicked at|Assertion|assertion .*failed|No such file|cannot find|not found|timed out", line)):
                excerpt = "\n".join(lines[index:index + 4])
                append(result["messages"], clip(excerpt, 900))
                excerpts.append(excerpt)

        return clip("\n".join(dict.fromkeys(excerpts)) or text)

    for field, kind in (("duplicate_c_rust_symbols", "duplicate"),
                        ("unmatched_requested_symbols", "unmatched_requested")):
        for symbol in raw.get("link_evidence", {}).get(field, []):
            append(result["symbols"][kind], clip(symbol, 200))
    execution = raw.get("execution")
    for command in raw.get("stages", []):
        stage = command.get("stage", "unknown")
        if stage == "execution" or (command.get("exit_code") == 0 and not command.get("timed_out")):
            continue
        cwd = command.get("cwd", str(root))
        output = extract(command.get("stdout", "") + "\n" + command.get("stderr", ""), cwd, stage)
        append(result["failed_commands"], {"stage": stage, "exit_code": command.get("exit_code"),
            "timed_out": command.get("timed_out", False), "error_output": output}, 4)
    if execution is not None:
        code = execution.get("exit_code")
        timed_out = execution.get("timed_out", False)
        result["execution"] = {"exit_code": code, "timed_out": timed_out}
        if code != 0 or timed_out:
            cwd = execution.get("cwd", str(root))
            result["execution"]["error_output"] = extract(
                execution.get("stderr", "") + "\n" + execution.get("stdout", ""), cwd, "execution")
        if isinstance(code, int) and code < 0:
            result["signal"] = -code
            try:
                result["signal_name"] = signal.Signals(-code).name
            except ValueError:
                result["signal_name"] = "unknown"



    def size() -> int:
        return len(json.dumps(result, ensure_ascii=False).encode())

    while size() > max_bytes:
        truncated = True
        strings: list[tuple[dict | list, str | int, str]] = []
        lists: list[list] = []

        def walk(value: object) -> None:
            if isinstance(value, (dict, list)):
                if isinstance(value, list) and len(value) > 1:
                    lists.append(value)
                for key, item in (value.items() if isinstance(value, dict) else enumerate(value)):
                    if isinstance(item, str) and len(item) > 100:
                        strings.append((value, key, item))
                    else:
                        walk(item)
        walk(result)
        if strings:
            parent, key, text = max(strings, key=lambda item: len(item[2]))
            parent[key] = text[:len(text) // 2] + "...[truncated]"
        elif lists:
            max(lists, key=lambda items: len(json.dumps(items))).pop()
        else:
            break
    result["truncated"] = truncated
    return result
