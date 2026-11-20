from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class StateStore:
    def __init__(self, root: Path) -> None:
        self.state_path = root / "state.json"
        self.report_path = root / "report.json"

    def write_state(self, value: dict[str, Any]) -> None:
        self._write(self.state_path, value)

    def write_report(self, value: dict[str, Any]) -> None:
        self._write(self.report_path, value)

    @staticmethod
    def _write(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(path)
