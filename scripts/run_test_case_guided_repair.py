


from __future__ import annotations

import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
LIAN_SRC_ROOT = REPO_ROOT / "lian" / "src"
for import_root in (REPO_ROOT, SRC_ROOT, LIAN_SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from TestCaseGuidedRepair.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
