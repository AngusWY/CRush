


from __future__ import annotations

import argparse
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
LIAN_SRC_ROOT = REPO_ROOT / "lian" / "src"
for import_root in (REPO_ROOT, SRC_ROOT, LIAN_SRC_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from SemanticInlining.pipeline import main as semantic_inlining_main
from TranslationPreprocess.config import DEFAULT_WORKSPACE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run SemanticInlining and generate the semantic hint store."
    )
    parser.add_argument(
        "-w",
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help=f"workflow workspace directory (default: {DEFAULT_WORKSPACE})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return semantic_inlining_main(["--workspace", str(args.workspace.resolve())])


if __name__ == "__main__":
    raise SystemExit(main())
