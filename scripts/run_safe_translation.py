


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

from SafeTranslation.pipeline import main as safe_translation_main
from TranslationPreprocess.config import DEFAULT_WORKSPACE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the SafeTranslation pipeline.")
    parser.add_argument(
        "-w",
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help=f"workflow workspace directory (default: {DEFAULT_WORKSPACE})",
    )
    parser.add_argument(
        "--max-repair-attempts",
        type=int,
        default=3,
        help="maximum repair attempts per entity",
    )
    parser.add_argument(
        "--translation-concurrency",
        type=int,
        default=3,
        help="maximum initial translation requests to run concurrently per batch",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress progress logs",
    )
    parser.add_argument(
        "--no-reset-generated",
        action="store_true",
        help="do not clear previous SafeTranslation-generated code before running",
    )
    parser.add_argument(
        "--resume-from-entity",
        type=int,
        default=None,
        help="resume translation from this entity id using translation-state.json",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    forwarded = [
        "--workspace",
        str(args.workspace.resolve()),
        "--max-repair-attempts",
        str(args.max_repair_attempts),
        "--translation-concurrency",
        str(args.translation_concurrency),
    ]
    if args.quiet:
        forwarded.append("--quiet")
    if args.no_reset_generated:
        forwarded.append("--no-reset-generated")
    if args.resume_from_entity is not None:
        forwarded.extend(["--resume-from-entity", str(args.resume_from_entity)])
    return safe_translation_main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
