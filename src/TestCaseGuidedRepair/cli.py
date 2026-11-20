from __future__ import annotations

import argparse
import json
import sys
import traceback
import os
from pathlib import Path

from SafeTranslation.agents.llm_client import OpenAICompatibleTranslationLLMClient

from .agent import OpenAICorrectnessRepairAgent
from .models import CTestConfig, RepairConfig, RepairStatus
from .pipeline import CorrectnessRepairPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bridge and repair translated Rust using existing test cases.",
        epilog=(
            "Simple C test: %(prog)s TRANSLATED_PROJECT C_TEST_FILE. "
            "The workspace and C project root are inferred automatically."
        ),
    )
    parser.add_argument(
        "translated_project",
        type=Path,
        nargs="?",
        help="translated Rust project directory or its CRUSH workspace",
    )
    parser.add_argument(
        "c_test_file",
        type=Path,
        nargs="?",
        help="C test file; enables C mode and automatic project discovery",
    )
    parser.add_argument("-w", "--workspace", type=Path)
    parser.add_argument("--test-project", type=Path)
    parser.add_argument(
        "--test-target",
        action="append",
        dest="test_targets",
        help="One Cargo target, or an optional name for the current C test",
    )
    parser.add_argument(
        "--c-test-entry", type=Path,
        help="C test entry relative to --test-project",
    )
    for option in ("source", "helper", "include-dir", "resource"):
        parser.add_argument(f"--c-{option}", type=Path, action="append", default=[])
    for option in ("define", "cflag", "ldflag", "library", "arg", "symbol"):
        parser.add_argument(
            f"--c-{option}", action="append", default=[],
            help="C compiler flag" if option == "cflag" else None,
        )
    parser.add_argument("--c-cwd", type=Path, default=Path("."))
    parser.add_argument("--c-compiler", default="cc", help="C compiler executable")
    parser.add_argument("--max-bridge-repairs", type=int, default=3)
    parser.add_argument("--max-test-repairs", type=int, default=3)
    parser.add_argument("--check-timeout", type=int, default=120)
    parser.add_argument("--test-timeout", type=int, default=300)
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="prepare and inspect the isolated run without calling an LLM",
    )
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--max-agent-rounds", type=int, default=24)
    parser.add_argument(
        "--llm-timeout",
        type=float,
        default=None,
        help="LLM request deadline in seconds (env CORRECTNESS_AGENT_TIMEOUT, default 300)",
    )
    parser.add_argument("--max-tool-bytes", type=int, default=400_000)
    parser.add_argument("--max-history-bytes", type=int, default=800_000)
    return parser


def _workspace_from_translated_project(path: Path) -> Path:
    resolved = path.resolve()
    if (resolved / "rust-module-layout.json").is_file():
        return resolved
    if not (resolved / "Cargo.toml").is_file():
        raise ValueError(
            "translated project must be a CRUSH workspace or a Rust Cargo project: "
            f"{resolved}"
        )

    for candidate in resolved.parents:
        layout_path = candidate / "rust-module-layout.json"
        if not layout_path.is_file():
            continue
        try:
            data = json.loads(layout_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rust_project = data.get("rust_project") if isinstance(data, dict) else None
        if not isinstance(rust_project, str) or not rust_project:
            continue
        recorded = Path(rust_project)
        recorded = (
            recorded.resolve()
            if recorded.is_absolute()
            else (candidate / recorded).resolve()
        )
        if recorded == resolved:
            return candidate
    raise ValueError(
        "cannot find the CRUSH workspace for translated Rust project "
        f"{resolved}; pass --workspace explicitly"
    )


def _infer_c_project(test_file: Path) -> Path:
    markers = (
        "compile_commands.json",
        "Makefile",
        "CMakeLists.txt",
        "meson.build",
        ".git",
    )
    for candidate in (test_file.parent, *test_file.parent.parents):
        if any((candidate / marker).exists() for marker in markers):
            return candidate
    raise ValueError(
        f"cannot infer the C project root for {test_file}; pass --test-project"
    )


def _resolve_paths(args: argparse.Namespace) -> tuple[Path, Path, Path | None, str]:
    if args.translated_project is not None and args.workspace is not None:
        raise ValueError("use either translated_project or --workspace, not both")
    workspace = (
        _workspace_from_translated_project(args.translated_project)
        if args.translated_project is not None
        else args.workspace.resolve() if args.workspace is not None else None
    )
    if workspace is None:
        raise ValueError("missing translated project or --workspace")

    c_entry = args.c_test_entry
    test_project = args.test_project.resolve() if args.test_project is not None else None
    if args.c_test_file is not None:
        if c_entry is not None:
            raise ValueError("use either c_test_file or --c-test-entry, not both")
        test_file = args.c_test_file.resolve()
        if not test_file.is_file():
            raise ValueError(f"C test file does not exist: {test_file}")
        test_project = test_project or _infer_c_project(test_file)
        try:
            c_entry = test_file.relative_to(test_project)
        except ValueError as exc:
            raise ValueError(
                f"C test file is outside test project {test_project}: {test_file}"
            ) from exc

    if test_project is None:
        raise ValueError("missing C test project; pass a C test file or --test-project")
    if c_entry is None:
        raise ValueError("missing C test file or --c-test-entry")
    return workspace, test_project, c_entry, "c"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        workspace, test_project, c_test_entry, test_mode = _resolve_paths(args)
        assert c_test_entry is not None
        c_test = CTestConfig(
            entry=c_test_entry,
            sources=tuple(args.c_source),
            helpers=tuple(args.c_helper),
            include_dirs=tuple(args.c_include_dir),
            resources=tuple(args.c_resource),
            defines=tuple(args.c_define),
            cflags=tuple(args.c_cflag),
            ldflags=tuple(args.c_ldflag),
            libraries=tuple(args.c_library),
            args=tuple(args.c_arg),
            cwd=args.c_cwd,
            compiler=args.c_compiler,
            symbols=tuple(args.c_symbol),
        )
        targets = tuple(dict.fromkeys(args.test_targets or (
            [c_test.entry.stem] if c_test is not None else []
        )))
        if len(targets) != 1:
            raise ValueError("exactly one --test-target is required per run")

        if c_test is not None:
            c_test.validate(test_project)

        client = (
            None
            if args.prepare_only
            else OpenAICompatibleTranslationLLMClient(
                role="correctness", timeout_seconds=args.llm_timeout
            )
        )
        config = RepairConfig(
            workspace=workspace,
            test_project=test_project,
            test_targets=targets,
            test_mode=test_mode,
            c_test=c_test,
            max_bridge_repairs=args.max_bridge_repairs,
            max_test_repairs=args.max_test_repairs,
            check_timeout=args.check_timeout,
            test_timeout=args.test_timeout,
            prepare_only=args.prepare_only,
            max_agent_rounds=args.max_agent_rounds,
            llm_timeout=(
                args.llm_timeout
                if args.llm_timeout is not None
                else float(os.getenv("CORRECTNESS_AGENT_TIMEOUT", "300"))
            ),
            max_tool_bytes=args.max_tool_bytes,
            max_history_bytes=args.max_history_bytes,
        )
        agent = None
        if not args.prepare_only:
            assert client is not None
            agent = OpenAICorrectnessRepairAgent(
                client,
                max_rounds=config.max_agent_rounds,
                request_timeout=config.llm_timeout,
                max_tool_bytes=config.max_tool_bytes,
                max_history_bytes=config.max_history_bytes,
                log=None if args.quiet else print,
            )
        report = CorrectnessRepairPipeline(
            config,
            agent=agent,
            log=None if args.quiet else print,
        ).run_sync()
    except Exception as exc:
        traceback.print_exc()
        print(f"error: correctness repair failed: {exc}", file=sys.stderr)
        return 2

    print(f"status: {report['status']}")
    print(f"report: {Path(report['run_root']) / 'report.json'}")
    return (
        0
        if report["status"] in {RepairStatus.PASSED.value, RepairStatus.PREPARED.value}
        else 1
    )
