


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

from TranslationOrientedAnalysis.pipeline import (
    SemanticAnalysisPipeline,
    SemanticAnalysisPipelineError,
)
from TranslationPreprocess.config import DEFAULT_WORKSPACE
from TranslationPreprocess.lian_analyzer import LianAnalysisError, LianAnalyzer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run programmatic TranslationOrientedAnalysis, optionally with Agent repair."
        )
    )
    parser.add_argument(
        "-w",
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help=f"workflow workspace directory (default: {DEFAULT_WORKSPACE})",
    )
    parser.add_argument(
        "--run-agent",
        action="store_true",
        default=False,
        help="run the semantic analysis Agent after programmatic analysis",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="suppress programmatic semantic analysis progress output",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    workspace = args.workspace.resolve()

    def emit(message: str) -> None:
        if not args.quiet:
            print(f"[semantic] {message}", flush=True)

    try:
        emit(f"workspace: {workspace}")
        emit("restoring Lian loader")
        loader = LianAnalyzer(workspace=workspace).load_loader()
        emit("Lian loader restored")
        emit("starting programmatic semantic analysis")
        sem_result = SemanticAnalysisPipeline(
            loader=loader,
            workspace=workspace,
            debug=not args.quiet,
        ).run()
    except (LianAnalysisError, SemanticAnalysisPipelineError) as exc:
        print(f"error: semantic analysis failed: {exc}", file=sys.stderr)
        return 2

    print(f"workspace: {workspace}")
    print(f"pointer semantics: {sem_result.pointer_semantics_path}")
    print(f"pointer targets: {sem_result.pointer_target_count}")
    print(f"pointer results: {sem_result.pointer_result_count}")
    print(f"variable semantics: {sem_result.variable_semantics_path}")
    print(f"variable targets: {sem_result.variable_target_count}")
    print(f"variable results: {sem_result.variable_result_count}")
    print(f"unsafe stmt semantics: {sem_result.unsafe_stmt_semantics_path}")
    print(f"unsafe stmt targets: {sem_result.unsafe_stmt_target_count}")
    print(f"unsafe stmt results: {sem_result.unsafe_stmt_result_count}")
    print(
        "function return semantics: "
        f"{sem_result.function_return_semantics_path}"
    )
    print(
        "function return results: "
        f"{sem_result.function_return_result_count}"
    )
    print(f"external type semantics: {sem_result.external_type_semantics_path}")
    print(f"external types: {sem_result.external_type_count}")
    print(
        "callback interfaces: "
        f"{sem_result.callback_interface_count}"
    )
    print(
        "callback interface semantics: "
        f"{sem_result.callback_interface_semantics_path}"
    )
    print(f"agent-required entities: {sem_result.agent_required_entity_count}")
    if sem_result.agent_required_entity_count:
        print(f"agent-required file: {sem_result.agent_required_entities_path}")

    if not args.run_agent:
        return 0

    try:
        from TranslationOrientedAnalysis.semantic_analysis_agent.agent_pipeline import (
            AgentPipelineError,
            SemanticAgentPipeline,
        )
    except ImportError as exc:
        print(f"error: cannot import semantic Agent pipeline: {exc}", file=sys.stderr)
        return 3

    print("\n--- running semantic analysis Agent ---")
    try:
        agent_result = SemanticAgentPipeline(
            loader=loader,
            workspace=workspace,
        ).run_sync()
    except AgentPipelineError as exc:
        print(f"error: semantic analysis Agent failed: {exc}", file=sys.stderr)
        return 4
    except Exception as exc:
        print(f"error: semantic analysis Agent failed: {exc}", file=sys.stderr)
        return 4

    print(
        f"Agent tasks: {agent_result.completed_tasks}/"
        f"{agent_result.total_tasks} completed"
        f" (+{agent_result.failed_tasks} failed)"
    )
    print(f"fields filled by Agent: {agent_result.fields_filled}")
    print(f"conflicts: {agent_result.conflicts}")
    if agent_result.remaining_entity_ids:
        print(
            "entities still have unresolved fields: "
            f"{list(agent_result.remaining_entity_ids)}"
        )
    print(f"merged pointer semantics: {agent_result.pointer_semantics_path}")
    print(f"merged variable semantics: {agent_result.variable_semantics_path}")
    print(f"merged unsafe stmt semantics: {agent_result.unsafe_stmt_semantics_path}")
    print(f"Agent run report: {agent_result.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
