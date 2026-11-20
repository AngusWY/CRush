from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from TranslationOrientedAnalysis.pipeline import (
    SemanticAnalysisPipeline,
    SemanticAnalysisPipelineError,
)
from TranslationPreprocess.config import DEFAULT_WORKSPACE
from TranslationPreprocess.dependency_builder import (
    DependencyBuildError,
    DependencyBuilder,
)
from TranslationPreprocess.entity_merger import EntityMergeError, EntityMerger
from TranslationPreprocess.lian_analyzer import LianAnalysisError, LianAnalyzer
from TranslationPreprocess.project_loader import ProjectLoadError, ProjectLoader
from TranslationPreprocess.preprocessor import CPreprocessor, PreprocessError
from TranslationPreprocess.rust_module_layout import (
    RustModuleLayoutBuilder,
    RustModuleLayoutError,
)
from TranslationPreprocess.translation_entity_builder import (
    TranslationEntityBuildError,
    TranslationEntityBuilder,
)
from TranslationPreprocess.translation_planner import (
    TranslationPlanError,
    TranslationPlanner,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Preprocess a C project and run Lian P1/P3 analysis."
    )
    parser.add_argument("project_dir", type=Path, help="C project root directory")
    parser.add_argument(
        "-p",
        "--compile-commands",
        type=Path,
        default=None,
        help="compile_commands.json path (default: project root or project/build)",
    )
    parser.add_argument(
        "-w",
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help=f"workspace directory (default: {DEFAULT_WORKSPACE})",
    )
    parser.add_argument(
        "--clang",
        default="clang",
        help="clang executable used for preprocessing (default: clang)",
    )
    parser.add_argument(
        "--run-agent",
        action="store_true",
        default=False,
        help="run the semantic analysis Agent to fill unresolved pointer fields",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        project_loader = ProjectLoader(
            project_root=args.project_dir,
            workspace=args.workspace,
            compile_commands_path=args.compile_commands,
        )
        manifest = project_loader.build_manifest()
        output_path = project_loader.write_manifest(manifest)
        preprocessed_paths = CPreprocessor(clang=args.clang).run(manifest)
        lian_result = LianAnalyzer(workspace=manifest.workspace).run()
        entity_index_path = EntityMerger(manifest=manifest).run(
            lian_result.loader
        )
        translation_entities_path = TranslationEntityBuilder(
            manifest=manifest
        ).run()
        entity_dependencies_path = DependencyBuilder(
            manifest=manifest
        ).run(lian_result.loader)
        rust_module_layout_path = RustModuleLayoutBuilder(
            manifest=manifest
        ).run()
        translation_plan_path = TranslationPlanner(
            manifest=manifest
        ).run()
    except (
        ProjectLoadError,
        PreprocessError,
        LianAnalysisError,
        EntityMergeError,
        TranslationEntityBuildError,
        DependencyBuildError,
        RustModuleLayoutError,
        TranslationPlanError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"wrote {output_path}")
    print(f"compile units: {len(manifest.units)}")
    print(f"preprocessed units: {len(preprocessed_paths)}")
    for path in preprocessed_paths:
        print(f"  {path}")
    print(f"lian workspace: {lian_result.workspace}")
    print(f"entity index: {entity_index_path}")
    print(f"translation entities: {translation_entities_path}")
    print(f"entity dependencies: {entity_dependencies_path}")
    print(f"rust module layout: {rust_module_layout_path}")
    print(f"translation plan: {translation_plan_path}")



    try:
        sem_pipeline = SemanticAnalysisPipeline(
            loader=lian_result.loader,
            workspace=manifest.workspace,
            debug=True,
        )
        sem_result = sem_pipeline.run()
    except SemanticAnalysisPipelineError as exc:
        print(f"error: semantic analysis failed: {exc}", file=sys.stderr)
        return 3

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
        "agent-required entities: "
        f"{sem_result.agent_required_entity_count}"
    )
    if sem_result.agent_required_entity_count:
        print(
            f"  -> {sem_result.agent_required_entities_path}"
        )



    if not args.run_agent:
        return 0

    try:
        from TranslationOrientedAnalysis.semantic_analysis_agent.agent_pipeline import (
            AgentPipelineError,
            SemanticAgentPipeline,
        )
    except ImportError as exc:
        print(
            f"error: cannot import Agent pipeline: {exc}",
            file=sys.stderr,
        )
        return 4

    print("\n--- running semantic Agent pipeline ---")
    try:
        agent_result = SemanticAgentPipeline(
            loader=lian_result.loader,
            workspace=manifest.workspace,
        ).run_sync()
    except AgentPipelineError as exc:
        print(f"error: Agent pipeline failed: {exc}", file=sys.stderr)
        return 5
    except Exception as exc:


        print(f"error: Agent pipeline failed: {exc}", file=sys.stderr)
        return 5

    print(
        f"Agent tasks: {agent_result.completed_tasks}/{agent_result.total_tasks}"
        f" completed"
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
    print(f"Agent run report: {agent_result.report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
