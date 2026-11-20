


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
        description="Run TranslationPreprocess, Lian analysis, and translation planning."
    )
    parser.add_argument("project_dir", type=Path, help="C project root directory")
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
    project_dir = args.project_dir.resolve()
    workspace = args.workspace.resolve()

    try:
        project_loader = ProjectLoader(
            project_root=project_dir,
            workspace=workspace,
            compile_commands_path=None,
        )
        manifest = project_loader.build_manifest()
        manifest_path = project_loader.write_manifest(manifest)
        preprocessed_paths = CPreprocessor().run(manifest)
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
        translation_plan_path = TranslationPlanner(manifest=manifest).run()
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
        print(f"error: preprocessing failed: {exc}", file=sys.stderr)
        return 2

    print(f"project: {project_dir}")
    print(f"workspace: {workspace}")
    print(f"preprocess manifest: {manifest_path}")
    print(f"compile units: {len(manifest.units)}")
    print(f"preprocessed units: {len(preprocessed_paths)}")
    print(f"lian workspace: {lian_result.workspace}")
    print(f"entity index: {entity_index_path}")
    print(f"translation entities: {translation_entities_path}")
    print(f"entity dependencies: {entity_dependencies_path}")
    print(f"rust module layout: {rust_module_layout_path}")
    print(f"translation plan: {translation_plan_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
