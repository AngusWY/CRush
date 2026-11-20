from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKSPACE = REPO_ROOT / "tests" / "c2rust_workspace"
PREPROCESS_MANIFEST_NAME = "preprocess-manifest.json"
PROJECT_MACROS_NAME = "project-macros.json"
PREPROCESSED_DIR_NAME = "preprocessed"
PREPROCESSED_ORIGIN_DIR_NAME = "preprocessed_origin"
COMMENTED_PREPROCESSED_DIR_NAME = "preprocessed_with_comments"
COMMENTED_PREPROCESSED_ORIGIN_DIR_NAME = "preprocessed_with_comments_origin"
LIAN_WORKSPACE_DIR_NAME = "lian_workspace"
LIAN_COMPLETE_MARKER_NAME = ".p3_complete"
ENTITY_INDEX_NAME = "entity-index.json"
TRANSLATION_ENTITIES_NAME = "translation-entities.json"
ENTITY_DEPENDENCIES_NAME = "entity-dependencies.json"
RUST_MODULE_LAYOUT_NAME = "rust-module-layout.json"
RUST_PROJECT_DIR_NAME = "rust_project"
TRANSLATION_PLAN_NAME = "translation-plan.json"
SUPPORTED_C_EXTENSIONS = frozenset({".c"})
