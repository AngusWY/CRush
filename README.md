# CRUSH

CRUSH is a semantics-guided C-to-safe-Rust translation prototype. It combines
project preparation, translation-oriented program analysis, source-level
semantic annotation, compiler-guided LLM translation, and test-case-guided
repair to produce and validate a Rust crate from a C project.

## What It Does

CRUSH takes:

- a C project root,
- a valid `compile_commands.json` for that project,
- Clang and the bundled LIAN analysis backend,
- credentials for an OpenAI-compatible LLM service,

and produces a shared workspace containing:

- prepared C translation entities and their dependencies,
- recovered declaration and unsafe-operation semantics,
- source-aligned semantic hints,
- a generated Rust crate,
- translation state and a final translation report,
- optional isolated test-repair runs and reports.

The implementation follows four translation phases and one optional repair
phase:

1. `TranslationPreprocess` prepares translation entities and dependencies.
2. `TranslationOrientedAnalysis` recovers semantics required for safe
   translation.
3. `SemanticInlining` attaches recovered semantics to source constructs.
4. `SafeTranslation` generates and compiler-checks the Rust crate.
5. `TestCaseGuidedRepair` optionally bridges existing tests to the translated
   crate and repairs failures.

## Repository Layout

```text
CRUSH/
├── src/
│   ├── TranslationPreprocess/
│   ├── TranslationOrientedAnalysis/
│   ├── SemanticInlining/
│   ├── SafeTranslation/
│   └── TestCaseGuidedRepair/
├── scripts/                 # command-line entry points
├── lian/                    # bundled program analysis backend
├── requirements.txt
└── README.md
```

The entry scripts load the stage packages from `src/` automatically. Run all
commands from the repository root.

## Environment Setup

Requirements:

- Linux
- Python 3.11+
- Clang 14.0.0+
- Rust and Cargo 1.94.1+
- CMake or Make
- Bear, when generating a compilation database for a Make project

Create an isolated Python environment and install all Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

## Model Configuration

Create `.env` in the repository root and configure the model roles you use.
Each role can use a different OpenAI-compatible endpoint.

```dotenv
SEMANTIC_AGENT_API_KEY="your-api-key"
SEMANTIC_AGENT_BASE_URL="https://your-api-endpoint/v1"
SEMANTIC_AGENT_MODEL="your-model"

TRANSLATOR_API_KEY="your-api-key"
TRANSLATOR_BASE_URL="https://your-api-endpoint/v1"
TRANSLATOR_MODEL="your-model"

CHECKER_API_KEY="your-api-key"
CHECKER_BASE_URL="https://your-api-endpoint/v1"
CHECKER_MODEL="your-model"

CORRECTNESS_AGENT_API_KEY="your-api-key"
CORRECTNESS_AGENT_BASE_URL="https://your-api-endpoint/v1"
CORRECTNESS_AGENT_MODEL="your-model"
```

The semantic-agent configuration is required when the second phase is run with
`--run-agent`. The translator and checker configurations are required by
`SafeTranslation`. The correctness-agent configuration is required only when
running `TestCaseGuidedRepair` without `--prepare-only`.

## Preparing a C Project

The target project root must contain `compile_commands.json`, and every file
path recorded in it must be valid on the current machine.

For a CMake project:

```bash
PROJECT=/absolute/path/to/c-project

cmake -S "$PROJECT" -B "$PROJECT/build" \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build "$PROJECT/build" -j"$(nproc)"
ln -sf "$PROJECT/build/compile_commands.json" \
  "$PROJECT/compile_commands.json"
```

For a Make project, Bear can capture the compilation commands. Run `make clean`
first so that every source file is compiled and recorded:

```bash
PROJECT=/absolute/path/to/c-project

cd "$PROJECT"
make clean
bear -- make -j"$(nproc)"
```

## Running CRUSH

Return to the CRUSH repository root and set absolute paths for the target
project and shared workspace:

```bash
cd /absolute/path/to/CRUSH
source .venv/bin/activate

PROJECT=/absolute/path/to/c-project
WORKSPACE=/absolute/path/to/workspace

set -euo pipefail
test -f "$PROJECT/compile_commands.json"
```

Run the four translation phases in order. Every phase must use the same
`WORKSPACE`.

```bash
# 1. TranslationPreprocess
python scripts/run_translation_preprocess.py \
  "$PROJECT" --workspace "$WORKSPACE"

# 2. TranslationOrientedAnalysis
python scripts/run_translation_oriented_analysis.py \
  --workspace "$WORKSPACE" --run-agent

# 3. SemanticInlining
python scripts/run_semantic_inlining.py \
  --workspace "$WORKSPACE"

# 4. SafeTranslation
python scripts/run_safe_translation.py \
  --workspace "$WORKSPACE"
```

`--run-agent` is optional. Without it, phase 2 runs only the programmatic
analysis. Use `--resume-from-entity ID` with phase 4 to resume an interrupted
translation from `translation-state.json`.

## Test-Case-Guided Repair

After translation, a C test can be run against the translated Rust
project with two positional arguments:

```bash
python scripts/run_test_case_guided_repair.py \
  "$WORKSPACE/rust_project" \
  /absolute/path/to/c-project/tests/test.c
```

The first argument may be either the generated Rust project or its CRUSH
workspace. The script infers the workspace, C project root, C test mode, and
test target. The C project should contain a recognizable root marker such as
`compile_commands.json`, `Makefile`, `CMakeLists.txt`, `meson.build`, or `.git`.

To validate discovery and prepare the isolated run without calling an LLM:

```bash
python scripts/run_test_case_guided_repair.py \
  "$WORKSPACE" \
  /absolute/path/to/c-project/tests/test.c \
  --prepare-only
```

Advanced C tests can use `--c-source`, `--c-helper`, `--c-include-dir`,
`--c-define`, `--c-cflag`, `--c-library`, and related options shown by
`python scripts/run_test_case_guided_repair.py --help`.

## Output

All intermediate artifacts and final results are written under `WORKSPACE`.
The principal outputs are:

```text
WORKSPACE/
├── preprocess-manifest.json
├── project-macros.json
├── preprocessed/
├── preprocessed_origin/
├── preprocessed_with_comments/
├── preprocessed_with_comments_origin/
├── entity-index.json
├── translation-entities.json
├── entity-dependencies.json
├── rust-module-layout.json
├── translation-plan.json
├── lian_workspace/
├── semantic_analysis/
│   ├── pointer-semantics.json
│   ├── variable-semantics.json
│   ├── unsafe-stmt-semantics.json
│   ├── function-return-semantics.json
│   ├── external-type-semantics.json
│   ├── callback-interface-semantics.json
│   ├── agent-required-entities.json
│   └── agent-run-report.json          # present when --run-agent is used
├── semantic_hints/
│   ├── entities/
│   ├── manifest.json
│   ├── hint-store.json
│   └── human-comment-store.json
├── rust_project/                      # generated Rust crate
├── translation-debug/
├── translation-state.json
├── translation-report.json
└── test_case_repair/
    └── runs/
        └── <run-id>/
            └── report.json
```
