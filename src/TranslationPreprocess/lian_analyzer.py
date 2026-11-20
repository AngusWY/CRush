from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import networkx as nx

from .config import (
    LIAN_COMPLETE_MARKER_NAME,
    LIAN_WORKSPACE_DIR_NAME,
    PREPROCESSED_DIR_NAME,
    REPO_ROOT,
)


LIAN_SOURCE_ROOT = REPO_ROOT / "lian" / "src"
if str(LIAN_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(LIAN_SOURCE_ROOT))


from lian.main import Lian
from lian.basics.basic_analysis import P1BasicSemanticAnalysis
from lian.core.global_semantics import P3GlobalSemanticAnalysis
from lian.core.prelim_semantics import P2PrelimSemanticAnalysis
from lian.config import config as lian_config
from lian.lang.lang_analysis import LangAnalysis
from lian.util import util
from lian.util.loader import Loader


class LianAnalysisError(RuntimeError):
    pass


def select_p3_coverage_roots(
    method_ids: set[int],
    call_graph: Any,
) -> list[int]:

    method_ids = {int(method_id) for method_id in method_ids}
    if not method_ids:
        return []

    graph = nx.DiGraph()
    graph.add_nodes_from(method_ids)
    source_graph = (
        call_graph
        if callable(getattr(call_graph, "edges", None))
        else getattr(call_graph, "graph", call_graph)
    )
    if source_graph is not None:
        for caller_id, callee_id in source_graph.edges():
            caller_id = int(caller_id)
            callee_id = int(callee_id)
            if caller_id in method_ids and callee_id in method_ids:
                graph.add_edge(caller_id, callee_id)

    components = list(nx.strongly_connected_components(graph))
    component_by_method = {
        method_id: component_id
        for component_id, component in enumerate(components)
        for method_id in component
    }
    source_components = set(range(len(components)))
    for caller_id, callee_id in graph.edges():
        caller_component = component_by_method[caller_id]
        callee_component = component_by_method[callee_id]
        if caller_component != callee_component:
            source_components.discard(callee_component)

    return sorted(
        min(components[component_id])
        for component_id in source_components
    )


def validate_p3_coverage(
    required_method_ids: set[int],
    completed_method_ids: set[int],
) -> None:
    uncovered = {
        int(method_id) for method_id in required_method_ids
    } - {
        int(method_id) for method_id in completed_method_ids
    }
    if uncovered:
        raise LianAnalysisError(
            "Lian P3 did not analyze all methods with P1/CFG data; "
            f"uncovered method ids: {sorted(uncovered)}"
        )


def _replace_entry_points(loader: Any, entry_points: set[int]) -> None:
    current_entry_points = loader.get_entry_points()
    if not isinstance(current_entry_points, set):
        raise LianAnalysisError(
            "Lian loader entry points must be a mutable set"
        )
    current_entry_points.clear()
    current_entry_points.update(entry_points)


class _CoverageTrackingP3GlobalSemanticAnalysis(
    P3GlobalSemanticAnalysis
):


    def __init__(self, lian: Any, analyzed_method_list: Any) -> None:
        super().__init__(lian, analyzed_method_list)
        self.completed_method_ids: set[int] = set()

    def generate_and_save_analysis_summary(
        self,
        frame: Any,
        method_summary: Any,
    ) -> Any:
        summary = super().generate_and_save_analysis_summary(
            frame,
            method_summary,
        )
        self.completed_method_ids.add(int(frame.method_id))
        return summary


def run_p3_with_one_coverage_retry(
    loader: Any,
    p3_analysis: Any,
    required_method_ids: set[int],
    initial_entry_points: list[int],
) -> None:
    p3_analysis.run()
    uncovered = {
        int(method_id) for method_id in required_method_ids
    } - {
        int(method_id) for method_id in p3_analysis.completed_method_ids
    }
    if uncovered:
        retry_entry_points = sorted(uncovered)
        print(
            "[lian] P3 coverage retry: "
            f"entry_points={retry_entry_points}"
        )
        _replace_entry_points(loader, set(retry_entry_points))
        try:
            p3_analysis.run()
        finally:
            _replace_entry_points(
                loader,
                set(initial_entry_points) | set(retry_entry_points)
            )

    validate_p3_coverage(
        required_method_ids,
        p3_analysis.completed_method_ids,
    )


LIAN_ENABLE_P2_ENV = "C2SAFETY_LIAN_ENABLE_P2"
_TRUE_ENV_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_ENV_VALUES = frozenset({"", "0", "false", "no", "off"})


def _p2_enabled_from_env() -> bool:
    raw_value = os.getenv(LIAN_ENABLE_P2_ENV, "")
    value = raw_value.strip().lower()
    if value in _TRUE_ENV_VALUES:
        return True
    if value in _FALSE_ENV_VALUES:
        return False
    accepted = ", ".join(sorted(_TRUE_ENV_VALUES | _FALSE_ENV_VALUES))
    raise LianAnalysisError(
        f"invalid {LIAN_ENABLE_P2_ENV} value {raw_value!r}; "
        f"expected one of: {accepted}"
    )


@dataclass(frozen=True)
class LianAnalysisResult:
    workspace: Path
    lian: Any
    loader: Any


class LianAnalyzer:


    def __init__(self, *, workspace: Path) -> None:
        self.workspace = workspace.resolve()
        self.preprocessed_root = self.workspace / PREPROCESSED_DIR_NAME
        self.lian_workspace = self.workspace / LIAN_WORKSPACE_DIR_NAME
        self.complete_marker = (
            self.lian_workspace / LIAN_COMPLETE_MARKER_NAME
        )

    def run(self) -> LianAnalysisResult:
        self._validate_input()
        enable_p2 = _p2_enabled_from_env()
        lian = Lian()
        lian.options = self._build_options(
            lian.options,
            enable_p2=enable_p2,
        )
        lian.set_workspace_dir(LIAN_WORKSPACE_DIR_NAME)

        try:
            self.complete_marker.unlink(missing_ok=True)
            lian.init_submodules()
            LangAnalysis(lian).run()
            P1BasicSemanticAnalysis(lian).run()
            analyzed_method_list: Any = []
            if enable_p2:
                analyzed_method_list = P2PrelimSemanticAnalysis(
                    lian
                ).run().analyzed_method_list

            required_method_ids = self._required_p3_method_ids(
                lian.loader,
                enable_p2=enable_p2,
            )
            original_entry_points = {
                int(method_id)
                for method_id in lian.loader.get_entry_points()
            }
            call_graph = self._p3_call_graph(
                lian.loader,
                enable_p2=enable_p2,
            )
            entry_points = select_p3_coverage_roots(
                required_method_ids,
                call_graph,
            )
            _replace_entry_points(lian.loader, set(entry_points))
            print(
                "[lian] P3 entry selection: "
                f"required={len(required_method_ids)} "
                f"original={len(original_entry_points)} "
                f"effective={entry_points}"
            )

            p3_analysis = _CoverageTrackingP3GlobalSemanticAnalysis(
                lian,
                analyzed_method_list,
            )
            run_p3_with_one_coverage_retry(
                lian.loader,
                p3_analysis,
                required_method_ids,
                entry_points,
            )
            lian.loader.export()
            self.complete_marker.write_text("p3\n", encoding="utf-8")
        except SystemExit as exc:
            raise LianAnalysisError(
                f"Lian analysis stopped with exit code {exc.code}"
            ) from exc
        except Exception as exc:
            raise LianAnalysisError(f"Lian analysis failed: {exc}") from exc

        return LianAnalysisResult(
            workspace=self.lian_workspace,
            lian=lian,
            loader=lian.loader,
        )

    @staticmethod
    def _required_p3_method_ids(
        loader: Any,
        *,
        enable_p2: bool = False,
    ) -> set[int]:
        required_method_ids = set()
        max_method_stmts = int(
            getattr(lian_config, "MAX_METHOD_STMTS", 0) or 0
        )
        for method_id in loader.get_all_method_ids():
            if not loader.contain_symbol_state_space_p1(method_id):
                continue
            state_phase = "P2" if enable_p2 else "P1"
            state_space_getter = (
                loader.get_symbol_state_space_p2
                if enable_p2
                else loader.get_symbol_state_space_p1
            )
            try:
                state_space = state_space_getter(method_id)
            except Exception as exc:
                raise LianAnalysisError(
                    f"failed to load {state_phase} state space for method "
                    f"{method_id}"
                ) from exc
            if util.is_empty(state_space):
                print(
                    f"[lian] P3 coverage excludes method with empty "
                    f"{state_phase} state space id={int(method_id)}"
                )
                continue
            method_stmt_ids = loader.convert_method_id_to_stmt_ids(method_id)
            stmt_count = len(method_stmt_ids or ())
            if max_method_stmts and stmt_count > max_method_stmts:
                print(
                    "[lian] P3 coverage excludes oversized method "
                    f"id={int(method_id)} stmts={stmt_count} "
                    f"limit={max_method_stmts}"
                )
                continue
            try:
                cfg = loader.get_method_cfg(method_id)
            except Exception as exc:
                raise LianAnalysisError(
                    f"failed to load CFG for method {method_id}"
                ) from exc
            if not util.is_empty(cfg):
                required_method_ids.add(int(method_id))
        return required_method_ids

    @staticmethod
    def _p3_call_graph(loader: Any, *, enable_p2: bool) -> Any:
        if enable_p2:
            p2_call_graph = loader.get_call_graph_p2()
            graph = getattr(p2_call_graph, "graph", p2_call_graph)
            if graph is not None and graph.number_of_edges() > 0:
                return p2_call_graph
        return loader.get_classified_method_call()

    def load_loader(self) -> Loader:

        if not self.lian_workspace.is_dir():
            raise LianAnalysisError(
                f"Lian workspace does not exist: {self.lian_workspace}"
            )
        if not self.complete_marker.is_file():
            raise LianAnalysisError(
                f"Lian P3 analysis is incomplete: {self.lian_workspace}"
            )

        options = self._build_options(Lian().options)
        loader = Loader(options)
        try:
            loader.restore()
        except Exception as exc:
            raise LianAnalysisError(
                f"failed to restore Lian loader from {self.lian_workspace}: {exc}"
            ) from exc
        return loader

    def _build_options(
        self,
        defaults: Any,
        *,
        enable_p2: bool = False,
    ) -> SimpleNamespace:
        values = vars(defaults).copy()
        values.update(
            {
                "workspace": str(self.lian_workspace),
                "default_workspace_dir": LIAN_WORKSPACE_DIR_NAME,
                "in_path": [str(self.preprocessed_root)],
                "lang": ["c"],
                "lang_extensions": [".c", ".h", ".i"],
                "sub_command": "semantic",
                "force": True,
                "incremental": False,
                "quiet": False,
                "debug": False,
                "cores": 1,
                "strict_parse_mode": False,
                "included_headers": "",
                "enable_header_preprocess": False,
                "nomock": True,
                "enable_p2": enable_p2,
                "graph": False,
                "complete_graph": False,
                "event_handlers": [],
            }
        )
        return SimpleNamespace(**values)

    def _validate_input(self) -> None:
        if not self.preprocessed_root.is_dir():
            raise LianAnalysisError(
                f"preprocessed source directory does not exist: "
                f"{self.preprocessed_root}"
            )
        if not any(self.preprocessed_root.rglob("*.c")):
            raise LianAnalysisError(
                f"no preprocessed C files found in {self.preprocessed_root}"
            )
