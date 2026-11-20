from __future__ import annotations

import ast
import dataclasses
import re
from collections import deque
from typing import Any

from .models import PointerAnalysisResult
from .resource_analysis import derive_resource_state_requirements
from .semantic_hint_schemas import (
    ResourceCapability,
    ResourceFlowEdge,
    ResourceFlowEdgeKind,
    ResourceOperation,
    ResourceOperationEffect,
    ResourceOperationOrigin,
    ResourceStateRequirement,
)

_TOKEN_PATTERN = re.compile(r"[A-Za-z_]\w*")


@dataclasses.dataclass(frozen=True)
class _Adjacent:
    anchor: str
    edge: ResourceFlowEdge
    operation_origin: ResourceOperationOrigin


class ResourceFlowAnalyzer:


    def __init__(self, context: Any) -> None:
        self.context = context

    def analyze(
        self,
        results: tuple[PointerAnalysisResult, ...],
    ) -> tuple[PointerAnalysisResult, ...]:
        resources = {
            self._anchor(result): result
            for result in results
            if result.semantics.resource_semantics is not None
        }
        if not resources:
            return results

        edges = self._build_edges(resources)
        adjacency = self._build_adjacency(resources, edges)
        components = self._components(resources, adjacency)
        replacements: dict[str, PointerAnalysisResult] = {}
        for component in components:
            protocol_id = (
                f"stdio-flow-{'-'.join(self._stmt_id(anchor) for anchor in component)}"
                if len(component) > 1
                else resources[component[0]].semantics.resource_semantics.protocol_id
            )
            component_edges = self._component_edges(component, edges)
            for anchor in component:
                replacements[anchor] = self._merge_for_anchor(
                    anchor=anchor,
                    component=component,
                    component_edges=component_edges,
                    adjacency=adjacency,
                    resources=resources,
                    protocol_id=protocol_id,
                )

        return tuple(replacements.get(self._anchor(result), result) for result in results)

    def _build_edges(
        self,
        resources: dict[str, PointerAnalysisResult],
    ) -> list[ResourceFlowEdge]:
        edges: dict[tuple[str, str, str, str], ResourceFlowEdge] = {}
        results_by_method: dict[int, tuple[PointerAnalysisResult, ...]] = {}
        mutable_by_method: dict[int, list[PointerAnalysisResult]] = {}
        for result in resources.values():
            if result.target.method_id is not None:
                mutable_by_method.setdefault(result.target.method_id, []).append(result)
        for method_id, method_results in mutable_by_method.items():
            results_by_method[method_id] = tuple(method_results)

        parameters: dict[tuple[int, int], PointerAnalysisResult] = {}
        for method_id in self._method_ids():
            for index, parameter in enumerate(self._parameters(method_id)):
                stmt_id = self._positive_id(getattr(parameter, "stmt_id", None))
                anchor = f"decl:{stmt_id}" if stmt_id is not None else ""
                if anchor in resources:
                    parameters[(method_id, index)] = resources[anchor]

        for caller_method_id in self._method_ids():
            caller_results = results_by_method.get(caller_method_id, ())
            for row in self.context.get_method_rows(caller_method_id):
                operation = self._text(getattr(row, "operation", ""))
                if operation == "call_stmt":
                    self._add_call_edges(
                        edges,
                        caller_method_id=caller_method_id,
                        caller_results=caller_results,
                        row=row,
                        parameters=parameters,
                        resources=resources,
                        results_by_method=results_by_method,
                    )
                elif operation in {
                    "assign_stmt",
                    "variable_decl",
                    "field_write",
                    "field_read",
                }:
                    self._add_assignment_edges(
                        edges,
                        row=row,
                        method_results=caller_results,
                    )

        for anchor, result in resources.items():
            contract = result.semantics.resource_semantics
            assert contract is not None
            if contract.handle.indirection <= 1:
                continue
            indexed_expression = re.compile(rf"\b{re.escape(result.target.name)}\s*\[[^]]+\]")
            for site in result.semantics.usage_path:
                match = indexed_expression.search(site)
                if match is not None:
                    self._store_edge(
                        edges,
                        ResourceFlowEdge(
                            kind=ResourceFlowEdgeKind.INDEXED_ELEMENT,
                            source=anchor,
                            target=f"element:{anchor}:{match.group(0)}",
                            site=site,
                        ),
                    )
        return sorted(edges.values(), key=self._edge_key)

    def _add_call_edges(
        self,
        edges: dict[tuple[str, str, str, str], ResourceFlowEdge],
        *,
        caller_method_id: int,
        caller_results: tuple[PointerAnalysisResult, ...],
        row: Any,
        parameters: dict[tuple[int, int], PointerAnalysisResult],
        resources: dict[str, PointerAnalysisResult],
        results_by_method: dict[int, tuple[PointerAnalysisResult, ...]],
    ) -> None:
        stmt_id = self._positive_id(getattr(row, "stmt_id", None))
        if stmt_id is None:
            return
        callee_name = self._call_name(stmt_id, row)
        callee_ids = tuple(
            method_id
            for method_id in self.context.get_callees(caller_method_id)
            if not callee_name
            or self._text(self.context.get_method_name(method_id)) == callee_name
        )
        arguments = self._call_arguments(row)
        site = f"{self._text(self.context.get_method_name(caller_method_id))}:"
        site += f"{callee_name}({', '.join(arguments)})"
        for index, argument in enumerate(arguments):
            callers = [
                result
                for result in caller_results
                if self._mentions_name(argument, result.target.name)
            ]
            callees = [
                parameters[(callee_id, index)]
                for callee_id in callee_ids
                if (callee_id, index) in parameters
            ]
            for caller in callers:
                for callee in callees:
                    self._store_edge(
                        edges,
                        ResourceFlowEdge(
                            kind=ResourceFlowEdgeKind.CALL_ARGUMENT,
                            source=self._anchor(caller),
                            target=self._anchor(callee),
                            site=site,
                        ),
                    )

        call_target = self._field(row, "target", "result", "lhs")
        caller_receivers = [
            result
            for result in caller_results
            if self._mentions_name(call_target, result.target.name)
        ]
        if not caller_receivers:
            return
        for callee_id in callee_ids:
            returned = self._returned_resources(
                callee_id,
                results_by_method.get(callee_id, ()),
            )
            for source in returned:
                for receiver in caller_receivers:
                    self._store_edge(
                        edges,
                        ResourceFlowEdge(
                            kind=ResourceFlowEdgeKind.RETURN_ASSIGNMENT,
                            source=self._anchor(source),
                            target=self._anchor(receiver),
                            site=site,
                        ),
                    )

    def _add_assignment_edges(
        self,
        edges: dict[tuple[str, str, str, str], ResourceFlowEdge],
        *,
        row: Any,
        method_results: tuple[PointerAnalysisResult, ...],
    ) -> None:
        target = self._field(row, "target", "lhs", "name")
        source = self._field(row, "operand", "source", "value", "rhs", "init")
        if not target or not source:
            return
        targets = [
            result
            for result in method_results
            if self._mentions_name(target, result.target.name)
        ]
        sources = [
            result
            for result in method_results
            if self._mentions_name(source, result.target.name)
        ]
        kind = (
            ResourceFlowEdgeKind.STORED
            if any(token in target for token in (".", "->"))
            else ResourceFlowEdgeKind.ALIAS
        )
        for source_result in sources:
            for target_result in targets:
                if source_result is target_result:
                    continue
                self._store_edge(
                    edges,
                    ResourceFlowEdge(
                        kind=kind,
                        source=self._anchor(source_result),
                        target=self._anchor(target_result),
                        site=f"{target} = {source}",
                    ),
                )

    def _returned_resources(
        self,
        method_id: int,
        method_results: tuple[PointerAnalysisResult, ...],
    ) -> list[PointerAnalysisResult]:
        returned: list[PointerAnalysisResult] = []
        for row in self.context.get_method_rows(method_id):
            if self._text(getattr(row, "operation", "")) != "return_stmt":
                continue
            value = self._field(row, "operand", "value", "source", "result")
            returned.extend(
                result
                for result in method_results
                if self._mentions_name(value, result.target.name)
                and result not in returned
            )
        return returned

    def _merge_for_anchor(
        self,
        *,
        anchor: str,
        component: tuple[str, ...],
        component_edges: list[ResourceFlowEdge],
        adjacency: dict[str, list[_Adjacent]],
        resources: dict[str, PointerAnalysisResult],
        protocol_id: str,
    ) -> PointerAnalysisResult:
        result = resources[anchor]
        contract = result.semantics.resource_semantics
        assert contract is not None
        paths = self._paths_from(anchor, adjacency)
        operations: dict[tuple[str, str, str, str, str], ResourceOperation] = {}
        capabilities: set[ResourceCapability] = set()
        requirements = set(contract.state_requirements)
        unresolved_fields = set(contract.unresolved_fields)

        for source_anchor in component:
            source_contract = resources[source_anchor].semantics.resource_semantics
            assert source_contract is not None
            capabilities.update(source_contract.capabilities)
            requirements.update(source_contract.state_requirements)
            unresolved_fields.update(source_contract.unresolved_fields)
            path = paths.get(source_anchor, ())
            for operation in source_contract.operations:
                propagated = operation
                if source_anchor != anchor:
                    call_path = tuple(item.edge.site for item in path if item.edge.site)
                    origin = next(
                        (
                            item.operation_origin
                            for item in path
                            if item.edge.kind
                            in {
                                ResourceFlowEdgeKind.CALL_ARGUMENT,
                                ResourceFlowEdgeKind.RETURN_ASSIGNMENT,
                            }
                        ),
                        ResourceOperationOrigin.DIRECT,
                    )
                    propagated = dataclasses.replace(
                        operation,
                        origin=origin,
                        call_path=call_path + operation.call_path,
                    )
                operations.setdefault(self._operation_key(propagated), propagated)

        merged_operations = sorted(operations.values(), key=self._operation_key)
        requirements.update(derive_resource_state_requirements(merged_operations))
        if (
            any(edge.kind is ResourceFlowEdgeKind.CALL_ARGUMENT for edge in component_edges)
            and any(op.effect is ResourceOperationEffect.READ for op in merged_operations)
            and any(op.effect is ResourceOperationEffect.TEST_EOF for op in merged_operations)
        ):
            requirements.add(ResourceStateRequirement.EOF_SURVIVES_FUNCTION_RETURN)

        merged_contract = dataclasses.replace(
            contract,
            protocol_id=protocol_id,
            capabilities=sorted(capabilities, key=lambda item: item.value),
            operations=merged_operations,
            flow_edges=component_edges,
            state_requirements=[
                item for item in ResourceStateRequirement if item in requirements
            ],
            unresolved_fields=sorted(unresolved_fields),
        )
        return dataclasses.replace(
            result,
            semantics=dataclasses.replace(
                result.semantics,
                resource_semantics=merged_contract,
            ),
        )

    @staticmethod
    def _build_adjacency(
        resources: dict[str, PointerAnalysisResult],
        edges: list[ResourceFlowEdge],
    ) -> dict[str, list[_Adjacent]]:
        adjacency = {anchor: [] for anchor in resources}
        for edge in edges:
            if edge.source not in resources or edge.target not in resources:
                continue
            if edge.kind is ResourceFlowEdgeKind.CALL_ARGUMENT:
                source_origin = ResourceOperationOrigin.CALLEE
                target_origin = ResourceOperationOrigin.CALLER
            elif edge.kind is ResourceFlowEdgeKind.RETURN_ASSIGNMENT:
                source_origin = ResourceOperationOrigin.CALLER
                target_origin = ResourceOperationOrigin.CALLEE
            else:
                source_origin = target_origin = ResourceOperationOrigin.DIRECT
            adjacency[edge.source].append(
                _Adjacent(edge.target, edge, source_origin)
            )
            adjacency[edge.target].append(
                _Adjacent(edge.source, edge, target_origin)
            )
        for items in adjacency.values():
            items.sort(key=lambda item: (item.anchor, ResourceFlowAnalyzer._edge_key(item.edge)))
        return adjacency

    @staticmethod
    def _components(
        resources: dict[str, PointerAnalysisResult],
        adjacency: dict[str, list[_Adjacent]],
    ) -> list[tuple[str, ...]]:
        remaining = set(resources)
        components: list[tuple[str, ...]] = []
        while remaining:
            first = min(remaining, key=ResourceFlowAnalyzer._stmt_id_int)
            pending = [first]
            component: set[str] = set()
            while pending:
                current = pending.pop()
                if current in component:
                    continue
                component.add(current)
                pending.extend(item.anchor for item in adjacency[current])
            remaining.difference_update(component)
            components.append(
                tuple(sorted(component, key=ResourceFlowAnalyzer._stmt_id_int))
            )
        return components

    @staticmethod
    def _paths_from(
        start: str,
        adjacency: dict[str, list[_Adjacent]],
    ) -> dict[str, tuple[_Adjacent, ...]]:
        paths: dict[str, tuple[_Adjacent, ...]] = {start: ()}
        pending = deque([start])
        while pending:
            current = pending.popleft()
            for adjacent in adjacency[current]:
                if adjacent.anchor in paths:
                    continue
                paths[adjacent.anchor] = paths[current] + (adjacent,)
                pending.append(adjacent.anchor)
        return paths

    @staticmethod
    def _component_edges(
        component: tuple[str, ...],
        edges: list[ResourceFlowEdge],
    ) -> list[ResourceFlowEdge]:
        anchors = set(component)
        return [
            edge
            for edge in edges
            if edge.source in anchors
            and (edge.target in anchors or edge.target.startswith("element:"))
        ]

    def _method_ids(self) -> tuple[int, ...]:
        return tuple(self.context.get_all_method_ids())

    def _parameters(self, method_id: int) -> tuple[Any, ...]:
        return tuple(
            sorted(
                self.context.get_method_parameters(method_id),
                key=lambda parameter: (
                    self._number(getattr(parameter, "start_line", 0)),
                    self._number(getattr(parameter, "start_col", 0)),
                    self._number(getattr(parameter, "stmt_id", 0)),
                ),
            )
        )

    def _call_name(self, stmt_id: int, row: Any) -> str:
        info = self.context.get_call_info(stmt_id)
        return self._field(info, "name", "callee", "callee_name") or self._field(
            row, "name", "callee", "callee_name"
        )

    @staticmethod
    def _call_arguments(row: Any) -> list[str]:
        raw = getattr(row, "positional_args", None)
        if isinstance(raw, (list, tuple)):
            return [str(item) for item in raw]
        try:
            parsed = ast.literal_eval(str(raw))
        except (SyntaxError, ValueError, TypeError):
            return []
        return [str(item) for item in parsed] if isinstance(parsed, list) else []

    @staticmethod
    def _mentions_name(expression: str, name: str) -> bool:
        return name in _TOKEN_PATTERN.findall(str(expression or ""))

    @staticmethod
    def _field(value: Any, *names: str) -> str:
        for name in names:
            raw = value.get(name) if isinstance(value, dict) else getattr(value, name, None)
            text = ResourceFlowAnalyzer._text(raw)
            if text:
                return text
        return ""

    @staticmethod
    def _store_edge(
        edges: dict[tuple[str, str, str, str], ResourceFlowEdge],
        edge: ResourceFlowEdge,
    ) -> None:
        edges.setdefault(ResourceFlowAnalyzer._edge_key(edge), edge)

    @staticmethod
    def _edge_key(edge: ResourceFlowEdge) -> tuple[str, str, str, str]:
        return edge.kind.value, edge.source, edge.target, edge.site or ""

    @staticmethod
    def _operation_key(operation: ResourceOperation) -> tuple[str, str, str, str, str]:
        return (
            operation.callee,
            operation.effect.value,
            operation.target,
            operation.site or "",
            "" if operation.open_mode is None else operation.open_mode.value,
        )

    @staticmethod
    def _anchor(result: PointerAnalysisResult) -> str:
        return f"decl:{result.target.stmt_id}"

    @staticmethod
    def _stmt_id(anchor: str) -> str:
        return anchor.rsplit(":", 1)[-1]

    @staticmethod
    def _stmt_id_int(anchor: str) -> int:
        return int(ResourceFlowAnalyzer._stmt_id(anchor))

    @staticmethod
    def _positive_id(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result > 0 else None

    @staticmethod
    def _number(value: Any) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError, OverflowError):
            return 0

    @staticmethod
    def _text(value: Any) -> str:
        return "" if value is None else str(value).strip()
