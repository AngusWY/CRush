from __future__ import annotations

import ast
import dataclasses
import re
from collections.abc import Iterable
from typing import Any, Callable

from .analysis_context import AnalysisContext
from .models import (
    PointerAnalysisResult,
    PointerLocation,
    PointerTarget,
    VariableAnalysisResult,
    VariableLocation,
    VariableTarget,
)
from .resource_flow_analysis import ResourceFlowAnalyzer
from .resource_analysis import (
    infer_stdio_resource_semantics,
    parse_stdio_handle_type,
)
from .semantic_hint_schemas import (
    CStringSemantics,
    GlobalPointerInitMode,
    Lifetime,
    Mutability,
    Nullability,
    Ownership,
    PointeeShape,
    PointerDeclarationOperation,
    PointerDeclarationSemantics,
    ResourceHandleRole,
    ResourceHandleSemantics,
    VariableDeclarationSemantics,
    VariableMutability,
)


_NULL_VALUES = frozenset(
    {
        "0",
        "NULL",
        "null",
        "nullptr",
        "((void*)0)",
        "((void *)0)",
    }
)
_ALLOCATORS = frozenset(
    {"malloc", "calloc", "realloc", "strdup", "strndup", "getline"}
)
_DEALLOCATORS = frozenset({"free"})
_STRING_FUNCTIONS = frozenset(
    {
        "strlen",
        "strcmp",
        "strncmp",
        "strcpy",
        "strncpy",
        "strcat",
        "strncat",
        "strchr",
        "strrchr",
        "strstr",
        "strdup",
        "strndup",
        "strtok",
        "strtok_r",
    }
)
_CALL_ARGUMENT_ACCESS: dict[str, dict[int, tuple[bool, bool]]] = {
    "strlen": {0: (True, False)},
    "strcmp": {0: (True, False), 1: (True, False)},
    "strncmp": {0: (True, False), 1: (True, False)},
    "strcpy": {0: (False, True), 1: (True, False)},
    "strncpy": {0: (False, True), 1: (True, False)},
    "strcat": {0: (True, True), 1: (True, False)},
    "strncat": {0: (True, True), 1: (True, False)},
    "strchr": {0: (True, False)},
    "strrchr": {0: (True, False)},
    "strstr": {0: (True, False), 1: (True, False)},
    "strdup": {0: (True, False)},
    "strndup": {0: (True, False)},
    "memcpy": {0: (False, True), 1: (True, False)},
    "memmove": {0: (False, True), 1: (True, False)},
    "memset": {0: (False, True)},
    "memcmp": {0: (True, False), 1: (True, False)},
    "memchr": {0: (True, False)},
    "puts": {0: (True, False)},
    "printf": {**{i: (True, False) for i in range(1, 16)}},
    "fprintf": {**{i: (True, False) for i in range(2, 16)}},
    "sprintf": {0: (False, True), **{i: (True, False) for i in range(2, 16)}},
    "snprintf": {0: (False, True), 1: (True, False), **{i: (True, False) for i in range(3, 16)}},
    "fputs": {0: (True, False), 1: (True, False)},
}
_MEMORY_FUNCTIONS = frozenset(
    {"memcpy", "memmove", "memset", "memcmp", "memchr"}
)
_POINTER_ARITHMETIC_OPERATORS = frozenset({"+", "-", "+=", "-="})
_TOKEN_PATTERN = re.compile(r"[A-Za-z_%][A-Za-z0-9_%]*")
_FUNCTION_POINTER_PATTERN = re.compile(
    r"\(\s*\*\s*(?:[A-Za-z_][A-Za-z0-9_]*)?\s*\)\s*\("
)
_STRING_LITERAL_RE = re.compile(r'"([^"\\]|\\.)*"')
_FIELD_ACCESS_RE = re.compile(r"(?:->|\.)\s*\w+")
_MUTATING_ARGUMENTS: dict[str, frozenset[int]] = {
    "memcpy": frozenset({0}),
    "memmove": frozenset({0}),
    "memset": frozenset({0}),
    "scanf": frozenset(range(0, 32)),
    "fscanf": frozenset(range(1, 32)),
    "sscanf": frozenset(range(1, 32)),
}
_OWNERSHIP_ALLOCATED_FROM_HEAP = "allocated_from_heap"
_OWNERSHIP_FREED = "freed"
_OWNERSHIP_BORROWED_SOURCE = "borrowed_source"
_OWNERSHIP_UNKNOWN = "unknown"
_BORROWED_ORIGINS = frozenset({"local", "static", "parameter", "field"})
_POINTEE_READ = "pointee_read"
_POINTEE_WRITTEN = "pointee_written"
_POINTEE_EXTERNAL_UNKNOWN = "external_unknown"
_NULLABILITY_NULL_RELATED = "null_related"
_NULLABILITY_NONNULL_EVIDENCE = "nonnull_evidence"
_NULLABILITY_UNKNOWN = "unknown"
_LIFETIME_OWNED_SOURCE = "owned_source"
_LIFETIME_STATIC_SOURCE = "static_source"
_LIFETIME_PARAM_SOURCE = "param_source"
_LIFETIME_LOCAL_SOURCE = "local_source"
_LIFETIME_STORED_SOURCE = "stored_source"
_LIFETIME_RETURNED = "returned"
_LIFETIME_STORED = "stored"
_LIFETIME_UNKNOWN = "unknown"
_SHAPE_ALLOC_SINGLE = "alloc_single"
_SHAPE_ALLOC_ARRAY = "alloc_array"
_SHAPE_INDEXED_ACCESS = "indexed_access"
_SHAPE_POINTER_ARITHMETIC = "pointer_arithmetic"
_SHAPE_BYTE_BUFFER_ACCESS = "byte_buffer_access"
_SHAPE_STRING_ACCESS = "string_access"
_SHAPE_FIELD_ACCESS = "field_access"
_SHAPE_DEREF_ACCESS = "deref_access"
_SHAPE_UNKNOWN = "unknown"


class PointerAnalysisError(RuntimeError):
    pass


class DeclarationAnalyzer:


    def __init__(
        self,
        context: AnalysisContext,
        *,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.pointer_analyzer = PointerAnalyzer(context, progress=progress)
        self.variable_analyzer = VariableAnalyzer(context, progress=progress)

    def analyze_pointers(
        self, targets: Iterable[PointerTarget]
    ) -> tuple[PointerAnalysisResult, ...]:
        return self.pointer_analyzer.analyze_all(targets)

    def analyze_variables(
        self, targets: Iterable[VariableTarget]
    ) -> tuple[VariableAnalysisResult, ...]:
        return self.variable_analyzer.analyze_all(targets)


@dataclasses.dataclass(frozen=True)
class _PointerRelatedStmt:
    method_id: int
    stmt_id: int
    symbol_ids: frozenset[int]
    target_symbol_ids: frozenset[int] = frozenset()

    @property
    def uses_alias(self) -> bool:
        return bool(self.symbol_ids) and not bool(
            self.symbol_ids & self.target_symbol_ids
        )


@dataclasses.dataclass(frozen=True)
class _PointerStmtAccess:
    pointer_read: bool = False
    pointer_written: bool = False
    pointee_read: bool = False
    pointee_written: bool = False
    alias_created: bool = False
    alias_pointee_written: bool = False
    stored: bool = False
    returned: bool = False
    passed_to_unknown_callee: bool = False
    array_access: bool = False
    single_access_observed: bool = False
    pointer_arithmetic: bool = False
    string_usage: bool = False
    byte_buffer_usage: bool = False


@dataclasses.dataclass(frozen=True)
class _PointerOwnershipEvents:
    kinds: frozenset[str] = frozenset()

    def has(self, kind: str) -> bool:
        return kind in self.kinds

    @property
    def allocated_from_heap(self) -> bool:
        return self.has(_OWNERSHIP_ALLOCATED_FROM_HEAP)

    @property
    def freed(self) -> bool:
        return self.has(_OWNERSHIP_FREED)

    @property
    def borrowed_source(self) -> bool:
        return self.has(_OWNERSHIP_BORROWED_SOURCE)

    @property
    def unknown(self) -> bool:
        return self.has(_OWNERSHIP_UNKNOWN)


@dataclasses.dataclass(frozen=True)
class _PointerPointeeMutabilityEvents:
    kinds: frozenset[str] = frozenset()

    def has(self, kind: str) -> bool:
        return kind in self.kinds

    @property
    def read(self) -> bool:
        return self.has(_POINTEE_READ)

    @property
    def written(self) -> bool:
        return self.has(_POINTEE_WRITTEN)

    @property
    def external_unknown(self) -> bool:
        return self.has(_POINTEE_EXTERNAL_UNKNOWN)


@dataclasses.dataclass(frozen=True)
class _PointerNullabilityEvents:
    kinds: frozenset[str] = frozenset()

    def has(self, kind: str) -> bool:
        return kind in self.kinds

    @property
    def null_related(self) -> bool:
        return self.has(_NULLABILITY_NULL_RELATED)

    @property
    def nonnull_evidence(self) -> bool:
        return self.has(_NULLABILITY_NONNULL_EVIDENCE)

    @property
    def unknown(self) -> bool:
        return self.has(_NULLABILITY_UNKNOWN)


@dataclasses.dataclass(frozen=True)
class _PointerLifetimeEvents:
    kinds: frozenset[str] = frozenset()

    def has(self, kind: str) -> bool:
        return kind in self.kinds

    @property
    def owned_source(self) -> bool:
        return self.has(_LIFETIME_OWNED_SOURCE)

    @property
    def static_source(self) -> bool:
        return self.has(_LIFETIME_STATIC_SOURCE)

    @property
    def param_source(self) -> bool:
        return self.has(_LIFETIME_PARAM_SOURCE)

    @property
    def local_source(self) -> bool:
        return self.has(_LIFETIME_LOCAL_SOURCE)

    @property
    def stored_source(self) -> bool:
        return self.has(_LIFETIME_STORED_SOURCE)

    @property
    def returned(self) -> bool:
        return self.has(_LIFETIME_RETURNED)

    @property
    def stored(self) -> bool:
        return self.has(_LIFETIME_STORED)

    @property
    def unknown(self) -> bool:
        return self.has(_LIFETIME_UNKNOWN)


@dataclasses.dataclass(frozen=True)
class _PointerPointeeShapeEvents:
    kinds: frozenset[str] = frozenset()

    def has(self, kind: str) -> bool:
        return kind in self.kinds

    @property
    def strong_array(self) -> bool:
        return bool(
            self.kinds
            & {
                _SHAPE_ALLOC_ARRAY,
                _SHAPE_INDEXED_ACCESS,
                _SHAPE_POINTER_ARITHMETIC,
                _SHAPE_STRING_ACCESS,
            }
        )

    @property
    def alloc_single(self) -> bool:
        return self.has(_SHAPE_ALLOC_SINGLE)

    @property
    def single_access(self) -> bool:
        return self.has(_SHAPE_FIELD_ACCESS) or self.has(_SHAPE_DEREF_ACCESS)

    @property
    def byte_buffer(self) -> bool:
        return self.has(_SHAPE_BYTE_BUFFER_ACCESS)


class PointerAnalyzer:


    def __init__(
        self,
        context: AnalysisContext,
        *,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.context = context
        self._progress = progress
        self._parameter_access_cache: dict[
            tuple[int, int], tuple[bool, bool]
        ] = {}
        self._parameter_shape_cache: dict[
            tuple[int, int, int], tuple[bool, bool, bool, bool, bool]
        ] = {}
        self._analysis_method_ids_cache: dict[int, tuple[int, ...]] = {}
        self._related_stmts_cache: dict[
            tuple[int, int], tuple[_PointerRelatedStmt, ...]
        ] = {}
        self._stmt_access_cache: dict[
            tuple[int, int, tuple[int, ...], tuple[int, ...], int],
            _PointerStmtAccess,
        ] = {}
        self._combined_access_cache: dict[int, _PointerStmtAccess] = {}
        self._ownership_events_cache: dict[
            tuple[int, str, PointerLocation], _PointerOwnershipEvents
        ] = {}
        self._pointee_mutability_events_cache: dict[
            tuple[int, str, PointerLocation], _PointerPointeeMutabilityEvents
        ] = {}
        self._nullability_events_cache: dict[
            tuple[int, str, PointerLocation], _PointerNullabilityEvents
        ] = {}
        self._lifetime_events_cache: dict[
            tuple[int, str, PointerLocation], _PointerLifetimeEvents
        ] = {}
        self._pointee_shape_events_cache: dict[
            tuple[int, str, PointerLocation], _PointerPointeeShapeEvents
        ] = {}
        self._method_return_shape_events_cache: dict[
            tuple[int, int], _PointerPointeeShapeEvents
        ] = {}
        self._parameter_shape_events_cache: dict[
            tuple[int, int, int], _PointerPointeeShapeEvents
        ] = {}
        self._freed_parameter_indices_cache: dict[
            tuple[int, int], frozenset[int]
        ] = {}
        self._method_touched_fields_cache: dict[int, frozenset[str]] = {}
        self._methods_by_touched_field_cache: (
            dict[str, tuple[int, ...]] | None
        ) = None
        self._field_temp_names_cache: dict[
            tuple[int, int], frozenset[str]
        ] = {}
        self._type_alias_cache: dict[str, str] | None = None
        self._field_aggregate_names_cache: dict[str, frozenset[str]] | None = None
        self._aggregate_field_type_cache: dict[str, dict[str, str]] | None = None
        self._method_ids_by_name: dict[str, tuple[int, ...]] | None = None
        self._call_producers_by_method: dict[
            int, dict[str, tuple[str, list[str]]]
        ] = {}

    def analyze(self, target: PointerTarget) -> PointerAnalysisResult:
        self._validate_target(target)
        if target.location is PointerLocation.TYPE_ALIAS:
            return self._analyze_type_alias_pointer(target)

        stdio_indirection = parse_stdio_handle_type(target.c_type)
        is_stdio_resource = stdio_indirection is not None
        usage_path = self._collect_usage_path(
            target,
            limit=100 if is_stdio_resource else 20,
        )

        ownership = self._infer_ownership(target)
        mutability = self._infer_mutability(target)
        pointee_shape = self._infer_pointee_shape(target)
        lifetime = self._infer_lifetime(target)
        resource_semantics = None
        if is_stdio_resource:
            assert stdio_indirection is not None
            declaration_source = self._stmt_source_text(target.stmt_id)
            standard_stream = self._stdio_standard_stream_evidence(
                target.name,
                (declaration_source, *usage_path),
            )
            opened_here = self._stdio_open_evidence(
                target.name,
                (declaration_source, *usage_path),
            )
            handle_role = self._stdio_handle_role(
                target.name,
                stdio_indirection,
                (declaration_source, *usage_path),
            )
            if standard_stream:
                ownership = Ownership.BORROWED
                lifetime = Lifetime.STATIC
            elif target.location is PointerLocation.PARAMETER:
                ownership = Ownership.BORROWED
                lifetime = Lifetime.PARAM
            elif opened_here and target.location is PointerLocation.LOCAL:
                ownership = Ownership.OWNED
                lifetime = Lifetime.LOCAL
            else:
                ownership = Ownership.BORROWED
                lifetime = (
                    Lifetime.LOCAL
                    if target.location is PointerLocation.LOCAL
                    else Lifetime.STORED
                )
            mutability = Mutability.MUTABLE
            pointee_shape = (
                PointeeShape.ARRAY
                if handle_role is ResourceHandleRole.SEQUENCE
                else PointeeShape.SINGLE
            )
            identity = (
                f"{target.aggregate_name}.{target.name}"
                if target.aggregate_name
                else target.name
            )
            resource_semantics = infer_stdio_resource_semantics(
                resource_identity=identity,
                protocol_id=f"stdio-decl-{target.stmt_id}",
                handle=ResourceHandleSemantics(
                    indirection=stdio_indirection,
                    role=handle_role,
                    element_ownership=(
                        ownership
                        if stdio_indirection == 1
                        else Ownership.OWNED if opened_here else None
                    ),
                    element_nullability=(
                        self._infer_nullability(target)
                        if stdio_indirection == 1
                        else Nullability.NULLABLE if opened_here else None
                    ),
                ),
                usage_path=usage_path,
            )

        semantics = PointerDeclarationSemantics(
            stmt_id=target.stmt_id,
            name=target.name,
            operation=target.operation,
            is_struct_member=target.is_aggregate_member,
            nullability=self._infer_nullability(target),
            ownership=ownership,
            mutability=mutability,
            pointee_shape=pointee_shape,
            lifetime=lifetime,
            init_mode=self._infer_global_pointer_init_mode(target),
            resource_required=is_stdio_resource,
            resource_semantics=resource_semantics,
            string_semantics=self._infer_c_string_semantics(
                target,
                usage_path,
            ),
            usage_path=usage_path,
        )
        return PointerAnalysisResult(target=target, semantics=semantics)

    def _analyze_type_alias_pointer(
        self,
        target: PointerTarget,
    ) -> PointerAnalysisResult:
        semantics = PointerDeclarationSemantics(
            stmt_id=target.stmt_id,
            name=target.name,
            operation=target.operation,
            is_struct_member=False,
            nullability=Nullability.NULLABLE,
            ownership=Ownership.NONE,
            mutability=self._type_alias_pointer_mutability(target.c_type),
            pointee_shape=None,
            lifetime=Lifetime.UNKNOWN,
            init_mode=None,
            resource_required=self._is_stdio_file_pointer_type(target.c_type),
            usage_path=[
                "typedef pointer alias; no value-level ownership or lifetime "
                "can be inferred from the typedef alone"
            ],
        )
        return PointerAnalysisResult(target=target, semantics=semantics)

    @staticmethod
    def _is_stdio_file_pointer_type(c_type: str) -> bool:
        return parse_stdio_handle_type(c_type) is not None

    @staticmethod
    def _stdio_handle_role(
        name: str,
        indirection: int,
        evidence: Iterable[str],
    ) -> ResourceHandleRole:
        if indirection == 1:
            return ResourceHandleRole.DIRECT
        escaped_name = re.escape(name)
        evidence_text = "\n".join(str(item) for item in evidence)
        if re.search(rf"\b{escaped_name}\s*\[", evidence_text):
            return ResourceHandleRole.SEQUENCE
        if re.search(rf"\*\s*{escaped_name}\s*=", evidence_text):
            return ResourceHandleRole.SLOT
        return ResourceHandleRole.UNKNOWN

    @staticmethod
    def _stdio_standard_stream_evidence(
        name: str,
        evidence: Iterable[str],
    ) -> bool:
        escaped_name = re.escape(name)
        return any(
            re.search(
                rf"\b{escaped_name}\s*=\s*(?:stdin|stdout|stderr)\b",
                str(item),
            )
            is not None
            for item in evidence
        )

    @staticmethod
    def _stdio_open_evidence(name: str, evidence: Iterable[str]) -> bool:
        escaped_name = re.escape(name)
        return any(
            re.search(
                rf"(?:\b{escaped_name}|{escaped_name}\s*\[[^]]+\])\s*=\s*"
                rf"(?:fopen|fdopen|freopen|popen)\s*\(",
                str(item),
            )
            is not None
            for item in evidence
        )

    @staticmethod
    def _type_alias_pointer_mutability(c_type: str) -> Mutability:
        text = re.sub(r"\s+", " ", c_type.replace("*", " * ")).strip()
        if re.search(r"\bconst\b", text) and "*" in text:
            return Mutability.CONST
        return Mutability.MUTABLE

    def analyze_all(
        self, targets: Iterable[PointerTarget]
    ) -> tuple[PointerAnalysisResult, ...]:
        targets = tuple(targets)
        results: list[PointerAnalysisResult] = []
        total = len(targets)
        for index, target in enumerate(targets, start=1):
            self._emit_progress(
                "pointer",
                index,
                total,
                (
                    f"stmt={target.stmt_id} name={target.name} "
                    f"location={target.location.value}"
                ),
            )
            results.append(self.analyze(target))
        string_results = self._propagate_c_string_semantics(tuple(results))
        return ResourceFlowAnalyzer(self.context).analyze(string_results)

    def _infer_c_string_semantics(
        self,
        target: PointerTarget,
        usage_path: Iterable[str],
    ) -> CStringSemantics | None:
        if not self._is_c_char_pointer_type(target.c_type):
            return None
        shape_events = self._collect_pointee_shape_events(target)
        if shape_events.has(_SHAPE_STRING_ACCESS):
            return CStringSemantics()
        evidence = [self._stmt_source_text(target.stmt_id), *usage_path]
        if any(self._source_has_c_string_evidence(item) for item in evidence):
            return CStringSemantics()
        return None

    def _propagate_c_string_semantics(
        self,
        results: tuple[PointerAnalysisResult, ...],
    ) -> tuple[PointerAnalysisResult, ...]:


        results_by_stmt = {
            result.target.stmt_id: result
            for result in results
        }
        mutable_results_by_method: dict[int, list[PointerAnalysisResult]] = {}
        for result in results:
            if result.target.method_id is not None:
                mutable_results_by_method.setdefault(
                    result.target.method_id,
                    [],
                ).append(result)
        results_by_method = {
            method_id: tuple(method_results)
            for method_id, method_results in mutable_results_by_method.items()
        }
        parameter_stmts: dict[tuple[int, int], int] = {}
        for method_id in self.context.get_all_method_ids():
            for index, parameter in enumerate(
                self._parameters_in_source_order(method_id)
            ):
                stmt_id = self._positive_id(getattr(parameter, "stmt_id", None))
                if stmt_id is not None and stmt_id in results_by_stmt:
                    parameter_stmts[(method_id, index)] = stmt_id

        confirmed = {
            stmt_id
            for stmt_id, result in results_by_stmt.items()
            if result.semantics.string_semantics is not None
        }
        confirmed_field_names = {
            result.target.name
            for stmt_id, result in results_by_stmt.items()
            if stmt_id in confirmed and result.target.is_aggregate_member
        }
        propagation_edges: dict[int, set[int]] = {}
        for caller_method_id in self.context.get_all_method_ids():
            for row in self.context.get_method_rows(caller_method_id):
                if self._text(getattr(row, "operation", "")) != "call_stmt":
                    continue
                call_stmt_id = self._positive_id(getattr(row, "stmt_id", None))
                if call_stmt_id is None:
                    continue
                callee_name = self._call_name(call_stmt_id, row)
                callee_ids = self._callee_method_ids_by_name(
                    caller_method_id,
                    callee_name,
                )
                if not callee_ids:
                    continue
                for index, argument in enumerate(self._call_arguments(row)):
                    caller_stmt_ids = self._pointer_stmts_for_call_argument(
                        results_by_method.get(caller_method_id, ()),
                        caller_method_id=caller_method_id,
                        call_stmt_id=call_stmt_id,
                        argument=argument,
                    )
                    callee_stmt_ids = {
                        parameter_stmts[(callee_id, index)]
                        for callee_id in callee_ids
                        if (callee_id, index) in parameter_stmts
                    }
                    for caller_stmt_id in caller_stmt_ids:
                        propagation_edges.setdefault(caller_stmt_id, set()).update(
                            callee_stmt_ids
                        )
                    for callee_stmt_id in callee_stmt_ids:
                        propagation_edges.setdefault(callee_stmt_id, set()).update(
                            caller_stmt_ids
                        )
                    if self._is_string_literal(argument) or any(
                        self._source_mentions_field_access(argument, field_name)
                        for field_name in confirmed_field_names
                    ):
                        confirmed.update(callee_stmt_ids)

        pending = list(confirmed)
        while pending:
            stmt_id = pending.pop()
            for adjacent_stmt_id in propagation_edges.get(stmt_id, ()):
                if adjacent_stmt_id not in confirmed:
                    confirmed.add(adjacent_stmt_id)
                    pending.append(adjacent_stmt_id)

        propagated: list[PointerAnalysisResult] = []
        for result in results:
            if result.target.stmt_id in confirmed:
                propagated.append(
                    dataclasses.replace(
                        result,
                        semantics=dataclasses.replace(
                            result.semantics,
                            pointee_shape=PointeeShape.ARRAY,
                            string_semantics=(
                                result.semantics.string_semantics
                                or CStringSemantics()
                            ),
                        ),
                    )
                )
            else:
                propagated.append(result)
        return tuple(propagated)

    def _pointer_stmts_for_call_argument(
        self,
        caller_results: tuple[PointerAnalysisResult, ...],
        *,
        caller_method_id: int,
        call_stmt_id: int,
        argument: str,
    ) -> set[int]:
        matches: set[int] = set()
        for result in caller_results:
            target = result.target
            if self._mentions_alias(argument, {target.name}) or (
                self._is_temp_name(argument)
                and self._temp_traces_to_pointer(
                    caller_method_id,
                    call_stmt_id,
                    argument,
                    {target.name},
                )
            ):
                matches.add(target.stmt_id)
        return matches

    @staticmethod
    def _source_has_c_string_evidence(source: str) -> bool:
        text = str(source or "")
        if not text:
            return False
        if re.search(r"(?:u8|[uUL])?'(?:\\0{1,3}|\\x0+)'", text):
            return True
        return bool(
            re.search(
                r"\b(?:strlen|strcmp|strncmp|strcpy|strncpy|strcat|strncat|"
                r"strchr|strrchr|strstr|strdup|strndup|strtok|strtok_r)\s*\(",
                text,
            )
        )

    @staticmethod
    def _is_c_char_pointer_type(c_type: str) -> bool:
        text = re.sub(r"\b(?:const|volatile|restrict|__restrict)\b", " ", str(c_type))
        text = re.sub(r"\s+", " ", text).strip().lower()
        return "*" in text and bool(
            re.search(r"\b(?:char|signed char|unsigned char)\b", text)
        )

    def _emit_progress(
        self,
        kind: str,
        index: int,
        total: int,
        detail: str,
    ) -> None:
        if self._progress is not None:
            self._progress(f"analyzing {kind} {index}/{total}: {detail}")

    def _validate_target(self, target: PointerTarget) -> None:
        row = self.context.get_stmt(target.stmt_id)
        if row is None:
            raise PointerAnalysisError(
                f"pointer target statement does not exist: {target.stmt_id}"
            )
        operation = self._text(getattr(row, "operation", ""))
        if operation != target.operation.value:
            raise PointerAnalysisError(
                f"pointer target {target.stmt_id} operation mismatch: "
                f"target={target.operation.value}, GIR={operation!r}"
            )
        name = self._text(getattr(row, "name", ""))
        if name != target.name:
            raise PointerAnalysisError(
                f"pointer target {target.stmt_id} name mismatch: "
                f"target={target.name!r}, GIR={name!r}"
            )

    def _collect_usage_path(
        self,
        target: PointerTarget,
        *,
        limit: int = 20,
    ) -> list[str]:
        usage_path: list[str] = []
        for method_id in self._pointer_analysis_method_ids(target):
            for related in self._collect_pointer_related_stmts(
                target, method_id
            ):
                self._append_usage_path(usage_path, related.stmt_id)
                if len(usage_path) >= limit:
                    return usage_path
        return usage_path

    def _project_parameter_access(
        self, callee_name: str, argument_index: int
    ) -> tuple[bool, bool]:
        if not callee_name or argument_index < 0:
            return False, False
        method_ids = self._method_ids_for_name(callee_name)
        read = False
        write = False
        for method_id in method_ids:
            parameters = self.context.get_method_parameters(method_id)
            if argument_index >= len(parameters):
                continue
            parameter_id = self._positive_id(
                getattr(parameters[argument_index], "stmt_id", None)
            )
            if parameter_id is None:
                continue
            cache_key = (method_id, parameter_id)
            if cache_key not in self._parameter_access_cache:
                self._parameter_access_cache[cache_key] = (
                    self._scan_parameter_access(method_id, parameter_id)
                )
            parameter_read, parameter_write = self._parameter_access_cache[
                cache_key
            ]
            read |= parameter_read
            write |= parameter_write
        return read, write

    def _project_parameter_shape(
        self, callee_name: str, argument_index: int, *, max_depth: int
    ) -> tuple[bool, bool, bool, bool, bool]:
        if not callee_name or argument_index < 0 or max_depth <= 0:
            return False, False, False, False, False
        method_ids = self._method_ids_for_name(callee_name)
        array_access = False
        single_access = False
        pointer_arithmetic = False
        string_usage = False
        byte_buffer_usage = False
        cache = getattr(self, "_parameter_shape_cache", None)
        if cache is None:
            cache = {}
            self._parameter_shape_cache = cache
        for method_id in method_ids:
            parameters = self.context.get_method_parameters(method_id)
            if argument_index >= len(parameters):
                continue
            parameter = parameters[argument_index]
            parameter_id = self._positive_id(getattr(parameter, "stmt_id", None))
            parameter_name = self._field(parameter, "name")
            if parameter_id is None or not parameter_name:
                continue
            cache_key = (method_id, parameter_id, max_depth)
            if cache_key not in cache:
                cache[cache_key] = self._scan_parameter_shape(
                    method_id,
                    parameter_id,
                    parameter_name,
                    max_depth=max_depth - 1,
                )
            projected = cache[cache_key]
            array_access |= projected[0]
            single_access |= projected[1]
            pointer_arithmetic |= projected[2]
            string_usage |= projected[3]
            byte_buffer_usage |= projected[4]
        return (
            array_access,
            single_access,
            pointer_arithmetic,
            string_usage,
            byte_buffer_usage,
        )

    def _scan_parameter_shape(
        self,
        method_id: int,
        parameter_id: int,
        parameter_name: str,
        *,
        max_depth: int,
    ) -> tuple[bool, bool, bool, bool, bool]:
        target = PointerTarget(
            stmt_id=parameter_id,
            entity_id=parameter_id,
            unit_id=self.context.get_unit_id(parameter_id) or -1,
            method_id=method_id,
            name=parameter_name,
            c_type="",
            operation=PointerDeclarationOperation.PARAMETER_DECL,
            location=PointerLocation.PARAMETER,
        )
        array_access = False
        single_access = False
        pointer_arithmetic = False
        string_usage = False
        byte_buffer_usage = False
        for related in self._collect_pointer_related_stmts(target, method_id):
            access = self._classify_pointer_stmt_access(
                related, shape_depth=max_depth, target_name=target.name
            )
            array_access |= access.array_access
            single_access |= access.single_access_observed
            pointer_arithmetic |= access.pointer_arithmetic
            string_usage |= access.string_usage
            byte_buffer_usage |= access.byte_buffer_usage
        return (
            array_access,
            single_access,
            pointer_arithmetic,
            string_usage,
            byte_buffer_usage,
        )

    def _scan_parameter_access(
        self, method_id: int, parameter_id: int
    ) -> tuple[bool, bool]:
        row = self.context.get_stmt(parameter_id)
        if row is None:
            return False, False
        parameter_name = self._field(row, "name")


        symbol_ids = self.context.resolve_decl_symbol_ids(
            method_id, parameter_id, parameter_name
        )
        if symbol_ids:
            param_symbol_id = symbol_ids[0]
            def_sites = self.context.get_defined_stmt_ids_for_symbol(
                method_id, param_symbol_id
            )
            use_sites = self.context.get_used_stmt_ids_for_symbol(
                method_id, param_symbol_id
            )

            write = any(
                sid != parameter_id for sid in def_sites
            )
            read = any(
                sid != parameter_id for sid in use_sites
            )
            if read or write or not (def_sites or use_sites):


                return read, write


        aliases = {parameter_name}
        read = False
        write = False
        for stmt in self.context.get_method_rows(method_id):
            operation = self._text(getattr(stmt, "operation", ""))
            if operation in {"assign_stmt", "binary_expression"}:
                operand = self._field(stmt, "operand", "source")
                target = self._field(stmt, "target")
                if self._mentions_alias(operand, aliases) and target:
                    aliases.add(target)
            elif operation == "array_read" and self._mentions_alias(
                self._field(stmt, "array"), aliases
            ):
                read = True
            elif operation == "array_write" and self._mentions_alias(
                self._field(stmt, "array"), aliases
            ):
                write = True
            elif operation == "mem_read" and self._mentions_alias(
                self._field(stmt, "address", "operand"), aliases
            ):
                read = True
            elif operation == "mem_write" and self._mentions_alias(
                self._field(stmt, "address", "target"), aliases
            ):
                write = True
            elif operation == "field_read" and self._mentions_alias(
                self._field(stmt, "receiver_object", "object"), aliases
            ):
                read = True
            elif operation == "field_write" and self._mentions_alias(
                self._field(stmt, "receiver_object", "object"), aliases
            ):
                write = True
        return read, write

    def _infer_nullability(
        self, target: PointerTarget
    ) -> Nullability | None:
        events = self._collect_pointer_nullability_events(target)
        if events.null_related:
            return Nullability.NULLABLE
        if events.unknown:
            return Nullability.NULLABLE
        if events.nonnull_evidence:
            return Nullability.NONNULL
        return None

    def _collect_pointer_nullability_events(
        self, target: PointerTarget
    ) -> _PointerNullabilityEvents:
        cache_key = (target.stmt_id, target.name, target.location)
        cached = self._nullability_events_cache.get(cache_key)
        if cached is not None:
            return cached

        kinds: set[str] = set()
        for method_id in self._pointer_analysis_method_ids(target):
            for related in self._collect_pointer_related_stmts(
                target, method_id
            ):
                kinds.update(
                    self._nullability_events_from_related(target, related)
                )

        result = _PointerNullabilityEvents(frozenset(kinds))
        self._nullability_events_cache[cache_key] = result
        return result

    def _nullability_events_from_related(
        self, target: PointerTarget, related: _PointerRelatedStmt
    ) -> set[str]:
        kinds: set[str] = set()
        if self._stmt_has_nullable_signal(
            related.method_id, related.stmt_id, related.symbol_ids
        ):
            kinds.add(_NULLABILITY_NULL_RELATED)
        if self._stmt_has_nonnull_signal(
            related.method_id, related.stmt_id, related.symbol_ids
        ):
            kinds.add(_NULLABILITY_NONNULL_EVIDENCE)
        if target.is_aggregate_member:
            kinds.update(
                self._aggregate_member_nullability_events_from_related(
                    target, related
                )
            )
        kinds.update(self._call_return_nullability_events_from_related(related))
        return kinds

    def _pointer_analysis_method_ids(
        self, target: PointerTarget
    ) -> tuple[int, ...]:
        cached = self._analysis_method_ids_cache.get(target.stmt_id)
        if cached is not None:
            return cached
        if target.method_id is not None:
            result = (target.method_id,)
            self._analysis_method_ids_cache[target.stmt_id] = result
            return result
        candidates: list[int] = []
        if target.is_aggregate_member:
            candidates = list(self._methods_touching_field(target.name))
            result = tuple(candidates) or tuple(self.context.get_all_method_ids())
            self._analysis_method_ids_cache[target.stmt_id] = result
            return result

        for method_id in self.context.get_all_method_ids():
            symbol_ids = self._target_symbol_ids_for_method(target, method_id)
            if not symbol_ids:
                continue
            summary = self.context.get_method_def_use_summary(method_id)
            if summary is None or set(symbol_ids) & self._summary_symbol_ids(summary):
                candidates.append(method_id)
        result = tuple(candidates) or tuple(self.context.get_all_method_ids())
        self._analysis_method_ids_cache[target.stmt_id] = result
        return result

    def _method_ids_for_name(self, method_name: str) -> tuple[int, ...]:
        if not method_name:
            return ()
        if self._method_ids_by_name is None:
            ids_by_name: dict[str, list[int]] = {}
            for method_id in self.context.get_all_method_ids():
                name = self.context.get_method_name(method_id)
                if name:
                    ids_by_name.setdefault(name, []).append(method_id)
            self._method_ids_by_name = {
                name: tuple(ids) for name, ids in ids_by_name.items()
            }
        return self._method_ids_by_name.get(method_name, ())

    def _collect_pointer_related_stmts(
        self, target: PointerTarget, method_id: int
    ) -> tuple[_PointerRelatedStmt, ...]:
        cache_key = (target.stmt_id, method_id)
        cached = self._related_stmts_cache.get(cache_key)
        if cached is not None:
            return cached

        if target.is_aggregate_member:
            field_related = self._collect_field_related_stmts(target, method_id)
            propagated = self._propagate_field_temps(
                field_related, method_id
            )
            merge_map: dict[int, frozenset[int]] = {}
            for rs in field_related:
                merge_map[rs.stmt_id] = rs.symbol_ids
            for rs in propagated:
                if rs.stmt_id not in merge_map:
                    merge_map[rs.stmt_id] = rs.symbol_ids
            result = tuple(
                _PointerRelatedStmt(
                    method_id=method_id,
                    stmt_id=stmt_id,
                    symbol_ids=merge_map[stmt_id],
                )
                for stmt_id in sorted(merge_map)
            )
            self._related_stmts_cache[cache_key] = result
            return result

        symbol_ids = set(self._target_symbol_ids_for_method(target, method_id))
        if not symbol_ids:
            self._related_stmts_cache[cache_key] = ()
            return ()
        target_symbol_ids = frozenset(symbol_ids)

        related = self._collect_pointer_related_stmts_by_index(
            method_id=method_id,
            symbol_ids=symbol_ids,
            target_symbol_ids=target_symbol_ids,
            include_stmt_id=(
                target.stmt_id if target.method_id == method_id else None
            ),
        )
        if related:
            self._related_stmts_cache[cache_key] = related
            return related
        result = self._collect_pointer_related_stmts_by_status_scan(
            method_id=method_id,
            symbol_ids=symbol_ids,
            target_symbol_ids=target_symbol_ids,
        )
        self._related_stmts_cache[cache_key] = result
        return result

    def _target_symbol_ids_for_method(
        self, target: PointerTarget, method_id: int
    ) -> tuple[int, ...]:
        symbol_ids = self.context.resolve_decl_symbol_ids(
            method_id,
            target.stmt_id,
            target.name,
        )
        if symbol_ids:
            return symbol_ids
        return tuple(
            symbol_id
            for symbol in self.context.find_symbols_by_name(
                method_id, target.name
            )
            if (symbol_id := self._lian_id(getattr(symbol, "symbol_id", None)))
            is not None
        )

    def _collect_pointer_related_stmts_by_index(
        self,
        *,
        method_id: int,
        symbol_ids: set[int],
        target_symbol_ids: frozenset[int],
        include_stmt_id: int | None = None,
    ) -> tuple[_PointerRelatedStmt, ...]:
        related: dict[int, frozenset[int]] = {}
        alias_def_site: dict[int, int] = {}
        worklist = list(symbol_ids)
        visited: set[int] = set()
        while worklist:
            symbol_id = worklist.pop()
            if symbol_id in visited:
                continue
            visited.add(symbol_id)
            candidate_stmt_ids = set(
                self.context.get_defined_stmt_ids_for_symbol(
                    method_id, symbol_id
                )
            )
            candidate_stmt_ids.update(
                self.context.get_used_stmt_ids_for_symbol(method_id, symbol_id)
            )
            if include_stmt_id is not None and symbol_id in target_symbol_ids:
                candidate_stmt_ids.add(include_stmt_id)

            for stmt_id in sorted(candidate_stmt_ids):
                direct_used = set(
                    self.context.get_stmt_direct_used_symbol_ids(stmt_id)
                )
                direct_defined = set(
                    self.context.get_stmt_direct_defined_symbol_ids(stmt_id)
                )
                implicit_used = set(
                    self.context.get_stmt_implicit_used_symbol_ids(stmt_id)
                )
                implicit_defined = set(
                    self.context.get_stmt_implicit_defined_symbol_ids(stmt_id)
                )
                touched = symbol_ids & (
                    direct_used
                    | direct_defined
                    | implicit_used
                    | implicit_defined
                )
                if not touched:
                    continue


                aliases_touched = touched - target_symbol_ids
                if aliases_touched and not (touched & target_symbol_ids):
                    if not self._alias_reaches_stmt(
                        method_id, stmt_id, aliases_touched, alias_def_site
                    ):
                        continue

                related[stmt_id] = frozenset(
                    set(related.get(stmt_id, frozenset())) | touched
                )

                propagated = set()
                if symbol_ids & direct_used:
                    propagated |= direct_defined
                if symbol_ids & direct_defined:
                    propagated |= direct_used
                propagated = {
                    item
                    for item in propagated
                    if self.context.find_symbol_by_id(method_id, item)
                    is not None
                }
                for item in sorted(propagated - symbol_ids):
                    symbol_ids.add(item)
                    alias_def_site[item] = stmt_id
                    worklist.append(item)

        return tuple(
            _PointerRelatedStmt(
                method_id=method_id,
                stmt_id=stmt_id,
                symbol_ids=related[stmt_id],
                target_symbol_ids=target_symbol_ids,
            )
            for stmt_id in sorted(related)
        )

    def _alias_reaches_stmt(
        self,
        method_id: int,
        use_stmt_id: int,
        alias_symbol_ids: set[int],
        alias_def_site: dict[int, int],
    ) -> bool:

        status = self.context.get_preferred_stmt_status(use_stmt_id)
        in_bits = getattr(status, "in_symbol_bits", None)
        if not in_bits:
            return True
        for alias_sym_id in alias_symbol_ids:
            def_stmt = alias_def_site.get(alias_sym_id)
            if def_stmt is None:
                continue
            for bit in in_bits:
                if (
                    getattr(bit, "symbol_id", None) == alias_sym_id
                    and getattr(bit, "stmt_id", None) == def_stmt
                ):
                    return True
        return False

    def _collect_pointer_related_stmts_by_status_scan(
        self,
        *,
        method_id: int,
        symbol_ids: set[int],
        target_symbol_ids: frozenset[int],
    ) -> tuple[_PointerRelatedStmt, ...]:
        related: dict[int, frozenset[int]] = {}
        changed = True
        while changed:
            changed = False
            for stmt_id in self._status_stmt_ids(method_id):
                direct_used = set(
                    self.context.get_stmt_direct_used_symbol_ids(stmt_id)
                )
                direct_defined = set(
                    self.context.get_stmt_direct_defined_symbol_ids(stmt_id)
                )
                implicit_used = set(
                    self.context.get_stmt_implicit_used_symbol_ids(stmt_id)
                )
                implicit_defined = set(
                    self.context.get_stmt_implicit_defined_symbol_ids(stmt_id)
                )
                touched = symbol_ids & (
                    direct_used
                    | direct_defined
                    | implicit_used
                    | implicit_defined
                )
                if not touched:
                    continue
                related[stmt_id] = frozenset(touched)

                propagated = set()
                if symbol_ids & direct_used:
                    propagated |= direct_defined
                if symbol_ids & direct_defined:
                    propagated |= direct_used
                propagated = {
                    item
                    for item in propagated
                    if self.context.find_symbol_by_id(method_id, item)
                    is not None
                }
                before = len(symbol_ids)
                symbol_ids.update(propagated)
                changed |= len(symbol_ids) != before

        return tuple(
            _PointerRelatedStmt(
                method_id=method_id,
                stmt_id=stmt_id,
                symbol_ids=related[stmt_id],
                target_symbol_ids=target_symbol_ids,
            )
            for stmt_id in sorted(related)
        )

    def _collect_field_related_stmts(
        self, target: PointerTarget, method_id: int
    ) -> tuple[_PointerRelatedStmt, ...]:
        related: list[_PointerRelatedStmt] = []
        for stmt_id in self._status_stmt_ids(method_id):
            if not self._stmt_touches_target_field(
                method_id, stmt_id, target
            ):
                continue
            symbol_ids = frozenset(
                self.context.get_stmt_direct_used_symbol_ids(stmt_id)
                + self.context.get_stmt_direct_defined_symbol_ids(stmt_id)
                + self.context.get_stmt_implicit_used_symbol_ids(stmt_id)
                + self.context.get_stmt_implicit_defined_symbol_ids(stmt_id)
            )
            related.append(
                _PointerRelatedStmt(
                    method_id=method_id,
                    stmt_id=stmt_id,
                    symbol_ids=symbol_ids,
                )
            )
        return tuple(related)

    def _propagate_field_temps(
        self,
        field_related: tuple[_PointerRelatedStmt, ...],
        method_id: int,
    ) -> tuple[_PointerRelatedStmt, ...]:

        phase1_ids = {rs.stmt_id for rs in field_related}


        temp_names: set[str] = set()
        for rs in field_related:
            for sym_id in self.context.get_stmt_direct_defined_symbol_ids(
                rs.stmt_id
            ):
                name = self.context.get_symbol_name(method_id, sym_id)
                if name and name.startswith("%vv"):
                    temp_names.add(name)

        if not temp_names:
            return ()




        _TEMP_SCAN_FIELDS = (
            "positional_args",
            "operand",
            "source",
            "value",
            "array",
            "address",
            "target",
            "receiver_object",
            "object",
            "name",
        )
        result: list[_PointerRelatedStmt] = []
        for stmt in self.context.get_method_rows(method_id):
            stmt_id = self._positive_id(getattr(stmt, "stmt_id", None))
            if stmt_id is None or stmt_id in phase1_ids:
                continue
            field_values: list[str] = []
            for field_name in _TEMP_SCAN_FIELDS:
                raw = getattr(stmt, field_name, None)
                if raw is not None:
                    field_values.append(str(raw))
            row_text = " ".join(field_values)
            matching = {t for t in temp_names if t in row_text}
            if not matching:
                continue
            symbol_ids = frozenset(
                self.context.get_stmt_direct_used_symbol_ids(stmt_id)
                + self.context.get_stmt_direct_defined_symbol_ids(stmt_id)
                + self.context.get_stmt_implicit_used_symbol_ids(stmt_id)
                + self.context.get_stmt_implicit_defined_symbol_ids(stmt_id)
            )
            self._field_temp_names_cache[
                (method_id, stmt_id)
            ] = frozenset(matching)
            result.append(
                _PointerRelatedStmt(
                    method_id=method_id,
                    stmt_id=stmt_id,
                    symbol_ids=symbol_ids,
                )
            )

        return tuple(result)

    def _stmt_has_nullable_signal(
        self,
        method_id: int,
        stmt_id: int,
        symbol_ids: frozenset[int],
    ) -> bool:
        row = self.context.get_stmt(stmt_id)
        operation = self._text(getattr(row, "operation", ""))
        names = self._symbol_names(method_id, symbol_ids)

        if operation in {"binary_expression", "assign_stmt"} and (
            self._null_relation_in_row(row, names)
        ):
            return True
        if operation == "call_stmt" and self._call_defines_target_allocator(
            row, stmt_id, symbol_ids
        ):
            return True
        return self._states_have_null_origin(method_id, stmt_id, symbol_ids)

    def _stmt_has_nonnull_signal(
        self,
        method_id: int,
        stmt_id: int,
        symbol_ids: frozenset[int],
    ) -> bool:
        row = self.context.get_stmt(stmt_id)
        names = self._symbol_names(method_id, symbol_ids)
        access = self._classify_pointer_stmt_access(
            _PointerRelatedStmt(method_id, stmt_id, symbol_ids), names
        )

        if access.pointee_read or access.pointee_written:
            return True
        operation = self._text(getattr(row, "operation", ""))
        if operation == "addr_of" and self._row_defines_symbol(row, names):
            return True
        if self._row_defines_symbol(row, names) and self._field(
            row, "operand", "source", "value"
        ).startswith("&"):
            return True
        if self._row_defines_symbol(row, names) and self._is_string_literal(
            self._field(row, "operand", "source", "value")
            ):
                return True
        return self._states_have_nonnull_origin(method_id, stmt_id, symbol_ids)

    def _call_return_nullability_events_from_related(
        self, related: _PointerRelatedStmt
    ) -> set[str]:
        row = self.context.get_stmt(related.stmt_id)
        operation = self._text(getattr(row, "operation", ""))
        if operation == "call_stmt":
            defined = set(
                self.context.get_stmt_direct_defined_symbol_ids(related.stmt_id)
            )
            if not (defined & related.symbol_ids):
                return set()
            callee = self._call_name(related.stmt_id, row)
            return self._call_return_nullability_events_by_name(
                related.method_id, callee, max_depth=5
            )

        if operation not in {"assign_stmt", "variable_decl"}:
            return set()
        direct_defined = set(
            self.context.get_stmt_direct_defined_symbol_ids(related.stmt_id)
        )
        if related.target_symbol_ids and not (
            direct_defined & related.target_symbol_ids
        ):
            return set()
        rhs = self._source_assignment_rhs(self._stmt_source_text(related.stmt_id))
        if not rhs:
            return set()
        return self._call_expression_nullability_events(
            related.method_id, rhs, max_depth=5
        )

    def _call_expression_nullability_events(
        self, method_id: int, expression: str, *, max_depth: int
    ) -> set[str]:
        calls = self._source_call_names(expression)
        if not calls:
            return set()
        kinds: set[str] = set()
        for callee in calls:
            kinds.update(
                self._call_return_nullability_events_by_name(
                    method_id, callee, max_depth=max_depth
                )
            )
        return kinds

    def _call_return_nullability_events_by_name(
        self, method_id: int, callee_name: str, *, max_depth: int
    ) -> set[str]:
        if not callee_name:
            return {_NULLABILITY_UNKNOWN}
        if callee_name in _ALLOCATORS:
            return {_NULLABILITY_NULL_RELATED}
        if max_depth <= 0:
            return {_NULLABILITY_UNKNOWN}
        callee_ids = self._callee_method_ids_by_name(method_id, callee_name)
        if not callee_ids:
            return {_NULLABILITY_UNKNOWN}

        kinds: set[str] = set()
        for callee_id in callee_ids:
            kinds.update(
                self._method_return_nullability_events(
                    callee_id, max_depth=max_depth - 1
                )
            )
        return kinds or {_NULLABILITY_UNKNOWN}

    def _method_return_nullability_events(
        self, method_id: int, *, max_depth: int
    ) -> set[str]:
        if max_depth <= 0:
            return {_NULLABILITY_UNKNOWN}
        kinds: set[str] = set()
        current_name = self.context.get_method_name(method_id) or ""
        for row in self.context.get_method_rows(method_id):
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if stmt_id is None:
                continue
            if self._text(getattr(row, "operation", "")) != "return_stmt":
                continue
            returned = self._source_return_expression(
                self._stmt_source_text(stmt_id)
            ) or self._field(row, "name", "value", "operand")
            if not returned:
                kinds.add(_NULLABILITY_UNKNOWN)
            elif self._is_null(returned):
                kinds.add(_NULLABILITY_NULL_RELATED)
            elif self._is_string_literal(returned) or returned.startswith("&"):
                kinds.add(_NULLABILITY_NONNULL_EVIDENCE)
            elif self._source_call_names(returned):
                for callee in self._source_call_names(returned):
                    if callee == current_name:
                        continue
                    kinds.update(
                        self._call_return_nullability_events_by_name(
                            method_id,
                            callee,
                            max_depth=max_depth - 1,
                        )
                    )
            else:
                kinds.update(
                    self._return_symbol_nullability_events(
                        method_id, stmt_id, returned
                    )
                )
        return kinds or {_NULLABILITY_UNKNOWN}

    def _return_symbol_nullability_events(
        self, method_id: int, stmt_id: int, symbol_name: str
    ) -> set[str]:
        if self._is_null(symbol_name):
            return {_NULLABILITY_NULL_RELATED}
        if self._is_string_literal(symbol_name) or symbol_name.startswith("&"):
            return {_NULLABILITY_NONNULL_EVIDENCE}
        symbol = self.context.find_symbol_by_name(method_id, symbol_name)
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        if symbol_id is None:
            return {_NULLABILITY_UNKNOWN}
        if self._states_have_null_origin(method_id, stmt_id, frozenset({symbol_id})):
            return {_NULLABILITY_NULL_RELATED}
        if self._states_have_nonnull_origin(method_id, stmt_id, frozenset({symbol_id})):
            return {_NULLABILITY_NONNULL_EVIDENCE}
        storage = self.context.symbol_storage_kind(method_id, symbol_id)
        if storage in {"param", "global", "field"} or self._is_method_parameter_name(
            method_id, symbol_name
        ):
            return {_NULLABILITY_UNKNOWN}
        return {_NULLABILITY_UNKNOWN}

    def _classify_pointer_stmt_access(
        self,
        related: _PointerRelatedStmt,
        names: set[str] | None = None,
        *,
        shape_depth: int = 2,
        is_struct_member: bool = False,
        target_name: str = "",
    ) -> _PointerStmtAccess:
        extra_field_temp_names = self._field_temp_names_cache.get(
            (related.method_id, related.stmt_id), frozenset()
        )
        cache_key = (
            related.method_id,
            related.stmt_id,
            tuple(sorted(related.symbol_ids)),
            tuple(sorted(related.target_symbol_ids)),
            shape_depth,
            is_struct_member,
            target_name,
            extra_field_temp_names,
        )
        cached = self._stmt_access_cache.get(cache_key)
        if cached is not None:
            return cached

        row = self.context.get_stmt(related.stmt_id)
        operation = self._text(getattr(row, "operation", ""))
        names = set(names or self._symbol_names(related.method_id, related.symbol_ids))
        if extra_field_temp_names:
            names |= extra_field_temp_names




        _pointee_names = (
            extra_field_temp_names
            if is_struct_member and extra_field_temp_names
            else names
        )
        direct_used = set(
            self.context.get_stmt_direct_used_symbol_ids(related.stmt_id)
        )
        direct_defined = set(
            self.context.get_stmt_direct_defined_symbol_ids(related.stmt_id)
        )
        pointer_read = bool(direct_used & related.symbol_ids)
        pointer_written = bool(direct_defined & related.symbol_ids)

        pointee_read, pointee_written = self._row_pointee_access(
            row,
            operation,
            _pointee_names,
            self_field_name=target_name,
            method_id=related.method_id,
            stmt_id=related.stmt_id,
        )
        call_read, call_write, unknown_call = self._call_pointee_access(
            row,
            related.stmt_id,
            _pointee_names,
            require_field_access_names=frozenset(names) if is_struct_member else frozenset(),
            method_id=related.method_id,
        )
        pointee_read |= call_read
        pointee_written |= call_write

        (
            call_array,
            call_single,
            call_pointer_arithmetic,
            call_string,
            call_byte_buffer,
        ) = self._call_shape_access(
            row, related.stmt_id, _pointee_names, max_depth=shape_depth
        )
        array_access = (
            operation in {"array_read", "array_write"}
            or call_array
            or self._states_have_array_access_path(
                related.method_id, related.stmt_id, related.symbol_ids
            )
        )
        single_access_observed = (
            operation in {"mem_read", "mem_write", "field_read", "field_write"}
            and (pointee_read or pointee_written)
        ) or call_single
        pointer_arithmetic = self._stmt_has_pointer_arithmetic(
            row, operation, names
        ) or call_pointer_arithmetic
        string_usage = call_string
        byte_buffer_usage = call_byte_buffer
        array_access |= pointer_arithmetic or string_usage or byte_buffer_usage

        alias_created = self._stmt_creates_alias(
            related, direct_used, direct_defined
        )
        alias_pointee_written = pointee_written and related.uses_alias
        stored = self._stmt_stores_pointer(
            related.method_id, row, operation, names
        )
        returned = operation == "return_stmt" and self._mentions_alias(
            self._field(row, "name", "value", "operand"), names
        )

        result = _PointerStmtAccess(
            pointer_read=pointer_read,
            pointer_written=pointer_written,
            pointee_read=pointee_read,
            pointee_written=pointee_written,
            alias_created=alias_created,
            alias_pointee_written=alias_pointee_written,
            stored=stored,
            returned=returned,
            passed_to_unknown_callee=unknown_call,
            array_access=array_access,
            single_access_observed=single_access_observed,
            pointer_arithmetic=pointer_arithmetic,
            string_usage=string_usage,
            byte_buffer_usage=byte_buffer_usage,
        )
        self._stmt_access_cache[cache_key] = result
        return result

    def _row_pointee_access(
        self,
        row: Any,
        operation: str,
        names: set[str],
        *,
        self_field_name: str = "",
        method_id: int = 0,
        stmt_id: int = 0,
    ) -> tuple[bool, bool]:
        if operation == "mem_read":
            address = self._field(row, "address", "operand", "source")
            if self._mentions_alias(address, names):
                return True, False
            if (
                method_id
                and stmt_id
                and self._is_temp_name(address)
                and self._temp_traces_to_pointer(method_id, stmt_id, address, names)
            ):
                return True, False
            return False, False
        if operation == "mem_write":
            address = self._field(row, "address", "target", "operand")
            if self._mentions_alias(address, names):
                return False, True
            if (
                method_id
                and stmt_id
                and self._is_temp_name(address)
                and self._temp_traces_to_pointer(method_id, stmt_id, address, names)
            ):
                return False, True
            return False, False
        if operation == "array_read":
            return self._mentions_alias(self._field(row, "array"), names), False
        if operation == "array_write":
            return False, self._mentions_alias(self._field(row, "array"), names)
        if operation == "field_read":
            field_name = self._field(row, "field", "field_name")
            if self_field_name and field_name == self_field_name:
                return False, False
            receiver = self._field(row, "receiver_object", "object")
            if self._mentions_alias(receiver, names):
                return True, False
            if (
                method_id
                and stmt_id
                and self._is_temp_name(receiver)
                and self._temp_traces_to_pointer(method_id, stmt_id, receiver, names)
            ):
                return True, False
            return False, False
        if operation == "field_write":
            field_name = self._field(row, "field", "field_name")
            if self_field_name and field_name == self_field_name:
                return False, False
            receiver = self._field(row, "receiver_object", "object")
            if self._mentions_alias(receiver, names):
                return False, True
            if (
                method_id
                and stmt_id
                and self._is_temp_name(receiver)
                and self._temp_traces_to_pointer(method_id, stmt_id, receiver, names)
            ):
                return False, True
            return False, False
        return False, False

    def _call_pointee_access(
        self,
        row: Any,
        stmt_id: int,
        names: set[str],
        require_field_access_names: frozenset[str] = frozenset(),
        *,
        method_id: int = 0,
    ) -> tuple[bool, bool, bool]:
        operation = self._text(getattr(row, "operation", ""))
        if operation != "call_stmt":
            return False, False, False
        callee = self._call_name(stmt_id, row)
        args = self._call_arguments(row)
        positions = [
            index
            for index, argument in enumerate(args)
            if self._mentions_alias(argument, names)
        ]

        if method_id and not positions:
            for index, argument in enumerate(args):
                if self._is_temp_name(argument) and self._temp_traces_to_pointer(
                    method_id, stmt_id, argument, names
                ):
                    positions.append(index)
        if require_field_access_names and positions:
            positions = [
                pos
                for pos in positions
                if not any(
                    name in require_field_access_names
                    and not name.startswith("%vv")
                    and self._mentions_alias(str(args[pos]), {name})
                    and f"->{name}" not in str(args[pos])
                    and f".{name}" not in str(args[pos])
                    for name in require_field_access_names
                )
            ]
        if not positions:
            return False, False, False
        read = False
        write = False
        for position in positions:
            known_read, known_write = _CALL_ARGUMENT_ACCESS.get(
                callee, {}
            ).get(position, (False, False))
            project_read, project_write = self._project_parameter_access(
                callee, position
            )
            read |= known_read or project_read
            write |= known_write or project_write
        unknown = (
            callee not in _ALLOCATORS
            and callee not in _DEALLOCATORS
            and callee not in _CALL_ARGUMENT_ACCESS
            and not (read or write)
        )
        return read, write, unknown

    def _call_shape_access(
        self,
        row: Any,
        stmt_id: int,
        names: set[str],
        *,
        max_depth: int,
    ) -> tuple[bool, bool, bool, bool, bool]:
        operation = self._text(getattr(row, "operation", ""))
        if operation != "call_stmt":
            return False, False, False, False, False
        callee = self._call_name(stmt_id, row)
        args = self._call_arguments(row)
        positions = [
            index
            for index, argument in enumerate(args)
            if self._mentions_alias(argument, names)
        ]
        if not positions:
            return False, False, False, False, False

        string_usage = callee in _STRING_FUNCTIONS
        byte_buffer_usage = callee in _MEMORY_FUNCTIONS
        array_access = string_usage or byte_buffer_usage
        single_access = False
        pointer_arithmetic = False

        if max_depth > 0:
            for position in positions:
                projected = self._project_parameter_shape(
                    callee, position, max_depth=max_depth
                )
                array_access |= projected[0]
                single_access |= projected[1]
                pointer_arithmetic |= projected[2]
                string_usage |= projected[3]
                byte_buffer_usage |= projected[4]
        return (
            array_access,
            single_access,
            pointer_arithmetic,
            string_usage,
            byte_buffer_usage,
        )

    def _stmt_has_pointer_arithmetic(
        self, row: Any, operation: str, names: set[str]
    ) -> bool:
        operator = self._field(row, "operator")
        if operator not in _POINTER_ARITHMETIC_OPERATORS | {"++", "--"}:
            return False
        if operation not in {
            "assign_stmt",
            "binary_expression",
            "unary_expression",
        }:
            return False
        return any(
            self._mentions_alias(value, names)
            for value in (
                self._field(row, "target", "name"),
                self._field(row, "operand", "source", "value"),
                self._field(row, "operand2"),
            )
        )

    def _stmt_creates_alias(
        self,
        related: _PointerRelatedStmt,
        direct_used: set[int],
        direct_defined: set[int],
    ) -> bool:
        if related.symbol_ids & direct_used and direct_defined - related.symbol_ids:
            candidate_ids = direct_defined - related.symbol_ids
            if any(
                self._symbol_is_pointer_like(related.method_id, sid)
                for sid in candidate_ids
            ):
                return True
        if related.symbol_ids & direct_defined and direct_used - related.symbol_ids:
            candidate_ids = direct_used - related.symbol_ids
            if any(
                self._symbol_is_pointer_like(related.method_id, sid)
                for sid in candidate_ids
            ):
                return True
        return False

    def _symbol_is_pointer_like(self, method_id: int, symbol_id: int) -> bool:

        symbol = self.context.find_symbol_by_id(method_id, symbol_id)
        if symbol is None:
            return False
        data_type = self._text(getattr(symbol, "default_data_type", ""))
        return "*" in data_type or "[" in data_type

    def _stmt_stores_pointer(
        self, method_id: int, row: Any, operation: str, names: set[str]
    ) -> bool:
        if operation == "field_write":
            return self._mentions_alias(
                self._field(row, "source", "value", "operand"), names
            )
        if operation == "array_write":
            return self._mentions_alias(
                self._field(row, "source", "value", "operand"), names
            )
        if operation == "assign_stmt":
            source = self._field(row, "operand", "source", "value")
            if not self._mentions_alias(source, names):
                return False
            target_name = self._field(row, "target", "name")
            if "." in target_name or "->" in target_name:
                return True
            symbol = self.context.find_symbol_by_name(method_id, target_name)
            symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
            if symbol_id is None:
                return False
            return self.context.symbol_storage_kind(method_id, symbol_id) in {
                "global",
                "field",
            }
        return False

    def _states_have_null_origin(
        self, method_id: int, stmt_id: int, symbol_ids: frozenset[int]
    ) -> bool:
        return any(
            self._origin_is_null(method_id, state)
            for state in self._target_states(method_id, stmt_id, symbol_ids)
        )

    def _states_have_nonnull_origin(
        self, method_id: int, stmt_id: int, symbol_ids: frozenset[int]
    ) -> bool:
        return any(
            self._origin_is_nonnull(method_id, state)
            for state in self._target_states(method_id, stmt_id, symbol_ids)
        )

    def _states_have_array_access_path(
        self, method_id: int, stmt_id: int, symbol_ids: frozenset[int]
    ) -> bool:
        for state in self._target_states(method_id, stmt_id, symbol_ids):
            if self._state_has_array_access_path(method_id, state):
                return True
        return False

    def _state_has_array_access_path(self, method_id: int, state: Any) -> bool:
        value = self._text(getattr(state, "value", ""))
        if self._path_has_index(value):
            return True
        state_id = self._positive_id(getattr(state, "state_id", None))
        if state_id is None:
            return False
        origin = self.context.trace_state_origin(method_id, state_id)
        if origin is None:
            return False
        for step in origin.chain:
            if self._path_has_index(step.access_path) or self._path_has_index(
                step.value
            ):
                return True
        return False

    def _target_states(
        self, method_id: int, stmt_id: int, symbol_ids: frozenset[int]
    ) -> tuple[Any, ...]:
        states: list[Any] = []
        for symbol_id in symbol_ids:
            modes = ("in", "defined", "out")
            for mode in modes:
                states.extend(
                    self.context.trace_symbol_current_states(
                        method_id, symbol_id, stmt_id, mode=mode
                    )
                )
        unique: dict[int, Any] = {}
        for state in states:
            state_id = self._positive_id(getattr(state, "state_id", None))
            if state_id is not None:
                unique[state_id] = state
        return tuple(unique.values())

    def _origin_is_null(self, method_id: int, state: Any) -> bool:
        if self._is_null(getattr(state, "value", None)):
            return True
        state_id = self._positive_id(getattr(state, "state_id", None))
        if state_id is None:
            return False
        origin = self.context.trace_state_origin(method_id, state_id)
        return any(
            self._is_null(step.value) for step in (origin.chain if origin else ())
        )

    def _origin_is_nonnull(self, method_id: int, state: Any) -> bool:
        if self._is_string_literal(getattr(state, "value", None)):
            return True
        state_id = self._positive_id(getattr(state, "state_id", None))
        if state_id is None:
            return False
        origin = self.context.trace_state_origin(method_id, state_id)
        if origin is None:
            return False
        for step in origin.chain:
            value = self._text(step.value)
            path = self._text(step.access_path)
            if self._is_string_literal(value):
                return True
            if value.startswith("&") or path.startswith("&"):
                return True
        return False

    def _null_relation_in_row(self, row: Any, names: set[str]) -> bool:
        target_name = self._field(row, "target", "name")
        operand = self._field(row, "operand", "source", "value")
        operand2 = self._field(row, "operand2")
        operator = self._field(row, "operator")
        if operator in {"==", "!="}:
            return (
                self._mentions_alias(operand, names)
                and self._is_null(operand2)
            ) or (
                self._mentions_alias(operand2, names)
                and self._is_null(operand)
            )
        if operator == "!" and (
            self._mentions_alias(operand, names)
            or self._mentions_alias(target_name, names)
        ):
            return True
        return self._mentions_alias(target_name, names) and self._is_null(
            operand
        )

    def _call_defines_target_allocator(
        self, row: Any, stmt_id: int, symbol_ids: frozenset[int]
    ) -> bool:
        if self._call_name(stmt_id, row) not in _ALLOCATORS:
            return False
        defined = set(self.context.get_stmt_direct_defined_symbol_ids(stmt_id))
        return bool(defined & symbol_ids)

    def _row_defines_symbol(self, row: Any, names: set[str]) -> bool:
        return self._mentions_alias(self._field(row, "target", "name"), names)

    def _stmt_touches_target_field(
        self, method_id: int, stmt_id: int, target: PointerTarget
    ) -> bool:
        field_name = target.name
        row = self.context.get_stmt(stmt_id)
        if self._field(row, "field", "field_name") == field_name:
            return self._row_field_receiver_matches_target(
                method_id, stmt_id, row, target
            )
        return field_name in self._stmt_touched_fields(method_id, stmt_id)

    def _row_field_receiver_matches_target(
        self,
        method_id: int,
        stmt_id: int,
        row: Any,
        target: PointerTarget,
    ) -> bool:
        target_types = self._target_aggregate_type_names(target)
        if not target_types:
            return True
        receiver = self._field(row, "receiver_object", "object")
        receiver_types = self._receiver_type_names(method_id, stmt_id, receiver)
        if receiver_types:
            return bool(receiver_types & target_types)
        if self._field_name_has_multiple_aggregates(target.name):
            return False
        return True

    def _field_name_has_multiple_aggregates(self, field_name: str) -> bool:
        return len(self._field_aggregate_names().get(field_name, frozenset())) > 1

    def _field_aggregate_names(self) -> dict[str, frozenset[str]]:
        if self._field_aggregate_names_cache is not None:
            return self._field_aggregate_names_cache
        field_map: dict[str, set[str]] = {}
        current_aggregate_by_unit: dict[int, str] = {}
        for unit_id in self.context.get_all_unit_ids():
            for row in self.context.get_unit_rows(unit_id):
                operation = self._text(getattr(row, "operation", ""))
                name = self._text(getattr(row, "name", ""))
                if operation in {"struct_decl", "union_decl"} and name:
                    current_aggregate_by_unit[unit_id] = name
                    continue
                if operation == "block_end":
                    current_aggregate_by_unit.pop(unit_id, None)
                    continue
                if operation == "variable_decl" and name:
                    aggregate = current_aggregate_by_unit.get(unit_id)
                    if aggregate:
                        field_map.setdefault(name, set()).add(aggregate)
        self._field_aggregate_names_cache = {
            field: frozenset(aggregates)
            for field, aggregates in field_map.items()
        }
        return self._field_aggregate_names_cache

    def _target_aggregate_type_names(self, target: PointerTarget) -> set[str]:
        names: set[str] = set()
        for raw in (target.aggregate_name, target.c_type):
            names.update(self._canonical_type_names(raw))
        if target.aggregate_name:
            names.add(self._normalize_type_name(target.aggregate_name))
        return {name for name in names if name}

    def _receiver_type_names(
        self, method_id: int, stmt_id: int, receiver: str
    ) -> set[str]:
        receiver = self._text(receiver)
        if not receiver:
            return set()
        if self._is_temp_name(receiver):
            return self._temp_type_names(method_id, stmt_id, receiver)
        return self._symbol_type_names(method_id, stmt_id, receiver)

    def _symbol_type_names(
        self, method_id: int, stmt_id: int, symbol_name: str
    ) -> set[str]:
        best: Any | None = None
        best_stmt_id = -1
        for symbol in self.context.find_symbols_by_name(method_id, symbol_name):
            sym_stmt_id = self._positive_id(getattr(symbol, "stmt_id", None))
            if sym_stmt_id is None or sym_stmt_id > stmt_id:
                continue
            data_type = self._symbol_data_type(symbol)
            if not data_type:
                continue
            if sym_stmt_id >= best_stmt_id:
                best = symbol
                best_stmt_id = sym_stmt_id
        if best is None:
            return set()
        return self._canonical_type_names(self._symbol_data_type(best))

    def _temp_type_names(
        self, method_id: int, stmt_id: int, temp_name: str
    ) -> set[str]:
        for row in reversed(self.context.get_method_rows(method_id)):
            row_stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if row_stmt_id is None or row_stmt_id >= stmt_id:
                continue
            if self._field(row, "target", "name") != temp_name:
                continue
            data_type = self._field(row, "data_type", "default_data_type")
            if data_type:
                return self._canonical_type_names(data_type)
            operation = self._text(getattr(row, "operation", ""))
            if operation == "call_stmt":
                return self._call_return_type_names(method_id, row_stmt_id, row)
            if operation == "field_read":
                field_type_names = self._field_read_result_type_names(
                    method_id, row_stmt_id, row
                )
                if field_type_names:
                    return field_type_names
            if operation in {"assign_stmt", "variable_decl", "field_read"}:
                source = self._field(
                    row, "source", "value", "operand", "receiver_object"
                )
                if source and source != temp_name:
                    return self._receiver_type_names(method_id, row_stmt_id, source)
            return set()
        return set()

    def _call_return_type_names(
        self, caller_method_id: int, stmt_id: int, row: Any
    ) -> set[str]:
        callee = self._call_name(stmt_id, row)
        if not callee:
            return set()
        result: set[str] = set()
        for method_id in self._callee_method_ids_by_name(
            caller_method_id, callee
        ):
            method = self.context.get_stmt(method_id)
            result.update(
                self._canonical_type_names(
                    self._field(method, "data_type", "default_data_type")
                )
            )
        return result

    def _field_read_result_type_names(
        self, method_id: int, stmt_id: int, row: Any
    ) -> set[str]:
        field_name = self._field(row, "field", "field_name")
        receiver = self._field(row, "receiver_object", "object")
        if not field_name or not receiver:
            return set()
        result: set[str] = set()
        field_types = self._aggregate_field_types()
        for receiver_type in self._receiver_type_names(method_id, stmt_id, receiver):
            raw_type = field_types.get(receiver_type, {}).get(field_name, "")
            result.update(self._canonical_type_names(raw_type))
        return result

    def _symbol_data_type(self, symbol: Any) -> str:
        return self._field(
            symbol,
            "default_data_type",
            "data_type",
            "c_type",
            "type",
            "type_name",
        )

    def _canonical_type_names(self, raw_type: Any) -> set[str]:
        name = self._normalize_type_name(raw_type)
        if not name:
            return set()
        aliases = self._type_aliases()
        result = {name}
        seen: set[str] = set()
        current = name
        while current and current not in seen:
            seen.add(current)
            current = aliases.get(current, "")
            if current:
                result.add(current)
        return result

    def _type_aliases(self) -> dict[str, str]:
        if self._type_alias_cache is not None:
            return self._type_alias_cache
        aliases: dict[str, str] = {}
        for unit_id in self.context.get_all_unit_ids():
            for row in self.context.get_unit_rows(unit_id):
                if self._text(getattr(row, "operation", "")) != "type_alias_decl":
                    continue
                name = self._normalize_type_name(getattr(row, "name", ""))
                data_type = self._normalize_type_name(
                    self._field(row, "data_type", "default_data_type")
                )
                if name and data_type:
                    aliases[name] = data_type
        self._type_alias_cache = aliases
        return aliases

    def _aggregate_field_types(self) -> dict[str, dict[str, str]]:
        if self._aggregate_field_type_cache is not None:
            return self._aggregate_field_type_cache
        result: dict[str, dict[str, str]] = {}
        current_aggregate = ""
        for unit_id in self.context.get_all_unit_ids():
            current_aggregate = ""
            for row in self.context.get_unit_rows(unit_id):
                operation = self._text(getattr(row, "operation", ""))
                name = self._text(getattr(row, "name", ""))
                if operation in {"struct_decl", "union_decl"} and name:
                    current_aggregate = self._normalize_type_name(name)
                    result.setdefault(current_aggregate, {})
                    continue
                if operation == "block_end" and current_aggregate:
                    current_aggregate = ""
                    continue
                if operation == "variable_decl" and current_aggregate and name:
                    data_type = self._field(row, "data_type", "default_data_type")
                    if data_type:
                        result.setdefault(current_aggregate, {})[name] = data_type
        self._aggregate_field_type_cache = result
        return result

    @staticmethod
    def _normalize_type_name(raw_type: Any) -> str:
        text = str(raw_type or "").strip()
        if not text:
            return ""
        text = re.sub(r"\b(?:const|volatile|restrict|signed|unsigned)\b", " ", text)
        text = re.sub(r"\bstruct\s+", " ", text)
        text = re.sub(r"\bunion\s+", " ", text)
        text = re.sub(r"\benum\s+", " ", text)
        text = re.sub(r"\[[^\]]*\]", " ", text)
        text = text.replace("*", " ")
        parts = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)
        return parts[-1] if parts else ""

    def _origin_mentions_field(self, origin: Any, field_name: str) -> bool:
        needle = field_name.strip()
        if not needle:
            return False
        for step in getattr(origin, "chain", ()) or ():
            path = self._text(getattr(step, "access_path", ""))
            value = self._text(getattr(step, "value", ""))
            if self._path_mentions_field(path, needle):
                return True
            if self._path_mentions_field(value, needle):
                return True
        return False

    def _method_may_touch_field(self, method_id: int, field_name: str) -> bool:
        return field_name in self._method_touched_fields(method_id)

    def _methods_touching_field(self, field_name: str) -> tuple[int, ...]:
        field = self._text(field_name)
        if not field:
            return ()
        return self._methods_by_touched_field().get(field, ())

    def _methods_by_touched_field(self) -> dict[str, tuple[int, ...]]:
        if self._methods_by_touched_field_cache is not None:
            return self._methods_by_touched_field_cache
        mutable: dict[str, list[int]] = {}
        for method_id in self.context.get_all_method_ids():
            for field in self._method_touched_fields(method_id):
                mutable.setdefault(field, []).append(method_id)
        self._methods_by_touched_field_cache = {
            field: tuple(sorted(method_ids))
            for field, method_ids in mutable.items()
        }
        return self._methods_by_touched_field_cache

    def _method_touched_fields(self, method_id: int) -> frozenset[str]:
        cached = self._method_touched_fields_cache.get(method_id)
        if cached is not None:
            return cached
        fields: set[str] = set()
        for stmt_id in self._status_stmt_ids(method_id):
            row = self.context.get_stmt(stmt_id)
            fields.update(self._field_names_from_text(self._field(row, "field", "field_name")))
            fields.update(self._stmt_touched_fields(method_id, stmt_id))
        result = frozenset(fields)
        self._method_touched_fields_cache[method_id] = result
        return result

    def _stmt_touched_fields(self, method_id: int, stmt_id: int) -> frozenset[str]:
        fields: set[str] = set()
        state_ids = set(self.context.get_stmt_in_state_ids(stmt_id))
        state_ids.update(self.context.get_stmt_out_state_ids(stmt_id))
        state_ids.update(self.context.get_stmt_defined_state_ids(stmt_id))
        for state_id in state_ids:
            access_path = self.context.get_state_access_path(method_id, state_id)
            fields.update(self._field_names_from_text(access_path))
        return frozenset(fields)

    def _status_stmt_ids(self, method_id: int) -> tuple[int, ...]:
        statuses = self.context.get_preferred_stmt_statuses(method_id)
        return tuple(sorted(statuses))

    def _symbol_names(
        self, method_id: int, symbol_ids: frozenset[int]
    ) -> set[str]:
        names = {
            name
            for symbol_id in symbol_ids
            if (name := self.context.get_symbol_name(method_id, symbol_id))
        }
        return names

    @staticmethod
    def _summary_symbol_ids(summary: Any) -> set[int]:
        result: set[int] = set()
        for field_name in (
            "parameter_symbol_ids",
            "local_symbol_ids",
            "defined_external_symbol_ids",
            "used_external_symbol_ids",
            "defined_global_symbol_ids",
            "used_global_symbol_ids",
        ):
            raw = getattr(summary, field_name, ())
            if raw is None:
                continue


            values = tuple(raw) if not isinstance(raw, (tuple, list)) else raw
            for value in values:
                try:
                    symbol_id = int(value)
                except (TypeError, ValueError):
                    continue
                if symbol_id not in {-1, 0}:
                    result.add(symbol_id)
        return result

    @staticmethod
    def _path_mentions_field(path: str, field_name: str) -> bool:
        return bool(
            re.search(
                rf"(?:^|\.|->|\[|\]|\s){re.escape(field_name)}"
                rf"(?:$|\.|->|\[|\]|\s)",
                path,
            )
        )

    @staticmethod
    def _field_names_from_text(value: Any) -> set[str]:
        text = str(value or "")
        if not text:
            return set()
        return {
            match.group(1)
            for match in re.finditer(
                r"(?:\.|->)\s*([A-Za-z_][A-Za-z0-9_]*)", text
            )
        }

    @staticmethod
    def _path_has_index(path: Any) -> bool:
        return bool(re.search(r"\[[^\]]+\]", str(path or "")))

    def _infer_ownership(self, target: PointerTarget) -> Ownership | None:
        if _FUNCTION_POINTER_PATTERN.search(target.c_type):
            return Ownership.NONE

        events = self._collect_pointer_ownership_events(target)
        if events.freed:
            return Ownership.OWNED
        if events.allocated_from_heap:
            return Ownership.OWNED
        if events.unknown:
            return None
        if events.borrowed_source:
            return Ownership.BORROWED
        if target.location is PointerLocation.PARAMETER:
            return Ownership.BORROWED

        return None

    def _collect_pointer_ownership_events(
        self, target: PointerTarget
    ) -> _PointerOwnershipEvents:
        cache_key = (target.stmt_id, target.name, target.location)
        cached = self._ownership_events_cache.get(cache_key)
        if cached is not None:
            return cached

        kinds: set[str] = set()
        for method_id in self._pointer_analysis_method_ids(target):
            for related in self._collect_pointer_related_stmts(
                target, method_id
            ):
                kinds.update(self._ownership_events_from_related(target, related))

        result = _PointerOwnershipEvents(frozenset(kinds))
        self._ownership_events_cache[cache_key] = result
        return result

    def _ownership_events_from_related(
        self, target: PointerTarget, related: _PointerRelatedStmt
    ) -> set[str]:
        kinds: set[str] = set()
        if self._stmt_frees_pointer(related) or self._stmt_frees_pointer_via_callee(
            target, related
        ):
            kinds.add(_OWNERSHIP_FREED)

        origins = self._ownership_origins_from_related(related)
        kinds.update(self._ownership_events_from_origins(origins))
        if target.is_aggregate_member:
            kinds.update(
                self._aggregate_member_ownership_events_from_related(
                    target, related
                )
            )
        return kinds

    @staticmethod
    def _ownership_events_from_origins(origins: set[str]) -> set[str]:
        kinds: set[str] = set()
        meaningful = origins - {"parameter_default"}
        concrete = meaningful - {"unknown"}
        if "heap" in meaningful:
            kinds.add(_OWNERSHIP_ALLOCATED_FROM_HEAP)
        if meaningful & _BORROWED_ORIGINS:
            kinds.add(_OWNERSHIP_BORROWED_SOURCE)
        if "unknown" in meaningful or len(concrete) > 1:
            kinds.add(_OWNERSHIP_UNKNOWN)
        if "call" in meaningful:
            kinds.add(_OWNERSHIP_UNKNOWN)
        return kinds

    def _stmt_frees_pointer(self, related: _PointerRelatedStmt) -> bool:
        row = self.context.get_stmt(related.stmt_id)
        if self._text(getattr(row, "operation", "")) != "call_stmt":
            return False
        if self._call_name(related.stmt_id, row) not in _DEALLOCATORS:
            return False
        names = self._symbol_names(related.method_id, related.symbol_ids)
        return any(
            self._mentions_alias(argument, names)
            for argument in self._call_arguments(row)
        )

    def _stmt_frees_pointer_via_callee(
        self, target: PointerTarget, related: _PointerRelatedStmt
    ) -> bool:
        row = self.context.get_stmt(related.stmt_id)
        if self._text(getattr(row, "operation", "")) != "call_stmt":
            return False
        callee = self._call_name(related.stmt_id, row)
        freed_indices = self._freed_parameter_indices_for_callee_name(
            related.method_id, callee
        )
        if not freed_indices:
            return False
        args = self._call_arguments(row)
        if target.is_aggregate_member:
            return any(
                index in freed_indices
                and self._source_mentions_field_access(argument, target.name)
                for index, argument in enumerate(args)
            )
        names = self._symbol_names(related.method_id, related.target_symbol_ids)
        return any(
            index in freed_indices and self._mentions_alias(argument, names)
            for index, argument in enumerate(args)
        )

    def _aggregate_member_ownership_events_from_related(
        self, target: PointerTarget, related: _PointerRelatedStmt
    ) -> set[str]:
        row = self.context.get_stmt(related.stmt_id)
        source = self._stmt_source_text(related.stmt_id)
        if not self._row_or_source_mentions_field(row, source, target.name):
            return set()

        kinds: set[str] = set()
        operation = self._text(getattr(row, "operation", ""))
        if operation == "call_stmt":
            callee = self._call_name(related.stmt_id, row)
            freed_indices = self._freed_parameter_indices_for_callee_name(
                related.method_id, callee
            )
            if any(
                index in freed_indices
                and self._source_mentions_field_access(argument, target.name)
                for index, argument in enumerate(self._call_arguments(row))
            ):
                kinds.add(_OWNERSHIP_FREED)

            if self._call_result_is_written_to_field(row, source, target.name):
                if self._call_returns_heap_by_name(related.method_id, callee):
                    kinds.add(_OWNERSHIP_ALLOCATED_FROM_HEAP)
                elif callee and callee not in _DEALLOCATORS:
                    kinds.add(_OWNERSHIP_UNKNOWN)

        if self._source_assigns_field_from_heap_call(
            related.method_id, source, target.name
        ):
            kinds.add(_OWNERSHIP_ALLOCATED_FROM_HEAP)
        if self._source_frees_field(related.method_id, source, target.name):
            kinds.add(_OWNERSHIP_FREED)
        if self._row_assigns_field_from_borrowed_source(
            related.method_id, row, operation, target.name
        ):
            kinds.add(_OWNERSHIP_BORROWED_SOURCE)
        kinds.update(
            self._ownership_events_from_origins(
                self._field_write_source_origins(
                    related.method_id,
                    related.stmt_id,
                    row,
                    operation,
                    target.name,
                )
            )
        )
        return kinds

    def _aggregate_member_nullability_events_from_related(
        self, target: PointerTarget, related: _PointerRelatedStmt
    ) -> set[str]:
        row = self.context.get_stmt(related.stmt_id)
        operation = self._text(getattr(row, "operation", ""))
        value = self._field_write_source_value(
            row,
            operation,
            target.name,
            source_text=self._stmt_source_text(related.stmt_id),
        )
        source_rhs = self._source_assignment_rhs(
            self._stmt_source_text(related.stmt_id)
        )
        if self._is_null(source_rhs):
            return {_NULLABILITY_NULL_RELATED}
        if not value:
            return set()
        if self._is_null(value):
            return {_NULLABILITY_NULL_RELATED}
        symbol = self.context.find_symbol_by_name(related.method_id, value)
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        if symbol_id is None:
            return set()
        if self._states_have_null_origin(
            related.method_id, related.stmt_id, frozenset({symbol_id})
        ):
            return {_NULLABILITY_NULL_RELATED}
        return set()

    def _row_assigns_field_from_borrowed_source(
        self, method_id: int, row: Any, operation: str, field_name: str
    ) -> bool:
        if operation not in {"assign_stmt", "field_write"}:
            return False
        target = self._field(row, "target", "name")
        row_field = self._field(row, "field", "field_name")
        if row_field != field_name and not self._source_mentions_field_access(
            target, field_name
        ):
            return False
        source = self._field(row, "source", "value", "operand")
        if not source:
            return False
        if source.startswith("&") or self._is_string_literal(source):
            return True
        symbol = self.context.find_symbol_by_name(method_id, source)
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        if symbol_id is None:
            return False
        return self.context.symbol_storage_kind(method_id, symbol_id) in {
            "param",
            "global",
            "field",
        }

    def _field_write_source_origins(
        self,
        method_id: int,
        stmt_id: int,
        row: Any,
        operation: str,
        field_name: str,
    ) -> set[str]:
        value = self._field_write_source_value(
            row,
            operation,
            field_name,
            source_text=self._stmt_source_text(stmt_id),
        )
        if not value or self._is_null(value):
            return set()
        if self._is_string_literal(value):
            return {"static"}
        if value.startswith("&"):
            return {self._address_origin_kind(method_id, value[1:])}
        if self._source_call_names(value):
            return self._return_call_expression_origins(
                method_id, value, max_depth=5
            )
        symbol = self.context.find_symbol_by_name(method_id, value)
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        if symbol_id is not None:
            storage = self.context.symbol_storage_kind(method_id, symbol_id)
            if storage == "param" or self._is_method_parameter_name(
                method_id, value
            ):
                return {"parameter"}
            if storage == "global":
                return {"static"}
            if storage == "field":
                return {"field"}
            traced = self._trace_symbol_value_by_id(
                method_id,
                stmt_id,
                symbol_id,
                value,
                max_depth=4,
            )
            if traced:
                return traced
        if self._is_temp_name(value):
            traced = self._trace_temp_origin(method_id, stmt_id, value)
            if traced:
                return traced
        return set()

    def _field_write_source_value(
        self,
        row: Any,
        operation: str,
        field_name: str,
        *,
        source_text: str = "",
    ) -> str:
        if operation not in {"assign_stmt", "field_write"}:
            return ""
        target = self._field(row, "target", "name")
        row_field = self._field(row, "field", "field_name")
        if (
            row_field != field_name
            and not self._source_mentions_field_access(target, field_name)
            and not self._source_mentions_field_access(source_text, field_name)
        ):
            return ""
        value = self._field(row, "source", "value", "operand")
        if value:
            return value
        return self._source_assignment_rhs(source_text)

    def _call_result_is_written_to_field(
        self, row: Any, source: str, field_name: str
    ) -> bool:
        target = self._field(row, "target", "name")
        if self._source_mentions_field_access(target, field_name):
            return True
        return bool(
            source
            and self._source_mentions_field_access(source, field_name)
            and re.search(r"(?<![=!<>])=(?!=)", source)
        )

    def _source_assigns_field_from_heap_call(
        self, method_id: int, source: str, field_name: str
    ) -> bool:
        if not source or not self._source_mentions_field_access(source, field_name):
            return False
        assignment = re.search(r"(?<![=!<>])=(?!=)", source)
        if assignment is None:
            return False
        lhs = source[: assignment.start()]
        rhs = source[assignment.end() :]
        if not self._source_mentions_field_access(lhs, field_name):
            return False
        return any(
            self._call_returns_heap_by_name(method_id, callee)
            for callee in self._source_call_names(rhs)
        )

    def _source_frees_field(
        self, method_id: int, source: str, field_name: str
    ) -> bool:
        if not source or not self._source_mentions_field_access(source, field_name):
            return False
        for callee in self._source_call_names(source):
            freed_indices = self._freed_parameter_indices_for_callee_name(
                method_id, callee
            )
            if not freed_indices:
                continue
            for args in self._source_call_argument_lists(source, callee):
                if any(
                    index in freed_indices
                    and self._source_mentions_field_access(argument, field_name)
                    for index, argument in enumerate(args)
                ):
                    return True
        return False

    def _call_returns_heap_by_name(
        self, caller_method_id: int, callee_name: str, *, max_depth: int = 2
    ) -> bool:
        if not callee_name:
            return False
        if callee_name in _ALLOCATORS:
            return True
        if max_depth <= 0:
            return False
        for callee_id in self._callee_method_ids_by_name(
            caller_method_id, callee_name
        ):
            origins = self._method_return_origins(
                callee_id, max_depth=max_depth - 1
            )
            if origins == {"heap"}:
                return True
        return False

    def _freed_parameter_indices_for_callee_name(
        self, caller_method_id: int, callee_name: str, *, max_depth: int = 4
    ) -> frozenset[int]:
        if not callee_name:
            return frozenset()
        if callee_name in _DEALLOCATORS:
            return frozenset({0})
        if max_depth <= 0:
            return frozenset()
        result: set[int] = set()
        for callee_id in self._callee_method_ids_by_name(
            caller_method_id, callee_name
        ):
            result.update(
                self._method_freed_parameter_indices(
                    callee_id, max_depth=max_depth - 1
                )
            )
        return frozenset(result)

    def _method_freed_parameter_indices(
        self,
        method_id: int,
        *,
        max_depth: int = 4,
        visiting: frozenset[int] = frozenset(),
    ) -> frozenset[int]:
        if max_depth <= 0 or method_id in visiting:
            return frozenset()
        cache_key = (method_id, max_depth)
        if not visiting:
            cached = self._freed_parameter_indices_cache.get(cache_key)
            if cached is not None:
                return cached

        parameters: list[tuple[int, str]] = []
        for index, symbol in enumerate(self.context.get_method_parameters(method_id)):
            name = self._field(symbol, "name", "target")
            if not name:
                continue
            parameters.append((index, name))

        freed: set[int] = set()
        for row in self.context.get_method_rows(method_id):
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if stmt_id is None:
                continue
            if self._text(getattr(row, "operation", "")) != "call_stmt":
                continue
            callee = self._call_name(stmt_id, row)
            args = self._call_arguments(row)
            if not args:
                continue
            if callee in _DEALLOCATORS:
                freed_arg_indices = frozenset({0})
            else:
                freed_arg_indices = self._freed_parameter_indices_for_nested_callee(
                    method_id,
                    callee,
                    max_depth=max_depth - 1,
                    visiting=visiting | {method_id},
                )
            if not freed_arg_indices:
                continue
            for index, name in parameters:
                if any(
                    arg_index < len(args)
                    and self._mentions_alias(args[arg_index], {name})
                    and not _FIELD_ACCESS_RE.search(str(args[arg_index]))
                    for arg_index in freed_arg_indices
                ):
                    freed.add(index)

        result = frozenset(freed)
        if not visiting:
            self._freed_parameter_indices_cache[cache_key] = result
        return result

    def _freed_parameter_indices_for_nested_callee(
        self,
        caller_method_id: int,
        callee_name: str,
        *,
        max_depth: int,
        visiting: frozenset[int],
    ) -> frozenset[int]:
        if not callee_name or max_depth <= 0:
            return frozenset()
        if callee_name in _DEALLOCATORS:
            return frozenset({0})
        result: set[int] = set()
        for callee_id in self._callee_method_ids_by_name(
            caller_method_id, callee_name
        ):
            result.update(
                self._method_freed_parameter_indices(
                    callee_id,
                    max_depth=max_depth - 1,
                    visiting=visiting,
                )
            )
        return frozenset(result)

    def _callee_method_ids_by_name(
        self, caller_method_id: int, callee_name: str
    ) -> tuple[int, ...]:
        callee_ids = [
            callee_id
            for callee_id in self.context.get_callees(caller_method_id)
            if (self.context.get_method_name(callee_id) or "") == callee_name
        ]
        if callee_ids:
            return tuple(callee_ids)

        name_matches = list(self._method_ids_for_name(callee_name))
        return tuple(name_matches) if len(name_matches) == 1 else ()

    def _row_or_source_mentions_field(
        self, row: Any, source: str, field_name: str
    ) -> bool:
        return (
            self._field(row, "field", "field_name") == field_name
            or self._source_mentions_field_access(source, field_name)
            or self._source_mentions_field_access(
                self._field(row, "target", "name"), field_name
            )
            or self._source_mentions_field_access(
                self._field(row, "operand", "source", "value"), field_name
            )
        )

    def _stmt_source_text(self, stmt_id: int) -> str:
        source = self.context.get_stmt_source(stmt_id)
        if isinstance(source, (tuple, list)):
            return " ".join(str(item).strip() for item in source if str(item).strip())
        return str(source or "").strip()

    @staticmethod
    def _source_mentions_field_access(source: Any, field_name: str) -> bool:
        if not source or not field_name:
            return False
        return bool(
            re.search(
                rf"(?:->|\.)\s*{re.escape(field_name)}\b",
                str(source),
            )
        )

    @staticmethod
    def _source_call_names(source: str) -> tuple[str, ...]:
        if not source:
            return ()
        keywords = {"if", "for", "while", "switch", "return", "sizeof"}
        return tuple(
            name
            for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", source)
            if name not in keywords
        )

    @staticmethod
    def _source_call_argument_lists(
        source: str, callee_name: str
    ) -> tuple[tuple[str, ...], ...]:
        if not source or not callee_name:
            return ()
        results: list[tuple[str, ...]] = []
        pattern = re.compile(rf"\b{re.escape(callee_name)}\s*\(")
        for match in pattern.finditer(source):
            open_index = match.end() - 1
            close_index = PointerAnalyzer._matching_paren_index(
                source, open_index
            )
            if close_index is None:
                continue
            argument_text = source[open_index + 1 : close_index]
            results.append(PointerAnalyzer._split_call_arguments(argument_text))
        return tuple(results)

    @staticmethod
    def _matching_paren_index(source: str, open_index: int) -> int | None:
        if open_index < 0 or open_index >= len(source) or source[open_index] != "(":
            return None
        depth = 0
        in_string = False
        escaped = False
        for index in range(open_index, len(source)):
            char = source[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return index
        return None

    @staticmethod
    def _split_call_arguments(argument_text: str) -> tuple[str, ...]:
        if not argument_text.strip():
            return ()
        args: list[str] = []
        start = 0
        depth = 0
        in_string = False
        escaped = False
        for index, char in enumerate(argument_text):
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char in "([{":
                depth += 1
            elif char in ")]}":
                depth = max(depth - 1, 0)
            elif char == "," and depth == 0:
                args.append(argument_text[start:index].strip())
                start = index + 1
        args.append(argument_text[start:].strip())
        return tuple(args)

    @staticmethod
    def _source_assignment_rhs(source: str) -> str:
        if not source:
            return ""
        assignment = re.search(r"(?<![=!<>])=(?!=)", source)
        if assignment is None:
            return ""
        return source[assignment.end() :].rstrip(";").strip()

    @staticmethod
    def _source_return_expression(source: str) -> str:
        if not source:
            return ""
        match = re.search(r"\breturn\b(?P<expr>.*?);?$", source.strip())
        if match is None:
            return ""
        return match.group("expr").strip().rstrip(";").strip()

    def _ownership_origins_from_related(
        self, related: _PointerRelatedStmt
    ) -> set[str]:
        row = self.context.get_stmt(related.stmt_id)
        direct_defined = set(
            self.context.get_stmt_direct_defined_symbol_ids(related.stmt_id)
        )
        defined_symbols = direct_defined & related.target_symbol_ids
        if not defined_symbols:
            return set()

        names = self._symbol_names(related.method_id, defined_symbols)
        intrinsic_origins = self._ownership_intrinsic_origins_from_row(
            related.method_id, related.stmt_id, row, names
        )
        if intrinsic_origins:
            return intrinsic_origins

        origins: set[str] = set()
        for symbol_id in defined_symbols:
            origins.update(
                self._ownership_origins_from_states(
                    related.method_id, related.stmt_id, symbol_id
                )
            )
        if origins and origins != {"unknown"}:
            return origins

        fallback = self._ownership_fallback_origins_from_row(
            related.method_id, related.stmt_id, row, names
        )
        return fallback or origins

    def _ownership_origins_from_states(
        self, method_id: int, stmt_id: int, symbol_id: int
    ) -> set[str]:
        origins: set[str] = set()
        for state in self.context.trace_symbol_current_states(
            method_id, symbol_id, stmt_id, mode="defined"
        ):
            origins.update(self._ownership_origin_from_state(method_id, state))
        return origins

    def _ownership_origin_from_state(
        self, method_id: int, state: Any
    ) -> set[str]:
        value = self._text(getattr(state, "value", ""))
        if self._is_string_literal(value):
            return {"static"}
        if value.startswith("&"):
            return {self._address_origin_kind(method_id, value[1:])}
        state_id = self._positive_id(getattr(state, "state_id", None))
        if state_id is None:
            return set()
        origin = self.context.trace_state_origin(method_id, state_id)
        if origin is None:
            return set()

        kinds: set[str] = set()
        for step in origin.chain:
            step_value = self._text(step.value)
            step_path = self._text(step.access_path)
            if self._is_string_literal(step_value):
                kinds.add("static")
            elif step_value.startswith("&"):
                kinds.add(self._address_origin_kind(method_id, step_value[1:]))
            elif step_path.startswith("&"):
                kinds.add(self._address_origin_kind(method_id, step_path[1:]))
            elif step.source_symbol_id not in {None, -1, 0}:
                storage = self.context.symbol_storage_kind(
                    method_id, int(step.source_symbol_id)
                )
                if storage == "param":
                    kinds.add("parameter")
                elif storage == "global":
                    kinds.add("static")
                elif storage == "field":
                    kinds.add("field")
            if kinds:
                return kinds
        return kinds

    def _ownership_intrinsic_origins_from_row(
        self,
        method_id: int,
        stmt_id: int,
        row: Any,
        names: set[str],
    ) -> set[str]:
        operation = self._text(getattr(row, "operation", ""))
        if not self._row_defines_symbol(row, names):
            return set()

        if operation == "call_stmt":
            callee = self._call_name(stmt_id, row)
            if callee in _ALLOCATORS:
                return {"heap"}
            return set()

        if operation == "addr_of":
            source = self._field(row, "source", "operand", "value", "name")
            return {self._address_origin_kind(method_id, source)}

        operand = self._field(row, "operand", "source", "value")
        if self._is_string_literal(operand):
            return {"static"}
        if operand.startswith("&"):
            return {self._address_origin_kind(method_id, operand[1:])}
        if operation == "field_read":
            return {"field"}
        if operation == "variable_decl":
            source = self.context.get_stmt_source(stmt_id)
            if source and isinstance(source, (tuple, list)):
                source_text = " ".join(str(s) for s in source)
            else:
                source_text = str(source or "")
            if '"{' in source_text or '"{' in source_text:
                pass
            elif _STRING_LITERAL_RE.search(source_text):
                return {"static"}
        return set()

    def _ownership_fallback_origins_from_row(
        self,
        method_id: int,
        stmt_id: int,
        row: Any,
        names: set[str],
    ) -> set[str]:
        operation = self._text(getattr(row, "operation", ""))
        if not self._row_defines_symbol(row, names):
            return set()

        if operation == "call_stmt":
            resolved = self._resolve_call_return_origins(
                method_id, stmt_id, max_depth=5
            )
            return resolved or {"call", "unknown"}

        if operation in {"assign_stmt", "variable_decl"}:
            rhs = self._source_assignment_rhs(self._stmt_source_text(stmt_id))
            if self._source_call_names(rhs):
                return self._return_call_expression_origins(
                    method_id, rhs, max_depth=5
                )

        operand = self._field(row, "operand", "source", "value")
        symbol = self.context.find_symbol_by_name(method_id, operand)
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        if symbol_id is not None:
            storage = self.context.symbol_storage_kind(method_id, symbol_id)
            if storage == "param" or self._is_method_parameter_name(
                method_id, operand
            ):
                return {"parameter"}
            if storage == "global":
                return {"static"}
            if storage == "field":
                return {"field"}


            traced = self._trace_symbol_value(
                method_id, stmt_id, operand, max_depth=4
            )
            if traced:
                return traced
        if self._is_temp_name(operand):
            origin = self._trace_temp_origin(method_id, stmt_id, operand)
            if origin:
                return origin
        return set()

    @staticmethod
    def _is_temp_name(name: str) -> bool:
        return bool(name) and name.startswith("%vv")

    def _trace_temp_origin(
        self,
        method_id: int,
        assign_stmt_id: int,
        temp_name: str,
    ) -> set[str] | None:

        rows = self.context.get_method_rows(method_id)

        for row in reversed(rows):
            row_stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if row_stmt_id is None or row_stmt_id >= assign_stmt_id:
                continue

            row_target = self._text(getattr(row, "target", ""))
            if row_target != temp_name:
                continue
            operation = self._text(getattr(row, "operation", ""))
            if operation == "call_stmt":
                callee = self._call_name(row_stmt_id, row)
                if callee in _ALLOCATORS:
                    return {"heap"}
                resolved = self._resolve_call_return_origins(
                    method_id, row_stmt_id, max_depth=2
                )
                if resolved:
                    return resolved
                return None
            return None
        return None

    def _temp_traces_to_pointer(
        self,
        method_id: int,
        stmt_id: int,
        temp_name: str,
        names: set[str],
        *,
        max_depth: int = 4,
    ) -> bool:

        if max_depth <= 0 or not temp_name or not names:
            return False
        rows = self.context.get_method_rows(method_id)
        for row in reversed(rows):
            row_stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if row_stmt_id is None or row_stmt_id >= stmt_id:
                continue
            if self._text(getattr(row, "target", "")) != temp_name:
                continue
            operation = self._text(getattr(row, "operation", ""))

            operand = self._field(row, "operand", "source", "value")
            if operand and self._mentions_alias(operand, names):
                return True

            source_text = self._stmt_source_text(row_stmt_id)
            if any(
                re.search(rf"\b{re.escape(n)}\s*(?:->|\.)\s*\w", source_text)
                for n in names
            ):
                return True

            if operation in {"assign_stmt", "variable_decl"}:
                next_temp = self._field(row, "operand", "source", "value")
                if self._is_temp_name(next_temp) and next_temp != temp_name:
                    return self._temp_traces_to_pointer(
                        method_id,
                        row_stmt_id,
                        next_temp,
                        names,
                        max_depth=max_depth - 1,
                    )
            return False
        return False

    def _trace_symbol_value(
        self, method_id: int, stmt_id: int, symbol_name: str, *, max_depth: int
    ) -> set[str] | None:

        if max_depth <= 0:
            return None
        symbol = self.context.find_symbol_by_name(method_id, symbol_name)
        if symbol is None:
            return None
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        if symbol_id is None:
            return None

        return self._trace_symbol_value_by_id(
            method_id,
            stmt_id,
            symbol_id,
            symbol_name,
            max_depth=max_depth,
        )

    def _trace_symbol_value_by_id(
        self,
        method_id: int,
        stmt_id: int,
        symbol_id: int,
        symbol_name: str,
        *,
        max_depth: int,
    ) -> set[str] | None:

        if max_depth <= 0:
            return None
        defining_ids = self.context.get_defined_stmt_ids_for_symbol(
            method_id, symbol_id
        )
        for def_stmt_id in sorted(defining_ids, reverse=True):
            if def_stmt_id >= stmt_id:
                continue
            row = self.context.get_stmt(def_stmt_id)
            operation = self._text(getattr(row, "operation", ""))


            if operation == "call_stmt":
                callee = self._call_name(def_stmt_id, row)
                if callee in _ALLOCATORS:
                    return {"heap"}
                resolved = self._resolve_call_return_origins(
                    method_id, def_stmt_id, max_depth=max_depth - 1
                )
                if resolved:
                    return resolved

            if operation in {"assign_stmt", "variable_decl"}:
                rhs = self._source_assignment_rhs(
                    self._stmt_source_text(def_stmt_id)
                )
                if self._source_call_names(rhs):
                    origin = self._return_call_expression_origins(
                        method_id, rhs, max_depth=max_depth - 1
                    )
                    if origin:
                        return origin

            operand = self._field(row, "operand", "source", "value")
            if self._is_string_literal(operand):
                return {"static"}
            if operand.startswith("&"):
                return {self._address_origin_kind(method_id, operand[1:])}


            if operation in {"assign_stmt", "variable_decl"} and operand:
                if self._is_temp_name(operand):
                    origin = self._trace_temp_origin(
                        method_id, def_stmt_id, operand
                    )
                    if origin:
                        return origin
                else:
                    origin = self._trace_symbol_value(
                        method_id, def_stmt_id, operand, max_depth=max_depth - 1
                    )
                    if origin:
                        return origin

        return None

    def _resolve_call_return_origins(
        self, method_id: int, call_stmt_id: int, *, max_depth: int
    ) -> set[str]:
        if max_depth <= 0:
            return {"unknown"}
        row = self.context.get_stmt(call_stmt_id)
        callee_name = self._call_name(call_stmt_id, row)
        if not callee_name:
            return {"unknown"}

        callee_ids = [
            callee_id
            for callee_id in self.context.get_callees(method_id)
            if (self.context.get_method_name(callee_id) or "") == callee_name
        ]
        if not callee_ids:




            name_matches = list(self._method_ids_for_name(callee_name))
            if len(name_matches) == 1:
                callee_ids = name_matches
        if not callee_ids:
            return {"unknown"}

        origins: set[str] = set()
        for callee_id in callee_ids:
            origins.update(
                self._method_return_origins(callee_id, max_depth=max_depth - 1)
            )
        return origins or {"unknown"}

    def _method_return_origins(
        self, method_id: int, *, max_depth: int
    ) -> set[str]:
        if max_depth <= 0:
            return {"unknown"}
        origins: set[str] = set()
        for row in self.context.get_method_rows(method_id):
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if stmt_id is None:
                continue
            if self._text(getattr(row, "operation", "")) != "return_stmt":
                continue
            returned = self._source_return_expression(
                self._stmt_source_text(stmt_id)
            ) or self._field(row, "name", "value", "operand")
            if self._is_null(returned):
                continue
            if self._is_string_literal(returned):
                origins.add("static")
            elif returned.startswith("&"):
                origins.add(self._address_origin_kind(method_id, returned[1:]))
            elif self._source_call_names(returned):
                origins.update(
                    self._return_call_expression_origins(
                        method_id, returned, max_depth=max_depth - 1
                    )
                )
            else:
                origins.update(
                    self._return_symbol_origins(method_id, stmt_id, returned)
                )
        concrete = origins - {"unknown"}
        return concrete or origins or {"unknown"}

    def _return_call_expression_origins(
        self, method_id: int, expression: str, *, max_depth: int
    ) -> set[str]:
        if max_depth <= 0:
            return {"unknown"}
        origins: set[str] = set()
        current_name = self.context.get_method_name(method_id) or ""
        for callee_name in self._source_call_names(expression):
            if callee_name in _ALLOCATORS:
                origins.add("heap")
                continue
            if callee_name == current_name:
                continue
            callee_ids = self._callee_method_ids_by_name(method_id, callee_name)
            if not callee_ids:
                origins.add("unknown")
                continue
            for callee_id in callee_ids:
                origins.update(
                    self._method_return_origins(
                        callee_id, max_depth=max_depth - 1
                    )
                )
        concrete = origins - {"unknown"}
        return concrete or origins or {"unknown"}

    def _return_symbol_origins(
        self, method_id: int, stmt_id: int, symbol_name: str
    ) -> set[str]:
        candidate_ids = self._return_symbol_ids_for_name(
            method_id, stmt_id, symbol_name
        )
        if not candidate_ids:
            return {"unknown"}

        origins: set[str] = set()
        for symbol_id in candidate_ids:
            storage = self._symbol_storage_kind_by_declaration(
                method_id, symbol_id
            )
            if storage == "param" or self._is_method_parameter_name(
                method_id, symbol_name
            ):
                origins.add("parameter")
                continue
            if storage == "global":
                origins.add("static")
                continue
            if storage == "field":
                origins.add("field")
                continue

            traced = self._trace_symbol_value_by_id(
                method_id,
                stmt_id,
                symbol_id,
                symbol_name,
                max_depth=4,
            )
            if traced:
                origins.update(traced)
                continue

            state_origins = self._ownership_origins_from_states(
                method_id, stmt_id, symbol_id
            )
            if state_origins:
                origins.update(state_origins)

        concrete = origins - {"unknown"}
        return concrete or origins or {"unknown"}

    def _return_symbol_ids_for_name(
        self, method_id: int, stmt_id: int, symbol_name: str
    ) -> tuple[int, ...]:
        direct_used = self.context.get_stmt_direct_used_symbol_ids(stmt_id)
        result: list[int] = []
        for symbol_id in direct_used:
            symbol = self.context.find_symbol_by_id(method_id, symbol_id)
            if self._field(symbol, "name") == symbol_name:
                result.append(int(symbol_id))
        if result:
            return tuple(dict.fromkeys(result))

        symbol = self.context.find_symbol_by_name(method_id, symbol_name)
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        return (symbol_id,) if symbol_id is not None else ()

    def _symbol_storage_kind_by_declaration(
        self, method_id: int, symbol_id: int
    ) -> str | None:
        symbol = self.context.find_symbol_by_id(method_id, symbol_id)
        stmt_id = self._positive_id(getattr(symbol, "stmt_id", None))
        row = self.context.get_stmt(stmt_id) if stmt_id is not None else None
        operation = self._text(getattr(row, "operation", ""))
        if operation == "parameter_decl":
            return "param"
        if operation == "variable_decl":
            return "local"
        return self.context.symbol_storage_kind(method_id, symbol_id)

    def _address_origin_kind(self, method_id: int, expression: str) -> str:
        name = self._first_token(expression)
        if self._is_method_parameter_name(method_id, name):
            return "parameter"
        symbol = self.context.find_symbol_by_name(method_id, name)
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        if symbol_id is not None:
            storage = self.context.symbol_storage_kind(method_id, symbol_id)
            if storage == "param":
                return "parameter"
            if storage == "global":
                return "static"
            if storage == "field":
                return "field"
        return "local"

    def _is_method_parameter_name(self, method_id: int, name: str) -> bool:
        if not name:
            return False
        return any(
            self._field(parameter, "name", "target") == name
            for parameter in self.context.get_method_parameters(method_id)
        )

    def _infer_mutability(self, target: PointerTarget) -> Mutability | None:
        events = self._collect_pointee_mutability_events(target)
        if self._pointee_is_const(target.c_type):
            if events.written:
                return None
            return Mutability.CONST
        if events.written:
            return Mutability.MUTABLE
        if events.read:
            return Mutability.CONST
        return None

    def _collect_pointee_mutability_events(
        self, target: PointerTarget
    ) -> _PointerPointeeMutabilityEvents:
        cache_key = (target.stmt_id, target.name, target.location)
        cached = self._pointee_mutability_events_cache.get(cache_key)
        if cached is not None:
            return cached

        kinds: set[str] = set()
        for method_id in self._pointer_analysis_method_ids(target):
            for related in self._collect_pointer_related_stmts(
                target, method_id
            ):
                kinds.update(
                    self._pointee_mutability_events_from_related(
                        target, related
                    )
                )

        result = _PointerPointeeMutabilityEvents(frozenset(kinds))
        self._pointee_mutability_events_cache[cache_key] = result
        return result

    def _pointee_mutability_events_from_related(
        self, target: PointerTarget, related: _PointerRelatedStmt
    ) -> set[str]:
        access = self._classify_pointer_stmt_access(
            related,
            is_struct_member=target.is_aggregate_member,
            target_name=target.name,
        )
        kinds: set[str] = set()
        if access.pointee_read:
            kinds.add(_POINTEE_READ)
        if access.pointee_written:
            kinds.add(_POINTEE_WRITTEN)
        if access.passed_to_unknown_callee:
            kinds.add(_POINTEE_EXTERNAL_UNKNOWN)
        return kinds

    def _collect_pointer_stmt_access(
        self, target: PointerTarget
    ) -> _PointerStmtAccess:
        cached = self._combined_access_cache.get(target.stmt_id)
        if cached is not None:
            return cached

        combined = _PointerStmtAccess()
        for method_id in self._pointer_analysis_method_ids(target):
            for related in self._collect_pointer_related_stmts(
                target, method_id
            ):
                access = self._classify_pointer_stmt_access(
                    related,
                    is_struct_member=target.is_aggregate_member,
                    target_name=target.name,
                )
                combined = _PointerStmtAccess(
                    pointer_read=combined.pointer_read or access.pointer_read,
                    pointer_written=combined.pointer_written
                    or access.pointer_written,
                    pointee_read=combined.pointee_read or access.pointee_read,
                    pointee_written=combined.pointee_written
                    or access.pointee_written,
                    alias_created=combined.alias_created
                    or access.alias_created,
                    alias_pointee_written=combined.alias_pointee_written
                    or access.alias_pointee_written,
                    stored=combined.stored or access.stored,
                    returned=combined.returned or access.returned,
                    passed_to_unknown_callee=(
                        combined.passed_to_unknown_callee
                        or access.passed_to_unknown_callee
                    ),
                    array_access=combined.array_access or access.array_access,
                    single_access_observed=(
                        combined.single_access_observed
                        or access.single_access_observed
                    ),
                    pointer_arithmetic=(
                        combined.pointer_arithmetic
                        or access.pointer_arithmetic
                    ),
                    string_usage=combined.string_usage or access.string_usage,
                    byte_buffer_usage=(
                        combined.byte_buffer_usage or access.byte_buffer_usage
                    ),
                )
        self._combined_access_cache[target.stmt_id] = combined
        return combined

    def _infer_pointee_shape(self, target: PointerTarget) -> PointeeShape | None:
        events = self._collect_pointee_shape_events(target)
        if events.strong_array:
            return PointeeShape.ARRAY
        if events.byte_buffer and self._is_byte_like_pointer_type(target.c_type):
            return PointeeShape.ARRAY
        if events.alloc_single:
            return PointeeShape.SINGLE
        if events.single_access:
            return PointeeShape.SINGLE
        return None

    def _collect_pointee_shape_events(
        self, target: PointerTarget
    ) -> _PointerPointeeShapeEvents:
        cache_key = (target.stmt_id, target.name, target.location)
        cached = self._pointee_shape_events_cache.get(cache_key)
        if cached is not None:
            return cached

        kinds: set[str] = set()
        for method_id in self._pointer_analysis_method_ids(target):
            for related in self._collect_pointer_related_stmts(
                target, method_id
            ):
                kinds.update(
                    self._pointee_shape_events_from_related(
                        target, related, max_depth=3
                    )
                )

        result = _PointerPointeeShapeEvents(frozenset(kinds))
        self._pointee_shape_events_cache[cache_key] = result
        return result

    def _pointee_shape_events_from_related(
        self,
        target: PointerTarget,
        related: _PointerRelatedStmt,
        *,
        max_depth: int,
    ) -> set[str]:
        row = self.context.get_stmt(related.stmt_id)
        operation = self._text(getattr(row, "operation", ""))
        names = self._symbol_names(related.method_id, related.symbol_ids)
        if target.is_aggregate_member:
            names |= self._field_temp_names_cache.get(
                (related.method_id, related.stmt_id), frozenset()
            )

        kinds: set[str] = set()
        kinds.update(
            self._shape_allocation_events_from_related(target, related, row, operation)
        )

        if operation in {"array_read", "array_write"} and self._mentions_alias(
            self._field(row, "array"), names
        ):
            kinds.add(_SHAPE_INDEXED_ACCESS)
        if self._stmt_has_pointer_arithmetic(row, operation, names):
            kinds.add(_SHAPE_POINTER_ARITHMETIC)
        if operation in {"field_read", "field_write"}:
            receiver = self._field(row, "receiver_object", "object")
            if self._mentions_alias(receiver, names) or (
                self._is_temp_name(receiver)
                and self._temp_traces_to_pointer(
                    related.method_id, related.stmt_id, receiver, names
                )
            ):
                kinds.add(_SHAPE_FIELD_ACCESS)
        if operation in {"mem_read", "mem_write"}:
            address = self._field(row, "address", "target", "operand", "source")
            if self._mentions_alias(address, names) or (
                self._is_temp_name(address)
                and self._temp_traces_to_pointer(
                    related.method_id, related.stmt_id, address, names
                )
            ):
                kinds.add(_SHAPE_DEREF_ACCESS)
        if operation == "call_stmt":
            kinds.update(
                self._call_shape_events_for_target(
                    related.method_id,
                    related.stmt_id,
                    row,
                    names,
                    max_depth=max_depth,
                ).kinds
            )
        else:
            kinds.update(
                self._source_call_shape_events_for_target(
                    related.method_id,
                    self._stmt_source_text(related.stmt_id),
                    names,
                    max_depth=max_depth,
                ).kinds
            )
        if self._states_have_array_access_path(
            related.method_id, related.stmt_id, related.symbol_ids
        ):
            kinds.add(_SHAPE_INDEXED_ACCESS)
        return kinds

    def _shape_allocation_events_from_related(
        self,
        target: PointerTarget,
        related: _PointerRelatedStmt,
        row: Any,
        operation: str,
    ) -> set[str]:
        direct_defined = set(
            self.context.get_stmt_direct_defined_symbol_ids(related.stmt_id)
        )
        if related.target_symbol_ids and not (
            direct_defined & related.target_symbol_ids
        ):
            return set()
        source = self._stmt_source_text(related.stmt_id)
        if operation == "call_stmt":
            callee = self._call_name(related.stmt_id, row)
            if callee in _ALLOCATORS or self._call_returns_heap_by_name(
                related.method_id, callee
            ):
                return set(
                    self._allocation_shape_events_from_call(
                        related.method_id,
                        callee,
                        self._call_arguments(row),
                        source,
                    ).kinds
                )
        if operation in {"assign_stmt", "variable_decl"}:
            rhs = self._source_assignment_rhs(source)
            if rhs:
                return set(
                    self._call_expression_shape_events(
                        related.method_id, rhs, max_depth=5
                    ).kinds
                )
        return set()

    def _call_shape_events_for_target(
        self,
        method_id: int,
        stmt_id: int,
        row: Any,
        names: set[str],
        *,
        max_depth: int,
    ) -> _PointerPointeeShapeEvents:
        callee = self._call_name(stmt_id, row)
        args = self._call_arguments(row)
        positions = [
            index
            for index, argument in enumerate(args)
            if self._mentions_alias(argument, names)
        ]
        if method_id and not positions:
            for index, argument in enumerate(args):
                if self._is_temp_name(argument) and self._temp_traces_to_pointer(
                    method_id, stmt_id, argument, names
                ):
                    positions.append(index)
        if not positions:
            return _PointerPointeeShapeEvents()

        kinds: set[str] = set()
        if callee in _STRING_FUNCTIONS:
            kinds.add(_SHAPE_STRING_ACCESS)
        if callee in _MEMORY_FUNCTIONS:
            kinds.add(_SHAPE_BYTE_BUFFER_ACCESS)
        if max_depth > 0:
            for position in positions:
                kinds.update(
                    self._project_parameter_shape_events(
                        callee, position, max_depth=max_depth - 1
                    ).kinds
                )
        if (
            callee not in _ALLOCATORS
            and callee not in _DEALLOCATORS
            and callee not in _CALL_ARGUMENT_ACCESS
            and not self._callee_method_ids_by_name(method_id, callee)
        ):
            kinds.add(_SHAPE_UNKNOWN)
        return _PointerPointeeShapeEvents(frozenset(kinds))

    def _project_parameter_shape_events(
        self, callee_name: str, argument_index: int, *, max_depth: int
    ) -> _PointerPointeeShapeEvents:
        if not callee_name or argument_index < 0 or max_depth <= 0:
            return _PointerPointeeShapeEvents()
        kinds: set[str] = set()
        for method_id in self._callee_method_ids_by_name(0, callee_name):
            parameters = self._parameters_in_source_order(method_id)
            if argument_index >= len(parameters):
                continue
            parameter = parameters[argument_index]
            parameter_id = self._positive_id(getattr(parameter, "stmt_id", None))
            parameter_name = self._field(parameter, "name")
            if parameter_id is None or not parameter_name:
                continue
            cache_key = (method_id, parameter_id, max_depth)
            cached = self._parameter_shape_events_cache.get(cache_key)
            if cached is None:
                cached = self._scan_parameter_shape_events(
                    method_id,
                    parameter_id,
                    parameter_name,
                    max_depth=max_depth - 1,
                )
                self._parameter_shape_events_cache[cache_key] = cached
            kinds.update(cached.kinds)
        return _PointerPointeeShapeEvents(frozenset(kinds))

    def _source_call_shape_events_for_target(
        self,
        method_id: int,
        source: str,
        names: set[str],
        *,
        max_depth: int,
    ) -> _PointerPointeeShapeEvents:
        if not source or not names or max_depth <= 0:
            return _PointerPointeeShapeEvents()
        kinds: set[str] = set()
        for callee in self._source_call_names(source):
            argument_lists = self._source_call_argument_lists(source, callee)
            for args in argument_lists:
                positions = [
                    index
                    for index, argument in enumerate(args)
                    if self._mentions_alias(argument, names)
                ]
                if not positions:
                    continue
                if callee in _STRING_FUNCTIONS:
                    kinds.add(_SHAPE_STRING_ACCESS)
                if callee in _MEMORY_FUNCTIONS:
                    kinds.add(_SHAPE_BYTE_BUFFER_ACCESS)
                for position in positions:
                    kinds.update(
                        self._project_parameter_shape_events(
                            callee,
                            position,
                            max_depth=max_depth - 1,
                        ).kinds
                    )
                if (
                    callee not in _ALLOCATORS
                    and callee not in _DEALLOCATORS
                    and callee not in _CALL_ARGUMENT_ACCESS
                    and not self._callee_method_ids_by_name(method_id, callee)
                ):
                    kinds.add(_SHAPE_UNKNOWN)
        return _PointerPointeeShapeEvents(frozenset(kinds))

    def _parameters_in_source_order(self, method_id: int) -> tuple[Any, ...]:
        return tuple(
            sorted(
                self.context.get_method_parameters(method_id),
                key=lambda parameter: (
                    self._numeric_field(parameter, "start_line", default=0),
                    self._numeric_field(parameter, "start_col", default=0),
                    self._numeric_field(parameter, "stmt_id", default=0),
                ),
            )
        )

    @staticmethod
    def _numeric_field(value: Any, field_name: str, *, default: int) -> int:
        raw = getattr(value, field_name, default) if value is not None else default
        try:
            return int(float(raw))
        except (TypeError, ValueError):
            return default

    def _scan_parameter_shape_events(
        self,
        method_id: int,
        parameter_id: int,
        parameter_name: str,
        *,
        max_depth: int,
    ) -> _PointerPointeeShapeEvents:
        if max_depth <= 0:
            return _PointerPointeeShapeEvents()
        target = PointerTarget(
            stmt_id=parameter_id,
            entity_id=parameter_id,
            unit_id=self.context.get_unit_id(parameter_id) or -1,
            method_id=method_id,
            name=parameter_name,
            c_type="",
            operation=PointerDeclarationOperation.PARAMETER_DECL,
            location=PointerLocation.PARAMETER,
        )
        kinds: set[str] = set()
        for related in self._collect_pointer_related_stmts(target, method_id):
            kinds.update(
                self._pointee_shape_events_from_related(
                    target, related, max_depth=max_depth
                )
            )
        return _PointerPointeeShapeEvents(frozenset(kinds))

    def _call_expression_shape_events(
        self, method_id: int, expression: str, *, max_depth: int
    ) -> _PointerPointeeShapeEvents:
        if max_depth <= 0:
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_UNKNOWN}))
        kinds: set[str] = set()
        for callee in self._source_call_names(expression):
            argument_lists = self._source_call_argument_lists(expression, callee)
            args = list(argument_lists[0]) if argument_lists else []
            if callee in _ALLOCATORS or self._call_returns_heap_by_name(
                method_id, callee
            ):
                kinds.update(
                    self._allocation_shape_events_from_call(
                        method_id, callee, args, expression
                    ).kinds
                )
            else:
                callee_ids = self._callee_method_ids_by_name(method_id, callee)
                if not callee_ids:
                    kinds.add(_SHAPE_UNKNOWN)
                for callee_id in callee_ids:
                    kinds.update(
                        self._method_return_shape_events(
                            callee_id, max_depth=max_depth - 1
                        ).kinds
                    )
        return _PointerPointeeShapeEvents(frozenset(kinds))

    def _allocation_shape_events_from_call(
        self,
        method_id: int,
        callee: str,
        args: list[str],
        source: str,
    ) -> _PointerPointeeShapeEvents:
        if callee in {"strdup", "strndup", "getline"}:
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_ALLOC_ARRAY}))
        if callee == "calloc":
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_ALLOC_ARRAY}))

        size_expr = args[0] if args else ""
        if not size_expr:
            for arg_list in self._source_call_argument_lists(source, callee):
                if arg_list:
                    size_expr = arg_list[0]
                    break
        if self._size_expr_is_array_allocation(size_expr):
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_ALLOC_ARRAY}))
        if self._size_expr_is_single_allocation(size_expr):
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_ALLOC_SINGLE}))
        if callee in _ALLOCATORS or self._call_returns_heap_by_name(method_id, callee):
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_UNKNOWN}))
        return _PointerPointeeShapeEvents()

    @staticmethod
    def _size_expr_is_array_allocation(size_expr: str) -> bool:
        text = str(size_expr or "")
        if not text:
            return False
        return "sizeof" in text and bool(re.search(r"[*+/]", text))

    @staticmethod
    def _size_expr_is_single_allocation(size_expr: str) -> bool:
        text = str(size_expr or "").strip()
        if not text:
            return False
        return bool(re.fullmatch(r"sizeof\s*\([^()]+\)", text))

    @staticmethod
    def _is_byte_like_pointer_type(c_type: str) -> bool:
        text = str(c_type or "").lower()
        return "*" in text and any(
            token in text
            for token in (
                "void",
                "char",
                "uint8_t",
                "int8_t",
                "byte",
                "unsigned char",
                "signed char",
            )
        )

    def _method_return_shape_events(
        self, method_id: int, *, max_depth: int
    ) -> _PointerPointeeShapeEvents:
        if max_depth <= 0:
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_UNKNOWN}))
        cache_key = (method_id, max_depth)
        cached = self._method_return_shape_events_cache.get(cache_key)
        if cached is not None:
            return cached

        kinds: set[str] = set()
        current_name = self.context.get_method_name(method_id) or ""
        for row in self.context.get_method_rows(method_id):
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if stmt_id is None:
                continue
            if self._text(getattr(row, "operation", "")) != "return_stmt":
                continue
            returned = self._source_return_expression(
                self._stmt_source_text(stmt_id)
            ) or self._field(row, "name", "value", "operand")
            if not returned or self._is_null(returned):
                continue
            if returned.startswith("&"):
                kinds.add(_SHAPE_ALLOC_SINGLE)
            elif self._source_call_names(returned):
                for callee in self._source_call_names(returned):
                    if callee == current_name:
                        continue
                kinds.update(
                    self._call_expression_shape_events(
                        method_id, returned, max_depth=max_depth - 1
                    ).kinds
                )
            else:
                kinds.update(
                    self._return_symbol_shape_events(
                        method_id,
                        stmt_id,
                        returned,
                        max_depth=max_depth - 1,
                    ).kinds
                )

        result = _PointerPointeeShapeEvents(frozenset(kinds))
        self._method_return_shape_events_cache[cache_key] = result
        return result

    def _return_symbol_shape_events(
        self, method_id: int, stmt_id: int, symbol_name: str, *, max_depth: int
    ) -> _PointerPointeeShapeEvents:
        kinds: set[str] = set()
        for symbol_id in self._return_symbol_ids_for_name(
            method_id, stmt_id, symbol_name
        ):
            kinds.update(
                self._trace_symbol_shape_by_id(
                    method_id,
                    stmt_id,
                    symbol_id,
                    max_depth=max_depth,
                ).kinds
            )
        return _PointerPointeeShapeEvents(frozenset(kinds))

    def _trace_symbol_shape_by_id(
        self, method_id: int, stmt_id: int, symbol_id: int, *, max_depth: int
    ) -> _PointerPointeeShapeEvents:
        if max_depth <= 0:
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_UNKNOWN}))
        kinds: set[str] = set()
        defining_ids = self.context.get_defined_stmt_ids_for_symbol(
            method_id, symbol_id
        )
        for def_stmt_id in sorted(defining_ids, reverse=True):
            if def_stmt_id >= stmt_id:
                continue
            row = self.context.get_stmt(def_stmt_id)
            operation = self._text(getattr(row, "operation", ""))
            if operation in {"field_write", "array_write"}:
                continue
            source = self._stmt_source_text(def_stmt_id)
            if operation == "call_stmt":
                callee = self._call_name(def_stmt_id, row)
                if callee in _ALLOCATORS or self._call_returns_heap_by_name(
                    method_id, callee
                ):
                    kinds.update(
                        self._allocation_shape_events_from_call(
                            method_id,
                            callee,
                            self._call_arguments(row),
                            source,
                        ).kinds
                    )
                    if kinds:
                        break
                else:
                    kinds.update(
                        self._call_expression_shape_events(
                            method_id, source, max_depth=max_depth - 1
                        ).kinds
                    )
                    if kinds:
                        break
            if operation in {"assign_stmt", "variable_decl"}:
                rhs = self._source_assignment_rhs(source)
                if self._source_call_names(rhs):
                    kinds.update(
                        self._call_expression_shape_events(
                            method_id, rhs, max_depth=max_depth - 1
                        ).kinds
                    )
                    if kinds:
                        break

            operand = self._field(row, "operand", "source", "value")
            if operand.startswith("&"):
                kinds.add(_SHAPE_ALLOC_SINGLE)
                break
            if self._is_temp_name(operand):
                kinds.update(
                    self._trace_temp_shape_events(
                        method_id,
                        def_stmt_id,
                        operand,
                        max_depth=max_depth - 1,
                    ).kinds
                )
                if kinds:
                    break
        return _PointerPointeeShapeEvents(frozenset(kinds))

    def _trace_temp_shape_events(
        self,
        method_id: int,
        assign_stmt_id: int,
        temp_name: str,
        *,
        max_depth: int,
    ) -> _PointerPointeeShapeEvents:
        if max_depth <= 0:
            return _PointerPointeeShapeEvents(frozenset({_SHAPE_UNKNOWN}))
        rows = self.context.get_method_rows(method_id)
        for row in reversed(rows):
            row_stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if row_stmt_id is None or row_stmt_id >= assign_stmt_id:
                continue
            if self._text(getattr(row, "target", "")) != temp_name:
                continue
            operation = self._text(getattr(row, "operation", ""))
            source = self._stmt_source_text(row_stmt_id)
            if operation == "call_stmt":
                callee = self._call_name(row_stmt_id, row)
                if callee in _ALLOCATORS or self._call_returns_heap_by_name(
                    method_id, callee
                ):
                    return self._allocation_shape_events_from_call(
                        method_id,
                        callee,
                        self._call_arguments(row),
                        source,
                    )
                return self._call_expression_shape_events(
                    method_id, source, max_depth=max_depth - 1
                )
            operand = self._field(row, "operand", "source", "value")
            if operand.startswith("&"):
                return _PointerPointeeShapeEvents(frozenset({_SHAPE_ALLOC_SINGLE}))
            if self._is_temp_name(operand):
                return self._trace_temp_shape_events(
                    method_id,
                    row_stmt_id,
                    operand,
                    max_depth=max_depth - 1,
                )
            break
        return _PointerPointeeShapeEvents()

    def _infer_lifetime(self, target: PointerTarget) -> Lifetime | None:
        if target.is_aggregate_member:
            return Lifetime.STORED

        events = self._collect_pointer_lifetime_events(target)
        if events.owned_source:
            return Lifetime.OWNED
        if events.static_source:
            return Lifetime.STATIC
        if events.local_source:
            if events.stored or events.returned:
                return Lifetime.UNKNOWN
            return Lifetime.LOCAL
        if events.param_source:
            return Lifetime.STORED if events.stored else Lifetime.PARAM
        if events.stored_source:
            return Lifetime.STORED
        if events.stored or events.returned:
            return Lifetime.STORED
        if events.unknown:
            return Lifetime.UNKNOWN
        if target.location is PointerLocation.GLOBAL:
            return Lifetime.UNKNOWN

        return None

    def _collect_pointer_lifetime_events(
        self, target: PointerTarget
    ) -> _PointerLifetimeEvents:
        cache_key = (target.stmt_id, target.name, target.location)
        cached = self._lifetime_events_cache.get(cache_key)
        if cached is not None:
            return cached

        kinds: set[str] = set()
        for method_id in self._pointer_analysis_method_ids(target):
            for related in self._collect_pointer_related_stmts(
                target, method_id
            ):
                kinds.update(self._lifetime_events_from_related(target, related))

        result = _PointerLifetimeEvents(frozenset(kinds))
        self._lifetime_events_cache[cache_key] = result
        return result

    def _lifetime_events_from_related(
        self, target: PointerTarget, related: _PointerRelatedStmt
    ) -> set[str]:
        access = self._classify_pointer_stmt_access(
            related,
            is_struct_member=target.is_aggregate_member,
            target_name=target.name,
        )
        kinds: set[str] = set()
        if access.returned:
            kinds.add(_LIFETIME_RETURNED)
        if access.stored:
            kinds.add(_LIFETIME_STORED)
        if access.passed_to_unknown_callee:
            kinds.add(_LIFETIME_UNKNOWN)
        if target.location is PointerLocation.PARAMETER and (
            access.returned
            or access.stored
            or access.pointer_read
            or access.pointer_written
            or access.pointee_read
            or access.pointee_written
        ):
            kinds.add(_LIFETIME_PARAM_SOURCE)

        origins = self._lifetime_origins_from_related(related)
        kinds.update(self._lifetime_events_from_origins(origins))
        return kinds

    def _lifetime_origins_from_related(
        self, related: _PointerRelatedStmt
    ) -> set[str]:
        row = self.context.get_stmt(related.stmt_id)
        operation = self._text(getattr(row, "operation", ""))
        if operation in {"assign_stmt", "variable_decl"}:
            rhs = self._source_assignment_rhs(
                self._stmt_source_text(related.stmt_id)
            )
            if self._source_call_names(rhs):
                return self._return_call_expression_origins(
                    related.method_id, rhs, max_depth=5
                )
        return self._ownership_origins_from_related(related)

    @staticmethod
    def _lifetime_events_from_origins(origins: set[str]) -> set[str]:
        kinds: set[str] = set()
        meaningful = origins - {"parameter_default"}
        if "heap" in meaningful:
            kinds.add(_LIFETIME_OWNED_SOURCE)
        if "static" in meaningful:
            kinds.add(_LIFETIME_STATIC_SOURCE)
        if "parameter" in meaningful:
            kinds.add(_LIFETIME_PARAM_SOURCE)
        if "local" in meaningful:
            kinds.add(_LIFETIME_LOCAL_SOURCE)
        if "field" in meaningful:
            kinds.add(_LIFETIME_STORED_SOURCE)
        if "call" in meaningful or "unknown" in meaningful:
            kinds.add(_LIFETIME_UNKNOWN)
        concrete = meaningful - {"unknown"}
        if len(concrete) > 1:
            kinds.add(_LIFETIME_UNKNOWN)
        return kinds

    def _infer_global_pointer_init_mode(
        self,
        target: PointerTarget,
    ) -> GlobalPointerInitMode | None:
        if target.location is not PointerLocation.GLOBAL:
            return None

        writes: list[tuple[int, Any]] = []
        lazy_write = False
        always_mutable = False
        for method_id in self._pointer_analysis_method_ids(target):
            for related in self._collect_pointer_related_stmts(
                target, method_id
            ):
                row = self.context.get_stmt(related.stmt_id)
                if row is None:
                    continue
                operation = self._text(getattr(row, "operation", ""))
                if self._row_mutates_pointer_value(row, {target.name}):
                    always_mutable = True
                if self._row_reassigns_pointer(row, {target.name}):
                    writes.append((related.stmt_id, row))
                    lazy_write |= self._has_prior_null_guard(
                        method_id, related.stmt_id, target.name
                    )

        if always_mutable:
            return GlobalPointerInitMode.ALWAYS_MUTABLE
        if len(writes) > 1:
            return GlobalPointerInitMode.RELOADABLE
        if len(writes) == 1:
            if lazy_write or self._global_pointer_decl_init_is_null(target):
                return GlobalPointerInitMode.LAZY_ONCE
            return GlobalPointerInitMode.RUNTIME_ONCE

        initializer = self._global_pointer_initializer(target)
        if not initializer:
            return GlobalPointerInitMode.NULL
        if self._is_null(initializer):
            return GlobalPointerInitMode.NULL
        return GlobalPointerInitMode.COMPILE_TIME

    def _global_pointer_decl_init_is_null(self, target: PointerTarget) -> bool:
        initializer = self._global_pointer_initializer(target)
        return bool(initializer) and self._is_null(initializer)

    def _global_pointer_initializer(self, target: PointerTarget) -> str:
        row = self.context.get_stmt(target.stmt_id)
        return self._field(
            row,
            "initializer",
            "init",
            "value",
            "operand",
            "source",
        )

    def _row_reassigns_pointer(self, row: Any, names: set[str]) -> bool:
        operation = self._text(getattr(row, "operation", ""))
        if operation in {"assign_stmt", "binary_expression", "type_cast_stmt"}:
            target_name = self._field(row, "target", "name")
            operator = self._field(row, "operator")
            if self._mentions_alias(target_name, names):
                return operator in {"", "=", ":=", "+=", "-="}
        if operation == "call_stmt":
            return self._row_defines_symbol(row, names)
        return False

    def _row_mutates_pointer_value(self, row: Any, names: set[str]) -> bool:
        operation = self._text(getattr(row, "operation", ""))
        operator = self._field(row, "operator")
        if operation in {"assign_stmt", "binary_expression"} and operator in {
            "+=",
            "-=",
        }:
            return self._mentions_alias(
                self._field(row, "target", "name"),
                names,
            )
        if operation == "unary_expression" and operator in {"++", "--"}:
            return self._mentions_alias(
                self._field(row, "target", "name", "operand", "source"),
                names,
            )
        return False

    def _has_prior_null_guard(
        self,
        method_id: int,
        stmt_id: int,
        pointer_name: str,
    ) -> bool:
        target_id = self._positive_id(stmt_id)
        if target_id is None:
            return False
        names = {pointer_name}
        for row in self.context.get_method_rows(method_id):
            row_id = self._positive_id(getattr(row, "stmt_id", None))
            if row_id is None or row_id >= target_id:
                continue
            operation = self._text(getattr(row, "operation", ""))
            if operation == "unary_expression" and self._field(row, "operator") == "!":
                if self._mentions_alias(
                    self._field(row, "operand", "source", "value", "name"),
                    names,
                ):
                    return True
            if operation in {"binary_expression", "assign_stmt"}:
                operator = self._field(row, "operator")
                if operator not in {"==", "!="}:
                    continue
                values = (
                    self._field(row, "target", "name"),
                    self._field(row, "operand", "source", "value"),
                    self._field(row, "operand2"),
                )
                if any(self._mentions_alias(value, names) for value in values) and any(
                    self._is_null(value) for value in values
                ):
                    return True
        return False

    def _append_usage_path(self, usage_path: list[str], stmt_id: int) -> None:
        source = " ".join(
            line.strip()
            for line in self.context.get_stmt_source(stmt_id)
            if line.strip()
        )
        if not source:
            source = self._structured_usage_evidence(stmt_id)
        if source and source not in usage_path:
            usage_path.append(source)

    def _structured_usage_evidence(self, stmt_id: int) -> str:
        row = self.context.get_stmt(stmt_id)
        if row is None:
            return ""
        operation = self._text(getattr(row, "operation", ""))
        if operation == "call_stmt":
            return self._render_call_evidence(stmt_id, row)
        if operation != "field_write":
            return ""

        method_id = self.context.get_method_id(stmt_id)
        source_value = self._field(row, "source", "value", "operand")
        if method_id is None or not source_value:
            return ""
        producer = self._call_producers(method_id).get(source_value)
        if producer is None:
            return ""
        callee, arguments = producer
        return f"{callee}({', '.join(arguments)})"

    def _call_producers(
        self,
        method_id: int,
    ) -> dict[str, tuple[str, list[str]]]:
        cached = self._call_producers_by_method.get(method_id)
        if cached is not None:
            return cached
        result: dict[str, tuple[str, list[str]]] = {}
        for row in self.context.get_method_rows(method_id):
            if self._text(getattr(row, "operation", "")) != "call_stmt":
                continue
            target = self._field(row, "target")
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if not target or stmt_id is None:
                continue
            callee = self._call_name(stmt_id, row)
            if callee:
                result[target] = (callee, self._call_arguments(row))
        self._call_producers_by_method[method_id] = result
        return result

    def _render_call_evidence(self, stmt_id: int, row: Any) -> str:
        callee = self._call_name(stmt_id, row)
        if not callee:
            return ""
        return f"{callee}({', '.join(self._call_arguments(row))})"

    def _call_name(self, stmt_id: int, row: Any) -> str:
        call_info = self.context.get_call_info(stmt_id)
        return self._field(
            call_info, "name", "callee", "callee_name"
        ) or self._field(row, "name", "callee", "callee_name")

    @staticmethod
    def _call_arguments(row: Any) -> list[str]:
        raw = getattr(row, "positional_args", None)
        if raw is None:
            return []
        if isinstance(raw, (list, tuple)):
            return [str(item) for item in raw]
        try:
            parsed = ast.literal_eval(str(raw))
        except (SyntaxError, ValueError, TypeError):
            return []
        if not isinstance(parsed, list):
            return []
        return [str(item) for item in parsed]

    @staticmethod
    def _mentions_alias(value: Any, aliases: set[str]) -> bool:
        if not aliases or value is None:
            return False
        text = str(value)
        if text in aliases:
            return True
        return bool(set(_TOKEN_PATTERN.findall(text)) & aliases)

    @staticmethod
    def _first_token(value: Any) -> str:
        match = _TOKEN_PATTERN.search(str(value or ""))
        return "" if match is None else match.group(0)

    @staticmethod
    def _field(value: Any, *field_names: str) -> str:
        for field_name in field_names:
            if isinstance(value, dict):
                raw = value.get(field_name)
            else:
                raw = getattr(value, field_name, None) if value is not None else None
            text = PointerAnalyzer._text(raw)
            if text:
                return text
        return ""

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        return "" if text == "nan" else text

    @staticmethod
    def _positive_id(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result > 0 else None

    @staticmethod
    def _lian_id(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return None if result in {-1, 0} else result

    @staticmethod
    def _is_null(value: Any) -> bool:
        return str(value or "").strip() in _NULL_VALUES

    @staticmethod
    def _is_string_literal(value: Any) -> bool:
        text = str(value or "").strip()
        return len(text) >= 2 and text[0] == '"' and text[-1] == '"'

    @staticmethod
    def _pointee_is_const(c_type: str) -> bool:
        text = " ".join(c_type.split())
        return bool(re.search(r"(?:^|\s)const(?:\s|$)", text))


class VariableAnalysisError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class _VariableRelatedStmt:
    method_id: int
    stmt_id: int
    symbol_ids: frozenset[int]
    target_symbol_ids: frozenset[int]
    matched_by_access_path: bool = False


@dataclasses.dataclass(frozen=True)
class _VariableAccess:
    read: bool = False
    written: bool = False
    maybe_written_by_call: bool = False
    has_lian_status: bool = False


_VARIABLE_READ = "read"
_VARIABLE_WRITTEN = "written"
_VARIABLE_UNKNOWN_CALL = "unknown_call"


@dataclasses.dataclass(frozen=True)
class _VariableMutabilityEvents:
    kinds: frozenset[str] = frozenset()

    def has(self, kind: str) -> bool:
        return kind in self.kinds

    @property
    def read(self) -> bool:
        return self.has(_VARIABLE_READ)

    @property
    def written(self) -> bool:
        return self.has(_VARIABLE_WRITTEN)

    @property
    def unknown_call(self) -> bool:
        return self.has(_VARIABLE_UNKNOWN_CALL)


class VariableAnalyzer:


    def __init__(
        self,
        context: AnalysisContext,
        *,
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.context = context
        self._progress = progress
        self._analysis_method_ids_cache: dict[int, tuple[int, ...]] = {}
        self._related_stmts_cache: dict[
            tuple[int, int], tuple[_VariableRelatedStmt, ...]
        ] = {}
        self._variable_access_cache: dict[int, _VariableAccess] = {}
        self._mutability_events_cache: dict[
            int, _VariableMutabilityEvents
        ] = {}
        self._stmt_access_cache: dict[
            tuple[int, int, tuple[int, ...], tuple[int, ...], bool],
            _VariableAccess,
        ] = {}
        self._method_touched_members_cache: dict[int, frozenset[str]] = {}
        self._methods_by_touched_member_cache: (
            dict[str, tuple[int, ...]] | None
        ) = None
        self._method_ids_by_name: dict[str, tuple[int, ...]] | None = None

    def analyze(self, target: VariableTarget) -> VariableAnalysisResult:
        self._validate_target(target)
        semantics = VariableDeclarationSemantics(
            stmt_id=target.stmt_id,
            name=target.name,
            operation=target.operation,
            is_struct_member=target.is_aggregate_member,
            mutability=self._infer_mutability(target),
            usage_path=self._collect_usage_path(target),
        )
        return VariableAnalysisResult(target=target, semantics=semantics)

    def analyze_all(
        self, targets: Iterable[VariableTarget]
    ) -> tuple[VariableAnalysisResult, ...]:
        targets = tuple(targets)
        results: list[VariableAnalysisResult] = []
        total = len(targets)
        for index, target in enumerate(targets, start=1):
            self._emit_progress(
                "variable",
                index,
                total,
                (
                    f"stmt={target.stmt_id} name={target.name} "
                    f"location={target.location.value}"
                ),
            )
            results.append(self.analyze(target))
        return tuple(results)

    def _emit_progress(
        self,
        kind: str,
        index: int,
        total: int,
        detail: str,
    ) -> None:
        if self._progress is not None:
            self._progress(f"analyzing {kind} {index}/{total}: {detail}")

    def _validate_target(self, target: VariableTarget) -> None:
        row = self.context.get_stmt(target.stmt_id)
        if row is None:
            raise VariableAnalysisError(
                f"variable target statement does not exist: {target.stmt_id}"
            )
        operation = self._text(getattr(row, "operation", ""))
        if operation != target.operation.value:
            raise VariableAnalysisError(
                f"variable target {target.stmt_id} operation mismatch: "
                f"target={target.operation.value}, GIR={operation!r}"
            )
        name = self._text(getattr(row, "name", ""))
        if name != target.name:
            raise VariableAnalysisError(
                f"variable target {target.stmt_id} name mismatch: "
                f"target={target.name!r}, GIR={name!r}"
            )

    def _infer_mutability(
        self, target: VariableTarget
    ) -> VariableMutability | None:
        if self._is_const_qualified(target.c_type):
            return VariableMutability.CONST

        events = self._collect_variable_mutability_events(target)
        if events.written:
            return VariableMutability.MUTABLE
        if target.is_aggregate_member and not events.read:
            return None
        return VariableMutability.CONST

    def _collect_variable_mutability_events(
        self, target: VariableTarget
    ) -> _VariableMutabilityEvents:
        cached = self._mutability_events_cache.get(target.stmt_id)
        if cached is not None:
            return cached

        kinds: set[str] = set()
        for method_id in self._analysis_method_ids(target):
            for related in self._collect_related_stmts(target, method_id):
                kinds.update(
                    self._variable_mutability_events_from_related(
                        target, related
                    )
                )

        result = _VariableMutabilityEvents(frozenset(kinds))
        self._mutability_events_cache[target.stmt_id] = result
        return result

    def _variable_mutability_events_from_related(
        self, target: VariableTarget, related: _VariableRelatedStmt
    ) -> set[str]:
        access = self._classify_stmt_access(target, related)
        kinds: set[str] = set()
        if access.read:
            kinds.add(_VARIABLE_READ)
        if access.written and not self._is_initializer_write(target, related):
            kinds.add(_VARIABLE_WRITTEN)
        if access.maybe_written_by_call:
            kinds.add(_VARIABLE_WRITTEN)
        elif self._is_unknown_call_use(target, related):
            kinds.add(_VARIABLE_UNKNOWN_CALL)
        return kinds

    def _is_initializer_write(
        self, target: VariableTarget, related: _VariableRelatedStmt
    ) -> bool:
        if related.stmt_id == target.stmt_id:
            return True
        row = self.context.get_stmt(related.stmt_id)
        if self._text(getattr(row, "operation", "")) != "assign_stmt":
            return False
        if not self._row_defines_target_name(row, target.name):
            return False
        target_source = self._stmt_source_text(target.stmt_id)
        related_source = self._stmt_source_text(related.stmt_id)
        if target_source and target_source == related_source:
            return True
        target_row = self.context.get_stmt(target.stmt_id)
        if target_row is None or row is None:
            return False
        return (
            self._positive_id(getattr(target_row, "start_row", None))
            == self._positive_id(getattr(row, "start_row", None))
            and self._positive_id(getattr(target_row, "end_row", None))
            == self._positive_id(getattr(row, "end_row", None))
        )

    def _is_unknown_call_use(
        self, target: VariableTarget, related: _VariableRelatedStmt
    ) -> bool:
        row = self.context.get_stmt(related.stmt_id)
        if self._text(getattr(row, "operation", "")) != "call_stmt":
            return False
        if not self._classify_stmt_access(target, related).read:
            return False
        callee = self._call_name(related.stmt_id, row)
        if callee in _MUTATING_ARGUMENTS:
            return False
        if callee in _CALL_ARGUMENT_ACCESS:
            return False
        if self._project_has_callee(callee):
            return False
        return True

    def _project_has_callee(self, callee_name: str) -> bool:
        return bool(self._method_ids_for_name(callee_name))

    def _method_ids_for_name(self, method_name: str) -> tuple[int, ...]:
        if not method_name:
            return ()
        if self._method_ids_by_name is None:
            ids_by_name: dict[str, list[int]] = {}
            for method_id in self.context.get_all_method_ids():
                name = self.context.get_method_name(method_id)
                if name:
                    ids_by_name.setdefault(name, []).append(method_id)
            self._method_ids_by_name = {
                name: tuple(ids) for name, ids in ids_by_name.items()
            }
        return self._method_ids_by_name.get(method_name, ())

    @staticmethod
    def _row_defines_target_name(row: Any, name: str) -> bool:
        target_name = PointerAnalyzer._field(row, "target", "name")
        return target_name == name or PointerAnalyzer._mentions_alias(
            target_name, {name}
        )

    def _collect_variable_access(
        self, target: VariableTarget
    ) -> _VariableAccess:
        cached = self._variable_access_cache.get(target.stmt_id)
        if cached is not None:
            return cached

        combined = _VariableAccess()
        for method_id in self._analysis_method_ids(target):
            for related in self._collect_related_stmts(target, method_id):
                access = self._classify_stmt_access(target, related)
                combined = _VariableAccess(
                    read=combined.read or access.read,
                    written=combined.written or access.written,
                    maybe_written_by_call=(
                        combined.maybe_written_by_call
                        or access.maybe_written_by_call
                    ),
                    has_lian_status=(
                        combined.has_lian_status or access.has_lian_status
                    ),
                )
        self._variable_access_cache[target.stmt_id] = combined
        return combined

    def _collect_usage_path(self, target: VariableTarget) -> list[str]:
        usage_path: list[str] = []
        for method_id in self._analysis_method_ids(target):
            for related in self._collect_related_stmts(target, method_id):
                self._append_usage_path(usage_path, related.stmt_id)
                if len(usage_path) >= 20:
                    return usage_path
        return usage_path

    def _analysis_method_ids(self, target: VariableTarget) -> tuple[int, ...]:
        cached = self._analysis_method_ids_cache.get(target.stmt_id)
        if cached is not None:
            return cached
        if target.method_id is not None:
            result = (target.method_id,)
            self._analysis_method_ids_cache[target.stmt_id] = result
            return result

        if target.is_aggregate_member:
            candidates = list(self._methods_touching_member(target.name))
            result = tuple(candidates) or tuple(self.context.get_all_method_ids())
            self._analysis_method_ids_cache[target.stmt_id] = result
            return result

        candidates: list[int] = []
        for method_id in self.context.get_all_method_ids():
            symbol_ids = self._target_symbol_ids(target, method_id)
            if not symbol_ids:
                continue
            summary = self.context.get_method_def_use_summary(method_id)
            if summary is None or set(symbol_ids) & self._summary_symbol_ids(summary):
                candidates.append(method_id)
        result = tuple(candidates) or tuple(self.context.get_all_method_ids())
        self._analysis_method_ids_cache[target.stmt_id] = result
        return result

    def _collect_related_stmts(
        self,
        target: VariableTarget,
        method_id: int,
    ) -> tuple[_VariableRelatedStmt, ...]:
        cache_key = (target.stmt_id, method_id)
        cached = self._related_stmts_cache.get(cache_key)
        if cached is not None:
            return cached

        if target.is_aggregate_member:
            result = self._collect_member_related_stmts(target, method_id)
            self._related_stmts_cache[cache_key] = result
            return result

        target_symbol_ids = self._target_symbol_ids(target, method_id)
        if not target_symbol_ids:
            self._related_stmts_cache[cache_key] = ()
            return ()

        related = self._collect_variable_related_stmts_by_index(
            method_id=method_id,
            target_symbol_ids=target_symbol_ids,
            exclude_stmt_id=target.stmt_id,
        )
        if related:
            self._related_stmts_cache[cache_key] = related
            return related
        result = self._collect_variable_related_stmts_by_status_scan(
            method_id=method_id,
            target_symbol_ids=target_symbol_ids,
            exclude_stmt_id=target.stmt_id,
        )
        self._related_stmts_cache[cache_key] = result
        return result

    def _collect_variable_related_stmts_by_index(
        self,
        *,
        method_id: int,
        target_symbol_ids: frozenset[int],
        exclude_stmt_id: int | None = None,
    ) -> tuple[_VariableRelatedStmt, ...]:
        related: dict[int, frozenset[int]] = {}
        for symbol_id in sorted(target_symbol_ids):
            candidate_stmt_ids = set(
                self.context.get_defined_stmt_ids_for_symbol(method_id, symbol_id)
            )
            candidate_stmt_ids.update(
                self.context.get_used_stmt_ids_for_symbol(method_id, symbol_id)
            )
            for stmt_id in sorted(candidate_stmt_ids):
                if stmt_id == exclude_stmt_id:
                    continue
                touched = self._stmt_touched_variable_symbols(
                    stmt_id, target_symbol_ids
                )
                if not touched:
                    continue
                related[stmt_id] = frozenset(
                    set(related.get(stmt_id, frozenset())) | touched
                )

        return tuple(
            _VariableRelatedStmt(
                method_id=method_id,
                stmt_id=stmt_id,
                symbol_ids=related[stmt_id],
                target_symbol_ids=target_symbol_ids,
            )
            for stmt_id in sorted(related)
        )

    def _collect_variable_related_stmts_by_status_scan(
        self,
        *,
        method_id: int,
        target_symbol_ids: frozenset[int],
        exclude_stmt_id: int | None = None,
    ) -> tuple[_VariableRelatedStmt, ...]:
        related: dict[int, frozenset[int]] = {}
        for stmt_id in self._status_stmt_ids(method_id):
            if stmt_id == exclude_stmt_id:
                continue
            touched = self._stmt_touched_variable_symbols(stmt_id, target_symbol_ids)
            if touched:
                related[stmt_id] = touched
        return tuple(
            _VariableRelatedStmt(
                method_id=method_id,
                stmt_id=stmt_id,
                symbol_ids=related[stmt_id],
                target_symbol_ids=target_symbol_ids,
            )
            for stmt_id in sorted(related)
        )

    def _collect_member_related_stmts(
        self,
        target: VariableTarget,
        method_id: int,
    ) -> tuple[_VariableRelatedStmt, ...]:
        related: list[_VariableRelatedStmt] = []
        for stmt_id in self._status_stmt_ids(method_id):
            if not self._stmt_mentions_member_path(target, method_id, stmt_id):
                continue
            symbol_ids = frozenset(
                self.context.get_stmt_direct_used_symbol_ids(stmt_id)
                + self.context.get_stmt_direct_defined_symbol_ids(stmt_id)
                + self.context.get_stmt_implicit_used_symbol_ids(stmt_id)
                + self.context.get_stmt_implicit_defined_symbol_ids(stmt_id)
            )
            related.append(
                _VariableRelatedStmt(
                    method_id=method_id,
                    stmt_id=stmt_id,
                    symbol_ids=symbol_ids,
                    target_symbol_ids=frozenset(),
                    matched_by_access_path=True,
                )
            )
        return tuple(related)

    def _stmt_touched_variable_symbols(
        self, stmt_id: int, target_symbol_ids: frozenset[int]
    ) -> frozenset[int]:
        direct_used = set(self.context.get_stmt_direct_used_symbol_ids(stmt_id))
        direct_defined = set(self.context.get_stmt_direct_defined_symbol_ids(stmt_id))
        implicit_used = set(self.context.get_stmt_implicit_used_symbol_ids(stmt_id))
        implicit_defined = set(
            self.context.get_stmt_implicit_defined_symbol_ids(stmt_id)
        )
        return frozenset(
            target_symbol_ids
            & (direct_used | direct_defined | implicit_used | implicit_defined)
        )

    def _classify_stmt_access(
        self,
        target: VariableTarget,
        related: _VariableRelatedStmt,
    ) -> _VariableAccess:
        cache_key = (
            target.stmt_id,
            related.stmt_id,
            tuple(sorted(related.symbol_ids)),
            tuple(sorted(related.target_symbol_ids)),
            related.matched_by_access_path,
        )
        cached = self._stmt_access_cache.get(cache_key)
        if cached is not None:
            return cached

        stmt_id = related.stmt_id
        row = self.context.get_stmt(stmt_id)
        operation = self._text(getattr(row, "operation", "")) if row else ""
        direct_used = set(self.context.get_stmt_direct_used_symbol_ids(stmt_id))
        implicit_used = set(
            self.context.get_stmt_implicit_used_symbol_ids(stmt_id)
        )
        direct_defined = set(
            self.context.get_stmt_direct_defined_symbol_ids(stmt_id)
        )
        implicit_defined = set(
            self.context.get_stmt_implicit_defined_symbol_ids(stmt_id)
        )
        target_ids = set(related.target_symbol_ids)

        read = bool((direct_used | implicit_used) & target_ids)
        written = bool((direct_defined | implicit_defined) & target_ids)

        if not written and related.matched_by_access_path:
            written = operation in {
                "assign_stmt",
                "array_write",
                "field_write",
                "mem_write",
            } and self._operation_writes_target_path(target, row)

        maybe_written_by_call = False
        if operation == "call_stmt" and read and not written:
            maybe_written_by_call = self._call_may_write_argument(target, row)

        result = _VariableAccess(
            read=read or related.matched_by_access_path,
            written=written,
            maybe_written_by_call=maybe_written_by_call,
            has_lian_status=bool(related.symbol_ids),
        )
        self._stmt_access_cache[cache_key] = result
        return result

    def _target_symbol_ids(
        self,
        target: VariableTarget,
        method_id: int,
    ) -> frozenset[int]:
        return frozenset(
            self.context.resolve_decl_symbol_ids(
                method_id,
                target.stmt_id,
                target.name,
            )
        )

    def _status_stmt_ids(self, method_id: int) -> tuple[int, ...]:
        statuses = self.context.get_preferred_stmt_statuses(method_id)
        return tuple(sorted(statuses))

    def _method_may_touch_member(self, method_id: int, member_name: str) -> bool:
        return member_name in self._method_touched_members(method_id)

    def _methods_touching_member(self, member_name: str) -> tuple[int, ...]:
        member = self._text(member_name)
        if not member:
            return ()
        return self._methods_by_touched_member().get(member, ())

    def _methods_by_touched_member(self) -> dict[str, tuple[int, ...]]:
        if self._methods_by_touched_member_cache is not None:
            return self._methods_by_touched_member_cache
        mutable: dict[str, list[int]] = {}
        for method_id in self.context.get_all_method_ids():
            for member in self._method_touched_members(method_id):
                mutable.setdefault(member, []).append(method_id)
        self._methods_by_touched_member_cache = {
            member: tuple(sorted(method_ids))
            for member, method_ids in mutable.items()
        }
        return self._methods_by_touched_member_cache

    def _method_touched_members(self, method_id: int) -> frozenset[str]:
        cached = self._method_touched_members_cache.get(method_id)
        if cached is not None:
            return cached
        members: set[str] = set()
        for stmt_id in self._status_stmt_ids(method_id):
            row = self.context.get_stmt(stmt_id)
            for field_name in (
                "field",
                "field_name",
                "target",
                "array",
                "address",
                "object",
                "receiver",
                "receiver_object",
                "source",
                "value",
                "operand",
                "name",
            ):
                members.update(
                    self._field_names_from_text(
                        self._text(getattr(row, field_name, ""))
                    )
                )
            for state_id in (
                *self.context.get_stmt_in_state_ids(stmt_id),
                *self.context.get_stmt_out_state_ids(stmt_id),
                *self.context.get_stmt_defined_state_ids(stmt_id),
            ):
                members.update(
                    self._field_names_from_text(
                        self.context.get_state_access_path(method_id, state_id)
                    )
                )
        result = frozenset(members)
        self._method_touched_members_cache[method_id] = result
        return result

    def _stmt_mentions_member_name(
        self, method_id: int, stmt_id: int, member_name: str
    ) -> bool:
        return self._stmt_mentions_member(method_id, stmt_id, member_name)

    def _stmt_mentions_member_path(
        self,
        target: VariableTarget,
        method_id: int,
        stmt_id: int,
    ) -> bool:
        return self._stmt_mentions_member(method_id, stmt_id, target.name)

    def _stmt_mentions_member(
        self,
        method_id: int,
        stmt_id: int,
        member: str,
    ) -> bool:
        for state_id in (
            *self.context.get_stmt_in_state_ids(stmt_id),
            *self.context.get_stmt_out_state_ids(stmt_id),
            *self.context.get_stmt_defined_state_ids(stmt_id),
        ):
            access_path = self.context.get_state_access_path(
                method_id, state_id
            )
            if self._access_path_mentions_member(access_path, member):
                return True
        return self._stmt_text_mentions_member(member, stmt_id)

    def _operation_writes_target_path(
        self,
        target: VariableTarget,
        row: Any | None,
    ) -> bool:
        if row is None:
            return False
        candidates = (
            "target",
            "array",
            "address",
            "field",
            "object",
            "receiver",
            "name",
        )
        for field_name in candidates:
            value = self._text(getattr(row, field_name, ""))
            if self._path_mentions_target(target, value):
                return True
        return False

    def _call_may_write_argument(
        self,
        target: VariableTarget,
        row: Any | None,
    ) -> bool:
        if row is None:
            return False
        callee = (
            self._text(getattr(row, "name", ""))
            or self._text(getattr(row, "callee", ""))
            or self._text(getattr(row, "target", ""))
        ).lower()
        writable = _MUTATING_ARGUMENTS.get(callee)
        if not writable:
            return False
        for index in writable:
            value = self._argument_value(row, index)
            if self._path_mentions_target(target, value):
                return True
        return False

    def _argument_value(self, row: Any, index: int) -> str:
        for field_name in (
            f"argument{index}",
            f"arg{index}",
            f"parameter{index}",
        ):
            value = self._text(getattr(row, field_name, ""))
            if value:
                return value
        arguments = getattr(row, "arguments", None)
        if isinstance(arguments, (list, tuple)) and index < len(arguments):
            return self._text(arguments[index])
        args = getattr(row, "args", None)
        if isinstance(args, (list, tuple)) and index < len(args):
            return self._text(args[index])
        return ""

    def _stmt_source_text(self, stmt_id: int) -> str:
        source = self.context.get_stmt_source(stmt_id)
        if isinstance(source, (tuple, list)):
            return " ".join(str(item).strip() for item in source if str(item).strip())
        return str(source or "").strip()

    def _call_name(self, stmt_id: int, row: Any) -> str:
        call_info = self.context.get_call_info(stmt_id)
        return PointerAnalyzer._field(
            call_info, "name", "callee", "callee_name"
        ) or PointerAnalyzer._field(row, "name", "callee", "callee_name")

    def _append_usage_path(self, usage_path: list[str], stmt_id: int) -> None:
        for line in self.context.get_stmt_source(stmt_id):
            text = self._text(line)
            if text and text not in usage_path:
                usage_path.append(text)
                return
        row = self.context.get_stmt(stmt_id)
        if row is None:
            return
        operation = self._text(getattr(row, "operation", ""))
        if operation and operation not in usage_path:
            usage_path.append(operation)

    def _stmt_text_mentions_member(
        self,
        member: str,
        stmt_id: int,
    ) -> bool:
        for line in self.context.get_stmt_source(stmt_id):
            if self._access_path_mentions_member(line, member):
                return True
        return False

    def _path_mentions_target(
        self,
        target: VariableTarget,
        value: str,
    ) -> bool:
        text = self._text(value)
        if not text:
            return False
        if target.is_aggregate_member:
            return self._access_path_mentions_member(text, target.name)
        return text == target.name or text.startswith(target.name + "[")

    @staticmethod
    def _access_path_mentions_member(value: str | None, member: str) -> bool:
        if not value or not member:
            return False
        return (
            value == member
            or value.endswith("." + member)
            or value.endswith("->" + member)
            or ("." + member + "[") in value
            or ("->" + member + "[") in value
        )

    @staticmethod
    def _field_names_from_text(value: Any) -> set[str]:
        text = str(value or "")
        if not text:
            return set()
        return {
            match.group(1)
            for match in re.finditer(
                r"(?:\.|->)\s*([A-Za-z_][A-Za-z0-9_]*)", text
            )
        }

    @staticmethod
    def _is_const_qualified(c_type: str) -> bool:
        return "const" in {
            token.lower()
            for token in c_type.replace("*", " ").replace("[", " ").split()
        }

    @staticmethod
    def _summary_symbol_ids(summary: Any) -> set[int]:
        result: set[int] = set()
        for field_name in (
            "parameter_symbol_ids",
            "local_symbol_ids",
            "defined_external_symbol_ids",
            "used_external_symbol_ids",
            "defined_global_symbol_ids",
            "used_global_symbol_ids",
        ):
            raw = getattr(summary, field_name, ())
            if raw is None:
                continue


            values = tuple(raw) if not isinstance(raw, (tuple, list)) else raw
            for value in values:
                try:
                    symbol_id = int(value)
                except (TypeError, ValueError):
                    continue
                if symbol_id not in {-1, 0}:
                    result.add(symbol_id)
        return result

    @staticmethod
    def _lian_id(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result != 0 else None

    @staticmethod
    def _positive_id(value: Any) -> int | None:
        try:
            result = int(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return result if result > 0 else None

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()
