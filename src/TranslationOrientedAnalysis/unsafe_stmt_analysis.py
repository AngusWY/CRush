from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable
from enum import Enum
from typing import Any, Callable

from .analysis_context import AnalysisContext
from .models import PointerAnalysisResult, UnsafeStmtAnalysisResult, UnsafeStmtTarget
from .semantic_hint_schemas import (
    ArrayReadHints,
    ArrayRole,
    ArrayWriteHints,
    AlignmentGuarantee,
    ArithmeticBaseObjectKind,
    ArithmeticBasePointeeShape,
    AssignmentFlowHints,
    BorrowKind,
    CallEffectHints,
    CallKind,
    CastKind,
    CStringRead,
    CStringReadRole,
    CStringTermination,
    DerivedPointerFacts,
    FieldReadHints,
    FieldWriteHints,
    MemoryReadHints,
    MemoryWriteHints,
    OriginKind,
    Ownership,
    PointerOffsetUnit,
    AddrOfHints,
    ReturnLifetimeHints,
    ReturnLifetimeKind,
    ReturnValueHints,
    StorageKind,
    TypeCastHints,
    TransferKind,
    UnsafeSemanticKind,
    UnsafeStmtOperation,
    UnsafeStmtSemantics,
    make_unsafe_stmt_semantics,
)


_POINTER_ARITHMETIC_OPERATORS = frozenset({"+", "-"})
_ALLOCATION_CALLEES = frozenset({"malloc", "calloc", "realloc"})
_DEALLOCATION_CALLEES = frozenset({"free"})
_BYTE_COPY_CALLEES = frozenset({"memcpy", "memmove", "bcopy"})
_BYTE_SET_CALLEES = frozenset({"memset", "bzero"})
_C_TYPE_KEYWORDS = frozenset(
    {
        "void",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "size_t",
        "ssize_t",
        "intptr_t",
        "uintptr_t",
        "bool",
        "_Bool",
    }
)


class UnsafeStmtAnalysisError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class _ArrayAlias:
    alias: str
    base: str
    base_path: str
    offset: str = "0"
    derived_from: str = ""
    stmt_id: int = -1

    @property
    def element_base(self) -> str:
        return self.base_path or self.base


@dataclasses.dataclass(frozen=True)
class _PointerAccess:
    base: str
    base_path: str
    offset: str = "0"
    alias: str = ""

    def element(self, index: str = "0") -> str:
        base_path = self.base_path or self.base
        combined = _combine_offsets(self.offset, "+", index or "0")
        return f"{base_path}[{combined}]"


@dataclasses.dataclass(frozen=True)
class _ReturnOrigin:
    expression: str
    semantic_source: str
    lian_access_path: str = ""


@dataclasses.dataclass(frozen=True)
class _UnsafeStmtLianFlow:
    stmt_id: int
    method_id: int | None
    direct_used_symbol_ids: tuple[int, ...] = ()
    implicit_used_symbol_ids: tuple[int, ...] = ()
    direct_defined_symbol_ids: tuple[int, ...] = ()
    implicit_defined_symbol_ids: tuple[int, ...] = ()
    used_symbol_names: tuple[str, ...] = ()
    defined_symbol_names: tuple[str, ...] = ()
    read_state_ids: tuple[int, ...] = ()
    written_state_ids: tuple[int, ...] = ()
    read_paths: tuple[str, ...] = ()
    written_paths: tuple[str, ...] = ()


class UnsafeStmtProgrammaticAnalyzer:


    def __init__(
        self,
        context: AnalysisContext,
        *,
        pointer_results: Iterable[PointerAnalysisResult] = (),
        progress: Callable[[str], None] | None = None,
    ) -> None:
        self.context = context
        self._progress = progress
        self._aliases_by_scope: dict[tuple[int, int], dict[str, _ArrayAlias]] = {}
        self._lian_flow_by_stmt: dict[int, _UnsafeStmtLianFlow] = {}
        self._state_origin_cache: dict[tuple[int, int], str] = {}
        self._reachability_cache: dict[tuple[int, int, int], bool] = {}
        self._param_rw_cache: dict[tuple[int, int], tuple[bool, bool]] = {}
        self._addr_escape_map: dict[int, list[str]] = {}
        self._temp_resolution_cache: dict[tuple[int, str], str] = {}
        self._all_units_type_rows: tuple[Any, ...] | None = None
        self._all_units_type_cache: dict[str, dict[str, str]] = {}
        self._rows_by_scope: dict[tuple[int, int], tuple[Any, ...]] = {}
        self._type_lookup_rows_cache: dict[
            tuple[int, int], tuple[Any, ...]
        ] = {}
        self._c_string_names_by_method: dict[int, set[str]] = {}
        self._c_string_field_names: set[str] = set()
        self._c_string_global_names: set[str] = set()
        for result in pointer_results:
            if result.semantics.string_semantics is None:
                continue
            target = result.target
            if target.method_id is not None:
                self._c_string_names_by_method.setdefault(
                    target.method_id,
                    set(),
                ).add(target.name)
            elif target.is_aggregate_member:
                self._c_string_field_names.add(target.name)
            else:
                self._c_string_global_names.add(target.name)

    def analyze(self, target: UnsafeStmtTarget) -> UnsafeStmtAnalysisResult:
        try:
            semantics = self._analyze_target(target)
        except Exception as exc:
            raise UnsafeStmtAnalysisError(
                f"failed to analyze unsafe stmt {target.stmt_id}: {exc}"
            ) from exc
        return UnsafeStmtAnalysisResult(target=target, semantics=semantics)

    def analyze_all(
        self, targets: Iterable[UnsafeStmtTarget]
    ) -> tuple[UnsafeStmtAnalysisResult, ...]:
        targets = tuple(targets)
        self._emit_progress(
            f"prebuilding unsafe stmt context for {len(targets)} targets"
        )
        self._prebuild_addr_escape_map(targets)
        results: list[UnsafeStmtAnalysisResult] = []
        total = len(targets)
        for index, target in enumerate(targets, start=1):
            self._emit_progress(
                "analyzing unsafe stmt "
                f"{index}/{total}: stmt={target.stmt_id} "
                f"operation={target.operation.value} "
                f"semantic_kind={target.semantic_kind.value}"
            )
            results.append(self.analyze(target))
        return tuple(results)

    def _emit_progress(self, message: str) -> None:
        if self._progress is not None:
            self._progress(message)

    def _cached_reachable(
        self, method_id: int, def_stmt: int, use_stmt: int
    ) -> bool:
        key = (method_id, def_stmt, use_stmt)
        cached = self._reachability_cache.get(key)
        if cached is not None:
            return cached
        result = self.context.definition_must_precede(method_id, def_stmt, use_stmt)
        self._reachability_cache[key] = result
        return result

    def _analyze_target(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        if target.operation is UnsafeStmtOperation.ASSIGN_STMT:
            return self._analyze_assign_stmt(target)
        if target.operation is UnsafeStmtOperation.MEM_READ:
            return self._analyze_mem_read(target)
        if target.operation is UnsafeStmtOperation.MEM_WRITE:
            return self._analyze_mem_write(target)
        if target.operation is UnsafeStmtOperation.ARRAY_READ:
            return self._analyze_array_read(target)
        if target.operation is UnsafeStmtOperation.ARRAY_WRITE:
            return self._analyze_array_write(target)





        if target.operation is UnsafeStmtOperation.RETURN_STMT:
            return self._analyze_return_stmt(target)
        if target.operation is UnsafeStmtOperation.ADDR_OF:
            return self._analyze_addr_of(target)
        if target.operation is UnsafeStmtOperation.TYPE_CAST_STMT:
            return self._analyze_type_cast_stmt(target)
        if target.operation is UnsafeStmtOperation.FIELD_READ:
            return self._analyze_field_read(target)
        if target.operation is UnsafeStmtOperation.FIELD_WRITE:
            return self._analyze_field_write(target)

        return self._make_semantics(
            target,
            semantic_hints={},
            agent_missing_fields=(),
        )

    def _analyze_assign_stmt(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        flow = self._lian_stmt_flow(target)
        defined_names = flow.defined_symbol_names
        used_names = flow.used_symbol_names
        lian_write_path = self._preferred_lian_access_path(flow.written_paths)
        lian_read_path = self._preferred_lian_access_path(flow.read_paths)
        alias = self._alias_for_stmt(target)
        if alias is None:
            alias = self._lian_alias_for_stmt(
                target,
                lian_write_path=lian_write_path,
                lian_read_path=lian_read_path,
            )
        arith_base = self._assignment_pointer_arith_base(target, alias)
        hints = self._assignment_arith_hints(target, arith_base)
        facts: dict[str, Any] = {
            "lian_defined_symbols": list(defined_names),
            "lian_used_symbols": list(used_names),
            "lian_write_path": lian_write_path or None,
            "lian_write_paths": list(flow.written_paths) or None,
            "lian_read_path": lian_read_path or None,
            "lian_read_paths": list(flow.read_paths) or None,
            "pointer_arith_base": arith_base or None,
        }
        if alias is not None:
            facts["array_alias"] = {
                "alias": alias.alias,
                "base": alias.base,
                "base_path": alias.base_path,
                "offset": alias.offset,
                "derived_from": alias.derived_from,
            }
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts=facts,
            agent_missing_fields=self._missing_hint_fields(
                hints.to_fields(),
                ("arith_base_pointee_shape", "arith_base_object_kind"),
            )
            if arith_base
            else (),
            semantic_kind=(
                UnsafeSemanticKind.ARRAY_ALIAS
                if alias is not None
                else target.semantic_kind
            ),
        )

    def _analyze_mem_read(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        address = self._first(target.raw_gir, "address", "source", "operand")
        flow = self._lian_stmt_flow(target)
        access = self._pointer_access(target, address)
        lian_path = self._preferred_lian_access_path(flow.read_paths)
        hints = MemoryReadHints(
            address_origin_expr=self._address_origin_expr(
                target, address, flow=flow
            )
            or None,
        )
        if lian_path:
            hints.resolves_to_element = lian_path
            hints.array_role = self._array_role_from_path(target, lian_path)
        elif access is not None:
            element = access.element()
            hints.array_role = (
                ArrayRole.ALIAS
                if access.alias
                else self._array_role(target, access.base)
            )
            hints.resolves_to_element = element
        else:

            hints.array_role = self._array_role(target, address)
            if not hints.resolves_to_element and address:
                hints.resolves_to_element = self._resolve_temp_in_str(
                    target, f"*{address}"
                )
        hints.c_string_read = self._c_string_read(
            target,
            buffer=(
                hints.address_origin_expr
                or self._array_base_from_element(hints.resolves_to_element or "")
                or address
            ),
            access_index="0",
        )
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "lian_read_path": lian_path or None,
                "lian_read_paths": list(flow.read_paths) or None,
                "lian_used_symbols": list(flow.used_symbol_names) or None,
            },
            agent_missing_fields=self._mem_read_missing_fields(
                target,
                address=address,
                hints=hints,
            ),
        )

    def _analyze_mem_write(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        address = self._first(target.raw_gir, "address", "target", "operand")
        source = self._first(target.raw_gir, "source", "value", "operand")
        flow = self._lian_stmt_flow(target)
        access = self._pointer_access(target, address)
        lian_path = self._preferred_lian_access_path(flow.written_paths)
        hints = MemoryWriteHints(
            write_source_deps=self._write_source_deps(
                target,
                source=source,
                exclude_names={address},
                written_path=lian_path,
                lian_read_paths=flow.read_paths,
                flow=flow,
            ),
            address_origin_expr=self._address_origin_expr(
                target, address, flow=flow
            )
            or None,
        )
        if lian_path:
            hints.resolves_to_element = lian_path
            hints.array_role = self._array_role_from_path(target, lian_path)
        elif access is not None:
            element = access.element()
            hints.array_role = (
                ArrayRole.ALIAS
                if access.alias
                else self._array_role(target, access.base)
            )
            hints.resolves_to_element = element
        else:

            hints.array_role = self._array_role(target, address)
            if not hints.resolves_to_element and address:
                hints.resolves_to_element = self._resolve_temp_in_str(
                    target, f"*{address}"
                )
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "lian_write_path": lian_path or None,
                "lian_write_paths": list(flow.written_paths) or None,
                "lian_read_paths": list(flow.read_paths) or None,
                "lian_used_symbols": list(flow.used_symbol_names) or None,
                "lian_defined_symbols": list(flow.defined_symbol_names) or None,
            },
            agent_missing_fields=self._mem_write_missing_fields(
                target,
                address=address,
                source=source,
                hints=hints,
            ),
        )

    def _analyze_array_read(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        array = self._first(target.raw_gir, "array", "receiver_object")
        index = self._first(target.raw_gir, "index", "offset")
        flow = self._lian_stmt_flow(target)
        lian_path = self._preferred_lian_access_path(flow.read_paths)
        hints = self._array_access_hints(
            target,
            array=array,
            index=index,
            lian_path=lian_path,
        )
        hints.c_string_read = self._c_string_read(
            target,
            buffer=(
                self._array_base_from_element(hints.resolves_to_element or "")
                or array
            ),
            access_index=index or "0",
        )
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "lian_read_path": lian_path or None,
                "lian_read_paths": list(flow.read_paths) or None,
                "lian_used_symbols": list(flow.used_symbol_names) or None,
            },
            agent_missing_fields=self._array_read_missing_fields(
                array=array,
                hints=hints,
            ),
        )

    def _analyze_array_write(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        array = self._first(target.raw_gir, "array", "receiver_object")
        index = self._first(target.raw_gir, "index", "offset")
        source = self._first(target.raw_gir, "source", "value", "operand")
        flow = self._lian_stmt_flow(target)
        lian_path = self._preferred_lian_access_path(flow.written_paths)
        lian_read_paths = list(flow.read_paths)
        access_hints = self._array_access_hints(
            target,
            array=array,
            index=index,
            lian_path=lian_path,
        )
        hints = ArrayWriteHints(
            array_role=access_hints.array_role,
            resolves_to_element=access_hints.resolves_to_element,
            write_source_deps=self._write_source_deps(
                target,
                source=source,
                lian_read_paths=lian_read_paths,
                exclude_names={array, index},
                written_path=access_hints.resolves_to_element or lian_path,
                flow=flow,
            ),
            c_string_termination=self._c_string_termination(
                target,
                array=array,
                index=index,
                source=source,
                write_target=(
                    access_hints.resolves_to_element or lian_path
                ),
            ),
        )
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "lian_write_path": lian_path or None,
                "lian_write_paths": list(flow.written_paths) or None,
                "lian_read_paths": lian_read_paths or None,
                "lian_used_symbols": list(flow.used_symbol_names) or None,
                "lian_defined_symbols": list(flow.defined_symbol_names) or None,
            },
            agent_missing_fields=self._array_write_missing_fields(
                array=array,
                source=source,
                hints=hints,
            ),
        )

    def _analyze_call_stmt(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        callee = self._call_name(target).lower()
        args = self._call_args(target.raw_gir)
        call_kind = self._call_kind(callee)
        hints = CallEffectHints(call_kind=call_kind)

        if callee in _ALLOCATION_CALLEES:
            recipient = self._first(target.raw_gir, "target")
            hints.target_symbol = recipient or None
            hints.ownership = Ownership.OWNED
            hints.origin_kind = OriginKind.CALL_RETURN
            hints.storage_kind = StorageKind.HEAP
            hints.transfer_kind = TransferKind.CREATE_OWNER
            hints.allocation_size_bytes = self._allocation_size(callee, args)
        elif callee in _DEALLOCATION_CALLEES:
            freed = args[0] if args else ""
            hints.target_symbol = freed or None
            hints.ownership = self._ownership_for_symbol(target, freed)
            hints.origin_kind = self._origin_kind_for_symbol(target, freed)
            hints.storage_kind = self._storage_kind_for_symbol(target, freed)
            hints.transfer_kind = TransferKind.END_OWNER_LIFETIME
        elif callee in {"memcpy", "memmove"} and len(args) >= 3:
            hints.target_symbol = args[0]
            hints.ownership = self._ownership_for_symbol(target, args[0])
            hints.origin_kind = self._origin_kind_for_symbol(target, args[0])
            hints.storage_kind = self._storage_kind_for_symbol(target, args[0])
            hints.source_storage_kind = self._storage_kind_for_symbol(target, args[1])
            hints.byte_count = args[2]
            hints.transfer_kind = TransferKind.MUTATE_OWNER_CONTENTS
            hints.arg_effects = [
                f"arg0:{args[0]}:write",
                f"arg1:{args[1]}:read",
                f"arg2:{args[2]}:byte_count",
            ]
        elif callee == "memset" and len(args) >= 3:
            hints.target_symbol = args[0]
            hints.ownership = self._ownership_for_symbol(target, args[0])
            hints.origin_kind = self._origin_kind_for_symbol(target, args[0])
            hints.storage_kind = self._storage_kind_for_symbol(target, args[0])
            hints.byte_count = args[2]
            hints.transfer_kind = TransferKind.MUTATE_OWNER_CONTENTS
            hints.arg_effects = [
                f"arg0:{args[0]}:write",
                f"arg1:{args[1]}:fill_value",
                f"arg2:{args[2]}:byte_count",
            ]
        elif callee == "bcopy" and len(args) >= 3:
            hints.target_symbol = args[1]
            hints.ownership = self._ownership_for_symbol(target, args[1])
            hints.origin_kind = self._origin_kind_for_symbol(target, args[1])
            hints.storage_kind = self._storage_kind_for_symbol(target, args[1])
            hints.source_storage_kind = self._storage_kind_for_symbol(target, args[0])
            hints.byte_count = args[2]
            hints.transfer_kind = TransferKind.MUTATE_OWNER_CONTENTS
            hints.arg_effects = [
                f"arg0:{args[0]}:read",
                f"arg1:{args[1]}:write",
                f"arg2:{args[2]}:byte_count",
            ]
        elif callee == "bzero" and len(args) >= 2:
            hints.target_symbol = args[0]
            hints.ownership = self._ownership_for_symbol(target, args[0])
            hints.origin_kind = self._origin_kind_for_symbol(target, args[0])
            hints.storage_kind = self._storage_kind_for_symbol(target, args[0])
            hints.byte_count = args[1]
            hints.transfer_kind = TransferKind.MUTATE_OWNER_CONTENTS
            hints.arg_effects = [
                f"arg0:{args[0]}:write",
                f"arg1:{args[1]}:byte_count",
            ]

        project_call_facts = self._project_internal_call_effects(
            target, callee, args
        )
        if project_call_facts:
            hints.arg_effects.extend(project_call_facts.get("arg_effects", []))
            hints.arg_borrows.extend(project_call_facts.get("arg_borrows", []))
            hints.arg_escapes.extend(project_call_facts.get("arg_escapes", []))
            if hints.transfer_kind is None and project_call_facts.get(
                "returns_argument"
            ):
                hints.transfer_kind = TransferKind.BORROW_ALIAS

        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "callee": callee or None,
                "args": args,
                "project_call": project_call_facts or None,
            },
            agent_missing_fields=self._call_missing_fields(
                callee=callee,
                call_kind=call_kind,
                args=args,
                hints=hints,
                project_call_facts=project_call_facts,
            ),
        )

    def _analyze_return_stmt(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        flow = self._lian_stmt_flow(target)
        value = self._return_value(target.raw_gir)
        if not value:
            used_names = flow.used_symbol_names
            value = used_names[0] if used_names else ""
        origin = self._return_origin(target, value, flow=flow)
        resolved_return_source = origin.semantic_source or origin.expression
        derived_pointer = self._derived_pointer_return_facts(target, origin)

        return_lifetime = (
            ReturnLifetimeHints(
                kind=ReturnLifetimeKind.PARAM,
                source=derived_pointer.borrow_source,
            )
            if derived_pointer is not None
            and derived_pointer.base_storage is StorageKind.PARAM
            else self._return_lifetime_hints(target, origin, flow=flow)
        )

        hints = ReturnValueHints(
            return_lifetime=return_lifetime,
            derived_pointer=derived_pointer,
        )
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "return_value": origin.expression or None,
                "resolved_return_source": resolved_return_source or None,
                "lian_return_access_path": origin.lian_access_path or None,
                "lian_read_paths": list(flow.read_paths) or None,
                "lian_used_symbols": list(flow.used_symbol_names) or None,
            },
            agent_missing_fields=self._return_missing_fields(
                value=resolved_return_source,
                hints=hints,
            ),
        )

    def _derived_pointer_return_facts(
        self,
        target: UnsafeStmtTarget,
        origin: _ReturnOrigin,
    ) -> DerivedPointerFacts | None:
        if target.method_id is None:
            return None

        method_row = self.context.get_stmt(target.method_id)
        result_c_type = self._first_from_row(
            method_row, "data_type", "default_data_type"
        ) if method_row is not None else ""
        result_pointee_type = self._pointer_pointee_type(result_c_type)
        if not result_pointee_type:
            return None

        base, offset = self._pointer_offset_origin_before(
            target, origin.expression
        )
        base = self._resolve_temp_name(target, base)
        offset = self._resolve_temp_in_str(target, offset)
        if not base or not offset:
            return None

        base_storage = self._storage_kind_for_symbol(target, base)
        if base_storage is not StorageKind.PARAM:
            return None

        base_c_type = self._value_type_for_name(target, base)
        if not self._is_byte_addressed_pointer_type(base_c_type):
            return None

        return DerivedPointerFacts(
            base=base,
            base_c_type=base_c_type,
            base_storage=base_storage,
            offset_expr=offset,
            offset_unit=PointerOffsetUnit.BYTES,
            result_c_type=result_c_type,
            access_width_expr=f"sizeof({result_pointee_type})",
            alignment_guarantee=AlignmentGuarantee.NOT_PROVEN,
            borrow_source=base,
        )

    @staticmethod
    def _pointer_pointee_type(c_type: str) -> str:
        text = re.sub(r"\b(?:const|volatile|restrict)\b", " ", c_type)
        star = text.rfind("*")
        if star <= 0:
            return ""
        return re.sub(r"\s+", " ", text[:star]).strip()

    @classmethod
    def _is_byte_addressed_pointer_type(cls, c_type: str) -> bool:
        pointee = cls._pointer_pointee_type(c_type).lower()
        return pointee in {
            "void",
            "char",
            "signed char",
            "unsigned char",
            "int8_t",
            "uint8_t",
        }

    def _prebuild_addr_escape_map(
        self, targets: tuple[UnsafeStmtTarget, ...]
    ) -> None:
        addr_targets = [
            t for t in targets
            if t.operation is UnsafeStmtOperation.ADDR_OF
            and t.stmt_id not in self._addr_escape_map
        ]
        if not addr_targets:
            return
        by_scope: dict[tuple[int, int], list[UnsafeStmtTarget]] = {}
        for t in addr_targets:
            scope_key = (t.unit_id, t.method_id or t.entity_id)
            by_scope.setdefault(scope_key, []).append(t)
        for scope_targets in by_scope.values():
            self._build_scope_addr_escapes(scope_targets)

    def _build_scope_addr_escapes(
        self, targets: list[UnsafeStmtTarget]
    ) -> None:
        first = targets[0]
        rows = self._rows_for_target(first)
        if not rows:
            return
        target_by_stmt: dict[int, UnsafeStmtTarget] = {
            t.stmt_id: t for t in targets
        }

        Pointers = dict[str, tuple[set[str], set[str], list[str]]]
        pointers: Pointers = {}

        def _ptr_name(target: UnsafeStmtTarget) -> str:
            fn = self._first(target.raw_gir, "target", "name")
            if fn:
                return fn
            flow = self._lian_flow_by_stmt.get(target.stmt_id)
            if flow is not None and flow.defined_symbol_names:
                return flow.defined_symbol_names[0]
            return ""

        def _add_escape(escapes: list[str], entry: str) -> None:
            if entry and entry not in escapes:
                escapes.append(entry)

        for row in rows:
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            op = self._text(getattr(row, "operation", ""))


            if stmt_id in target_by_stmt:
                t = target_by_stmt[stmt_id]
                pname = _ptr_name(t)
                if pname and pname not in pointers:
                    pointers[pname] = ({pname}, set(), [])


            for _pn, (_vals, _mem, _esc) in list(pointers.items()):
                if op == "return_stmt" and self._addr_expr_has_value_origin(
                    self._return_value_from_row(row), _vals, _mem
                ):
                    _add_escape(_esc, "returned")

                elif op == "call_stmt":
                    callee = self._first_from_row(row, "name", "callee", "callee_name")
                    for idx, arg in enumerate(
                        self._call_args(self._row_to_raw(row))
                    ):
                        if self._addr_expr_has_value_origin(arg, _vals, _mem):
                            ct = f"{callee}(arg{idx})" if callee else f"arg{idx}"
                            _add_escape(_esc, f"passed_to_call:{ct}")

                elif op == "assign_stmt":
                    src = self._first_from_row(
                        row, "source", "operand", "value", "address"
                    )
                    tgt = self._assignment_target(row)
                    if tgt and self._addr_expr_has_value_origin(src, _vals, _mem):
                        if (
                            self._storage_kind_for_symbol(first, tgt)
                            is StorageKind.GLOBAL
                        ):
                            _add_escape(_esc, f"stored_global:{tgt}")
                            _mem.add(tgt)
                        else:
                            _vals.add(tgt)

                elif op == "type_cast_stmt":
                    src = self._first_from_row(
                        row, "source", "operand", "value", "address"
                    )
                    tgt = self._assignment_target(row)
                    if tgt and self._addr_expr_has_value_origin(src, _vals, _mem):
                        _vals.add(tgt)

                elif op == "field_write":
                    receiver = self._first_from_row(row, "receiver_object", "object")
                    field = self._first_from_row(row, "field", "field_name")
                    member = self._member_path(receiver, field)
                    src = self._first_from_row(row, "source", "value", "operand")
                    if self._addr_expr_has_value_origin(src, _vals, _mem):
                        if member:
                            _add_escape(_esc, f"stored_field:{member}")
                            _mem.add(member)
                        else:
                            _add_escape(_esc, "stored_field")

                elif op == "field_read":
                    receiver = self._first_from_row(row, "receiver_object", "object")
                    field = self._first_from_row(row, "field", "field_name")
                    member = self._member_path(receiver, field)
                    tgt = self._assignment_target(row)
                    if tgt and member in _mem:
                        _vals.add(tgt)

                elif op == "array_write":
                    arr = self._first_from_row(row, "array", "receiver_object")
                    idx = self._first_from_row(row, "index", "offset")
                    element = f"{arr}[{idx or '0'}]" if arr else ""
                    src = self._first_from_row(row, "source", "value", "operand")
                    if self._addr_expr_has_value_origin(src, _vals, _mem):
                        if element:
                            _add_escape(_esc, f"stored_array:{element}")
                            _mem.add(element)
                        else:
                            _add_escape(_esc, "stored_array")

                elif op == "array_read":
                    arr = self._first_from_row(row, "array", "receiver_object")
                    idx = self._first_from_row(row, "index", "offset")
                    element = f"{arr}[{idx or '0'}]" if arr else ""
                    tgt = self._assignment_target(row)
                    if tgt and element in _mem:
                        _vals.add(tgt)

                elif op == "mem_write":
                    address = self._first_from_row(
                        row, "address", "target", "operand"
                    )
                    src = self._first_from_row(row, "source", "value", "operand")
                    if self._addr_expr_has_value_origin(src, _vals, _mem):
                        escaped_to = f"*{address}" if address else "*"
                        _add_escape(_esc, f"stored_indirect:{escaped_to}")


            if stmt_id in target_by_stmt:
                t = target_by_stmt[stmt_id]
                pname = _ptr_name(t)
                if pname and pname in pointers:
                    self._addr_escape_map[stmt_id] = list(
                        _dedupe(pointers[pname][2])
                    )

    def _analyze_addr_of(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        flow = self._lian_stmt_flow(target)
        source = self._first(target.raw_gir, "source", "address", "operand")
        if not source:
            used_names = flow.used_symbol_names
            source = used_names[0] if used_names else ""
        target_name = self._first(target.raw_gir, "target", "name")
        if not target_name:
            defined_names = flow.defined_symbol_names
            target_name = defined_names[0] if defined_names else ""
        lian_source_path = self._preferred_lian_access_path(flow.read_paths)
        cached_escapes = self._addr_escape_map.get(target.stmt_id)
        if cached_escapes is not None:
            escapes = list(cached_escapes)
        else:
            escapes = self._addr_escapes(target, target_name)
        hints = AddrOfHints(escape=escapes)
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "address_source": source or None,
                "address_target": target_name or None,
                "lian_source_path": lian_source_path or None,
                "lian_read_paths": list(flow.read_paths) or None,
                "lian_write_paths": list(flow.written_paths) or None,
                "lian_used_symbols": list(flow.used_symbol_names) or None,
                "lian_defined_symbols": list(flow.defined_symbol_names) or None,
            },
            agent_missing_fields=self._addr_of_missing_fields(
                target_name=target_name,
                hints=hints,
            ),
        )

    def _analyze_type_cast_stmt(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        source = self._first(target.raw_gir, "source", "operand", "value", "address")
        if not source:
            used_names = self.context.get_stmt_used_symbol_names(target.stmt_id)
            source = used_names[0] if used_names else ""
        lian_source_path = self._legacy_lian_access_path_for_stmt(
            target, mode="read"
        )
        target_type = self._first(target.raw_gir, "data_type", "target_type")
        source_type = self._value_type_for_name(target, source)
        if not source_type and lian_source_path:
            source_type = self._value_type_for_name(
                target, self._path_base(lian_source_path)
            )
        cast_kind = self._cast_kind(source_type, target_type)
        offset_base, offset = self._pointer_offset_origin_before(target, source)
        if not offset_base and lian_source_path:
            offset_base, offset = self._split_lian_offset_path(lian_source_path)
        hints = TypeCastHints(
            cast_kind=cast_kind,
            offset_base=offset_base or None,
            offset=offset or None,
            constraints=self._type_cast_constraints(cast_kind, target_type),
        )
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "source": source or None,
                "source_c_type": source_type or None,
                "target_c_type": target_type or None,
                "lian_source_path": lian_source_path or None,
                "lian_used_symbols": list(
                    self.context.get_stmt_used_symbol_names(target.stmt_id)
                ),
                "lian_defined_symbols": list(
                    self.context.get_stmt_defined_symbol_names(target.stmt_id)
                ),
            },
            agent_missing_fields=self._type_cast_missing_fields(
                source=source,
                target_type=target_type,
                hints=hints,
            ),
        )

    def _analyze_field_read(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        receiver = self._first(target.raw_gir, "receiver_object", "object")
        field = self._first(target.raw_gir, "field", "field_name")
        target_name = self._first(target.raw_gir, "target", "name")
        flow = self._lian_stmt_flow(target)
        lian_read_path = self._preferred_lian_access_path(flow.read_paths)
        member = self._member_path(receiver, field) or lian_read_path
        is_pointer_field = self._field_is_pointer_from_context(
            target,
            receiver=receiver,
            field=field or self._path_field(lian_read_path),
            member=member,
            access_path=lian_read_path,
            value_name=target_name,
            flow=flow,
        )
        hints = FieldReadHints(
            is_pointer_field=is_pointer_field,
        )
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts={
                "member": member or None,
                "lian_read_path": lian_read_path or None,
                "lian_read_paths": list(flow.read_paths) or None,
                "lian_used_symbols": list(flow.used_symbol_names) or None,
                "lian_defined_symbols": list(flow.defined_symbol_names) or None,
            },
            agent_missing_fields=self._field_read_missing_fields(
                member=member,
                hints=hints,
            ),
        )

    def _analyze_field_write(self, target: UnsafeStmtTarget) -> UnsafeStmtSemantics:
        receiver = self._first(target.raw_gir, "receiver_object", "object")
        field = self._first(target.raw_gir, "field", "field_name")
        source = self._first(target.raw_gir, "source", "value", "operand")
        flow = self._lian_stmt_flow(target)
        lian_write_path = self._preferred_lian_access_path(flow.written_paths)
        lian_read_path = self._preferred_lian_access_path(flow.read_paths)
        member = self._member_path(receiver, field) or lian_write_path
        alias = self._alias_for_stmt(target)
        is_pointer_field = self._field_is_pointer_from_context(
            target,
            receiver=receiver,
            field=field or self._path_field(lian_write_path),
            member=member,
            access_path=lian_write_path,
            flow=flow,
        )
        write_source_deps = self._write_source_deps(
            target,
            source=source,
            lian_read_paths=flow.read_paths,
            exclude_names={receiver, self._path_base(member), member},
            written_path=lian_write_path or member,
            flow=flow,
        )
        hints = FieldWriteHints(
            is_pointer_field=is_pointer_field,
            establishes_alias=self._field_write_establishes_alias(
                target,
                source=source,
                is_pointer_field=is_pointer_field,
                lian_read_path=lian_read_path,
                alias=alias,
                flow=flow,
            ),
            write_source_deps=write_source_deps,
        )
        facts: dict[str, Any] = {
            "member": member or None,
            "lian_write_path": lian_write_path or None,
            "lian_write_paths": list(flow.written_paths) or None,
            "lian_read_path": lian_read_path or None,
            "lian_read_paths": list(flow.read_paths) or None,
            "lian_defined_symbols": list(flow.defined_symbol_names) or None,
            "lian_used_symbols": list(flow.used_symbol_names) or None,
        }
        if alias is not None:
            facts["array_alias"] = {
                "alias": alias.alias,
                "base": alias.base,
                "base_path": alias.base_path,
                "offset": alias.offset,
                "derived_from": alias.derived_from,
            }
        return self._make_semantics(
            target,
            semantic_hints=hints.to_fields(),
            programmatic_facts=facts,
            agent_missing_fields=self._field_write_missing_fields(
                member=member,
                source=source,
                hints=hints,
            ),
            semantic_kind=(
                UnsafeSemanticKind.ARRAY_ALIAS
                if alias is not None
                else target.semantic_kind
            ),
        )

    def _mem_read_missing_fields(
        self,
        target: UnsafeStmtTarget,
        *,
        address: str,
        hints: MemoryReadHints,
    ) -> tuple[str, ...]:
        fields: list[str] = []
        if self._address_may_need_resolution(target, address):
            if hints.array_role is None:
                fields.append("array_role")
            if not hints.resolves_to_element:
                fields.append("resolves_to_element")
            if not hints.address_origin_expr:
                fields.append("address_origin_expr")
        return tuple(fields)

    def _mem_write_missing_fields(
        self,
        target: UnsafeStmtTarget,
        *,
        address: str,
        source: str,
        hints: MemoryWriteHints,
    ) -> tuple[str, ...]:
        fields = list(
            self._mem_read_missing_fields(
                target,
                address=address,
                hints=MemoryReadHints(
                    array_role=hints.array_role,
                    resolves_to_element=hints.resolves_to_element,
                    address_origin_expr=hints.address_origin_expr,
                ),
            )
        )
        if (
            self._value_may_need_dependency_trace(source)
            and not hints.write_source_deps
        ):
            fields.append("write_source_deps")
        return tuple(fields)

    def _array_read_missing_fields(
        self,
        *,
        array: str,
        hints: ArrayReadHints,
    ) -> tuple[str, ...]:
        if not array:
            return ()
        fields: list[str] = []
        if hints.array_role is None:
            fields.append("array_role")
        if not hints.resolves_to_element:
            fields.append("resolves_to_element")
        return tuple(fields)

    def _array_write_missing_fields(
        self,
        *,
        array: str,
        source: str,
        hints: ArrayWriteHints,
    ) -> tuple[str, ...]:
        fields = list(
            self._array_read_missing_fields(
                array=array,
                hints=ArrayReadHints(
                    array_role=hints.array_role,
                    resolves_to_element=hints.resolves_to_element,
                ),
            )
        )
        if (
            self._value_may_need_dependency_trace(source)
            and not hints.write_source_deps
        ):
            fields.append("write_source_deps")
        return tuple(_dedupe(fields))

    def _call_missing_fields(
        self,
        *,
        callee: str,
        call_kind: CallKind,
        args: list[str],
        hints: CallEffectHints,
        project_call_facts: dict[str, Any],
    ) -> tuple[str, ...]:
        fields: list[str] = []
        hint_fields = hints.to_fields()
        if call_kind is CallKind.UNKNOWN and callee:
            fields.append("call_kind")
        if args and not hints.arg_effects and (
            project_call_facts or call_kind is CallKind.UNKNOWN
        ):
            fields.append("arg_effects")
        if self._is_missing_agent_value(hint_fields.get("transfer_kind")) and (
            call_kind is not CallKind.UNKNOWN or project_call_facts
        ):
            fields.append("transfer_kind")
        return tuple(_dedupe(fields))

    def _return_missing_fields(
        self,
        *,
        value: str,
        hints: ReturnValueHints,
    ) -> tuple[str, ...]:
        if not value or self._is_null_pointer_value(value):
            return ()
        return ()

    def _addr_of_missing_fields(
        self,
        *,
        target_name: str,
        hints: AddrOfHints,
    ) -> tuple[str, ...]:
        fields: list[str] = []
        if target_name and self._is_missing_agent_value(hints.escape):
            fields.append("escape")
        return tuple(fields)

    def _type_cast_missing_fields(
        self,
        *,
        source: str,
        target_type: str,
        hints: TypeCastHints,
    ) -> tuple[str, ...]:
        fields = list(
            self._missing_hint_fields(
                hints.to_fields(),
                ("cast_kind",),
            )
        )
        if source and target_type and hints.cast_kind in {
            CastKind.POINTER_TO_POINTER,
            CastKind.POINTER_TO_INTEGER,
            CastKind.INTEGER_TO_POINTER,
        }:
            if not hints.constraints:
                fields.append("constraints")
        return tuple(_dedupe(fields))

    def _field_read_missing_fields(
        self,
        *,
        member: str,
        hints: FieldReadHints,
    ) -> tuple[str, ...]:
        fields: list[str] = []
        if member and hints.is_pointer_field is None:
            fields.append("is_pointer_field")
        return tuple(fields)

    def _field_write_missing_fields(
        self,
        *,
        member: str,
        source: str,
        hints: FieldWriteHints,
    ) -> tuple[str, ...]:
        fields = list(
            self._field_read_missing_fields(
                member=member,
                hints=FieldReadHints(
                    is_pointer_field=hints.is_pointer_field,
                ),
            )
        )
        if hints.is_pointer_field is True and hints.establishes_alias is None:
            fields.append("establishes_alias")
        if (
            hints.is_pointer_field is True
            and self._value_may_need_dependency_trace(source)
            and not hints.write_source_deps
        ):
            fields.append("write_source_deps")
        return tuple(_dedupe(fields))

    @classmethod
    def _missing_hint_fields(
        cls,
        hints: dict[str, Any],
        candidate_fields: Iterable[str],
    ) -> tuple[str, ...]:
        return tuple(
            field
            for field in candidate_fields
            if cls._is_missing_agent_value(hints.get(field))
        )

    @staticmethod
    def _is_missing_agent_value(value: Any) -> bool:
        if value is None:
            return True
        if isinstance(value, Enum):
            return value.value == "unknown"
        if isinstance(value, str):
            return value.strip().lower() == "unknown"
        return False

    def _address_may_need_resolution(
        self,
        target: UnsafeStmtTarget,
        address: str,
    ) -> bool:
        address = self._text(address)
        if not address:
            return False
        if self._is_literal_value(address):
            return False
        if address.startswith("&") or "[" in address:
            return False
        return (
            self._is_temp_name(address)
            or self._storage_kind_for_symbol(target, address) is not None
            or self._has_prior_assignment(target, address)
        )

    def _value_may_need_dependency_trace(self, value: str) -> bool:
        value = self._text(value)
        if not value:
            return False
        if self._is_literal_value(value) or self._is_null_pointer_value(value):
            return False
        return True

    @staticmethod
    def _is_literal_value(value: str) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        if _is_int_literal(text):
            return True
        if (text.startswith('"') and text.endswith('"')) or (
            text.startswith("'") and text.endswith("'")
        ):
            return True
        return text in {"true", "false"}

    def _make_semantics(
        self,
        target: UnsafeStmtTarget,
        *,
        semantic_hints: dict[str, Any],
        programmatic_facts: dict[str, Any] | None = None,
        agent_missing_fields: Iterable[str] = (),
        semantic_kind: UnsafeSemanticKind | None = None,
    ) -> UnsafeStmtSemantics:
        self._resolve_temp_in_hints(target, semantic_hints)
        return make_unsafe_stmt_semantics(
            stmt_id=target.stmt_id,
            entity_id=target.entity_id,
            operation=target.operation,
            semantic_kind=semantic_kind or target.semantic_kind,
            raw_gir=target.raw_gir,
            related_symbols=list(target.related_symbols),
            semantic_hints=semantic_hints,
            programmatic_facts=programmatic_facts,
            agent_missing_fields=list(agent_missing_fields),
        )

    def _resolve_temp_in_hints(
        self,
        target: UnsafeStmtTarget,
        hints: dict[str, Any],
    ) -> None:


        elem = hints.get("resolves_to_element")
        if isinstance(elem, str) and "%vv" in elem:
            hints["resolves_to_element"] = self._resolve_temp_in_str(
                target, elem
            )


        addr = hints.get("address_origin_expr")
        if isinstance(addr, str) and "%vv" in addr:
            hints["address_origin_expr"] = self._resolve_temp_in_str(
                target, addr
            )


        deps = hints.get("write_source_deps")
        if isinstance(deps, list):
            hints["write_source_deps"] = [
                self._resolve_temp_in_str(target, str(dep))
                if isinstance(dep, str) and "%vv" in dep
                else dep
                for dep in deps
            ]


        ob = hints.get("offset_base")
        if isinstance(ob, str) and "%vv" in ob:
            hints["offset_base"] = self._resolve_temp_in_str(target, ob)


        off = hints.get("offset")
        if isinstance(off, str) and "%vv" in off:
            hints["offset"] = self._resolve_temp_in_str(target, off)


        rl = hints.get("return_lifetime")
        if isinstance(rl, dict):
            rl_src = rl.get("source")
            if isinstance(rl_src, str) and "%vv" in rl_src:
                rl["source"] = self._resolve_temp_in_str(target, rl_src)

        c_string_read = hints.get("c_string_read")
        if isinstance(c_string_read, dict):
            for field_name in ("buffer", "access_index"):
                value = c_string_read.get(field_name)
                if isinstance(value, str) and "%vv" in value:
                    c_string_read[field_name] = self._resolve_temp_in_str(
                        target,
                        value,
                    )

    def _resolve_temp_in_str(self, target: UnsafeStmtTarget, value: str) -> str:

        if not value or "%vv" not in value:
            return value

        result = value
        seen: set[str] = set()
        for _ in range(16):
            if "%vv" not in result:
                break
            prev = result

            def _replace(match: re.Match[str]) -> str:
                temp_name = match.group(0)
                resolved = self._resolve_temp_name(target, temp_name)
                if resolved and resolved != temp_name:
                    return resolved
                return temp_name

            result = re.sub(r"%vv\d+", _replace, prev)
            if result == prev:
                break

            if result in seen:
                break
            seen.add(result)

        return result

    def _aliases_for_target(self, target: UnsafeStmtTarget) -> dict[str, _ArrayAlias]:
        key = (target.unit_id, target.method_id or target.entity_id)
        if key not in self._aliases_by_scope:
            self._aliases_by_scope[key] = self._build_aliases(target)
        return self._aliases_by_scope[key]

    def _build_aliases(self, target: UnsafeStmtTarget) -> dict[str, _ArrayAlias]:
        aliases: dict[str, _ArrayAlias] = {}
        temp_origins: dict[str, _ArrayAlias] = {}
        rows = self._rows_for_target(target)
        pointer_names = self._pointer_decl_names(rows)
        array_names = self._array_decl_names(rows)

        for row in rows:
            op = self._text(getattr(row, "operation", ""))
            if op not in {"assign_stmt", "field_write"}:
                continue
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            target_name = self._assignment_target(row)
            source = self._first_from_row(row, "source", "operand", "value")
            operator = self._text(getattr(row, "operator", ""))
            operand = self._first_from_row(row, "operand", "source")
            operand2 = self._first_from_row(row, "operand2")

            alias = self._alias_from_assignment(
                target_name=target_name,
                source=source,
                operator=operator,
                operand=operand,
                operand2=operand2,
                stmt_id=stmt_id,
                aliases=aliases,
                temp_origins=temp_origins,
                pointer_names=pointer_names,
                array_names=array_names,
            )
            if alias is None:
                continue
            if self._is_temp_name(alias.alias):
                temp_origins[alias.alias] = alias
            else:
                aliases[alias.alias] = alias

        return aliases

    def _alias_from_assignment(
        self,
        *,
        target_name: str,
        source: str,
        operator: str,
        operand: str,
        operand2: str,
        stmt_id: int,
        aliases: dict[str, _ArrayAlias],
        temp_origins: dict[str, _ArrayAlias],
        pointer_names: set[str],
        array_names: set[str],
    ) -> _ArrayAlias | None:
        if not target_name:
            return None

        origin = self._pointer_offset_origin(
            operand=operand,
            operand2=operand2,
            operator=operator,
            aliases=aliases,
            temp_origins=temp_origins,
            array_names=array_names,
        )
        if origin is not None:
            return dataclasses.replace(origin, alias=target_name, stmt_id=stmt_id)

        if operator:
            return None

        if source in temp_origins:
            return dataclasses.replace(
                temp_origins[source],
                alias=target_name,
                stmt_id=stmt_id,
                derived_from=temp_origins[source].alias,
            )
        if source in aliases:
            source_alias = aliases[source]
            return dataclasses.replace(
                source_alias,
                alias=target_name,
                stmt_id=stmt_id,
                derived_from=source,
            )
        if source in array_names and (
            target_name in pointer_names
            or self._is_temp_name(target_name)
            or "." in target_name
        ):
            return _ArrayAlias(
                alias=target_name,
                base=source,
                base_path=source,
                stmt_id=stmt_id,
            )
        return None

    def _pointer_offset_origin(
        self,
        *,
        operand: str,
        operand2: str,
        operator: str,
        aliases: dict[str, _ArrayAlias],
        temp_origins: dict[str, _ArrayAlias],
        array_names: set[str],
    ) -> _ArrayAlias | None:
        if operator not in _POINTER_ARITHMETIC_OPERATORS:
            return None
        base_name = operand
        offset_name = operand2
        if not base_name:
            return None

        base_alias = aliases.get(base_name) or temp_origins.get(base_name)
        if base_alias is not None:
            return dataclasses.replace(
                base_alias,
                offset=_combine_offsets(base_alias.offset, operator, offset_name),
                derived_from=base_name,
            )
        if base_name in array_names:
            return _ArrayAlias(
                alias="",
                base=base_name,
                base_path=base_name,
                offset=offset_name or "0",
            )
        return None

    def _alias_for_stmt(self, target: UnsafeStmtTarget) -> _ArrayAlias | None:
        for alias in self._aliases_for_target(target).values():
            if alias.stmt_id == target.stmt_id:
                return alias
        return None

    def _active_alias_for_value(
        self,
        target: UnsafeStmtTarget,
        value: str,
    ) -> _ArrayAlias | None:
        alias = self._aliases_for_target(target).get(value)
        if alias is None:
            return None
        if alias.stmt_id <= 0:
            return alias
        if alias.stmt_id > target.stmt_id:
            return None
        if target.method_id is not None and not self._cached_reachable(
            target.method_id,
            alias.stmt_id,
            target.stmt_id,
        ):
            return None
        return alias

    def _pointer_access(
        self,
        target: UnsafeStmtTarget,
        address: str,
    ) -> _PointerAccess | None:
        if not address:
            return None
        alias = self._active_alias_for_value(target, address)
        if alias is not None:
            return _PointerAccess(
                base=alias.base,
                base_path=alias.base_path,
                offset=alias.offset,
                alias=alias.alias,
            )
        array_origin = self._array_origin(target, address)
        if array_origin:
            base, offset = _split_element(array_origin)
            return _PointerAccess(base=base, base_path=base, offset=offset)
        return None

    def _address_origin_expr(
        self,
        target: UnsafeStmtTarget,
        address: str,
        *,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> str:
        address = self._text(address)
        if not address:
            return ""

        alias = self._active_alias_for_value(target, address)
        if alias is not None:
            return self._alias_origin_expr(alias)

        lian_origin = self._lian_origin_path_for_value(target, address, flow=flow)
        if lian_origin and lian_origin != address:
            return lian_origin

        addr_of_source = self._addr_of_source_before(target, address, flow=flow)
        if addr_of_source:
            return f"&{addr_of_source}"

        origin = self._trace_value_origin_before(target, address)
        if origin and origin != address:
            return origin
        return ""

    def _alias_origin_expr(self, alias: _ArrayAlias) -> str:
        base = alias.base_path or alias.base
        if not base:
            return ""
        if alias.offset and alias.offset != "0":
            return f"{base} + {alias.offset}"
        return base

    def _addr_of_source_before(
        self,
        target: UnsafeStmtTarget,
        value: str,
        *,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> str:
        source = self._lian_origin_path_for_value(target, value, flow=flow)
        if not source:
            source = self._trace_addr_of_source_before(target, value)
        if not source:
            return ""
        if source.startswith("&"):
            source = source[1:].strip()
        return source

    def _lian_origin_path_for_value(
        self,
        target: UnsafeStmtTarget,
        value: str,
        *,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> str:
        if target.method_id is None:
            return ""
        value = self._text(value)
        if not value:
            return ""
        if flow is not None:
            for path in flow.read_paths:
                if path == value or self._path_base(path) == value:
                    return path
        symbol = self.context.find_symbol_by_name(target.method_id, value)
        symbol_id = self._int(getattr(symbol, "symbol_id", None), default=0)
        if symbol_id in {-1, 0}:
            return ""
        for state in self.context.trace_symbol_current_states(
            target.method_id,
            symbol_id,
            target.stmt_id,
            mode="in",
        ):
            state_id = self._int(getattr(state, "state_id", None), default=-1)
            if state_id <= 0:
                continue
            path = self.context.format_state_origin_path(
                target.method_id, state_id
            ) or self._format_lian_state_path(target, state_id)
            path = self._text(path)
            if path and path != value:
                return path
        return ""

    def _trace_addr_of_source_before(
        self,
        target: UnsafeStmtTarget,
        value: str,
        *,
        max_depth: int = 8,
    ) -> str:
        current = self._text(value)
        if not current:
            return ""
        seen = {current}

        for _ in range(max_depth):
            next_value = ""
            for row in reversed(self._rows_for_target(target)):
                stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
                if stmt_id >= target.stmt_id:
                    continue
                if self._assignment_target(row) != current:
                    continue

                op = self._text(getattr(row, "operation", ""))
                if op == "addr_of":
                    source = self._first_from_row(
                        row, "source", "address", "operand"
                    )
                    if not source:
                        return ""
                    return self._addr_source_element(target, source) or source
                if op in {"assign_stmt", "type_cast_stmt"}:
                    next_value = self._first_from_row(
                        row, "source", "operand", "value", "address"
                    )
                    break
                if op == "field_read":
                    receiver = self._first_from_row(row, "receiver_object", "object")
                    field = self._first_from_row(row, "field", "field_name")
                    next_value = self._member_path(receiver, field)
                    break

            if not next_value or next_value in seen:
                return ""
            if next_value.startswith("&"):
                return next_value[1:].strip()
            seen.add(next_value)
            current = next_value

        return ""

    def _trace_value_origin_before(
        self,
        target: UnsafeStmtTarget,
        value: str,
        *,
        max_depth: int = 8,
    ) -> str:
        current = self._text(value)
        if not current:
            return ""
        seen = {current}

        for _ in range(max_depth):
            origin = self._direct_value_origin_before(target, current)
            if not origin:
                return current if current != value else ""
            if origin in seen:
                return current if current != value else ""
            if origin.startswith("&"):
                return origin
            if not self._is_temp_name(origin) and not self._has_prior_assignment(
                target, origin
            ):
                return origin
            seen.add(origin)
            current = origin
        return current if current != value else ""

    def _has_prior_assignment(self, target: UnsafeStmtTarget, value: str) -> bool:
        if not value:
            return False
        for row in reversed(self._rows_for_target(target)):
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if stmt_id >= target.stmt_id:
                continue
            if self._assignment_target(row) == value:
                return True
        return False

    def _lian_access_path_for_stmt(
        self,
        target: UnsafeStmtTarget,
        *,
        mode: str,
    ) -> str:
        candidates = self._lian_access_paths_for_stmt(target, mode=mode)
        return self._preferred_lian_access_path(candidates)

    def _lian_access_paths_for_stmt(
        self,
        target: UnsafeStmtTarget,
        *,
        mode: str,
    ) -> list[str]:
        flow = self._lian_stmt_flow(target)
        return list(flow.written_paths if mode == "write" else flow.read_paths)

    @staticmethod
    def _preferred_lian_access_path(paths: Iterable[str]) -> str:
        candidates = _dedupe([_text(path) for path in paths if _text(path)])
        for candidate in candidates:
            if "[" in candidate or "." in candidate or "->" in candidate:
                return candidate
        return candidates[0] if candidates else ""

    def _lian_stmt_flow(self, target: UnsafeStmtTarget) -> _UnsafeStmtLianFlow:
        cached = self._lian_flow_by_stmt.get(target.stmt_id)
        if cached is not None:
            return cached

        if target.method_id is None:
            flow = _UnsafeStmtLianFlow(
                stmt_id=target.stmt_id,
                method_id=None,
            )
            self._lian_flow_by_stmt[target.stmt_id] = flow
            return flow

        direct_used = self.context.get_stmt_direct_used_symbol_ids(target.stmt_id)
        implicit_used = self.context.get_stmt_implicit_used_symbol_ids(
            target.stmt_id
        )
        direct_defined = self.context.get_stmt_direct_defined_symbol_ids(
            target.stmt_id
        )
        implicit_defined = self.context.get_stmt_implicit_defined_symbol_ids(
            target.stmt_id
        )
        read_symbol_ids = _dedupe_ints((*direct_used, *implicit_used))
        written_symbol_ids = _dedupe_ints((*direct_defined, *implicit_defined))
        read_state_ids = self._flow_state_ids_for_symbols(
            target,
            read_symbol_ids,
            mode="in",
            fallback_state_ids=self.context.get_stmt_used_state_ids(
                target.stmt_id
            ),
        )
        written_state_ids = self._flow_state_ids_for_symbols(
            target,
            written_symbol_ids,
            mode="defined",
            fallback_state_ids=self.context.get_stmt_defined_state_ids(
                target.stmt_id
            ),
        )
        flow = _UnsafeStmtLianFlow(
            stmt_id=target.stmt_id,
            method_id=target.method_id,
            direct_used_symbol_ids=direct_used,
            implicit_used_symbol_ids=implicit_used,
            direct_defined_symbol_ids=direct_defined,
            implicit_defined_symbol_ids=implicit_defined,
            used_symbol_names=self._flow_symbol_names(
                target.method_id, read_symbol_ids
            ),
            defined_symbol_names=self._flow_symbol_names(
                target.method_id, written_symbol_ids
            ),
            read_state_ids=read_state_ids,
            written_state_ids=written_state_ids,
            read_paths=self._flow_paths_for_states(target, read_state_ids),
            written_paths=self._flow_paths_for_states(target, written_state_ids),
        )
        self._lian_flow_by_stmt[target.stmt_id] = flow
        return flow

    def _flow_state_ids_for_symbols(
        self,
        target: UnsafeStmtTarget,
        symbol_ids: Iterable[int],
        *,
        mode: str,
        fallback_state_ids: Iterable[int],
    ) -> tuple[int, ...]:
        if target.method_id is None:
            return ()
        state_ids: list[int] = []
        for symbol_id in symbol_ids:
            for state in self.context.trace_symbol_current_states(
                target.method_id,
                symbol_id,
                target.stmt_id,
                mode=mode,
            ):
                state_id = self._positive_id(getattr(state, "state_id", None))
                if state_id is not None:
                    state_ids.append(state_id)
        state_ids.extend(
            state_id
            for state_id in fallback_state_ids
            if self._positive_id(state_id) is not None
        )
        return tuple(_dedupe_ints(state_ids))

    def _flow_paths_for_states(
        self,
        target: UnsafeStmtTarget,
        state_ids: Iterable[int],
    ) -> tuple[str, ...]:
        paths: list[str] = []
        for state_id in state_ids:
            path = self._format_lian_state_path(target, state_id)
            if path:
                paths.append(path)
        return tuple(_dedupe(paths))

    def _flow_symbol_names(
        self,
        method_id: int,
        symbol_ids: Iterable[int],
    ) -> tuple[str, ...]:
        return tuple(
            _dedupe(
                [
                    name
                    for symbol_id in symbol_ids
                    if (name := self.context.get_symbol_name(method_id, symbol_id))
                ]
            )
        )

    def _legacy_lian_access_path_for_stmt(
        self,
        target: UnsafeStmtTarget,
        *,
        mode: str,
    ) -> str:
        candidates = self._legacy_lian_access_paths_for_stmt(target, mode=mode)
        for candidate in candidates:
            if "[" in candidate or "." in candidate or "->" in candidate:
                return candidate
        return candidates[0] if candidates else ""

    def _legacy_lian_access_paths_for_stmt(
        self,
        target: UnsafeStmtTarget,
        *,
        mode: str,
    ) -> list[str]:
        if target.method_id is None:
            return []
        if mode == "write":
            state_ids = self.context.get_stmt_defined_state_ids(target.stmt_id)
            symbol_names = set(
                self.context.get_stmt_defined_symbol_names(target.stmt_id)
            )
        else:
            state_ids = self.context.get_stmt_used_state_ids(target.stmt_id)
            symbol_names = set(
                self.context.get_stmt_used_symbol_names(target.stmt_id)
            )

        candidates: list[str] = []
        for state_id in state_ids:
            path = self._format_lian_state_path(target, state_id)
            if not path:
                continue
            base = self._path_base(path)
            if symbol_names and base and base not in symbol_names:
                continue
            candidates.append(path)

        return _dedupe(candidates)

    def _array_access_hints(
        self,
        target: UnsafeStmtTarget,
        *,
        array: str,
        index: str,
        lian_path: str,
    ) -> ArrayReadHints:
        hints = ArrayReadHints()
        lian_path = self._usable_array_lian_path(lian_path)
        alias = self._active_alias_for_value(target, array)

        if lian_path and self._prefer_lian_array_path(
            array,
            index,
            lian_path,
        ):
            hints.resolves_to_element = lian_path
            hints.array_role = self._array_role_from_path(target, lian_path)
            lian_base = self._path_base(lian_path)
            lian_alias = self._active_alias_for_value(target, lian_base)
            if lian_alias is not None:
                hints.array_role = ArrayRole.ALIAS
            return hints

        if alias is not None:
            hints.array_role = ArrayRole.ALIAS
            hints.resolves_to_element = self._alias_element(alias, index)
            return hints

        if array:
            hints.array_role = self._array_role(target, array)
            hints.resolves_to_element = f"{array}[{index or '0'}]"
            if self._is_temp_name(array) and lian_path:
                hints.resolves_to_element = lian_path
                hints.array_role = self._array_role_from_path(target, lian_path)
            return hints

        if lian_path:
            hints.array_role = self._array_role_from_path(target, lian_path)
            hints.resolves_to_element = lian_path
        return hints

    def _c_string_termination(
        self,
        target: UnsafeStmtTarget,
        *,
        array: str,
        index: str,
        source: str,
        write_target: str,
    ) -> CStringTermination | None:


        source_origin = self._text(source)
        if not self._is_c_nul_character(source_origin):
            source_origin = self._trace_value_origin_before(
                target,
                source_origin,
            )
        if not self._is_c_nul_character(source_origin):
            return None

        resolved_index = self._resolve_temp_in_str(target, index).strip()
        resolved_target = self._resolve_temp_in_str(
            target,
            write_target,
        ).strip()
        if not resolved_index or not resolved_target:
            return None

        buffer = self._array_base_from_element(resolved_target)
        if not buffer:
            buffer = self._resolve_temp_in_str(target, array).strip()
        if not buffer:
            return None

        return CStringTermination(
            buffer=buffer,
            terminator_index=resolved_index,
            minimum_capacity=f"({resolved_index}) + 1",
            write_target=resolved_target,
        )

    def _c_string_read(
        self,
        target: UnsafeStmtTarget,
        *,
        buffer: str,
        access_index: str,
    ) -> CStringRead | None:
        resolved_buffer = self._resolve_temp_in_str(target, buffer).strip()
        if not self._is_confirmed_c_string_buffer(target, resolved_buffer):
            return None
        resolved_index = self._resolve_temp_in_str(
            target,
            access_index,
        ).strip() or "0"
        source = " ".join(self.context.get_stmt_source(target.stmt_id))
        if self._is_c_nul_character_in_source(source):
            role = CStringReadRole.TERMINATOR_TEST
        elif self._is_zero_index(resolved_index):
            role = CStringReadRole.END_BOUNDARY_PROBE
        else:
            role = CStringReadRole.LOOKAHEAD
        return CStringRead(
            buffer=resolved_buffer,
            access_index=resolved_index,
            role=role,
        )

    def _is_confirmed_c_string_buffer(
        self,
        target: UnsafeStmtTarget,
        buffer: str,
    ) -> bool:
        text = str(buffer or "").strip().lstrip("*&(").rstrip(") ")
        if not text:
            return False
        field_names = re.findall(r"(?:->|\.)\s*([A-Za-z_]\w*)", text)
        if any(name in self._c_string_field_names for name in field_names):
            return True
        base = self._path_base(text)
        if target.method_id is not None and base in self._c_string_names_by_method.get(
            target.method_id,
            set(),
        ):
            return True
        if base in self._c_string_global_names:
            return True
        alias = self._active_alias_for_value(target, base)
        if alias is None:
            return False
        alias_text = alias.element_base
        alias_fields = re.findall(
            r"(?:->|\.)\s*([A-Za-z_]\w*)",
            alias_text,
        )
        if any(name in self._c_string_field_names for name in alias_fields):
            return True
        alias_base = self._path_base(alias_text)
        return (
            target.method_id is not None
            and alias_base
            in self._c_string_names_by_method.get(target.method_id, set())
        ) or alias_base in self._c_string_global_names

    @staticmethod
    def _is_c_nul_character_in_source(source: str) -> bool:
        return bool(
            re.search(
                r"(?:u8|[uUL])?'(?:\\0{1,3}|\\x0+)'",
                str(source or ""),
            )
        )

    @staticmethod
    def _is_zero_index(index: str) -> bool:
        text = re.sub(r"[()\s]", "", str(index or ""))
        return text in {"0", "+0", "-0"}

    @staticmethod
    def _array_base_from_element(value: str) -> str:
        text = str(value or "").strip()
        bracket = text.rfind("[")
        if bracket > 0 and text.endswith("]"):
            return text[:bracket].strip()
        return ""

    @staticmethod
    def _is_c_nul_character(value: str) -> bool:
        text = str(value or "").strip()
        return bool(
            re.fullmatch(
                r"(?:u8|[uUL])?'(?:\\0{1,3}|\\x0+)'",
                text,
            )
        )

    def _usable_array_lian_path(self, path: str) -> str:
        path = self._text(path)
        if not path or not self._looks_like_access_path(path):
            return ""
        if path.endswith("[]"):
            return ""
        return path

    def _prefer_lian_array_path(
        self,
        array: str,
        index: str,
        lian_path: str,
    ) -> bool:
        if not lian_path:
            return False
        if not array:
            return True
        lian_base = self._path_base(lian_path)
        _, lian_index = _split_element(lian_path)
        if self._is_temp_name(array):
            return not self._is_temp_name(lian_base)
        if lian_base and lian_base != array and not self._is_temp_name(lian_base):
            return True
        if lian_base == array and (
            not index
            or self._is_temp_name(index)
            or (lian_index != "0" and lian_index != index)
        ):
            return True
        return False

    def _write_source_deps(
        self,
        target: UnsafeStmtTarget,
        *,
        source: str,
        exclude_names: Iterable[str] = (),
        written_path: str = "",
        lian_read_paths: Iterable[str] = (),
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> list[str]:
        source = self._text(source)
        if not self._value_may_need_dependency_trace(source):
            return []

        excluded = self._write_dep_exclusion_set(
            exclude_names=exclude_names,
            written_path=written_path,
        )
        deps: list[str] = []

        for path in lian_read_paths:
            self._append_write_dep(
                deps,
                self._text(path),
                source=source,
                excluded=excluded,
                written_path=written_path,
            )

        for path in self._lian_write_source_dep_paths(
            target,
            source,
            flow=flow,
        ):
            self._append_write_dep(
                deps,
                path,
                source=source,
                excluded=excluded,
                written_path=written_path,
            )

        if deps:
            return self._prefer_specific_deps(_dedupe(deps))

        return self._prefer_specific_deps(
            _dedupe(
                dep
                for dep in self._gir_value_read_deps(target, source)
                if self._write_dep_allowed(
                    dep,
                    source=source,
                    excluded=excluded,
                    written_path=written_path,
                )
            )
        )

    def _lian_write_source_dep_paths(
        self,
        target: UnsafeStmtTarget,
        source: str,
        *,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> list[str]:
        if target.method_id is None:
            return []

        source = self._text(source)
        source_base = self._path_base(source) or source
        source_is_temp = self._is_temp_name(source)
        deps: list[str] = []

        if flow is None:
            flow = self._lian_stmt_flow(target)

        for symbol_id in _dedupe_ints(
            (*flow.direct_used_symbol_ids, *flow.implicit_used_symbol_ids)
        ):
            symbol_name = self.context.get_symbol_name(target.method_id, symbol_id)
            if not symbol_name:
                continue
            if source and not self._symbol_matches_write_source(
                symbol_name,
                source=source,
                source_base=source_base,
                source_is_temp=source_is_temp,
            ):
                continue

            states = self.context.trace_symbol_current_states(
                target.method_id,
                symbol_id,
                target.stmt_id,
                mode="in",
            )
            if not states and source_is_temp:
                states = self.context.find_states_for_symbol(
                    target.method_id, symbol_id
                )
            for state in states:
                state_id = self._int(getattr(state, "state_id", None), default=-1)
                path = (
                    self.context.format_state_origin_path(
                        target.method_id, state_id
                    )
                    if state_id > 0
                    else None
                )
                path = self._text(path)
                if not path:
                    path = self._format_lian_state_path(target, state_id)
                if path and path != source:
                    deps.append(path)

            if not states and not source_is_temp:
                deps.append(source if source_base == symbol_name else symbol_name)

        if source and not source_is_temp and self._looks_like_access_path(source):
            deps.insert(0, source)

        return _dedupe(deps)

    def _symbol_matches_write_source(
        self,
        symbol_name: str,
        *,
        source: str,
        source_base: str,
        source_is_temp: bool,
    ) -> bool:
        if source_is_temp:
            return symbol_name == source
        return symbol_name == source or symbol_name == source_base

    def _append_write_dep(
        self,
        deps: list[str],
        dep: str,
        *,
        source: str,
        excluded: set[str],
        written_path: str,
    ) -> None:
        dep = self._usable_array_lian_path(dep) or self._text(dep)
        if self._write_dep_allowed(
            dep,
            source=source,
            excluded=excluded,
            written_path=written_path,
        ):
            deps.append(dep)

    def _write_dep_allowed(
        self,
        dep: str,
        *,
        source: str,
        excluded: set[str],
        written_path: str,
    ) -> bool:
        dep = self._text(dep)
        if not dep or dep == source and self._is_temp_name(source):
            return False
        if self._is_literal_value(dep) or self._is_null_pointer_value(dep):
            return False
        normalized_written = self._text(written_path)
        if normalized_written and dep == normalized_written:
            return False

        dep_base = self._path_base(dep) or dep
        if dep in excluded:
            return False
        if dep_base in excluded and not self._looks_like_access_path(dep):
            return False
        return True

    def _write_dep_exclusion_set(
        self,
        *,
        exclude_names: Iterable[str],
        written_path: str,
    ) -> set[str]:
        excluded: set[str] = set()
        for name in exclude_names:
            text = self._text(name)
            if not text:
                continue
            excluded.add(text)
            base = self._path_base(text)
            if base:
                excluded.add(base)
        written = self._text(written_path)
        if written:
            excluded.add(written)
        return excluded

    def _prefer_specific_deps(self, deps: Iterable[str]) -> list[str]:
        deduped = _dedupe(self._text(dep) for dep in deps if self._text(dep))
        specific_bases = {
            self._path_base(dep)
            for dep in deduped
            if self._looks_like_access_path(dep) and self._path_base(dep)
        }
        return [
            dep
            for dep in deduped
            if dep not in specific_bases
        ]

    def _format_lian_state_path(
        self,
        target: UnsafeStmtTarget,
        state_id: int,
    ) -> str:
        if target.method_id is None:
            return ""
        cache_key = (target.method_id, state_id)
        cached = self._state_origin_cache.get(cache_key)
        if cached is not None:
            return cached

        state = self.context.find_state_by_id(target.method_id, state_id)
        if state is None:
            self._state_origin_cache[cache_key] = ""
            return ""

        origin_path = self.context.format_state_origin_path(
            target.method_id, state_id
        )
        if origin_path:
            self._state_origin_cache[cache_key] = origin_path
            return origin_path

        access_path = self.context.get_state_access_path(
            target.method_id, state_id
        )
        source_symbol_id = self._int(
            getattr(state, "source_symbol_id", None), default=-1
        )
        source_name = (
            self.context.get_symbol_name(target.method_id, source_symbol_id)
            if source_symbol_id not in {-1, 0}
            else None
        )
        result = ""
        if source_name and access_path:
            if access_path == source_name or access_path.startswith(
                f"{source_name}."
            ):
                result = access_path
            elif access_path.startswith("[") or access_path.startswith("->"):
                result = f"{source_name}{access_path}"
            elif access_path.startswith("."):
                result = f"{source_name}{access_path}"
            else:
                result = f"{source_name}.{access_path}"
        elif access_path:
            result = access_path
        elif source_name:
            result = source_name
        else:
            result = self._text(getattr(state, "value", ""))
        self._state_origin_cache[cache_key] = result
        return result

    def _array_role_from_path(
        self,
        target: UnsafeStmtTarget,
        path: str,
    ) -> ArrayRole | None:
        base = self._path_base(path)
        if not base:
            return None
        alias = self._active_alias_for_value(target, base)
        if alias is not None:
            return ArrayRole.ALIAS
        return self._array_role(target, base)

    def _lian_alias_for_stmt(
        self,
        target: UnsafeStmtTarget,
        *,
        lian_write_path: str,
        lian_read_path: str,
    ) -> _ArrayAlias | None:
        alias_name = self._path_base(lian_write_path)
        base_name, offset = self._split_lian_offset_path(lian_read_path)
        if not alias_name or not base_name or alias_name == base_name:
            return None
        if self._storage_kind_for_symbol(target, alias_name) is not StorageKind.FIELD:
            rows = self._rows_for_target(target)
            pointer_names = self._pointer_decl_names(rows)
            if alias_name not in pointer_names and not self._is_temp_name(alias_name):
                return None
        array_role = self._array_role(target, base_name)
        base_storage = self._storage_kind_for_symbol(target, base_name)
        if array_role is None and base_storage not in {
            StorageKind.PARAM,
            StorageKind.GLOBAL,
            StorageKind.FIELD,
            StorageKind.STACK,
        }:
            return None
        return _ArrayAlias(
            alias=alias_name,
            base=base_name,
            base_path=base_name,
            offset=offset or "0",
            derived_from="lian_state_access_path",
            stmt_id=target.stmt_id,
        )

    @staticmethod
    def _path_base(path: str) -> str:
        if not path:
            return ""
        base = path.split("[", 1)[0]
        base = base.split(".", 1)[0]
        base = base.split("->", 1)[0]
        return base.strip()

    @staticmethod
    def _path_field(path: str) -> str:
        if not path:
            return ""
        if "->" in path:
            tail = path.rsplit("->", 1)[-1]
        elif "." in path:
            tail = path.rsplit(".", 1)[-1]
        else:
            return ""
        return tail.split("[", 1)[0].strip()

    @staticmethod
    def _split_lian_offset_path(path: str) -> tuple[str, str]:
        if not path:
            return "", ""
        base, offset = _split_element(path)
        if offset != "0":
            return UnsafeStmtProgrammaticAnalyzer._path_base(base), offset
        return UnsafeStmtProgrammaticAnalyzer._path_base(path), ""

    @staticmethod
    def _looks_like_access_path(path: str) -> bool:
        if not path:
            return False
        if path.endswith("[]") or "*" in path:
            return False
        return "[" in path or "." in path or "->" in path

    def _array_origin(self, target: UnsafeStmtTarget, value: str) -> str:
        if not value:
            return ""
        rows = self._rows_for_target(target)
        for row in reversed(rows):
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if stmt_id >= target.stmt_id:
                continue
            op = self._text(getattr(row, "operation", ""))
            if op != "array_read":
                continue
            if self._first_from_row(row, "target", "name") != value:
                continue
            array = self._first_from_row(row, "array", "receiver_object")
            index = self._first_from_row(row, "index", "offset")
            alias = self._active_alias_for_value(target, array)
            return self._alias_element(alias, index) if alias else f"{array}[{index}]"
        return ""

    def _resolve_value_origin_before(
        self,
        target: UnsafeStmtTarget,
        value: str,
        *,
        max_depth: int = 8,
    ) -> str:
        current = self._text(value)
        if not self._is_temp_name(current):
            return current
        seen = {current}
        for _ in range(max_depth):
            origin = self._direct_value_origin_before(target, current)
            if not origin or origin in seen:
                return current
            if not self._is_temp_name(origin):
                return origin
            seen.add(origin)
            current = origin
        return current

    def _direct_value_origin_before(
        self,
        target: UnsafeStmtTarget,
        value: str,
    ) -> str:
        for row in reversed(self._rows_for_target(target)):
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if stmt_id >= target.stmt_id:
                continue
            op = self._text(getattr(row, "operation", ""))
            row_target = self._first_from_row(row, "target", "name")
            if row_target != value:
                continue
            if op == "array_read":
                array = self._first_from_row(row, "array", "receiver_object")
                index = self._first_from_row(row, "index", "offset")
                return f"{array}[{index or '0'}]" if array else ""
            if op == "field_read":
                receiver = self._first_from_row(row, "receiver_object", "object")
                field = self._first_from_row(row, "field", "field_name")
                return self._member_path(receiver, field)
            if op == "mem_read":
                address = self._first_from_row(
                    row, "address", "source", "operand"
                )
                if address:
                    resolved_addr = self._resolve_temp_name(target, address)
                    return f"*{resolved_addr}"
                return ""
            if op == "addr_of":
                source = self._first_from_row(row, "source", "address", "operand")
                return f"&{source}" if source else ""
            if op == "type_cast_stmt":
                return self._first_from_row(row, "source", "operand", "value", "address")
            if op == "call_stmt":
                callee = self._first_from_row(row, "name", "callee", "callee_name")
                args = ", ".join(self._call_args(self._row_to_raw(row)))
                return f"{callee}({args})" if callee else ""
            if op == "assign_stmt":
                operator = self._text(getattr(row, "operator", ""))
                if operator:
                    left = self._first_from_row(row, "operand", "source")
                    right = self._first_from_row(row, "operand2")
                    return f"{left} {operator} {right}".strip()
                return self._first_from_row(row, "source", "operand", "value")
        return ""

    def _gir_value_read_deps(
        self, target: UnsafeStmtTarget, value: str
    ) -> list[str]:
        deps: list[str] = []
        seen: set[str] = set()
        resolved_value = self._trace_value_origin_before(target, value)
        if resolved_value and resolved_value != value:
            seen.add(resolved_value)
            deps.append(resolved_value)
        for name in self.context.get_stmt_used_symbol_names(target.stmt_id):
            name = (
                self._trace_value_origin_before(target, name)
                or self._resolve_value_origin_before(target, name)
            )
            if name == value or name in seen:
                continue
            seen.add(name)
            deps.append(name)
        if not value:
            return deps
        origin = self._array_origin(target, value)
        if origin and origin not in seen:
            deps.append(origin)
        return deps

    def _addr_source_element(self, target: UnsafeStmtTarget, source: str) -> str:
        if not source:
            return ""
        access = self._pointer_access(target, source)
        if access is not None:
            return access.element()
        origin = self._array_origin(target, source)
        return origin

    def _addr_escapes(self, target: UnsafeStmtTarget, pointer_name: str) -> list[str]:
        if not pointer_name:
            return []
        values = {pointer_name}
        memory: set[str] = set()
        escapes: list[str] = []
        for row in self._rows_for_target(target):
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if stmt_id <= target.stmt_id:
                continue
            if (
                target.method_id is not None
                and not self._cached_reachable(
                    target.method_id,
                    target.stmt_id,
                    stmt_id,
                )
            ):
                continue
            op = self._text(getattr(row, "operation", ""))

            if op == "return_stmt" and self._addr_expr_has_value_origin(
                self._return_value_from_row(row),
                values,
                memory,
            ):
                escapes.append("returned")

            if op == "call_stmt":
                callee = self._first_from_row(row, "name", "callee", "callee_name")
                for index, arg in enumerate(self._call_args(self._row_to_raw(row))):
                    if self._addr_expr_has_value_origin(arg, values, memory):
                        call_target = (
                            f"{callee}(arg{index})" if callee else f"arg{index}"
                        )
                        escapes.append(f"passed_to_call:{call_target}")

            if op == "assign_stmt":
                assign_target = self._assignment_target(row)
                source = self._first_from_row(
                    row, "source", "operand", "value", "address"
                )
                if self._addr_expr_has_value_origin(source, values, memory):
                    if assign_target:
                        if (
                            self._storage_kind_for_symbol(target, assign_target)
                            is StorageKind.GLOBAL
                        ):
                            escapes.append(f"stored_global:{assign_target}")
                            memory.add(assign_target)
                        else:
                            values.add(assign_target)

            if op == "type_cast_stmt":
                cast_target = self._assignment_target(row)
                source = self._first_from_row(
                    row, "source", "operand", "value", "address"
                )
                if cast_target and self._addr_expr_has_value_origin(
                    source,
                    values,
                    memory,
                ):
                    values.add(cast_target)

            if op == "field_write":
                receiver = self._first_from_row(row, "receiver_object", "object")
                field = self._first_from_row(row, "field", "field_name")
                member = self._member_path(receiver, field)
                source = self._first_from_row(row, "source", "value", "operand")
                if self._addr_expr_has_value_origin(source, values, memory):
                    if member:
                        escapes.append(f"stored_field:{member}")
                        memory.add(member)
                    else:
                        escapes.append("stored_field")

            if op == "field_read":
                read_target = self._assignment_target(row)
                receiver = self._first_from_row(row, "receiver_object", "object")
                field = self._first_from_row(row, "field", "field_name")
                member = self._member_path(receiver, field)
                if read_target and member in memory:
                    values.add(read_target)

            if op == "array_write":
                array = self._first_from_row(row, "array", "receiver_object")
                index = self._first_from_row(row, "index", "offset")
                element = f"{array}[{index or '0'}]" if array else ""
                source = self._first_from_row(row, "source", "value", "operand")
                if self._addr_expr_has_value_origin(source, values, memory):
                    if element:
                        escapes.append(f"stored_array:{element}")
                        memory.add(element)
                    else:
                        escapes.append("stored_array")

            if op == "array_read":
                read_target = self._assignment_target(row)
                array = self._first_from_row(row, "array", "receiver_object")
                index = self._first_from_row(row, "index", "offset")
                element = f"{array}[{index or '0'}]" if array else ""
                if read_target and element in memory:
                    values.add(read_target)

            if op == "mem_write":
                address = self._first_from_row(row, "address", "target", "operand")
                source = self._first_from_row(row, "source", "value", "operand")
                if self._addr_expr_has_value_origin(source, values, memory):
                    escaped_to = f"*{address}" if address else "*"
                    escapes.append(f"stored_indirect:{escaped_to}")
        return _dedupe(escapes)

    def _addr_expr_has_value_origin(
        self,
        expr: str,
        values: set[str],
        memory: set[str],
    ) -> bool:
        expr = self._text(expr)
        if not expr:
            return False
        return any(self._value_mentions(expr, value) for value in values) or expr in memory

    def _assignment_pointer_arith_base(
        self,
        target: UnsafeStmtTarget,
        alias: _ArrayAlias | None,
    ) -> str:
        if alias is not None and alias.offset and alias.offset != "0":
            return alias.base_path or alias.base

        operator = self._text(target.raw_gir.get("operator"))
        if operator not in _POINTER_ARITHMETIC_OPERATORS:
            return ""
        operand = self._first(target.raw_gir, "operand", "source")
        operand2 = self._first(target.raw_gir, "operand2")
        operand_is_pointer = self._operand_is_pointer_like(target, operand)
        operand2_is_pointer = self._operand_is_pointer_like(target, operand2)

        if operand_is_pointer:
            return operand
        if operator == "+" and operand2_is_pointer:
            return operand2
        return ""

    def _assignment_arith_hints(
        self,
        target: UnsafeStmtTarget,
        arith_base: str,
    ) -> AssignmentFlowHints:
        if not arith_base:
            return AssignmentFlowHints()
        return AssignmentFlowHints(
            arith_base_pointee_shape=self._arith_base_pointee_shape(
                target, arith_base
            ),
            arith_base_object_kind=self._arith_base_object_kind(
                target, arith_base
            ),
        )

    def _operand_is_pointer_like(
        self,
        target: UnsafeStmtTarget,
        operand: str,
    ) -> bool:
        operand = self._text(operand)
        if not operand or self._is_literal_value(operand):
            return False
        if self._active_alias_for_value(target, operand) is not None:
            return True
        if self._addr_of_source_before(target, operand):
            return True

        value_type = self._value_type_for_name(target, operand)
        if self._is_pointer_or_array_type(value_type):
            return True

        if "." in operand or "->" in operand:
            field_type = self._field_type_from_context(
                target,
                receiver=self._path_base(operand),
                field=self._path_field(operand),
                member=operand,
                access_path=operand,
            )
            if self._is_pointer_or_array_type(field_type):
                return True

        lian_type = self._lian_type_for_operand(target, operand)
        if self._is_pointer_or_array_type(lian_type):
            return True

        for path in self._lian_paths_for_operand(target, operand):
            path_type = self._value_type_for_name(target, self._path_base(path))
            if self._is_pointer_or_array_type(path_type):
                return True
            if "." in path or "->" in path:
                field_type = self._field_type_from_context(
                    target,
                    receiver=self._path_base(path),
                    field=self._path_field(path),
                    member=path,
                    access_path=path,
                )
                if self._is_pointer_or_array_type(field_type):
                    return True
        return False

    def _lian_type_for_operand(
        self,
        target: UnsafeStmtTarget,
        operand: str,
    ) -> str:
        if target.method_id is None or not operand:
            return ""
        symbol = self.context.find_symbol_by_name(target.method_id, operand)
        symbol_type = self._lian_item_type(symbol)
        if symbol_type:
            return symbol_type
        symbol_id = self._int(getattr(symbol, "symbol_id", None), default=-1)
        if symbol_id in {-1, 0}:
            return ""
        for state in self.context.find_states_for_symbol(target.method_id, symbol_id):
            state_type = self._lian_item_type(state)
            if state_type:
                return state_type
        return ""

    def _lian_paths_for_operand(
        self,
        target: UnsafeStmtTarget,
        operand: str,
    ) -> list[str]:
        if target.method_id is None or not operand:
            return []
        result: list[str] = []
        for state_id in self.context.get_stmt_used_state_ids(target.stmt_id):
            path = self._format_lian_state_path(target, state_id)
            if not path:
                continue
            if path == operand or self._path_base(path) == operand:
                result.append(path)
        return _dedupe(result)

    @staticmethod
    def _lian_item_type(item: Any) -> str:
        if item is None:
            return ""
        for attr in (
            "data_type",
            "default_data_type",
            "c_type",
            "type",
            "type_name",
            "value_type",
        ):
            value = _text(getattr(item, attr, ""))
            if value:
                return value
        return ""

    def _arith_base_pointee_shape(
        self,
        target: UnsafeStmtTarget,
        arith_base: str,
    ) -> ArithmeticBasePointeeShape:
        base = self._path_base(arith_base) or arith_base
        for path in self._lian_paths_for_operand(target, base):
            if "[" in path:
                return ArithmeticBasePointeeShape.ARRAY
            if "." in path or "->" in path:
                field_type = self._field_type_from_context(
                    target,
                    receiver=self._path_base(path),
                    field=self._path_field(path),
                    member=path,
                    access_path=path,
                )
                if self._is_pointer_or_array_type(field_type):
                    return ArithmeticBasePointeeShape.UNKNOWN
        if self._declared_array_role(target, base) is not None:
            return ArithmeticBasePointeeShape.ARRAY
        if self._active_alias_for_value(target, base) is not None:
            return ArithmeticBasePointeeShape.ARRAY
        addr_source = self._addr_of_source_before(target, base)
        if addr_source:
            addr_base = self._path_base(addr_source) or addr_source
            if (
                "[" in addr_source
                or self._declared_array_role(target, addr_base) is not None
            ):
                return ArithmeticBasePointeeShape.ARRAY
            return ArithmeticBasePointeeShape.SINGLE
        if "[" in arith_base:
            return ArithmeticBasePointeeShape.ARRAY
        return ArithmeticBasePointeeShape.UNKNOWN

    def _arith_base_object_kind(
        self,
        target: UnsafeStmtTarget,
        arith_base: str,
    ) -> ArithmeticBaseObjectKind:
        base = self._path_base(arith_base) or arith_base
        role = self._declared_array_role(target, base)
        if role is ArrayRole.LOCAL_ARRAY:
            return ArithmeticBaseObjectKind.LOCAL_ARRAY
        if role is ArrayRole.GLOBAL_ARRAY:
            return ArithmeticBaseObjectKind.GLOBAL_ARRAY
        if "." in arith_base or "->" in arith_base:
            return ArithmeticBaseObjectKind.FIELD
        storage = self._storage_kind_for_symbol(target, base)
        if storage is StorageKind.FIELD:
            return ArithmeticBaseObjectKind.FIELD
        if storage is StorageKind.PARAM:
            return ArithmeticBaseObjectKind.PARAMETER
        return ArithmeticBaseObjectKind.UNKNOWN

    def _declared_array_role(
        self,
        target: UnsafeStmtTarget,
        name: str,
    ) -> ArrayRole | None:
        if not name:
            return None

        def _classify(decl_name: str) -> ArrayRole | None:
            clean = self._path_base(decl_name) or decl_name
            for row in self._rows_for_target(target):
                if self._first_from_row(row, "name", "target") != clean:
                    continue
                c_type = self._first_from_row(row, "data_type", "default_data_type")
                if "[" not in c_type or "]" not in c_type:
                    return None
                op = self._text(getattr(row, "operation", ""))
                if op == "parameter_decl":
                    return ArrayRole.PARAMETER_ARRAY
                if op == "variable_decl":
                    return (
                        ArrayRole.LOCAL_ARRAY
                        if target.method_id is not None
                        else ArrayRole.GLOBAL_ARRAY
                    )
            return None

        result = _classify(name)
        if result is not None:
            return result

        resolved = self._resolve_temp_name(target, name)
        if resolved != name and not self._is_temp_name(resolved):
            return _classify(resolved)

        return None

    def _rows_for_target(self, target: UnsafeStmtTarget) -> tuple[Any, ...]:
        if target.method_id is not None:
            return self.context.get_method_rows(target.method_id)
        scope_key = (target.unit_id, target.entity_id)
        cached = self._rows_by_scope.get(scope_key)
        if cached is not None:
            return cached
        row = self.context.get_stmt(target.entity_id)
        if row is None:
            self._rows_by_scope[scope_key] = ()
            return ()
        rows: list[Any] = []
        seen: set[int] = set()
        stack = [row]
        while stack:
            current = stack.pop()
            stmt_id = self._int(getattr(current, "stmt_id", None), default=-1)
            if stmt_id <= 0 or stmt_id in seen:
                continue
            seen.add(stmt_id)
            rows.append(current)
            stack.extend(reversed(self.context.get_children(stmt_id)))
        result = tuple(rows)
        self._rows_by_scope[scope_key] = result
        return result

    def _pointer_decl_names(self, rows: tuple[Any, ...]) -> set[str]:
        result: set[str] = set()
        for row in rows:
            if self._text(getattr(row, "operation", "")) not in {
                "parameter_decl",
                "variable_decl",
            }:
                continue
            c_type = self._first_from_row(row, "data_type", "default_data_type")
            name = self._first_from_row(row, "name", "target")
            if name and "*" in c_type:
                result.add(name)
        return result

    def _array_decl_names(self, rows: tuple[Any, ...]) -> set[str]:
        result: set[str] = set()
        for row in rows:
            if self._text(getattr(row, "operation", "")) not in {
                "parameter_decl",
                "variable_decl",
            }:
                continue
            c_type = self._first_from_row(row, "data_type", "default_data_type")
            name = self._first_from_row(row, "name", "target")
            if name and "[" in c_type and "]" in c_type:
                result.add(name)
        return result

    def _resolve_temp_name(self, target: UnsafeStmtTarget, name: str) -> str:

        name = self._text(name)
        if not name or not self._is_temp_name(name):
            return name

        cache_key = (target.stmt_id, name)
        cached = self._temp_resolution_cache.get(cache_key)
        if cached is not None:
            return cached

        resolved = self._resolve_value_origin_before(target, name)
        result = resolved if resolved and resolved != name else name
        self._temp_resolution_cache[cache_key] = result
        return result

    def _array_role(self, target: UnsafeStmtTarget, name: str) -> ArrayRole | None:
        if not name:
            return None


        for row in self._rows_for_target(target):
            if self._first_from_row(row, "name", "target") != name:
                continue
            op = self._text(getattr(row, "operation", ""))
            if op == "parameter_decl":
                return ArrayRole.PARAMETER_ARRAY
            if op == "variable_decl":
                return ArrayRole.LOCAL_ARRAY if target.method_id else ArrayRole.GLOBAL_ARRAY


        resolved = self._resolve_temp_name(target, name)
        if resolved != name:

            if not self._is_temp_name(resolved):
                for row in self._rows_for_target(target):
                    if self._first_from_row(row, "name", "target") != resolved:
                        continue
                    op = self._text(getattr(row, "operation", ""))
                    if op == "parameter_decl":
                        return ArrayRole.PARAMETER_ARRAY
                    if op == "variable_decl":
                        return (
                            ArrayRole.LOCAL_ARRAY
                            if target.method_id
                            else ArrayRole.GLOBAL_ARRAY
                        )



                if "." in resolved or "->" in resolved:
                    base = self._path_base(resolved)
                    if base and base != resolved:
                        storage = self._storage_kind_for_symbol(target, base)
                        if storage is StorageKind.PARAM:
                            return ArrayRole.PARAMETER_ARRAY
                        if storage is StorageKind.GLOBAL:
                            return ArrayRole.GLOBAL_ARRAY
                        if storage is StorageKind.STACK:
                            return ArrayRole.LOCAL_ARRAY
                        if storage is StorageKind.FIELD:
                            return self._array_role(target, base)

        return None

    def _call_name(self, target: UnsafeStmtTarget) -> str:
        return self._first(target.raw_gir, "name", "callee", "callee_name", "target")

    def _call_args(self, raw_gir: dict[str, Any]) -> list[str]:
        positional = raw_gir.get("positional_args")
        if positional is None:
            positional = raw_gir.get("args")
        result = self._as_string_list(positional)
        packed = self._as_string_list(raw_gir.get("packed_positional_args"))
        if packed:
            result.extend(packed)
        named = raw_gir.get("named_args")
        if isinstance(named, dict):
            result.extend(str(value) for value in named.values())
        return result

    def _call_kind(self, callee: str) -> CallKind:
        if callee in _ALLOCATION_CALLEES:
            return CallKind.ALLOCATION
        if callee in _DEALLOCATION_CALLEES:
            return CallKind.DEALLOCATION
        if callee in _BYTE_COPY_CALLEES:
            return CallKind.BYTE_COPY
        if callee in _BYTE_SET_CALLEES:
            return CallKind.BYTE_SET
        return CallKind.UNKNOWN

    @staticmethod
    def _allocation_size(callee: str, args: list[str]) -> str | None:
        if callee == "malloc" and args:
            return args[0]
        if callee == "calloc" and len(args) >= 2:
            return f"{args[0]} * {args[1]}"
        if callee == "realloc" and len(args) >= 2:
            return args[1]
        return None

    def _return_value(self, raw_gir: dict[str, Any]) -> str:
        return self._first(raw_gir, "name", "source", "value", "operand", "target")

    def _return_value_from_row(self, row: Any) -> str:
        return self._first_from_row(row, "name", "source", "value", "operand", "target")

    def _return_origin(
        self,
        target: UnsafeStmtTarget,
        value: str,
        *,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> _ReturnOrigin:
        expression = self._text(value)
        lian_path = self._return_lian_access_path(
            target,
            expression,
            flow=flow,
        )
        traced = self._trace_value_origin_before(target, expression)
        resolved = self._resolve_value_origin_before(target, expression)

        semantic_source = ""
        if (
            lian_path
            and self._looks_like_access_path(lian_path)
            and self._return_lian_path_matches_value(
                target, lian_path, expression, traced, resolved
            )
        ):
            semantic_source = lian_path
        elif traced and traced != expression:
            semantic_source = traced
        elif lian_path and self._return_lian_path_matches_value(
            target, lian_path, expression, traced, resolved
        ):
            semantic_source = lian_path
        elif traced:
            semantic_source = traced
        elif resolved:
            semantic_source = resolved
        else:
            semantic_source = expression





        semantic_source = self._resolve_temp_in_str(target, semantic_source)

        return _ReturnOrigin(
            expression=expression,
            semantic_source=semantic_source,
            lian_access_path=lian_path,
        )

    def _return_lian_access_path(
        self,
        target: UnsafeStmtTarget,
        value: str,
        *,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> str:
        if target.method_id is None:
            return ""

        if flow is None:
            flow = self._lian_stmt_flow(target)
        candidates = [
            path
            for path in flow.read_paths
            if self._valid_return_lian_path(path)
        ]

        if not candidates:
            return ""

        value = self._text(value)
        used_names = set(flow.used_symbol_names)
        access_candidates = [
            candidate
            for candidate in candidates
            if self._looks_like_access_path(candidate)
        ]
        ordered_candidates = access_candidates or candidates

        for candidate in ordered_candidates:
            base = self._path_base(candidate)
            if value and (candidate == value or base == value):
                return candidate
            if base and base in used_names:
                return candidate

        return ordered_candidates[0]

    def _valid_return_lian_path(self, path: str) -> bool:
        if not path:
            return False
        if path.endswith("[]"):
            return False
        if "*" in path and not path.startswith("*"):
            return False
        return True

    def _return_lian_path_matches_value(
        self,
        target: UnsafeStmtTarget,
        path: str,
        value: str,
        traced: str,
        resolved: str,
    ) -> bool:
        if not path:
            return False
        base = self._path_base(path)
        if not value:
            return True
        if path == value or base == value:
            return True
        for candidate in (traced, resolved):
            if candidate and (path == candidate or base == self._path_base(candidate)):
                return True
        return base in set(self.context.get_stmt_used_symbol_names(target.stmt_id))

    def _return_lifetime_source(
        self,
        target: UnsafeStmtTarget,
        value: str,
    ) -> str | None:
        if not value:
            return None
        if value.startswith("&"):
            value = value[1:].strip()
        base = self._path_base(value) or value
        if base != value:
            return base
        addr_source = self._addr_of_source_before(target, base)
        if addr_source:
            return self._path_base(addr_source) or addr_source
        return base or None

    def _return_lifetime_hints(
        self,
        target: UnsafeStmtTarget,
        origin: _ReturnOrigin,
        *,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> ReturnLifetimeHints:
        expression = self._text(origin.expression)
        semantic_source = self._text(origin.semantic_source) or expression
        if self._is_null_pointer_value(semantic_source):
            return ReturnLifetimeHints(
                kind=ReturnLifetimeKind.NULL,
                source=semantic_source or expression or None,
            )

        allocator = self._return_allocator_source(target, origin)
        if allocator:
            return ReturnLifetimeHints(
                kind=ReturnLifetimeKind.HEAP,
                source=allocator,
            )

        lian_hint = self._return_lifetime_from_lian_origin(target, flow=flow)
        if lian_hint.kind in {
            ReturnLifetimeKind.PARAM,
            ReturnLifetimeKind.GLOBAL,
        }:
            return lian_hint

        direct_hint = self._return_lifetime_from_symbol(
            target, semantic_source
        )
        if direct_hint.kind is not ReturnLifetimeKind.UNKNOWN:
            return direct_hint
        if lian_hint.kind is ReturnLifetimeKind.LOCAL:
            return lian_hint

        return ReturnLifetimeHints(
            kind=ReturnLifetimeKind.UNKNOWN,
            source=(
                self._return_lifetime_source(target, semantic_source)
                or expression
                or None
            ),
        )

    def _return_allocator_source(
        self,
        target: UnsafeStmtTarget,
        origin: _ReturnOrigin,
    ) -> str:
        for value in (origin.expression, origin.semantic_source):
            callee = self._call_expr_name(value)
            if callee in _ALLOCATION_CALLEES:
                return callee
            base = self._path_base(value) or self._text(value)
            if base:
                origin_call = self._origin_call_before(target, base)
                if origin_call in _ALLOCATION_CALLEES:
                    return origin_call
        return ""

    def _return_lifetime_from_lian_origin(
        self,
        target: UnsafeStmtTarget,
        *,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> ReturnLifetimeHints:
        if target.method_id is None:
            return ReturnLifetimeHints(kind=ReturnLifetimeKind.UNKNOWN)

        if flow is None:
            flow = self._lian_stmt_flow(target)
        local_hint: ReturnLifetimeHints | None = None
        for state_id in flow.read_state_ids:
            traced = self.context.trace_state_origin(
                target.method_id, state_id
            )
            if traced is None:
                continue
            hint = self._return_lifetime_from_origin_chain(
                target, traced.chain
            )
            if hint.kind is ReturnLifetimeKind.PARAM:
                return hint
            if hint.kind is ReturnLifetimeKind.GLOBAL:
                return hint
            if hint.kind is ReturnLifetimeKind.LOCAL and local_hint is None:
                local_hint = hint

        return local_hint or ReturnLifetimeHints(
            kind=ReturnLifetimeKind.UNKNOWN
        )

    def _return_lifetime_from_origin_chain(
        self,
        target: UnsafeStmtTarget,
        chain: tuple[Any, ...],
    ) -> ReturnLifetimeHints:
        local_hint: ReturnLifetimeHints | None = None
        for step in chain:
            source_name = self._text(
                getattr(step, "source_symbol_name", None)
            )
            source_id = self._lian_id(
                getattr(step, "source_symbol_id", None)
            )
            value = self._text(getattr(step, "value", None))
            if self._is_null_pointer_value(value):
                return ReturnLifetimeHints(
                    kind=ReturnLifetimeKind.NULL,
                    source=value,
                )
            if self._call_expr_name(value) in _ALLOCATION_CALLEES:
                return ReturnLifetimeHints(
                    kind=ReturnLifetimeKind.HEAP,
                    source=self._call_expr_name(value),
                )
            if not source_name and value:
                source_name = self._path_base(value) or value
            if not source_name:
                continue

            storage = (
                self.context.symbol_storage_kind(target.method_id, source_id)
                if target.method_id is not None and source_id is not None
                else None
            )
            if storage is None and target.method_id is not None:
                storage = self.context.classify_symbol_storage(
                    target.method_id, source_name
                )
            hint = self._return_lifetime_kind_for_storage(
                storage, source_name
            )
            if hint.kind is ReturnLifetimeKind.PARAM:
                return hint
            if hint.kind is ReturnLifetimeKind.GLOBAL:
                return hint
            if (
                hint.kind is ReturnLifetimeKind.LOCAL
                and local_hint is None
            ):
                local_hint = hint

        return local_hint or ReturnLifetimeHints(
            kind=ReturnLifetimeKind.UNKNOWN
        )

    def _return_lifetime_from_symbol(
        self,
        target: UnsafeStmtTarget,
        value: str,
    ) -> ReturnLifetimeHints:
        source = self._return_lifetime_source(target, value)
        if not source:
            return ReturnLifetimeHints(kind=ReturnLifetimeKind.UNKNOWN)
        storage = self._storage_kind_for_symbol(target, source)
        if storage is StorageKind.PARAM:
            return ReturnLifetimeHints(
                kind=ReturnLifetimeKind.PARAM, source=source
            )
        if storage is StorageKind.GLOBAL:
            return ReturnLifetimeHints(
                kind=ReturnLifetimeKind.GLOBAL, source=source
            )
        if storage is StorageKind.STACK:
            return ReturnLifetimeHints(
                kind=ReturnLifetimeKind.LOCAL, source=source
            )
        return ReturnLifetimeHints(
            kind=ReturnLifetimeKind.UNKNOWN,
            source=source,
        )

    @staticmethod
    def _return_lifetime_kind_for_storage(
        storage: str | None,
        source: str,
    ) -> ReturnLifetimeHints:
        if storage == "param":
            return ReturnLifetimeHints(
                kind=ReturnLifetimeKind.PARAM, source=source
            )
        if storage == "global":
            return ReturnLifetimeHints(
                kind=ReturnLifetimeKind.GLOBAL, source=source
            )
        if storage == "local":
            return ReturnLifetimeHints(
                kind=ReturnLifetimeKind.LOCAL, source=source
            )
        return ReturnLifetimeHints(
            kind=ReturnLifetimeKind.UNKNOWN,
            source=source or None,
        )

    @staticmethod
    def _call_expr_name(value: str) -> str:
        text = str(value or "").strip()
        match = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
        return match.group(1).lower() if match else ""

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
        return result if result != 0 else None

    @staticmethod
    def _is_null_pointer_value(value: str) -> bool:
        return value.strip() in {"0", "NULL", "null", "nullptr", "((void*)0)", "((void *)0)"}

    def _ownership_for_symbol(
        self,
        target: UnsafeStmtTarget,
        symbol: str,
    ) -> Ownership | None:
        if not symbol:
            return None
        origin_call = self._origin_call_before(target, symbol)
        if origin_call in _ALLOCATION_CALLEES:
            return Ownership.OWNED
        if self._active_alias_for_value(target, symbol) is not None:
            return Ownership.BORROWED
        storage = self._storage_kind_for_symbol(target, symbol)
        if storage in {StorageKind.PARAM, StorageKind.GLOBAL, StorageKind.FIELD, StorageKind.STACK}:
            return Ownership.BORROWED
        return None

    def _origin_kind_for_symbol(
        self,
        target: UnsafeStmtTarget,
        symbol: str,
    ) -> OriginKind | None:
        if not symbol:
            return None
        if self._origin_call_before(target, symbol):
            return OriginKind.CALL_RETURN
        if self._active_alias_for_value(target, symbol) is not None:
            return OriginKind.ADDR_OF
        storage = self._storage_kind_for_symbol(target, symbol)
        if storage is StorageKind.PARAM:
            return OriginKind.PARAMETER
        if storage is StorageKind.GLOBAL:
            return OriginKind.GLOBAL
        if storage is StorageKind.FIELD:
            return OriginKind.FIELD
        if storage is StorageKind.STACK:
            return OriginKind.LOCAL
        return None

    def _storage_kind_for_symbol(
        self,
        target: UnsafeStmtTarget,
        symbol: str,
    ) -> StorageKind | None:
        if not symbol:
            return None

        def _classify(name: str) -> StorageKind | None:
            clean = name.strip("&*() ")
            if target.method_id is not None:
                storage = self.context.classify_symbol_storage(
                    target.method_id, clean
                )
                if storage == "param":
                    return StorageKind.PARAM
                if storage == "local":
                    return StorageKind.STACK
                if storage == "global":
                    return StorageKind.GLOBAL
                if storage == "field":
                    return StorageKind.FIELD
            for row in self._rows_for_target(target):
                row_name = self._first_from_row(row, "name", "target")
                if row_name != clean:
                    continue
                op = self._text(getattr(row, "operation", ""))
                if op == "parameter_decl":
                    return StorageKind.PARAM
                if op == "variable_decl":
                    return StorageKind.STACK if target.method_id else StorageKind.GLOBAL
            if "." in clean or "->" in clean:
                return StorageKind.FIELD
            return None

        result = _classify(symbol)
        if result is not None:
            return result

        resolved = self._resolve_temp_name(target, symbol)
        if resolved != symbol and not self._is_temp_name(resolved):
            return _classify(resolved)

        return None

    def _origin_call_before(
        self,
        target: UnsafeStmtTarget,
        symbol: str,
        seen: set[str] | None = None,
    ) -> str:
        if not symbol:
            return ""
        seen = set(seen or ())
        if symbol in seen:
            return ""
        seen.add(symbol)
        for row in reversed(self._rows_for_target(target)):
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if stmt_id >= target.stmt_id:
                continue
            operation = self._text(getattr(row, "operation", ""))
            if operation == "call_stmt" and self._first_from_row(row, "target") == symbol:
                return self._first_from_row(row, "name", "callee", "callee_name").lower()
            if operation != "assign_stmt":
                continue
            if self._assignment_target(row) != symbol:
                continue
            source = self._first_from_row(row, "source", "operand", "value")
            origin = self._origin_call_before(target, source, seen)
            if origin:
                return origin
        return ""

    def _project_internal_call_effects(
        self,
        target: UnsafeStmtTarget,
        callee: str,
        args: list[str],
    ) -> dict[str, Any]:
        if target.method_id is None or not callee:
            return {}
        callee_ids = [
            method_id
            for method_id in self.context.get_callees(target.method_id)
            if (self.context.get_method_name(method_id) or "").lower() == callee
        ]
        if not callee_ids:
            return {}

        result: dict[str, Any] = {"callee_ids": callee_ids}
        arg_effects: list[str] = []
        arg_borrows: list[str] = []
        arg_escapes: list[str] = []
        returns_argument = False

        for callee_id in callee_ids:
            params = self.context.get_method_parameters(callee_id)
            param_names = [
                self._first_from_row(param, "name", "target")
                for param in params
            ]
            return_stmt_ids = self._return_stmt_ids(callee_id)
            for index, param_name in enumerate(param_names):
                if not param_name or index >= len(args):
                    continue
                arg = args[index]
                param_symbol_ids = self._parameter_symbol_ids(
                    callee_id, params[index], param_name
                )
                read = self._symbols_have_used_stmts(callee_id, param_symbol_ids)
                written = self._symbols_have_defined_stmts(
                    callee_id, param_symbol_ids
                )
                returned = self._return_uses_symbols(
                    callee_id, return_stmt_ids, param_symbol_ids
                )
                if not param_symbol_ids:
                    returned = self._return_mentions_name(
                        return_stmt_ids, param_name
                    )

                if written:
                    arg_effects.append(f"arg{index}:{arg}:write")
                    arg_borrows.append(f"arg{index}:{arg}:mut_borrow")
                if read:
                    arg_effects.append(f"arg{index}:{arg}:read")
                    if not written:
                        arg_borrows.append(f"arg{index}:{arg}:shared_borrow")
                if returned:
                    arg_escapes.append(f"arg{index}:{arg}:returned")
                    returns_argument = True

        if arg_effects:
            result["arg_effects"] = _dedupe(arg_effects)
        if arg_borrows:
            result["arg_borrows"] = _dedupe(arg_borrows)
        if arg_escapes:
            result["arg_escapes"] = _dedupe(arg_escapes)
        if returns_argument:
            result["returns_argument"] = True
        return result

    def _parameter_symbol_ids(
        self, method_id: int, param: Any, param_name: str
    ) -> frozenset[int]:
        stmt_id = self._positive_id(getattr(param, "stmt_id", None))
        if stmt_id is None:
            return frozenset()
        return frozenset(
            self.context.resolve_decl_symbol_ids(method_id, stmt_id, param_name)
        )

    def _symbols_have_used_stmts(
        self, method_id: int, symbol_ids: frozenset[int]
    ) -> bool:
        for symbol_id in symbol_ids:
            use, _ = self._cached_param_rw(method_id, symbol_id)
            if use:
                return True
        return False

    def _symbols_have_defined_stmts(
        self, method_id: int, symbol_ids: frozenset[int]
    ) -> bool:
        for symbol_id in symbol_ids:
            _, define = self._cached_param_rw(method_id, symbol_id)
            if define:
                return True
        return False

    def _cached_param_rw(
        self, method_id: int, symbol_id: int
    ) -> tuple[bool, bool]:
        key = (method_id, symbol_id)
        cached = self._param_rw_cache.get(key)
        if cached is not None:
            return cached
        has_use = False
        has_def = False
        for stmt_id in self.context.get_used_stmt_ids_for_symbol(method_id, symbol_id):
            if not self._is_declaration_stmt(stmt_id):
                has_use = True
                break
        for stmt_id in self.context.get_defined_stmt_ids_for_symbol(method_id, symbol_id):
            if not self._is_declaration_stmt(stmt_id):
                has_def = True
                break
        result = (has_use, has_def)
        self._param_rw_cache[key] = result
        return result

    def _is_declaration_stmt(self, stmt_id: int) -> bool:
        row = self.context.get_stmt(stmt_id)
        return self._text(getattr(row, "operation", "")) in {
            "parameter_decl",
            "variable_decl",
        }

    def _return_stmt_ids(self, method_id: int) -> tuple[int, ...]:
        stmt_ids: list[int] = []
        for row in self.context.get_method_rows(method_id):
            if self._text(getattr(row, "operation", "")) != "return_stmt":
                continue
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if stmt_id is not None:
                stmt_ids.append(stmt_id)
        return tuple(stmt_ids)

    def _return_uses_symbols(
        self,
        method_id: int,
        return_stmt_ids: tuple[int, ...],
        symbol_ids: frozenset[int],
    ) -> bool:
        if not symbol_ids:
            return False
        used_stmt_ids: set[int] = set()
        for symbol_id in symbol_ids:
            used_stmt_ids.update(
                self.context.get_used_stmt_ids_for_symbol(method_id, symbol_id)
            )
        for stmt_id in return_stmt_ids:
            used = set(self.context.get_stmt_direct_used_symbol_ids(stmt_id))
            used.update(self.context.get_stmt_implicit_used_symbol_ids(stmt_id))
            if used & symbol_ids:
                return True
            if stmt_id in used_stmt_ids:
                return True
        return False

    def _return_mentions_name(
        self, return_stmt_ids: tuple[int, ...], name: str
    ) -> bool:
        for stmt_id in return_stmt_ids:
            row = self.context.get_stmt(stmt_id)
            returned_value = self._return_value_from_row(row)
            if self._value_mentions(returned_value, name):
                return True
        return False

    def _assignment_target(self, row: Any) -> str:
        if self._text(getattr(row, "operation", "")) == "field_write":
            receiver = self._first_from_row(row, "receiver_object", "object")
            field = self._first_from_row(row, "field", "field_name")
            return f"{receiver}.{field}" if receiver and field else ""
        return self._first_from_row(row, "target", "name")

    def _member_path(self, receiver: str, field: str) -> str:
        if not receiver or not field:
            return ""
        return f"{receiver}.{field}"

    def _field_is_pointer_from_context(
        self,
        target: UnsafeStmtTarget,
        *,
        receiver: str,
        field: str,
        member: str,
        access_path: str,
        value_name: str = "",
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> bool | None:
        field_type = self._field_type_from_context(
            target,
            receiver=receiver,
            field=field,
            member=member,
            access_path=access_path,
        )
        if field_type:
            return self._is_pointer_type(field_type)

        lian_field_type = self._lian_field_type_from_state(
            target,
            field=field,
            member=member or access_path,
            flow=flow,
        )
        if lian_field_type:
            return self._is_pointer_type(lian_field_type)

        value_type = self._value_type_for_name(target, value_name)
        if value_type:
            return self._is_pointer_type(value_type)
        return None

    def _lian_field_type_from_state(
        self,
        target: UnsafeStmtTarget,
        *,
        field: str,
        member: str,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> str:
        if target.method_id is None:
            return ""
        expected_field = field or self._path_field(member)
        if flow is None:
            flow = self._lian_stmt_flow(target)
        state_ids = (*flow.read_state_ids, *flow.written_state_ids)
        for state_id in state_ids:
            path = self._format_lian_state_path(target, state_id)
            if not path:
                continue
            if member and path != member and self._path_field(path) != expected_field:
                continue
            if expected_field and self._path_field(path) != expected_field:
                continue
            state = self.context.find_state_by_id(target.method_id, state_id)
            state_type = self._lian_item_type(state)
            if state_type:
                return state_type
        return ""

    def _field_type_from_context(
        self,
        target: UnsafeStmtTarget,
        *,
        receiver: str,
        field: str,
        member: str,
        access_path: str,
    ) -> str:
        field = field or self._path_field(member) or self._path_field(access_path)
        if not field:
            return ""

        receiver_type = self._receiver_c_type(target, receiver or self._path_base(member))
        if receiver_type:
            resolved = self._field_type_for_receiver_type(target, receiver_type, field)
            if resolved:
                return resolved

        path_base = self._path_base(access_path or member)
        if path_base and path_base != receiver:
            base_type = self._receiver_c_type(target, path_base)
            if base_type:
                resolved = self._field_type_for_receiver_type(target, base_type, field)
                if resolved:
                    return resolved

        return self._unique_field_type_by_name(target, field)

    def _receiver_c_type(self, target: UnsafeStmtTarget, receiver: str) -> str:
        receiver = self._path_base(receiver) or receiver
        if not receiver:
            return ""
        value_type = self._value_type_for_name(target, receiver)
        if value_type:
            return value_type
        traced = self._trace_value_origin_before(target, receiver)
        if traced and traced != receiver:
            base = self._path_base(traced) or traced
            value_type = self._value_type_for_name(target, base)
            if value_type:
                return value_type

        resolved = self._resolve_temp_name(target, receiver)
        if resolved and resolved != receiver:
            base = self._path_base(resolved) or resolved
            if base != receiver:
                value_type = self._value_type_for_name(target, base)
                if value_type:
                    return value_type
        return ""

    def _field_type_for_receiver_type(
        self,
        target: UnsafeStmtTarget,
        receiver_type: str,
        field: str,
    ) -> str:
        type_names = self._candidate_aggregate_type_names(receiver_type)
        if not type_names:
            return ""


        for row in self._type_lookup_rows(target):
            if self._text(getattr(row, "operation", "")) not in {
                "struct_decl",
                "union_decl",
            }:
                continue
            aggregate_name = self._first_from_row(row, "name", "target")
            if aggregate_name not in type_names:
                continue
            row_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if row_id <= 0:
                continue
            field_type = self._field_type_in_aggregate(row_id, field)
            if field_type:
                return field_type


        for aggregate_name in type_names:
            field_type = self._field_type_in_aggregate_global(aggregate_name, field)
            if field_type:
                return field_type

        return ""

    def _unique_field_type_by_name(
        self,
        target: UnsafeStmtTarget,
        field: str,
    ) -> str:
        def _collect(rows: tuple[Any, ...]) -> set[str]:
            matches: set[str] = set()
            for row in rows:
                if self._first_from_row(row, "name", "target") != field:
                    continue
                if not self._has_aggregate_ancestor(row):
                    continue
                field_type = self._first_from_row(
                    row, "data_type", "default_data_type"
                )
                if field_type:
                    matches.add(field_type)
            return matches

        matches = _collect(self._type_lookup_rows(target))
        if len(matches) == 1:
            return next(iter(matches))
        if not matches:

            matches = _collect(self._all_type_lookup_rows(target))

        if not matches:
            return ""

        if len(matches) == 1:
            return next(iter(matches))



        pointer_types = {t for t in matches if self._is_pointer_or_array_type(t)}
        if not pointer_types:

            return next(iter(matches))
        if len(pointer_types) == len(matches):

            return next(iter(matches))

        return ""

    def _type_lookup_rows(self, target: UnsafeStmtTarget) -> tuple[Any, ...]:
        scope_id = (
            target.method_id
            if target.method_id is not None
            else target.entity_id
        )
        cache_key = (target.unit_id, scope_id)
        cached = self._type_lookup_rows_cache.get(cache_key)
        if cached is not None:
            return cached
        rows: list[Any] = []
        seen: set[int] = set()
        for row in (
            *self._rows_for_target(target),
            *self.context.get_unit_rows(target.unit_id),
        ):
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if stmt_id > 0 and stmt_id in seen:
                continue
            if stmt_id > 0:
                seen.add(stmt_id)
            rows.append(row)
        result = tuple(rows)
        self._type_lookup_rows_cache[cache_key] = result
        return result

    def _all_type_lookup_rows(self, target: UnsafeStmtTarget) -> tuple[Any, ...]:

        local_rows = self._type_lookup_rows(target)
        all_units = self._build_all_units_type_rows()
        if not all_units:
            return local_rows

        seen: set[int] = {self._int(getattr(r, "stmt_id", None), default=-1) for r in local_rows}
        seen.discard(-1)
        extra: list[Any] = []
        for row in all_units:
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if stmt_id <= 0 or stmt_id in seen:
                continue
            seen.add(stmt_id)
            extra.append(row)
        return tuple((*local_rows, *extra))

    def _build_all_units_type_rows(self) -> tuple[Any, ...]:
        if self._all_units_type_rows is not None:
            return self._all_units_type_rows
        rows: list[Any] = []
        seen: set[int] = set()
        for unit_id in self.context.get_all_unit_ids():
            for row in self.context.get_unit_rows(unit_id):
                op = self._text(getattr(row, "operation", ""))
                if op not in {"struct_decl", "union_decl", "parameter_decl",
                               "variable_decl", "field_decl", "member_decl"}:
                    continue
                stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
                if stmt_id <= 0 or stmt_id in seen:
                    continue
                seen.add(stmt_id)
                rows.append(row)
        self._all_units_type_rows = tuple(rows)
        return self._all_units_type_rows

    def _field_type_in_aggregate_global(
        self,
        aggregate_name: str,
        field: str,
    ) -> str:

        cache_key = f"{aggregate_name}.{field}"
        cached = self._all_units_type_cache.get(aggregate_name, {}).get(field)
        if cached is not None:
            return cached

        all_rows = self._build_all_units_type_rows()
        for row in all_rows:
            if self._text(getattr(row, "operation", "")) not in {
                "struct_decl",
                "union_decl",
            }:
                continue
            if self._first_from_row(row, "name", "target") != aggregate_name:
                continue
            row_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if row_id <= 0:
                continue
            field_type = self._field_type_in_aggregate(row_id, field)
            if field_type:
                self._all_units_type_cache.setdefault(
                    aggregate_name, {}
                )[field] = field_type
                return field_type

        self._all_units_type_cache.setdefault(aggregate_name, {})[field] = ""
        return ""

    def _field_type_in_aggregate(self, aggregate_stmt_id: int, field: str) -> str:
        for child in self.context.get_children(aggregate_stmt_id):
            if self._first_from_row(child, "name", "target") != field:
                continue
            field_type = self._first_from_row(
                child, "data_type", "default_data_type"
            )
            if field_type:
                return field_type
        return ""

    def _has_aggregate_ancestor(self, row: Any) -> bool:
        stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
        if stmt_id <= 0:
            return False
        return any(
            self._text(getattr(ancestor, "operation", ""))
            in {"struct_decl", "union_decl"}
            for ancestor in self.context.get_ancestors(stmt_id)
        )

    def _candidate_aggregate_type_names(self, c_type: str) -> set[str]:
        text = self._strip_type_qualifiers(c_type)
        text = text.replace("*", " ")
        text = re.sub(r"\bstruct\s+", "", text)
        text = re.sub(r"\bunion\s+", "", text)
        text = re.sub(r"\s+", " ", text).strip()
        if not text:
            return set()
        tokens = [
            token.strip()
            for token in re.split(r"[^A-Za-z0-9_]+", text)
            if token.strip()
        ]
        return {
            token
            for token in tokens
            if token
            and token not in _C_TYPE_KEYWORDS
            and not self._is_integer_type(token)
        }

    @staticmethod
    def _strip_type_qualifiers(value: str) -> str:
        result = value
        for qualifier in (
            "const",
            "volatile",
            "restrict",
            "static",
            "signed",
            "unsigned",
        ):
            result = re.sub(rf"\b{qualifier}\b", " ", result)
        return result

    def _field_write_establishes_alias(
        self,
        target: UnsafeStmtTarget,
        *,
        source: str,
        is_pointer_field: bool | None,
        lian_read_path: str,
        alias: _ArrayAlias | None,
        flow: _UnsafeStmtLianFlow | None = None,
    ) -> bool | None:
        if alias is not None:
            return True
        if is_pointer_field is not True:
            return None
        source = self._text(source)
        if not source or self._is_null_pointer_value(source):
            return False
        if self._origin_call_before(target, source) in _ALLOCATION_CALLEES:
            return False
        traced = self._trace_value_origin_before(target, source)
        if traced and self._origin_call_before(target, traced) in _ALLOCATION_CALLEES:
            return False
        if self._source_expr_establishes_alias(target, source):
            return True
        if lian_read_path and self._source_expr_establishes_alias(
            target, lian_read_path
        ):
            return True
        if flow is not None:
            for path in flow.read_paths:
                if self._source_expr_establishes_alias(target, path):
                    return True
        if traced and traced != source:
            return self._source_expr_establishes_alias(target, traced)
        return None

    def _source_expr_establishes_alias(
        self,
        target: UnsafeStmtTarget,
        source: str,
    ) -> bool:
        source = self._text(source)
        if not source or self._is_null_pointer_value(source):
            return False
        if source.startswith("&"):
            return True
        if "[" in source or "." in source or "->" in source:
            return True
        if self._active_alias_for_value(target, source) is not None:
            return True
        if self._array_origin(target, source):
            return True
        base, offset = self._pointer_offset_origin_before(target, source)
        if base or offset:
            return True
        value_type = self._value_type_for_name(target, source)
        if value_type and self._is_pointer_type(value_type):
            return True
        storage = self._storage_kind_for_symbol(target, source)
        if storage in {StorageKind.PARAM, StorageKind.GLOBAL, StorageKind.FIELD}:
            return True
        return False

    def _value_type_for_name(self, target: UnsafeStmtTarget, name: str) -> str:
        if not name:
            return ""

        def _lookup(lookup_name: str) -> str:
            clean = lookup_name.strip("&*() ")
            for row in self._rows_for_target(target):
                if self._first_from_row(row, "name", "target") == clean:
                    return self._first_from_row(row, "data_type", "default_data_type")
            return ""

        result = _lookup(name)
        if result:
            return result

        resolved = self._resolve_temp_name(target, name)
        if resolved != name and not self._is_temp_name(resolved):
            return _lookup(resolved)

        return ""

    def _cast_kind(self, source_type: str, target_type: str) -> CastKind:
        source_is_ptr = self._is_pointer_type(source_type)
        target_is_ptr = self._is_pointer_type(target_type)
        source_is_int = self._is_integer_type(source_type)
        target_is_int = self._is_integer_type(target_type)
        if source_is_ptr and target_is_ptr:
            if self._strip_const(source_type) != self._strip_const(target_type):
                return CastKind.POINTER_TO_POINTER
            return CastKind.QUALIFIER_CHANGE
        if source_is_ptr and target_is_int:
            return CastKind.POINTER_TO_INTEGER
        if source_is_int and target_is_ptr:
            return CastKind.INTEGER_TO_POINTER
        if source_type or target_type:
            return CastKind.NUMERIC_CAST
        return CastKind.UNKNOWN

    def _pointer_offset_origin_before(
        self,
        target: UnsafeStmtTarget,
        value: str,
    ) -> tuple[str, str]:
        if not value:
            return "", ""
        alias = self._active_alias_for_value(target, value)
        if alias is not None:
            return alias.base_path or alias.base, alias.offset
        for row in reversed(self._rows_for_target(target)):
            stmt_id = self._int(getattr(row, "stmt_id", None), default=-1)
            if stmt_id >= target.stmt_id:
                continue
            if self._assignment_target(row) != value:
                continue
            operator = self._text(getattr(row, "operator", ""))
            if operator not in _POINTER_ARITHMETIC_OPERATORS:
                continue
            operand = self._first_from_row(row, "operand", "source")
            operand2 = self._first_from_row(row, "operand2")
            return operand, operand2
        return "", ""

    def _type_cast_constraints(
        self,
        cast_kind: CastKind,
        target_type: str,
    ) -> list[str]:
        constraints: list[str] = []
        if cast_kind is CastKind.INTEGER_TO_POINTER:
            constraints.append("integer-to-pointer cast cannot be translated as a safe Rust reference without external validity evidence")
        elif cast_kind is CastKind.POINTER_TO_INTEGER:
            constraints.append("pointer-to-integer cast must preserve address-sized integer semantics")
        elif cast_kind is CastKind.POINTER_TO_POINTER:
            constraints.append("pointer reinterpretation must preserve alignment, aliasing, and layout requirements")
        elif cast_kind is CastKind.QUALIFIER_CHANGE and "const" in target_type:
            constraints.append("const-qualified target should not become a mutable Rust reference")
        return constraints

    @staticmethod
    def _is_pointer_type(value: str) -> bool:
        return "*" in value or "ptr" in value.lower()

    @staticmethod
    def _is_pointer_or_array_type(value: str) -> bool:
        return (
            UnsafeStmtProgrammaticAnalyzer._is_pointer_type(value)
            or ("[" in value and "]" in value)
        )

    @staticmethod
    def _is_integer_type(value: str) -> bool:
        lowered = value.lower()
        return any(
            token in lowered
            for token in ("int", "long", "short", "char", "size_t", "intptr", "uintptr")
        )

    @staticmethod
    def _strip_const(value: str) -> str:
        return value.replace("const", "").replace("volatile", "").strip()

    @staticmethod
    def _value_mentions(value: str, needle: str) -> bool:
        if not value or not needle:
            return False
        return bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(needle)}(?![A-Za-z0-9_])", value))

    def _row_to_raw(self, row: Any) -> dict[str, Any]:
        asdict = getattr(row, "_asdict", None)
        if callable(asdict):
            return dict(asdict())
        if callable(getattr(row, "to_dict", None)):
            return dict(row.to_dict())
        if dataclasses.is_dataclass(row):
            return dataclasses.asdict(row)
        if hasattr(row, "__dict__"):
            return dict(vars(row))
        return {
            name: getattr(row, name)
            for name in dir(row)
            if not name.startswith("_")
            and not callable(getattr(row, name, None))
        }

    def _alias_element(self, alias: _ArrayAlias | None, index: str) -> str:
        if alias is None:
            return ""
        offset = _combine_offsets(alias.offset, "+", index or "0")
        return f"{alias.element_base}[{offset}]"

    @staticmethod
    def _first(raw: dict[str, Any], *field_names: str) -> str:
        for field_name in field_names:
            value = raw.get(field_name)
            text = _text(value)
            if text:
                return text
        return ""

    @staticmethod
    def _first_from_row(row: Any, *field_names: str) -> str:
        for field_name in field_names:
            value = getattr(row, field_name, None)
            text = _text(value)
            if text:
                return text
        return ""

    @staticmethod
    def _as_string_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return []
            try:
                import ast

                parsed = ast.literal_eval(text)
            except (SyntaxError, ValueError):
                return [item.strip() for item in text.split(",") if item.strip()]
            return UnsafeStmtProgrammaticAnalyzer._as_string_list(parsed)
        if isinstance(value, dict):
            return [str(item).strip() for item in value.values() if str(item).strip()]
        try:
            return [str(item).strip() for item in value if str(item).strip()]
        except TypeError:
            text = str(value).strip()
            return [text] if text else []

    @staticmethod
    def _is_temp_name(value: str) -> bool:
        return value.startswith("%") or value.startswith("tmp")

    @staticmethod
    def _text(value: Any) -> str:
        return _text(value)

    @staticmethod
    def _int(value: Any, *, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default


def _text(value: Any) -> str:
    if value is None:
        return ""
    try:
        if value != value:
            return ""
    except (TypeError, ValueError):
        pass
    if isinstance(value, list):
        return ", ".join(_text(item) for item in value if _text(item))
    if isinstance(value, tuple):
        return ", ".join(_text(item) for item in value if _text(item))
    return str(value).strip()


def _is_int_literal(value: str) -> bool:
    return bool(re.fullmatch(r"[+-]?(?:0|[1-9][0-9]*)", str(value or "").strip()))


def _combine_offsets(left: str, operator: str, right: str) -> str:
    left = left or "0"
    right = right or "0"
    if _is_int_literal(left) and _is_int_literal(right):
        delta = int(right) if operator == "+" else -int(right)
        return str(int(left) + delta)
    if right == "0":
        return left
    if left == "0":
        return right if operator == "+" else f"-{right}"
    return f"{left} {operator} {right}"


def _split_element(value: str) -> tuple[str, str]:
    last_open = value.rfind("[")
    last_close = value.rfind("]")
    if last_open <= 0 or last_close <= last_open:
        return value, "0"
    return value[:last_open], value[last_open + 1 : last_close]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _dedupe_ints(values: Iterable[Any]) -> tuple[int, ...]:
    seen: set[int] = set()
    result: list[int] = []
    for value in values:
        try:
            normalized = int(value)
        except (TypeError, ValueError, OverflowError):
            continue
        if normalized in seen or normalized in {-1, 0}:
            continue
        seen.add(normalized)
        result.append(normalized)
    return tuple(result)
