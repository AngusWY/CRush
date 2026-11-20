from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class AnalysisContextError(RuntimeError):
    pass


@dataclass(frozen=True)
class StateOriginStep:


    state_id: int
    stmt_id: int | None = None
    source_symbol_id: int | None = None
    source_symbol_name: str | None = None
    source_state_id: int | None = None
    access_path: str | None = None
    value: str | None = None
    data_type: str | None = None


@dataclass(frozen=True)
class StateOrigin:


    state_id: int
    stmt_id: int | None = None
    source_symbol_id: int | None = None
    source_symbol_name: str | None = None
    source_state_id: int | None = None
    access_path: str | None = None
    value: str | None = None
    data_type: str | None = None
    chain: tuple[StateOriginStep, ...] = ()
    phase: str = "preferred"


@dataclass(frozen=True)
class LianEvidence:


    phase: str
    source: str
    stmt_id: int | None = None
    method_id: int | None = None
    symbol_ids: tuple[int, ...] = ()
    state_ids: tuple[int, ...] = ()
    source_stmt_ids: tuple[int, ...] = ()
    access_paths: tuple[str, ...] = ()
    reason: str = ""
    confidence: str = "low"
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "phase": self.phase,
            "source": self.source,
            "stmt_id": self.stmt_id,
            "method_id": self.method_id,
            "symbol_ids": list(self.symbol_ids),
            "state_ids": list(self.state_ids),
            "source_stmt_ids": list(self.source_stmt_ids),
            "access_paths": list(self.access_paths),
            "reason": self.reason,
            "confidence": self.confidence,
        }
        if self.extra:
            result["extra"] = dict(self.extra)
        return result


@dataclass(frozen=True)
class UnitIndex:


    unit_id: int
    rows: tuple[Any, ...]
    rows_by_id: dict[int, Any]
    children_by_parent: dict[int, tuple[Any, ...]]


@dataclass(frozen=True)
class SymbolStateIndex:


    items: tuple[Any, ...]
    symbols_by_id: dict[int, Any]
    symbols_by_decl_stmt_id: dict[int, Any]
    symbols_by_name: dict[str, tuple[Any, ...]]
    states_by_id: dict[int, Any]
    states_for_symbol_id: dict[int, tuple[Any, ...]]


class AnalysisContext:


    def __init__(self, loader: Any) -> None:
        if loader is None:
            raise ValueError("loader must not be None")
        self.loader = loader
        self._unit_indexes: dict[int, UnitIndex] = {}
        self._all_unit_ids: tuple[int, ...] | None = None
        self._all_method_ids: tuple[int, ...] | None = None
        self._method_rows: dict[int, tuple[Any, ...]] = {}
        self._method_parameters: dict[int, tuple[Any, ...]] = {}
        self._stmt_to_unit: dict[int, int | None] = {}
        self._stmt_to_method: dict[int, int | None] = {}
        self._stmt_to_class: dict[int, int | None] = {}
        self._method_names: dict[int, str | None] = {}
        self._unit_paths: dict[int, Path | None] = {}
        self._stmt_statuses_p1: dict[int, dict[int, Any]] = {}
        self._stmt_statuses_p3: dict[int, dict[int, Any]] = {}
        self._symbol_state_spaces_p1: dict[int, Any | None] = {}
        self._symbol_state_spaces_p3: dict[int, Any | None] = {}
        self._symbol_state_indexes: dict[tuple[int, str], SymbolStateIndex] = {}
        self._defined_symbols_p1: dict[int, dict[int, tuple[int, ...]]] = {}
        self._defined_symbols_p3: dict[int, dict[int, tuple[int, ...]]] = {}
        self._used_symbols: dict[int, dict[int, tuple[int, ...]]] = {}
        self._method_def_use_summaries: dict[int, Any | None] = {}
        self._method_cfgs: dict[int, Any | None] = {}
        self._unit_symbol_declarations: dict[
            int, dict[str, tuple[int, ...]]
        ] = {}
        self._internal_callees: dict[int, tuple[Any, ...]] = {}
        self._callers: dict[int, tuple[int, ...]] = {}
        self._callees: dict[int, tuple[int, ...]] = {}
        self._stmt_sources: dict[int, tuple[str, ...]] = {}



    def get_stmt(self, stmt_id: int) -> Any | None:


        normalized_id = self._positive_id(stmt_id)
        if normalized_id is None:
            return None
        unit_id = self.get_unit_id(normalized_id)
        if unit_id is None:
            return None
        return self.get_unit_index(unit_id).rows_by_id.get(normalized_id)

    def get_unit_index(self, unit_id: int) -> UnitIndex:


        normalized_id = self._positive_id(unit_id)
        if normalized_id is None:
            return UnitIndex(-1, (), {}, {})
        if normalized_id in self._unit_indexes:
            return self._unit_indexes[normalized_id]

        raw_rows = self._call_optional("get_unit_gir", normalized_id)
        rows = self._as_tuple(raw_rows)
        rows_by_id: dict[int, Any] = {}
        mutable_children: dict[int, list[Any]] = {}
        for row in rows:
            stmt_id = self._positive_id(getattr(row, "stmt_id", None))
            if stmt_id is None:
                continue
            rows_by_id[stmt_id] = row
            self._stmt_to_unit[stmt_id] = normalized_id
            parent_id = self._id_or_default(
                getattr(row, "parent_stmt_id", None), default=0
            )
            mutable_children.setdefault(parent_id, []).append(row)

        children = {
            parent_id: tuple(items)
            for parent_id, items in mutable_children.items()
        }
        result = UnitIndex(
            unit_id=normalized_id,
            rows=rows,
            rows_by_id=rows_by_id,
            children_by_parent=children,
        )
        self._unit_indexes[normalized_id] = result
        return result

    def get_unit_rows(self, unit_id: int) -> tuple[Any, ...]:
        return self.get_unit_index(unit_id).rows

    def get_all_unit_ids(self) -> tuple[int, ...]:
        if self._all_unit_ids is None:
            value = self._call_optional("get_all_unit_ids")
            self._all_unit_ids = self._normalized_ids(value)
        return self._all_unit_ids

    def get_all_method_ids(self) -> tuple[int, ...]:
        if self._all_method_ids is None:
            value = self._call_optional("get_all_method_ids")
            self._all_method_ids = self._normalized_ids(value)
        return self._all_method_ids

    def get_method_rows(self, method_id: int) -> tuple[Any, ...]:


        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return ()
        if normalized_id in self._method_rows:
            return self._method_rows[normalized_id]

        stmt_ids = self._call_optional(
            "convert_method_id_to_stmt_ids", normalized_id
        )
        ordered_ids = [normalized_id]
        ordered_ids.extend(
            value
            for value in (
                self._positive_id(item) for item in self._as_tuple(stmt_ids)
            )
            if value is not None and value != normalized_id
        )
        seen: set[int] = set()
        rows: list[Any] = []
        for stmt_id in ordered_ids:
            if stmt_id in seen:
                continue
            seen.add(stmt_id)
            row = self.get_stmt(stmt_id)
            if row is not None:
                rows.append(row)
                self._stmt_to_method[stmt_id] = normalized_id

        result = tuple(rows)
        self._method_rows[normalized_id] = result
        return result

    def get_method_parameters(self, method_id: int) -> tuple[Any, ...]:
        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return ()
        if normalized_id in self._method_parameters:
            return self._method_parameters[normalized_id]

        parameter_ids = self._call_optional(
            "convert_method_id_to_parameter_ids", normalized_id
        )
        rows = tuple(
            row
            for row in (
                self.get_stmt(stmt_id)
                for stmt_id in (
                    self._positive_id(item)
                    for item in self._as_tuple(parameter_ids)
                )
                if stmt_id is not None
            )
            if row is not None
        )
        self._method_parameters[normalized_id] = rows
        return rows

    def get_parent(self, stmt_id: int) -> Any | None:
        row = self.get_stmt(stmt_id)
        if row is None:
            return None
        parent_id = self._positive_id(getattr(row, "parent_stmt_id", None))
        return None if parent_id is None else self.get_stmt(parent_id)

    def get_children(self, stmt_id: int) -> tuple[Any, ...]:
        normalized_id = self._positive_id(stmt_id)
        if normalized_id is None:
            return ()
        unit_id = self.get_unit_id(normalized_id)
        if unit_id is None:
            return ()
        return self.get_unit_index(unit_id).children_by_parent.get(
            normalized_id, ()
        )

    def get_ancestors(self, stmt_id: int) -> tuple[Any, ...]:


        ancestors: list[Any] = []
        seen = {self._id_or_default(stmt_id)}
        current = self.get_parent(stmt_id)
        while current is not None:
            current_id = self._positive_id(getattr(current, "stmt_id", None))
            if current_id is None or current_id in seen:
                break
            seen.add(current_id)
            ancestors.append(current)
            current = self.get_parent(current_id)
        return tuple(ancestors)



    def get_unit_id(self, stmt_id: int) -> int | None:
        normalized_id = self._positive_id(stmt_id)
        if normalized_id is None:
            return None
        if normalized_id not in self._stmt_to_unit:
            raw = self._call_optional(
                "convert_stmt_id_to_unit_id", normalized_id
            )
            self._stmt_to_unit[normalized_id] = self._positive_id(raw)
        return self._stmt_to_unit[normalized_id]

    def get_method_id(self, stmt_id: int) -> int | None:
        normalized_id = self._positive_id(stmt_id)
        if normalized_id is None:
            return None
        if normalized_id not in self._stmt_to_method:
            raw = self._call_optional(
                "convert_stmt_id_to_method_id", normalized_id
            )
            self._stmt_to_method[normalized_id] = self._positive_id(raw)
        return self._stmt_to_method[normalized_id]

    def get_class_id(self, stmt_id: int) -> int | None:
        normalized_id = self._positive_id(stmt_id)
        if normalized_id is None:
            return None
        if normalized_id not in self._stmt_to_class:
            raw = self._call_optional(
                "convert_stmt_id_to_class_id", normalized_id
            )
            self._stmt_to_class[normalized_id] = self._positive_id(raw)
        return self._stmt_to_class[normalized_id]

    def get_method_name(self, method_id: int) -> str | None:
        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return None
        if normalized_id not in self._method_names:
            value = self._call_optional(
                "convert_method_id_to_method_name", normalized_id
            )
            text = self._text(value)
            self._method_names[normalized_id] = text or None
        return self._method_names[normalized_id]

    def get_unit_path(self, unit_id: int) -> Path | None:
        normalized_id = self._positive_id(unit_id)
        if normalized_id is None:
            return None
        if normalized_id not in self._unit_paths:
            value = self._call_optional(
                "convert_unit_id_to_unit_path", normalized_id
            )
            text = self._text(value)
            self._unit_paths[normalized_id] = Path(text) if text else None
        return self._unit_paths[normalized_id]

    def get_unit_symbol_declarations(
        self, unit_id: int
    ) -> dict[str, tuple[int, ...]]:


        normalized_id = self._positive_id(unit_id)
        if normalized_id is None:
            return {}
        if normalized_id not in self._unit_symbol_declarations:
            value = self._call_optional(
                "get_unit_symbol_name_to_decl_ids", normalized_id
            )
            if value is None:
                result: dict[str, tuple[int, ...]] = {}
            elif isinstance(value, dict):
                result = {
                    str(name): self._normalized_ids(declaration_ids)
                    for name, declaration_ids in value.items()
                }
            else:
                raise AnalysisContextError(
                    "get_unit_symbol_name_to_decl_ids"
                    f"({normalized_id}) returned {type(value).__name__}, "
                    "expected dict or None"
                )
            self._unit_symbol_declarations[normalized_id] = result
        return self._unit_symbol_declarations[normalized_id]



    def get_stmt_statuses_p1(self, method_id: int) -> dict[int, Any]:
        return self._get_stmt_statuses(
            method_id, "get_stmt_status_p1", self._stmt_statuses_p1
        )

    def get_stmt_statuses_p2(self, method_id: int) -> dict[int, Any]:


        return self.get_stmt_statuses_p3(method_id)

    def get_stmt_statuses_p3(self, method_id: int) -> dict[int, Any]:
        return self._get_stmt_statuses(
            method_id, "get_stmt_status_p3", self._stmt_statuses_p3
        )

    def get_stmt_status_p1(self, stmt_id: int) -> Any | None:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return None
        return self.get_stmt_statuses_p1(method_id).get(
            self._id_or_default(stmt_id)
        )

    def get_stmt_status_p2(self, stmt_id: int) -> Any | None:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return None
        return self.get_stmt_statuses_p2(method_id).get(
            self._id_or_default(stmt_id)
        )

    def get_stmt_status_p3(self, stmt_id: int) -> Any | None:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return None
        return self.get_stmt_statuses_p3(method_id).get(
            self._id_or_default(stmt_id)
        )

    def get_symbol_state_space_p1(self, method_id: int) -> Any | None:
        return self._get_method_result(
            method_id,
            "get_symbol_state_space_p1",
            self._symbol_state_spaces_p1,
        )

    def get_symbol_state_space_p2(self, method_id: int) -> Any | None:


        return self.get_symbol_state_space_p3(method_id)

    def get_symbol_state_space_p3(self, method_id: int) -> Any | None:
        return self._get_method_result(
            method_id,
            "get_symbol_state_space_p3",
            self._symbol_state_spaces_p3,
        )

    def get_method_def_use_summary(self, method_id: int) -> Any | None:
        return self._get_method_result(
            method_id,
            "get_method_def_use_summary",
            self._method_def_use_summaries,
        )

    def get_method_defined_symbols_p1(
        self, method_id: int
    ) -> dict[int, tuple[int, ...]]:
        return self._get_symbol_stmt_index(
            method_id,
            "get_method_defined_symbols_p1",
            self._defined_symbols_p1,
        )

    def get_method_defined_symbols_p2(
        self, method_id: int
    ) -> dict[int, tuple[int, ...]]:


        return self.get_method_defined_symbols_p3(method_id)

    def get_method_defined_symbols_p3(
        self, method_id: int
    ) -> dict[int, tuple[int, ...]]:
        return self._get_symbol_stmt_index(
            method_id,
            "get_method_defined_symbols_p3",
            self._defined_symbols_p3,
        )

    def get_method_used_symbols(self, method_id: int) -> dict[int, tuple[int, ...]]:
        return self._get_symbol_stmt_index(
            method_id,
            "get_method_used_symbols",
            self._used_symbols,
        )

    def get_method_cfg(self, method_id: int) -> Any | None:
        return self._get_method_result(
            method_id, "get_method_cfg", self._method_cfgs
        )



    def get_preferred_stmt_status(self, stmt_id: int) -> Any | None:


        return self.get_stmt_status_p3(stmt_id) or self.get_stmt_status_p1(
            stmt_id
        )

    def get_preferred_stmt_statuses(self, method_id: int) -> dict[int, Any]:


        statuses = self.get_stmt_statuses_p3(method_id)
        if statuses:
            return statuses
        return self.get_stmt_statuses_p1(method_id)

    def get_preferred_symbol_state_space(
        self,
        method_id: int,
    ) -> Any | None:


        return self.get_symbol_state_space_p3(
            method_id
        ) or self.get_symbol_state_space_p1(method_id)

    def iter_symbol_state_space(
        self,
        method_id: int,
        *,
        phase: str = "preferred",
    ) -> tuple[Any, ...]:


        return self._symbol_state_index(method_id, phase).items

    def find_symbols_by_name(
        self,
        method_id: int,
        name: str,
        *,
        phase: str = "preferred",
    ) -> tuple[Any, ...]:
        normalized_name = self._text(name)
        if not normalized_name:
            return ()
        return self._symbol_state_index(
            method_id, phase
        ).symbols_by_name.get(normalized_name, ())

    def find_symbol_by_name(
        self,
        method_id: int,
        name: str,
        *,
        phase: str = "preferred",
    ) -> Any | None:
        symbols = self.find_symbols_by_name(method_id, name, phase=phase)
        return symbols[-1] if symbols else None

    def find_symbol_by_id(
        self,
        method_id: int,
        symbol_id: int,
        *,
        phase: str = "preferred",
    ) -> Any | None:
        normalized_id = self._lian_id(symbol_id)
        if normalized_id is None:
            return None
        return self._symbol_state_index(
            method_id, phase
        ).symbols_by_id.get(normalized_id)

    def find_symbol_by_decl_stmt_id(
        self,
        method_id: int,
        stmt_id: int,
        *,
        phase: str = "preferred",
    ) -> Any | None:
        normalized_id = self._positive_id(stmt_id)
        if normalized_id is None:
            return None
        return self._symbol_state_index(
            method_id, phase
        ).symbols_by_decl_stmt_id.get(normalized_id)

    def resolve_decl_symbol_ids(
        self,
        method_id: int,
        declaration_stmt_id: int,
        name: str = "",
        *,
        phase: str = "preferred",
    ) -> tuple[int, ...]:


        normalized_phase = self._resolve_phase(method_id, phase)
        symbol = self.find_symbol_by_decl_stmt_id(
            method_id, declaration_stmt_id, phase=normalized_phase
        )
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        if symbol_id is not None:
            return (symbol_id,)

        if normalized_phase == "p1":
            stmt_id = self._positive_id(declaration_stmt_id)
            return () if stmt_id is None else (stmt_id,)

        if name:
            return tuple(
                symbol_id
                for item in self.find_symbols_by_name(
                    method_id, name, phase=normalized_phase
                )
                if (
                    symbol_id := self._lian_id(
                        getattr(item, "symbol_id", None)
                    )
                )
                is not None
            )
        return ()

    def get_defined_stmt_ids_for_symbol(
        self,
        method_id: int,
        symbol_id: int,
        *,
        phase: str = "preferred",
    ) -> tuple[int, ...]:
        return self._loader_stmt_ids_for_symbol(
            method_id,
            symbol_id,
            defined=True,
        )

    def get_used_stmt_ids_for_symbol(
        self,
        method_id: int,
        symbol_id: int,
        *,
        phase: str = "preferred",
    ) -> tuple[int, ...]:
        return self._loader_stmt_ids_for_symbol(
            method_id,
            symbol_id,
            defined=False,
        )

    def _loader_stmt_ids_for_symbol(
        self,
        method_id: int,
        symbol_id: int,
        *,
        defined: bool,
    ) -> tuple[int, ...]:
        normalized_method_id = self._positive_id(method_id)
        normalized_symbol_id = self._lian_id(symbol_id)
        if normalized_method_id is None or normalized_symbol_id is None:
            return ()
        query = (
            self.loader.get_defined_stmt_ids_by_symbol
            if defined
            else self.loader.get_used_stmt_ids_by_symbol
        )
        stmt_ids = self._normalized_ids(query(normalized_symbol_id))
        return tuple(
            stmt_id
            for stmt_id in stmt_ids
            if self.get_method_id(stmt_id) == normalized_method_id
        )

    def find_state_by_id(
        self,
        method_id: int,
        state_id: int,
        *,
        phase: str = "preferred",
    ) -> Any | None:
        normalized_id = self._positive_id(state_id)
        if normalized_id is None:
            return None
        return self._symbol_state_index(
            method_id, phase
        ).states_by_id.get(normalized_id)

    def find_states_for_symbol(
        self,
        method_id: int,
        symbol_id: int,
        *,
        phase: str = "preferred",
    ) -> tuple[Any, ...]:
        normalized_id = self._lian_id(symbol_id)
        if normalized_id is None:
            return ()
        return self._symbol_state_index(
            method_id, phase
        ).states_for_symbol_id.get(normalized_id, ())

    def get_symbol_name(
        self,
        method_id: int,
        symbol_id: int,
        *,
        phase: str = "preferred",
    ) -> str | None:
        symbol = self.find_symbol_by_id(method_id, symbol_id, phase=phase)
        if symbol is None:
            return None
        name = self._text(getattr(symbol, "name", ""))
        return name or None

    def get_state_access_path(
        self,
        method_id: int,
        state_id: int,
        *,
        phase: str = "preferred",
    ) -> str | None:
        state = self.find_state_by_id(method_id, state_id, phase=phase)
        if state is None:
            return None
        if callable(getattr(state, "recover_access_path_str", None)):
            value = state.recover_access_path_str()
            text = self._text(value)
            if text:
                return text
        return self._format_access_path(getattr(state, "access_path", ()))

    def get_stmt_direct_used_symbol_ids(
        self, stmt_id: int
    ) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        return self._space_indices_to_symbol_ids(
            stmt_id,
            getattr(status, "used_symbols", ()),
        )

    def get_stmt_direct_defined_symbol_ids(
        self, stmt_id: int
    ) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        return self._space_indices_to_symbol_ids(
            stmt_id,
            getattr(status, "defined_symbol", ()),
        )

    def get_stmt_implicit_used_symbol_ids(
        self, stmt_id: int
    ) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        return self._space_indices_to_symbol_ids(
            stmt_id,
            getattr(status, "implicitly_used_symbols", ()),
        )

    def get_stmt_implicit_defined_symbol_ids(
        self, stmt_id: int
    ) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        return self._space_indices_to_symbol_ids(
            stmt_id,
            getattr(status, "implicitly_defined_symbols", ()),
        )

    def get_stmt_direct_used_symbol_names(
        self, stmt_id: int
    ) -> tuple[str, ...]:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return ()
        return self._symbol_names_for_ids(
            method_id, self.get_stmt_direct_used_symbol_ids(stmt_id)
        )

    def get_stmt_direct_defined_symbol_names(
        self, stmt_id: int
    ) -> tuple[str, ...]:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return ()
        return self._symbol_names_for_ids(
            method_id, self.get_stmt_direct_defined_symbol_ids(stmt_id)
        )

    def get_stmt_implicit_used_symbol_names(
        self, stmt_id: int
    ) -> tuple[str, ...]:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return ()
        return self._symbol_names_for_ids(
            method_id, self.get_stmt_implicit_used_symbol_ids(stmt_id)
        )

    def get_stmt_implicit_defined_symbol_names(
        self, stmt_id: int
    ) -> tuple[str, ...]:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return ()
        return self._symbol_names_for_ids(
            method_id, self.get_stmt_implicit_defined_symbol_ids(stmt_id)
        )

    def get_stmt_in_state_ids(self, stmt_id: int) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        return self._state_ids_from_def_nodes(
            getattr(status, "in_state_bits", ())
        )

    def get_stmt_out_state_ids(self, stmt_id: int) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        return self._state_ids_from_def_nodes(
            getattr(status, "out_state_bits", ())
        )

    def get_stmt_used_symbol_ids(self, stmt_id: int) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        return self._space_indices_to_symbol_ids(
            stmt_id,
            [
                *self._as_tuple(getattr(status, "used_symbols", ())),
                *self._as_tuple(
                    getattr(status, "implicitly_used_symbols", ())
                ),
            ],
        )

    def get_stmt_defined_symbol_ids(self, stmt_id: int) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        ids = list(self._as_tuple(getattr(status, "defined_symbol", None)))
        ids.extend(
            self._as_tuple(getattr(status, "implicitly_defined_symbols", ()))
        )
        return self._space_indices_to_symbol_ids(stmt_id, ids)

    def get_stmt_used_symbol_names(self, stmt_id: int) -> tuple[str, ...]:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return ()
        return self._symbol_names_for_ids(
            method_id, self.get_stmt_used_symbol_ids(stmt_id)
        )

    def get_stmt_defined_symbol_names(self, stmt_id: int) -> tuple[str, ...]:
        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return ()
        return self._symbol_names_for_ids(
            method_id, self.get_stmt_defined_symbol_ids(stmt_id)
        )

    def get_stmt_used_state_ids(self, stmt_id: int) -> tuple[int, ...]:
        return self.get_stmt_in_state_ids(stmt_id)

    def get_stmt_defined_state_ids(self, stmt_id: int) -> tuple[int, ...]:
        status = self.get_preferred_stmt_status(stmt_id)
        if status is None:
            return ()
        direct = self._normalized_ids(getattr(status, "defined_states", ()))
        bit_ids = self.get_stmt_out_state_ids(stmt_id)
        return tuple(sorted(set(direct) | set(bit_ids)))

    def trace_symbol_current_states(
        self,
        method_id: int,
        symbol_id: int,
        at_stmt_id: int,
        *,
        mode: str = "in",
        phase: str = "preferred",
    ) -> tuple[Any, ...]:


        symbol_states = {
            self._positive_id(getattr(state, "state_id", None))
            for state in self.find_states_for_symbol(
                method_id, symbol_id, phase=phase
            )
        }
        symbol_states.discard(None)
        if not symbol_states:
            return ()
        if mode == "out":
            visible = set(self.get_stmt_out_state_ids(at_stmt_id))
        elif mode == "defined":
            visible = set(self.get_stmt_defined_state_ids(at_stmt_id))
        else:
            visible = set(self.get_stmt_in_state_ids(at_stmt_id))
        state_ids = symbol_states & visible if visible else symbol_states
        return tuple(
            state
            for state_id in sorted(state_ids)
            if (
                state := self.find_state_by_id(
                    method_id, state_id, phase=phase
                )
            )
            is not None
        )

    def trace_state_origin(
        self,
        method_id: int,
        state_id: int,
        *,
        phase: str = "preferred",
        max_depth: int = 16,
    ) -> StateOrigin | None:


        normalized_id = self._positive_id(state_id)
        if normalized_id is None:
            return None
        resolved_phase = self._resolve_phase(method_id, phase)
        current_id: int | None = normalized_id
        seen: set[int] = set()
        steps: list[StateOriginStep] = []

        for _ in range(max_depth):
            if current_id is None or current_id in seen:
                break
            seen.add(current_id)
            state = self.find_state_by_id(
                method_id, current_id, phase=resolved_phase
            )
            if state is None:
                break
            step = self._state_origin_step(
                method_id, state, phase=resolved_phase
            )
            steps.append(step)
            current_id = step.source_state_id

        if not steps:
            return None
        first = steps[0]
        return StateOrigin(
            state_id=first.state_id,
            stmt_id=first.stmt_id,
            source_symbol_id=first.source_symbol_id,
            source_symbol_name=first.source_symbol_name,
            source_state_id=first.source_state_id,
            access_path=first.access_path,
            value=first.value,
            data_type=first.data_type,
            chain=tuple(steps),
            phase=resolved_phase,
        )

    def format_state_origin_path(
        self,
        method_id: int,
        state_id: int,
        *,
        phase: str = "preferred",
    ) -> str | None:


        origin = self.trace_state_origin(
            method_id, state_id, phase=phase
        )
        if origin is None:
            return None
        for step in origin.chain:
            path = self._join_symbol_and_access_path(
                step.source_symbol_name, step.access_path
            )
            if path:
                return path
        for step in origin.chain:
            if step.value:
                return step.value
        return None

    def symbol_storage_kind(
        self,
        method_id: int,
        symbol_id: int,
        *,
        phase: str = "preferred",
    ) -> str | None:
        symbol = self.find_symbol_by_id(method_id, symbol_id, phase=phase)
        if symbol is None:
            return None
        name = self._text(getattr(symbol, "name", ""))
        if name:
            return self.classify_symbol_storage(method_id, name)
        summary = self.get_method_def_use_summary(method_id)
        normalized_id = self._lian_id(symbol_id)
        if normalized_id is None or summary is None:
            return None
        if normalized_id in self._summary_id_set(
            getattr(summary, "parameter_symbol_ids", ())
        ):
            return "param"
        if normalized_id in self._summary_id_set(
            getattr(summary, "local_symbol_ids", ())
        ):
            return "local"
        external_ids = self._summary_id_set(
            getattr(summary, "defined_external_symbol_ids", ())
        ) | self._summary_id_set(
            getattr(summary, "used_external_symbol_ids", ())
        )
        if normalized_id in external_ids:
            return "global"
        return None

    def classify_symbol_storage(
        self,
        method_id: int,
        symbol_name: str,
    ) -> str | None:


        symbol = self.find_symbol_by_name(method_id, symbol_name)
        symbol_id = self._lian_id(getattr(symbol, "symbol_id", None))
        summary = self.get_method_def_use_summary(method_id)
        if symbol_id is not None and summary is not None:
            if symbol_id in self._summary_id_set(
                getattr(summary, "parameter_symbol_ids", ())
            ):
                return "param"
            if symbol_id in self._summary_id_set(
                getattr(summary, "local_symbol_ids", ())
            ):
                return "local"
            external_ids = self._summary_id_set(
                getattr(summary, "defined_external_symbol_ids", ())
            ) | self._summary_id_set(
                getattr(summary, "used_external_symbol_ids", ())
            )
            if symbol_id in external_ids:
                return "global"

        declaration = self._declaration_for_symbol_name(method_id, symbol_name)
        if declaration is not None:
            operation = self._text(getattr(declaration, "operation", ""))
            if operation == "parameter_decl":
                return "param"
            if operation == "variable_decl":
                declaration_method = self.get_method_id(
                    self._id_or_default(getattr(declaration, "stmt_id", None))
                )
                return "local" if declaration_method is not None else "global"
        if "." in symbol_name or "->" in symbol_name:
            return "field"
        return None



    def get_call_info(self, call_stmt_id: int) -> Any | None:
        normalized_id = self._positive_id(call_stmt_id)
        if normalized_id is None:
            return None
        return self._call_optional(
            "convert_stmt_id_to_call_stmt_format", normalized_id
        )

    def get_internal_callees(self, method_id: int) -> tuple[Any, ...]:
        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return ()
        if normalized_id not in self._internal_callees:
            value = self._call_optional(
                "get_method_internal_callees", normalized_id
            )
            self._internal_callees[normalized_id] = self._as_tuple(value)
        return self._internal_callees[normalized_id]

    def get_callers(self, method_id: int) -> tuple[int, ...]:
        return self._get_call_graph_ids(
            method_id, "get_caller_ids_by_id_in_p3", self._callers
        )

    def get_callees(self, method_id: int) -> tuple[int, ...]:
        return self._get_call_graph_ids(
            method_id, "get_callee_ids_by_id_in_p3", self._callees
        )

    def get_parameter_mapping(self, call_site: Any) -> Any | None:
        if call_site is None:
            return None
        return self._call_optional("get_parameter_mapping_p3", call_site)

    def get_call_site_parameter_mapping(
        self, call_stmt_id: int
    ) -> tuple[Any, ...]:


        call_site = self.get_call_info(call_stmt_id)
        if call_site is None:
            return ()
        mapping = self._call_optional("get_parameter_mapping_p3", call_site)
        return self._as_tuple(mapping)

    def get_internal_callee_summaries(
        self, call_stmt_id: int
    ) -> tuple[tuple[int, Any | None], ...]:


        method_id = self.get_method_id(call_stmt_id)
        if method_id is None:
            return ()
        call_info = self.get_call_info(call_stmt_id)
        callee_name = self._text(
            getattr(call_info, "name", "")
            or getattr(call_info, "callee", "")
            or getattr(call_info, "callee_name", "")
            or getattr(call_info, "target", "")
        ).lower()
        callee_ids = self.get_callees(method_id)
        if callee_name:
            callee_ids = tuple(
                callee_id
                for callee_id in callee_ids
                if (self.get_method_name(callee_id) or "").lower()
                == callee_name
            )
        return tuple(
            (callee_id, self.get_method_def_use_summary(callee_id))
            for callee_id in callee_ids
        )

    def get_reaching_defs(
        self, stmt_id: int, symbol_id: int
    ) -> tuple[int, ...]:


        method_id = self.get_method_id(stmt_id)
        normalized_symbol_id = self._lian_id(symbol_id)
        if method_id is None or normalized_symbol_id is None:
            return ()
        target_id = self._positive_id(stmt_id)
        if target_id is None:
            return ()

        reaching: set[int] = set()
        statuses = self.get_preferred_stmt_statuses(method_id)

        index_to_sid: dict[int, int] = {}
        space = self.get_preferred_symbol_state_space(method_id)
        if space is not None:
            for i, item in enumerate(self._as_tuple(space)):
                sid = self._lian_id(getattr(item, "symbol_id", None))
                if sid is not None:
                    index_to_sid[i] = sid
        for status in statuses.values():
            status_stmt_id = self._positive_id(
                getattr(status, "stmt_id", None)
            )
            if status_stmt_id is None or status_stmt_id >= target_id:
                continue
            resolved = {
                index_to_sid[idx]
                for idx in (
                    self._positive_id(raw)
                    for raw in (
                        *self._as_tuple(
                            getattr(status, "defined_symbol", ())
                        ),
                        *self._as_tuple(
                            getattr(status, "implicitly_defined_symbols", ())
                        ),
                    )
                )
                if idx is not None and idx in index_to_sid
            }
            if normalized_symbol_id in resolved and self._stmt_may_reach(
                method_id, status_stmt_id, target_id
            ):
                reaching.add(status_stmt_id)
        return tuple(sorted(reaching))

    def state_reaches_stmt(
        self, method_id: int, state_id: int, stmt_id: int
    ) -> bool:


        normalized_state_id = self._positive_id(state_id)
        target_id = self._positive_id(stmt_id)
        if normalized_state_id is None or target_id is None:
            return False
        if normalized_state_id in set(self.get_stmt_in_state_ids(target_id)):
            return True
        state = self.find_state_by_id(method_id, normalized_state_id)
        if state is None:
            return False
        source_stmt_id = self._positive_id(getattr(state, "stmt_id", None))
        if source_stmt_id is None:
            return False
        return self._stmt_may_reach(method_id, source_stmt_id, target_id)

    def definition_must_precede(
        self, method_id: int, def_stmt_id: int, use_stmt_id: int
    ) -> bool:


        def_id = self._positive_id(def_stmt_id)
        use_id = self._positive_id(use_stmt_id)
        if def_id is None or use_id is None or def_id >= use_id:
            return False
        cfg = self.get_method_cfg(method_id)
        if cfg is None:
            return True
        if not self._stmt_may_reach(method_id, def_id, use_id):
            return False
        predecessors = self._cfg_predecessors(cfg, use_id)
        if not predecessors:
            return True
        return all(
            pred == def_id or self._stmt_may_reach(method_id, def_id, pred)
            for pred in predecessors
        )

    def make_lian_evidence(
        self,
        *,
        source: str,
        stmt_id: int | None = None,
        method_id: int | None = None,
        phase: str = "preferred",
        symbol_ids: Any = (),
        state_ids: Any = (),
        source_stmt_ids: Any = (),
        access_paths: Any = (),
        reason: str = "",
        confidence: str = "low",
        extra: dict[str, Any] | None = None,
    ) -> LianEvidence:
        resolved_method_id = method_id
        if resolved_method_id is None and stmt_id is not None:
            resolved_method_id = self.get_method_id(stmt_id)
        resolved_phase = (
            self._resolve_phase(resolved_method_id, phase)
            if resolved_method_id is not None
            else phase
        )
        return LianEvidence(
            phase=resolved_phase,
            source=source,
            stmt_id=self._positive_id(stmt_id),
            method_id=self._positive_id(resolved_method_id),
            symbol_ids=self._normalized_lian_ids(symbol_ids),
            state_ids=self._normalized_ids(state_ids),
            source_stmt_ids=self._normalized_ids(source_stmt_ids),
            access_paths=tuple(
                text
                for item in self._as_tuple(access_paths)
                if (text := self._text(item))
            ),
            reason=reason,
            confidence=confidence,
            extra=dict(extra or {}),
        )



    def get_stmt_source(self, stmt_id: int) -> tuple[str, ...]:
        normalized_id = self._positive_id(stmt_id)
        if normalized_id is None or self.get_stmt(normalized_id) is None:
            return ()
        if normalized_id not in self._stmt_sources:
            value = self._call_optional(
                "get_stmt_source_code_with_comment", normalized_id
            )
            if isinstance(value, str):
                result = tuple(value.splitlines())
            else:
                result = tuple(str(line) for line in self._as_tuple(value))
            self._stmt_sources[normalized_id] = result
        return self._stmt_sources[normalized_id]



    def _get_stmt_statuses(
        self,
        method_id: int,
        loader_method: str,
        cache: dict[int, dict[int, Any]],
    ) -> dict[int, Any]:
        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return {}
        if normalized_id not in cache:
            value = self._call_optional(loader_method, normalized_id)
            if value is None:
                result: dict[int, Any] = {}
            elif isinstance(value, (dict, list)):

                result = (
                    {
                        key: status
                        for raw_id, status in value.items()
                        if (key := self._positive_id(raw_id)) is not None
                    }
                    if isinstance(value, dict)
                    else {}
                )
            else:
                raise AnalysisContextError(
                    f"{loader_method}({normalized_id}) returned "
                    f"{type(value).__name__}, expected dict or None"
                )
            cache[normalized_id] = result
        return cache[normalized_id]

    def _get_symbol_stmt_index(
        self,
        method_id: int,
        loader_method: str,
        cache: dict[int, dict[int, tuple[int, ...]]],
        *,
        fallback_loader_method: str | None = None,
    ) -> dict[int, tuple[int, ...]]:
        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return {}
        if normalized_id in cache:
            return cache[normalized_id]

        value = self._call_optional(loader_method, normalized_id)
        if value is None and fallback_loader_method:
            value = self._call_optional(fallback_loader_method, normalized_id)
        result = self._normalize_symbol_stmt_index(value)
        cache[normalized_id] = result
        return result

    def _normalize_symbol_stmt_index(
        self, value: Any
    ) -> dict[int, tuple[int, ...]]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            return {}
        result: dict[int, tuple[int, ...]] = {}
        for raw_symbol_id, raw_stmt_ids in value.items():
            symbol_id = self._lian_id(raw_symbol_id)
            if symbol_id is None:
                continue
            stmt_ids = self._stmt_ids_from_index_value(raw_stmt_ids)
            if stmt_ids:
                result[symbol_id] = stmt_ids
        return result

    def _stmt_ids_from_index_value(self, value: Any) -> tuple[int, ...]:
        result: set[int] = set()
        for item in self._as_tuple(value):
            if isinstance(item, (int, str)):
                stmt_id = self._positive_id(item)
            else:
                stmt_id = self._positive_id(
                    getattr(item, "stmt_id", None)
                    or getattr(item, "last_stmt_id", None)
                    or getattr(item, "index", None)
                )
            if stmt_id is not None:
                result.add(stmt_id)
        return tuple(sorted(result))

    def _space_indices_to_symbol_ids(
        self,
        stmt_id: int,
        raw_indices: Any,
    ) -> tuple[int, ...]:

        method_id = self.get_method_id(stmt_id)
        if method_id is None:
            return ()
        space = self.get_preferred_symbol_state_space(method_id)
        if space is None:
            return ()
        result: set[int] = set()
        for raw in self._as_tuple(raw_indices):
            index = self._positive_id(raw)
            if index is None:
                continue
            try:
                item = space[index]
            except (IndexError, TypeError):
                continue
            symbol_id = self._lian_id(getattr(item, "symbol_id", None))
            if symbol_id is not None:
                result.add(symbol_id)
        return tuple(sorted(result))

    def _get_method_result(
        self,
        method_id: int,
        loader_method: str,
        cache: dict[int, Any | None],
    ) -> Any | None:
        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return None
        if normalized_id not in cache:
            cache[normalized_id] = self._call_optional(
                loader_method, normalized_id
            )
        return cache[normalized_id]

    def _get_call_graph_ids(
        self,
        method_id: int,
        loader_method: str,
        cache: dict[int, tuple[int, ...]],
    ) -> tuple[int, ...]:
        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return ()
        if normalized_id not in cache:
            value = self._call_optional(loader_method, normalized_id)
            cache[normalized_id] = self._normalized_ids(value)
        return cache[normalized_id]

    def _symbol_state_space_for_phase(
        self,
        method_id: int,
        phase: str,
    ) -> Any | None:
        normalized_phase = self._text(phase).lower()
        if normalized_phase == "p1":
            return self.get_symbol_state_space_p1(method_id)
        if normalized_phase == "p2":
            return self.get_symbol_state_space_p3(method_id)
        if normalized_phase == "p3":
            return self.get_symbol_state_space_p3(method_id)
        if normalized_phase == "preferred":
            return self.get_preferred_symbol_state_space(method_id)
        raise AnalysisContextError(
            f"unsupported symbol state space phase: {phase!r}"
        )

    def _symbol_state_index(
        self,
        method_id: int,
        phase: str,
    ) -> SymbolStateIndex:
        normalized_id = self._positive_id(method_id)
        if normalized_id is None:
            return SymbolStateIndex((), {}, {}, {}, {}, {})

        resolved_phase = self._resolve_phase(normalized_id, phase)
        cache_key = (normalized_id, resolved_phase)
        cached = self._symbol_state_indexes.get(cache_key)
        if cached is not None:
            return cached

        space = self._symbol_state_space_for_phase(
            normalized_id, resolved_phase
        )
        items = self._as_tuple(space)
        symbols_by_id: dict[int, Any] = {}
        symbols_by_decl_stmt_id: dict[int, Any] = {}
        mutable_symbols_by_name: dict[str, list[Any]] = {}
        states_by_id: dict[int, Any] = {}

        for item in items:
            if self._is_lian_symbol(item):
                symbol_id = self._lian_id(getattr(item, "symbol_id", None))
                if symbol_id is not None:
                    symbols_by_id[symbol_id] = item

                decl_stmt_id = self._positive_id(
                    getattr(item, "stmt_id", None)
                )
                if decl_stmt_id is not None:
                    symbols_by_decl_stmt_id[decl_stmt_id] = item

                name = self._text(getattr(item, "name", ""))
                if name:
                    mutable_symbols_by_name.setdefault(name, []).append(item)
                continue

            if self._is_lian_state(item):
                state_id = self._positive_id(getattr(item, "state_id", None))
                if state_id is not None:
                    states_by_id[state_id] = item

        states_for_symbol_id: dict[int, tuple[Any, ...]] = {}
        for symbol_id, symbol in symbols_by_id.items():
            states = tuple(
                state
                for state_id in self._normalized_ids(
                    getattr(symbol, "states", ())
                )
                if (state := states_by_id.get(state_id)) is not None
            )
            states_for_symbol_id[symbol_id] = states

        result = SymbolStateIndex(
            items=items,
            symbols_by_id=symbols_by_id,
            symbols_by_decl_stmt_id=symbols_by_decl_stmt_id,
            symbols_by_name={
                name: tuple(symbols)
                for name, symbols in mutable_symbols_by_name.items()
            },
            states_by_id=states_by_id,
            states_for_symbol_id=states_for_symbol_id,
        )
        self._symbol_state_indexes[cache_key] = result
        return result

    def _resolve_phase(self, method_id: int, phase: str) -> str:
        normalized_phase = self._text(phase).lower()
        if normalized_phase == "p2":
            return "p3"
        if normalized_phase in {"p1", "p3"}:
            return normalized_phase
        if normalized_phase != "preferred":
            raise AnalysisContextError(
                f"unsupported symbol state space phase: {phase!r}"
            )
        if self.get_symbol_state_space_p3(method_id) is not None:
            return "p3"
        if self.get_symbol_state_space_p1(method_id) is not None:
            return "p1"
        return "preferred"

    @staticmethod
    def _is_lian_symbol(item: Any) -> bool:
        return hasattr(item, "symbol_id") and hasattr(item, "states")

    @staticmethod
    def _is_lian_state(item: Any) -> bool:
        return hasattr(item, "state_id") and hasattr(item, "source_state_id")

    def _symbol_names_for_ids(
        self,
        method_id: int,
        symbol_ids: tuple[int, ...],
    ) -> tuple[str, ...]:
        names: list[str] = []
        seen: set[str] = set()
        for symbol_id in symbol_ids:
            name = self.get_symbol_name(method_id, symbol_id)
            if not name or name in seen:
                continue
            seen.add(name)
            names.append(name)
        return tuple(names)

    def _state_origin_step(
        self,
        method_id: int,
        state: Any,
        *,
        phase: str,
    ) -> StateOriginStep:
        state_id = self._positive_id(getattr(state, "state_id", None)) or -1
        stmt_id = self._positive_id(getattr(state, "stmt_id", None))
        source_symbol_id = self._lian_id(
            getattr(state, "source_symbol_id", None)
        )
        source_symbol_name = (
            self.get_symbol_name(method_id, source_symbol_id, phase=phase)
            if source_symbol_id is not None
            else None
        )
        source_state_id = self._positive_id(
            getattr(state, "source_state_id", None)
        )
        access_path = self.get_state_access_path(
            method_id, state_id, phase=phase
        )
        value = self._text(getattr(state, "value", "")) or None
        data_type = self._first_text_attr(
            state,
            (
                "data_type",
                "default_data_type",
                "c_type",
                "type",
                "type_name",
                "value_type",
            ),
        )
        return StateOriginStep(
            state_id=state_id,
            stmt_id=stmt_id,
            source_symbol_id=source_symbol_id,
            source_symbol_name=source_symbol_name,
            source_state_id=source_state_id,
            access_path=access_path,
            value=value,
            data_type=data_type,
        )

    def _join_symbol_and_access_path(
        self, symbol_name: str | None, access_path: str | None
    ) -> str | None:
        symbol = self._text(symbol_name)
        path = self._text(access_path)
        if symbol and path:
            if path == symbol or path.startswith(f"{symbol}."):
                return path
            if path.startswith(("[", ".", "->")):
                return f"{symbol}{path}"
            return f"{symbol}.{path}"
        return path or symbol or None

    def _summary_id_set(self, value: Any) -> set[int]:
        result: set[int] = set()
        for item in self._as_tuple(value):
            if isinstance(item, (tuple, list)) and item:
                item = item[0]
            normalized = self._lian_id(item)
            if normalized is not None:
                result.add(normalized)
        return result

    def _stmt_may_reach(
        self, method_id: int, source_stmt_id: int, target_stmt_id: int
    ) -> bool:
        source_id = self._positive_id(source_stmt_id)
        target_id = self._positive_id(target_stmt_id)
        if source_id is None or target_id is None:
            return False
        if source_id == target_id:
            return True
        cfg = self.get_method_cfg(method_id)
        successors = self._cfg_successors(cfg, source_id)
        if not successors:
            return source_id < target_id
        seen = {source_id}
        worklist = list(successors)
        while worklist:
            current = worklist.pop()
            if current == target_id:
                return True
            if current in seen:
                continue
            seen.add(current)
            worklist.extend(
                succ
                for succ in self._cfg_successors(cfg, current)
                if succ not in seen
            )
        return False

    def _cfg_successors(self, cfg: Any, stmt_id: int) -> tuple[int, ...]:
        for attr in ("successors", "succs", "edges", "next"):
            value = getattr(cfg, attr, None)
            ids = self._cfg_neighbor_ids(value, stmt_id, successor=True)
            if ids:
                return ids
        if isinstance(cfg, dict):
            for key in ("successors", "succs", "edges", "next"):
                ids = self._cfg_neighbor_ids(
                    cfg.get(key), stmt_id, successor=True
                )
                if ids:
                    return ids
            ids = self._cfg_neighbor_ids(cfg, stmt_id, successor=True)
            if ids:
                return ids
        return ()

    def _cfg_predecessors(self, cfg: Any, stmt_id: int) -> tuple[int, ...]:
        for attr in ("predecessors", "preds", "prev"):
            value = getattr(cfg, attr, None)
            ids = self._cfg_neighbor_ids(value, stmt_id, successor=False)
            if ids:
                return ids
        if isinstance(cfg, dict):
            for key in ("predecessors", "preds", "prev"):
                ids = self._cfg_neighbor_ids(
                    cfg.get(key), stmt_id, successor=False
                )
                if ids:
                    return ids
        return ()

    def _cfg_neighbor_ids(
        self, value: Any, stmt_id: int, *, successor: bool
    ) -> tuple[int, ...]:
        if value is None:
            return ()
        if isinstance(value, dict):
            direct = value.get(stmt_id) or value.get(str(stmt_id))
            if direct is not None:
                return self._normalized_ids(direct)
            result: set[int] = set()
            for raw_source, raw_targets in value.items():
                source = self._positive_id(raw_source)
                targets = self._normalized_ids(raw_targets)
                if successor and source == stmt_id:
                    result.update(targets)
                elif not successor and stmt_id in targets and source:
                    result.add(source)
            return tuple(sorted(result))
        result: set[int] = set()
        for edge in self._as_tuple(value):
            if isinstance(edge, dict):
                source = self._positive_id(
                    edge.get("source")
                    or edge.get("from")
                    or edge.get("src")
                    or edge.get("start")
                )
                target = self._positive_id(
                    edge.get("target")
                    or edge.get("to")
                    or edge.get("dst")
                    or edge.get("end")
                )
            else:
                items = self._as_tuple(edge)
                if len(items) < 2:
                    continue
                source = self._positive_id(items[0])
                target = self._positive_id(items[1])
            if successor and source == stmt_id and target is not None:
                result.add(target)
            elif not successor and target == stmt_id and source is not None:
                result.add(source)
        return tuple(sorted(result))

    def _state_ids_from_def_nodes(self, value: Any) -> tuple[int, ...]:
        ids: set[int] = set()
        for item in self._as_tuple(value):
            state_id = self._positive_id(getattr(item, "state_id", None))
            if state_id is not None:
                ids.add(state_id)
                continue
            raw_id = self._positive_id(item)
            if raw_id is not None:
                ids.add(raw_id)
        return tuple(sorted(ids))

    def _format_access_path(self, access_path: Any) -> str | None:
        parts: list[str] = []
        for item in self._as_tuple(access_path):
            key = self._text(getattr(item, "key", ""))
            if key:
                parts.append(key)
        if not parts:
            return None
        return ".".join(parts)

    def _first_text_attr(
        self, item: Any, attr_names: tuple[str, ...]
    ) -> str | None:
        for attr in attr_names:
            text = self._text(getattr(item, attr, ""))
            if text:
                return text
        return None

    def _declaration_for_symbol_name(
        self,
        method_id: int,
        symbol_name: str,
    ) -> Any | None:
        name = self._text(symbol_name)
        if not name:
            return None

        unit_id = self.get_unit_id(method_id)
        if unit_id is not None:
            declarations = self.get_unit_symbol_declarations(unit_id)
            for declaration_id in declarations.get(name, ()):
                declaration = self.get_stmt(declaration_id)
                if declaration is not None:
                    return declaration

        for row in self.get_method_rows(method_id):
            if self._text(getattr(row, "name", "")) == name:
                return row
        return None

    def _call_optional(self, method_name: str, *args: Any) -> Any:
        method = getattr(self.loader, method_name, None)
        if not callable(method):
            raise AnalysisContextError(
                f"Lian loader has no callable {method_name}()"
            )
        try:
            return method(*args)
        except Exception as exc:
            rendered_args = ", ".join(repr(arg) for arg in args)
            raise AnalysisContextError(
                f"Lian loader query {method_name}({rendered_args}) failed: "
                f"{exc}"
            ) from exc

    @staticmethod
    def _as_tuple(value: Any) -> tuple[Any, ...]:
        if value is None:
            return ()
        if isinstance(value, tuple):
            return value
        if isinstance(value, str):
            return (value,)
        try:
            return tuple(value)
        except TypeError:
            return (value,)

    @classmethod
    def _normalized_ids(cls, value: Any) -> tuple[int, ...]:
        ids = {
            item
            for item in (
                cls._positive_id(raw) for raw in cls._as_tuple(value)
            )
            if item is not None
        }
        return tuple(sorted(ids))

    @classmethod
    def _normalized_lian_ids(cls, value: Any) -> tuple[int, ...]:
        ids = {
            item
            for item in (cls._lian_id(raw) for raw in cls._as_tuple(value))
            if item is not None
        }
        return tuple(sorted(ids))

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


        return result if result not in {-1, 0} else None

    @staticmethod
    def _id_or_default(value: Any, default: int = -1) -> int:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default

    @staticmethod
    def _text(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip()
