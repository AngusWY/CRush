from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Any


class PointerDeclarationOperation(str, Enum):


    VARIABLE_DECL = "variable_decl"
    PARAMETER_DECL = "parameter_decl"
    TYPE_ALIAS_DECL = "type_alias_decl"


class Nullability(str, Enum):
    NONNULL = "nonnull"
    NULLABLE = "nullable"


class Ownership(str, Enum):
    NONE = "none"
    BORROWED = "borrowed"
    OWNED = "owned"
    SHARED_OWNED = "shared owned"


class Mutability(str, Enum):
    CONST = "const"
    MUTABLE = "mutable"


class VariableDeclarationOperation(str, Enum):


    VARIABLE_DECL = "variable_decl"
    PARAMETER_DECL = "parameter_decl"


class VariableMutability(str, Enum):
    CONST = "const"
    MUTABLE = "mutable"


class PointeeShape(str, Enum):
    SINGLE = "single"
    ARRAY = "array"


class Lifetime(str, Enum):
    OWNED = "owned"
    LOCAL = "local"
    PARAM = "param"
    STORED = "stored"
    STATIC = "static"
    UNKNOWN = "unknown"


class GlobalPointerInitMode(str, Enum):
    NULL = "null"
    COMPILE_TIME = "compile_time"
    RUNTIME_ONCE = "runtime_once"
    LAZY_ONCE = "lazy_once"
    RELOADABLE = "reloadable"
    ALWAYS_MUTABLE = "always_mutable"


class ResourceKind(str, Enum):


    FILE_STREAM = "file_stream"


class CStringKind(str, Enum):


    NUL_TERMINATED_BYTES = "nul_terminated_bytes"


@dataclasses.dataclass
class CStringSemantics:


    kind: CStringKind = CStringKind.NUL_TERMINATED_BYTES
    payload_excludes_terminator: bool = True
    terminator_readable_in_c: bool = True

    def __post_init__(self) -> None:
        if self.payload_excludes_terminator is not True:
            raise ValueError("C string payload must exclude the terminator")
        if self.terminator_readable_in_c is not True:
            raise ValueError("the C string terminator must be readable")

    def to_dict(self) -> dict[str, Any]:
        return _dataclass_fields(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CStringSemantics":
        required_fields = {
            "kind",
            "payload_excludes_terminator",
            "terminator_readable_in_c",
        }
        missing_fields = required_fields - set(value)
        if missing_fields:
            raise ValueError(
                "C string semantics is missing fields: "
                + ", ".join(sorted(missing_fields))
            )
        unknown_fields = set(value) - required_fields
        if unknown_fields:
            raise ValueError(
                "C string semantics has unknown fields: "
                + ", ".join(sorted(unknown_fields))
            )
        payload_excludes_terminator = value["payload_excludes_terminator"]
        terminator_readable_in_c = value["terminator_readable_in_c"]
        if not isinstance(payload_excludes_terminator, bool):
            raise TypeError("payload_excludes_terminator must be a boolean")
        if not isinstance(terminator_readable_in_c, bool):
            raise TypeError("terminator_readable_in_c must be a boolean")
        return cls(
            kind=CStringKind(value["kind"]),
            payload_excludes_terminator=payload_excludes_terminator,
            terminator_readable_in_c=terminator_readable_in_c,
        )


class ResourceOpenMode(str, Enum):


    READ_EXISTING = "read_existing"
    WRITE_TRUNCATE = "write_truncate"
    APPEND = "append"
    READ_WRITE_EXISTING = "read_write_existing"
    READ_WRITE_TRUNCATE = "read_write_truncate"
    READ_APPEND = "read_append"
    INHERITED_DESCRIPTOR = "inherited_descriptor"
    PROCESS_PIPE = "process_pipe"


class ResourceCapability(str, Enum):
    READ = "read"
    WRITE = "write"
    SEEK = "seek"
    FLUSH = "flush"


class ResourceHandleRole(str, Enum):
    DIRECT = "direct"
    SEQUENCE = "sequence"
    SLOT = "slot"
    UNKNOWN = "unknown"


@dataclasses.dataclass
class ResourceHandleSemantics:


    indirection: int
    role: ResourceHandleRole
    element_ownership: Ownership | None = None
    element_nullability: Nullability | None = None

    def __post_init__(self) -> None:
        if self.indirection <= 0:
            raise ValueError("resource handle indirection must be positive")
        if self.role is ResourceHandleRole.DIRECT and self.indirection != 1:
            raise ValueError("a direct resource handle must have indirection one")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "indirection": self.indirection,
            "role": self.role.value,
        }
        if self.element_ownership is not None:
            result["element_ownership"] = self.element_ownership.value
        if self.element_nullability is not None:
            result["element_nullability"] = self.element_nullability.value
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ResourceHandleSemantics":
        allowed_fields = {
            "indirection",
            "role",
            "element_ownership",
            "element_nullability",
        }
        _reject_unknown_fields(value, allowed_fields, "resource handle semantics")
        return cls(
            indirection=int(value["indirection"]),
            role=ResourceHandleRole(value["role"]),
            element_ownership=(
                None
                if value.get("element_ownership") is None
                else Ownership(value["element_ownership"])
            ),
            element_nullability=(
                None
                if value.get("element_nullability") is None
                else Nullability(value["element_nullability"])
            ),
        )


class ResourceOperationEffect(str, Enum):
    OPEN = "open_resource"
    READ = "read_bytes_and_advance_cursor"
    WRITE = "write_bytes_and_advance_cursor"
    SEEK = "set_cursor"
    TELL = "query_cursor"
    REWIND = "rewind_cursor"
    FLUSH = "flush_buffered_output"
    CLOSE = "close_resource"
    TEST_EOF = "test_eof_state"
    TEST_ERROR = "test_error_state"
    PUSHBACK = "push_back_byte"
    CLEAR_STATUS = "clear_eof_and_error_state"


class ResourceOperationOrigin(str, Enum):
    DIRECT = "direct"
    CALLEE = "callee"
    CALLER = "caller"


class ResourceFlowEdgeKind(str, Enum):
    CALL_ARGUMENT = "call_argument"
    RETURN_ASSIGNMENT = "return_assignment"
    ALIAS = "alias"
    STORED = "stored"
    INDEXED_ELEMENT = "indexed_element"


@dataclasses.dataclass
class ResourceFlowEdge:
    kind: ResourceFlowEdgeKind
    source: str
    target: str
    site: str | None = None

    def __post_init__(self) -> None:
        if not self.source.strip() or not self.target.strip():
            raise ValueError("resource flow edge endpoints must not be empty")

    def to_dict(self) -> dict[str, Any]:
        result = {
            "kind": self.kind.value,
            "source": self.source,
            "target": self.target,
        }
        if self.site:
            result["site"] = self.site
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ResourceFlowEdge":
        _reject_unknown_fields(
            value,
            {"kind", "source", "target", "site"},
            "resource flow edge",
        )
        return cls(
            kind=ResourceFlowEdgeKind(value["kind"]),
            source=str(value.get("source", "")),
            target=str(value.get("target", "")),
            site=_optional_str(value.get("site")),
        )


class ResourceStateRequirement(str, Enum):
    EOF_IS_STICKY_AFTER_FAILED_READ = "eof_is_sticky_after_failed_read"
    EOF_SURVIVES_FUNCTION_RETURN = "eof_survives_function_return"
    ERROR_IS_STICKY_AFTER_FAILED_IO = "error_is_sticky_after_failed_io"
    EOF_AND_ERROR_ARE_DISTINGUISHABLE = "eof_and_error_are_distinguishable"
    PUSHBACK_SUPPORTS_AT_LEAST_ONE_BYTE = "pushback_supports_at_least_one_byte"
    SUCCESSFUL_PUSHBACK_CLEARS_EOF = "successful_pushback_clears_eof"
    PUSHBACK_DOES_NOT_REQUIRE_SEEK = "pushback_does_not_require_seek"
    SUCCESSFUL_SEEK_CLEARS_EOF_AND_PUSHBACK = (
        "successful_seek_clears_eof_and_pushback"
    )
    REWIND_CLEARS_EOF_AND_ERROR = "rewind_clears_eof_and_error"
    FREAD_RETURNS_COMPLETE_ELEMENT_COUNT = "fread_returns_complete_element_count"
    FWRITE_RETURNS_COMPLETE_ELEMENT_COUNT = "fwrite_returns_complete_element_count"


@dataclasses.dataclass
class ResourceOperation:
    callee: str
    effect: ResourceOperationEffect
    origin: ResourceOperationOrigin
    target: str
    site: str | None = None
    open_mode: ResourceOpenMode | None = None
    call_path: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.callee.strip():
            raise ValueError("resource operation callee must not be empty")
        if not self.target.strip():
            raise ValueError("resource operation target must not be empty")
        if any(not item.strip() for item in self.call_path):
            raise ValueError("resource operation call path entries must not be empty")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "callee": self.callee,
            "effect": self.effect.value,
            "origin": self.origin.value,
            "target": self.target,
        }
        if self.site:
            result["site"] = self.site
        if self.open_mode is not None:
            result["open_mode"] = self.open_mode.value
        if self.call_path:
            result["call_path"] = list(self.call_path)
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ResourceOperation":
        _reject_unknown_fields(
            value,
            {"callee", "effect", "origin", "target", "site", "open_mode", "call_path"},
            "resource operation",
        )
        call_path = value.get("call_path", [])
        if not isinstance(call_path, list):
            raise TypeError("resource operation call_path must be an array")
        return cls(
            callee=str(value.get("callee", "")).strip(),
            effect=ResourceOperationEffect(value["effect"]),
            origin=ResourceOperationOrigin(value["origin"]),
            target=str(value.get("target", "")).strip(),
            site=_optional_str(value.get("site")),
            open_mode=(
                None
                if value.get("open_mode") is None
                else ResourceOpenMode(value["open_mode"])
            ),
            call_path=tuple(str(item).strip() for item in call_path),
        )


@dataclasses.dataclass
class ResourceSemantics:


    resource_kind: ResourceKind
    resource_identity: str
    capabilities: list[ResourceCapability]
    protocol_id: str
    handle: ResourceHandleSemantics
    operations: list[ResourceOperation]
    flow_edges: list[ResourceFlowEdge]
    state_requirements: list[ResourceStateRequirement]
    open_mode: ResourceOpenMode | None = None
    creation_site: str | None = None
    end_site: str | None = None
    unresolved_fields: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.resource_identity.strip():
            raise ValueError("resource_identity must not be empty")
        if not self.protocol_id.strip():
            raise ValueError("resource protocol_id must not be empty")
        if len(self.capabilities) != len(set(self.capabilities)):
            raise ValueError("resource capabilities must not contain duplicates")
        if len(self.state_requirements) != len(set(self.state_requirements)):
            raise ValueError("resource state requirements must not contain duplicates")
        if len(self.unresolved_fields) != len(set(self.unresolved_fields)):
            raise ValueError("resource unresolved fields must not contain duplicates")

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "resource_kind": self.resource_kind.value,
            "resource_identity": self.resource_identity,
            "capabilities": [item.value for item in self.capabilities],
            "protocol_id": self.protocol_id,
            "handle": self.handle.to_dict(),
            "operations": [item.to_dict() for item in self.operations],
            "flow_edges": [item.to_dict() for item in self.flow_edges],
            "state_requirements": [item.value for item in self.state_requirements],
        }
        if self.open_mode is not None:
            result["open_mode"] = self.open_mode.value
        if self.creation_site:
            result["creation_site"] = self.creation_site
        if self.end_site:
            result["end_site"] = self.end_site
        if self.unresolved_fields:
            result["unresolved_fields"] = list(self.unresolved_fields)
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ResourceSemantics":
        allowed_fields = {
            "resource_kind",
            "resource_identity",
            "capabilities",
            "protocol_id",
            "handle",
            "operations",
            "flow_edges",
            "state_requirements",
            "open_mode",
            "creation_site",
            "end_site",
            "unresolved_fields",
        }
        _reject_unknown_fields(value, allowed_fields, "resource semantics")
        capabilities = value.get("capabilities", [])
        operations = value.get("operations", [])
        flow_edges = value.get("flow_edges", [])
        state_requirements = value.get("state_requirements", [])
        unresolved_fields = value.get("unresolved_fields", [])
        if not isinstance(capabilities, list):
            raise TypeError("resource capabilities must be an array")
        if not isinstance(operations, list):
            raise TypeError("resource operations must be an array")
        if not isinstance(flow_edges, list):
            raise TypeError("resource flow_edges must be an array")
        if not isinstance(state_requirements, list):
            raise TypeError("resource state_requirements must be an array")
        if not isinstance(unresolved_fields, list):
            raise TypeError("resource unresolved_fields must be an array")
        if not all(isinstance(item, dict) for item in operations):
            raise TypeError("resource operations must contain only objects")
        if not all(isinstance(item, dict) for item in flow_edges):
            raise TypeError("resource flow_edges must contain only objects")
        handle = value.get("handle")
        if not isinstance(handle, dict):
            raise TypeError("resource handle must be an object")
        return cls(
            resource_kind=ResourceKind(value["resource_kind"]),
            resource_identity=str(value.get("resource_identity", "")),
            capabilities=[ResourceCapability(item) for item in capabilities],
            protocol_id=str(value.get("protocol_id", "")),
            handle=ResourceHandleSemantics.from_dict(handle),
            operations=[
                ResourceOperation.from_dict(item)
                for item in operations
            ],
            flow_edges=[ResourceFlowEdge.from_dict(item) for item in flow_edges],
            state_requirements=[
                ResourceStateRequirement(item) for item in state_requirements
            ],
            open_mode=(
                None
                if value.get("open_mode") is None
                else ResourceOpenMode(value["open_mode"])
            ),
            creation_site=_optional_str(value.get("creation_site")),
            end_site=_optional_str(value.get("end_site")),
            unresolved_fields=[str(item) for item in unresolved_fields],
        )


@dataclasses.dataclass
class PointerDeclarationSemantics:


    stmt_id: int
    name: str
    operation: PointerDeclarationOperation
    is_struct_member: bool = False
    nullability: Nullability | None = None
    ownership: Ownership | None = None
    mutability: Mutability | None = None
    pointee_shape: PointeeShape | None = None
    lifetime: Lifetime | None = None
    init_mode: GlobalPointerInitMode | None = None
    resource_required: bool = False
    resource_semantics: ResourceSemantics | None = None
    string_semantics: CStringSemantics | None = None
    usage_path: list[str] = dataclasses.field(default_factory=list)

    def missing_fields(self) -> list[str]:


        field_names = (
            "nullability",
            "ownership",
            "mutability",
            "pointee_shape",
            "lifetime",
        )
        missing = [name for name in field_names if getattr(self, name) is None]
        if self.resource_required and (
            self.resource_semantics is None
            or self.resource_semantics.unresolved_fields
        ):
            missing.append("resource_semantics")
        return missing

    def to_dict(self) -> dict[str, Any]:


        return {
            "stmt_id": self.stmt_id,
            "name": self.name,
            "operation": self.operation.value,
            "is_struct_member": self.is_struct_member,
            "nullability": self._enum_value(self.nullability),
            "ownership": self._enum_value(self.ownership),
            "mutability": self._enum_value(self.mutability),
            "pointee_shape": self._enum_value(self.pointee_shape),
            "lifetime": self._enum_value(self.lifetime),
            "init_mode": self._enum_value(self.init_mode),
            "resource_required": self.resource_required,
            "resource_semantics": (
                None
                if self.resource_semantics is None
                else self.resource_semantics.to_dict()
            ),
            "string_semantics": (
                None
                if self.string_semantics is None
                else self.string_semantics.to_dict()
            ),
            "usage_path": list(self.usage_path),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "PointerDeclarationSemantics":


        return cls(
            stmt_id=int(value["stmt_id"]),
            name=str(value["name"]),
            operation=PointerDeclarationOperation(value["operation"]),
            is_struct_member=bool(value.get("is_struct_member", False)),
            nullability=cls._optional_enum(Nullability, value.get("nullability")),
            ownership=cls._optional_enum(Ownership, value.get("ownership")),
            mutability=cls._optional_enum(Mutability, value.get("mutability")),
            pointee_shape=cls._optional_enum(
                PointeeShape, value.get("pointee_shape")
            ),
            lifetime=cls._optional_enum(Lifetime, value.get("lifetime")),
            init_mode=cls._optional_enum(
                GlobalPointerInitMode, value.get("init_mode")
            ),
            resource_required=bool(value.get("resource_required", False)),
            resource_semantics=cls._optional_resource_semantics(
                value.get("resource_semantics")
            ),
            string_semantics=cls._optional_string_semantics(
                value.get("string_semantics")
            ),
            usage_path=[str(item) for item in value.get("usage_path", [])],
        )

    @staticmethod
    def _enum_value(value: Enum | None) -> str | None:
        return None if value is None else str(value.value)

    @staticmethod
    def _optional_enum(enum_type: type[Enum], value: Any) -> Any:
        return None if value is None else enum_type(value)

    @staticmethod
    def _optional_resource_semantics(value: Any) -> ResourceSemantics | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise TypeError("resource_semantics must be an object")
        return ResourceSemantics.from_dict(value)

    @staticmethod
    def _optional_string_semantics(value: Any) -> CStringSemantics | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise TypeError("string_semantics must be an object")
        return CStringSemantics.from_dict(value)


@dataclasses.dataclass
class VariableDeclarationSemantics:


    stmt_id: int
    name: str
    operation: VariableDeclarationOperation
    is_struct_member: bool = False
    mutability: VariableMutability | None = None
    usage_path: list[str] = dataclasses.field(default_factory=list)

    def missing_fields(self) -> list[str]:
        return ["mutability"] if self.mutability is None else []

    def to_dict(self) -> dict[str, Any]:
        return {
            "stmt_id": self.stmt_id,
            "name": self.name,
            "operation": self.operation.value,
            "is_struct_member": self.is_struct_member,
            "mutability": self._enum_value(self.mutability),
            "usage_path": list(self.usage_path),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "VariableDeclarationSemantics":
        return cls(
            stmt_id=int(value["stmt_id"]),
            name=str(value["name"]),
            operation=VariableDeclarationOperation(value["operation"]),
            is_struct_member=bool(value.get("is_struct_member", False)),
            mutability=cls._optional_enum(
                VariableMutability, value.get("mutability")
            ),
            usage_path=[str(item) for item in value.get("usage_path", [])],
        )

    @staticmethod
    def _enum_value(value: Enum | None) -> str | None:
        return None if value is None else str(value.value)

    @staticmethod
    def _optional_enum(enum_type: type[Enum], value: Any) -> Any:
        return None if value is None else enum_type(value)


class UnsafeStmtOperation(str, Enum):


    VARIABLE_DECL = "variable_decl"
    PARAMETER_DECL = "parameter_decl"
    CALL_STMT = "call_stmt"
    MEM_READ = "mem_read"
    MEM_WRITE = "mem_write"
    ADDR_OF = "addr_of"
    ARRAY_WRITE = "array_write"
    ARRAY_READ = "array_read"
    TYPE_CAST_STMT = "type_cast_stmt"
    RETURN_STMT = "return_stmt"
    FIELD_WRITE = "field_write"
    FIELD_READ = "field_read"
    ASSIGN_STMT = "assign_stmt"


class UnsafeSemanticKind(str, Enum):


    DECLARATION = "declaration"
    CALL_EFFECT = "call_effect"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    ADDRESS_FLOW = "address_flow"
    ARRAY_WRITE = "array_write"
    ARRAY_READ = "array_read"
    TYPE_CAST = "type_cast"
    RETURN_VALUE = "return_value"
    FIELD_WRITE = "field_write"
    FIELD_READ = "field_read"
    ASSIGNMENT_FLOW = "assignment_flow"
    ARRAY_ALIAS = "array_alias"
    POINTER_ARITHMETIC = "pointer_arithmetic"


class StorageKind(str, Enum):
    STACK = "stack"
    GLOBAL = "global"
    FIELD = "field"
    PARAM = "param"
    HEAP = "heap"
    UNKNOWN = "unknown"


class BorrowKind(str, Enum):
    SHARED_BORROW = "shared_borrow"
    MUT_BORROW = "mut_borrow"
    UNKNOWN = "unknown"


class ArrayRole(str, Enum):
    PARAMETER_ARRAY = "parameter_array"
    LOCAL_ARRAY = "local_array"
    GLOBAL_ARRAY = "global_array"
    ALIAS = "alias"
    UNKNOWN = "unknown"


class CallKind(str, Enum):
    ALLOCATION = "allocation"
    DEALLOCATION = "deallocation"
    BYTE_COPY = "byte_copy"
    BYTE_SET = "byte_set"
    RELOCATION = "relocation"
    BORROW = "borrow"
    MUTATION = "mutation"
    UNKNOWN = "unknown"


class CStringReadRole(str, Enum):
    TERMINATOR_TEST = "terminator_test"
    LOOKAHEAD = "lookahead"
    END_BOUNDARY_PROBE = "end_boundary_probe"


class OriginKind(str, Enum):
    CALL_RETURN = "call_return"
    PARAMETER = "parameter"
    LOCAL = "local"
    GLOBAL = "global"
    FIELD = "field"
    ADDR_OF = "addr_of"
    CAST = "cast"
    UNKNOWN = "unknown"


class TransferKind(str, Enum):
    NONE = "none"
    CREATE_OWNER = "create_owner"
    RECEIVE_OWNER = "receive_owner"
    RECEIVE_POINTER = "receive_pointer"
    BORROW_ALIAS = "borrow_alias"
    RETURN_OWNER = "return_owner"
    RETURN_BORROW = "return_borrow"
    RETURN_POINTER = "return_pointer"
    END_OWNER_LIFETIME = "end_owner_lifetime"
    TAKE_OWNERSHIP = "take_ownership"
    BORROW_FOR_CALL = "borrow_for_call"
    MUTATE_IN_PLACE = "mutate_in_place"
    MUTATE_OWNER_CONTENTS = "mutate_owner_contents"
    UNKNOWN = "unknown"


class ArithmeticBasePointeeShape(str, Enum):
    ARRAY = "array"
    SINGLE = "single"
    UNKNOWN = "unknown"


class ArithmeticBaseObjectKind(str, Enum):
    PARAMETER = "parameter"
    LOCAL_ARRAY = "local_array"
    GLOBAL_ARRAY = "global_array"
    FIELD = "field"
    UNKNOWN = "unknown"


class CastKind(str, Enum):
    POINTER_TO_POINTER = "pointer_to_pointer"
    POINTER_TO_INTEGER = "pointer_to_integer"
    INTEGER_TO_POINTER = "integer_to_pointer"
    QUALIFIER_CHANGE = "qualifier_change"
    NUMERIC = "numeric"
    NUMERIC_CAST = "numeric_cast"
    UNKNOWN = "unknown"


class ReturnLifetimeKind(str, Enum):
    PARAM = "param"
    GLOBAL = "global"
    LOCAL = "local"
    HEAP = "heap"
    NULL = "null"
    UNKNOWN = "unknown"


class PointerOffsetUnit(str, Enum):
    BYTES = "bytes"
    ELEMENTS = "elements"


class AlignmentGuarantee(str, Enum):
    PROVEN = "proven"
    NOT_PROVEN = "not_proven"


class PointerArithKind(str, Enum):
    POINTER_OFFSET = "pointer_offset"
    POINTER_DIFFERENCE = "pointer_difference"
    UNKNOWN = "unknown"


@dataclasses.dataclass
class UnsafeStmtSemantics:


    stmt_id: int
    operation: UnsafeStmtOperation
    semantic_kind: UnsafeSemanticKind
    entity_id: int | None = None
    source_snippet: str | None = None
    related_symbols: list[str] = dataclasses.field(default_factory=list)
    raw_gir: dict[str, Any] = dataclasses.field(default_factory=dict)
    programmatic_facts: dict[str, Any] = dataclasses.field(default_factory=dict)
    semantic_hints: dict[str, Any] = dataclasses.field(default_factory=dict)
    agent_missing_fields: list[str] = dataclasses.field(default_factory=list)
    needs_agent: bool = False

    def missing_fields(self) -> list[str]:
        return list(self.agent_missing_fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stmt_id": self.stmt_id,
            "entity_id": self.entity_id,
            "operation": self.operation.value,
            "semantic_kind": self.semantic_kind.value,
            "source_snippet": self.source_snippet,
            "related_symbols": list(self.related_symbols),
            "raw_gir": _jsonify(self.raw_gir),
            "programmatic_facts": _jsonify(self.programmatic_facts),
            "semantic_hints": _jsonify(self.semantic_hints),
            "agent_missing_fields": list(self.agent_missing_fields),
            "needs_agent": self.needs_agent,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "UnsafeStmtSemantics":
        return cls(
            stmt_id=int(value["stmt_id"]),
            entity_id=_optional_int(value.get("entity_id")),
            operation=UnsafeStmtOperation(value["operation"]),
            semantic_kind=UnsafeSemanticKind(value["semantic_kind"]),
            source_snippet=_optional_str(value.get("source_snippet")),
            related_symbols=[str(item) for item in value.get("related_symbols", [])],
            raw_gir=dict(value.get("raw_gir", {})),
            programmatic_facts=dict(value.get("programmatic_facts", {})),
            semantic_hints=dict(value.get("semantic_hints", value.get("fields", {}))),
            agent_missing_fields=[
                str(item) for item in value.get("agent_missing_fields", [])
            ],
            needs_agent=bool(value.get("needs_agent", False)),
        )


@dataclasses.dataclass
class DeclarationFacts:
    storage: StorageKind | None = None
    is_array_parameter: bool | None = None
    array_dimensions: list[str] = dataclasses.field(default_factory=list)

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


@dataclasses.dataclass
class CallEffectHints:
    call_kind: CallKind | None = None
    target_symbol: str | None = None
    ownership: Ownership | None = None
    origin_kind: OriginKind | None = None
    storage_kind: StorageKind | None = None
    transfer_kind: TransferKind | None = None
    allocation_shape: str | None = None
    allocation_size_bytes: str | None = None
    initialized_by: str | None = None
    escape_kind: str | None = None
    byte_count: str | None = None
    source_storage_kind: StorageKind | None = None
    arg_effects: list[str] = dataclasses.field(default_factory=list)
    arg_borrows: list[str] = dataclasses.field(default_factory=list)
    arg_escapes: list[str] = dataclasses.field(default_factory=list)

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


@dataclasses.dataclass
class CStringRead:


    buffer: str
    access_index: str
    role: CStringReadRole
    logical_end_value: int = 0

    def __post_init__(self) -> None:
        if not self.buffer.strip():
            raise ValueError("C string read buffer must not be empty")
        if not self.access_index.strip():
            raise ValueError("C string read access_index must not be empty")
        if self.logical_end_value != 0:
            raise ValueError("C string logical end value must be zero")

    def to_dict(self) -> dict[str, Any]:
        return _dataclass_fields(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CStringRead":
        required_fields = {
            "buffer",
            "access_index",
            "role",
            "logical_end_value",
        }
        missing_fields = required_fields - set(value)
        if missing_fields:
            raise ValueError(
                "C string read is missing fields: "
                + ", ".join(sorted(missing_fields))
            )
        unknown_fields = set(value) - required_fields
        if unknown_fields:
            raise ValueError(
                "C string read has unknown fields: "
                + ", ".join(sorted(unknown_fields))
            )
        logical_end_value = value["logical_end_value"]
        if isinstance(logical_end_value, bool) or not isinstance(
            logical_end_value, int
        ):
            raise TypeError("logical_end_value must be an integer")
        return cls(
            buffer=str(value["buffer"]),
            access_index=str(value["access_index"]),
            role=CStringReadRole(value["role"]),
            logical_end_value=logical_end_value,
        )


@dataclasses.dataclass
class MemoryReadHints:
    array_role: ArrayRole | None = None
    resolves_to_element: str | None = None
    address_origin_expr: str | None = None
    c_string_read: CStringRead | None = None

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


@dataclasses.dataclass
class MemoryWriteHints:
    array_role: ArrayRole | None = None
    resolves_to_element: str | None = None
    write_source_deps: list[str] = dataclasses.field(default_factory=list)
    address_origin_expr: str | None = None

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


@dataclasses.dataclass
class AddrOfHints:
    escape: list[str] = dataclasses.field(default_factory=list)

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


@dataclasses.dataclass
class CStringTermination:


    buffer: str
    terminator_index: str
    minimum_capacity: str
    write_target: str
    terminator_value: int = 0
    capacity_includes_terminator: bool = True

    def __post_init__(self) -> None:
        for field_name in (
            "buffer",
            "terminator_index",
            "minimum_capacity",
            "write_target",
        ):
            if not str(getattr(self, field_name)).strip():
                raise ValueError(f"{field_name} must not be empty")
        if self.terminator_value != 0:
            raise ValueError("C string terminator value must be zero")
        if self.capacity_includes_terminator is not True:
            raise ValueError("C string capacity must include the terminator")
        expected_capacity = f"({self.terminator_index.strip()}) + 1"
        if self.minimum_capacity.strip() != expected_capacity:
            raise ValueError(
                "minimum_capacity must be the terminator index plus one"
            )

    def to_dict(self) -> dict[str, Any]:
        return _dataclass_fields(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CStringTermination":
        required_fields = {
            "buffer",
            "terminator_index",
            "minimum_capacity",
            "write_target",
            "terminator_value",
            "capacity_includes_terminator",
        }
        missing_fields = required_fields - set(value)
        if missing_fields:
            raise ValueError(
                "C string termination is missing fields: "
                + ", ".join(sorted(missing_fields))
            )
        unknown_fields = set(value) - required_fields
        if unknown_fields:
            raise ValueError(
                "C string termination has unknown fields: "
                + ", ".join(sorted(unknown_fields))
            )
        terminator_value = value["terminator_value"]
        includes_terminator = value["capacity_includes_terminator"]
        if isinstance(terminator_value, bool) or not isinstance(
            terminator_value, int
        ):
            raise TypeError("terminator_value must be an integer")
        if not isinstance(includes_terminator, bool):
            raise TypeError("capacity_includes_terminator must be a boolean")
        return cls(
            buffer=str(value["buffer"]),
            terminator_index=str(value["terminator_index"]),
            minimum_capacity=str(value["minimum_capacity"]),
            write_target=str(value["write_target"]),
            terminator_value=terminator_value,
            capacity_includes_terminator=includes_terminator,
        )


@dataclasses.dataclass
class ArrayWriteHints:
    array_role: ArrayRole | None = None
    resolves_to_element: str | None = None
    write_source_deps: list[str] = dataclasses.field(default_factory=list)
    c_string_termination: CStringTermination | None = None

    def to_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.array_role is not None:
            fields["array_role"] = _jsonify(self.array_role)
        if self.resolves_to_element:
            fields["resolves_to_element"] = self.resolves_to_element
        if self.write_source_deps:
            fields["write_source_deps"] = list(self.write_source_deps)
        if self.c_string_termination is not None:
            fields["c_string_termination"] = (
                self.c_string_termination.to_dict()
            )
        return fields


@dataclasses.dataclass
class ArrayReadHints:
    array_role: ArrayRole | None = None
    resolves_to_element: str | None = None
    c_string_read: CStringRead | None = None

    def to_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.array_role is not None:
            fields["array_role"] = _jsonify(self.array_role)
        if self.resolves_to_element:
            fields["resolves_to_element"] = self.resolves_to_element
        if self.c_string_read is not None:
            fields["c_string_read"] = self.c_string_read.to_dict()
        return fields


@dataclasses.dataclass
class TypeCastHints:
    cast_kind: CastKind | None = None
    offset_base: str | None = None
    offset: str | None = None
    constraints: list[str] = dataclasses.field(default_factory=list)

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


@dataclasses.dataclass
class ReturnValueHints:
    return_lifetime: "ReturnLifetimeHints | None" = None
    derived_pointer: "DerivedPointerFacts | None" = None

    def to_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.return_lifetime is not None:
            fields["return_lifetime"] = self.return_lifetime.to_fields()
        if self.derived_pointer is not None:
            fields["derived_pointer"] = self.derived_pointer.to_fields()
        return fields


@dataclasses.dataclass
class ReturnLifetimeHints:
    kind: ReturnLifetimeKind | None = None
    source: str | None = None

    def to_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.kind is not None:
            fields["kind"] = _jsonify(self.kind)
        if self.source is not None:
            fields["source"] = self.source
        return fields


@dataclasses.dataclass
class DerivedPointerFacts:
    base: str
    base_c_type: str
    base_storage: StorageKind
    offset_expr: str
    offset_unit: PointerOffsetUnit
    result_c_type: str
    access_width_expr: str
    alignment_guarantee: AlignmentGuarantee
    borrow_source: str

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


@dataclasses.dataclass
class FieldWriteHints:
    is_pointer_field: bool | None = None
    establishes_alias: bool | None = None
    write_source_deps: list[str] = dataclasses.field(default_factory=list)

    def to_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.is_pointer_field is True:
            fields["is_pointer_field"] = True
        if self.establishes_alias is not None:
            fields["establishes_alias"] = self.establishes_alias
        if self.write_source_deps:
            fields["write_source_deps"] = list(self.write_source_deps)
        return fields


@dataclasses.dataclass
class FieldReadHints:
    is_pointer_field: bool | None = None

    def to_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.is_pointer_field is True:
            fields["is_pointer_field"] = True
        return fields


@dataclasses.dataclass
class AssignmentFlowHints:
    arith_base_pointee_shape: ArithmeticBasePointeeShape | None = None
    arith_base_object_kind: ArithmeticBaseObjectKind | None = None

    def to_fields(self) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        if self.arith_base_pointee_shape is not None:
            fields["arith_base_pointee_shape"] = _jsonify(
                self.arith_base_pointee_shape
            )
        if self.arith_base_object_kind is not None:
            fields["arith_base_object_kind"] = _jsonify(
                self.arith_base_object_kind
            )
        return fields


@dataclasses.dataclass
class ArrayAliasHints:
    alias: str | None = None
    base: str | None = None
    base_path: str | None = None
    offset_expr: str | None = None
    derived_from: str | None = None
    mutating_access_sites: list[int] = dataclasses.field(default_factory=list)
    escape_sites: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    valid_until_stmt_id: int | None = None
    ownership_kind: Ownership | None = None
    ownership_source: str | None = None

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


@dataclasses.dataclass
class PointerArithmeticHints:
    arith_kind: PointerArithKind | None = None
    base: str | None = None
    base_left: str | None = None
    base_right: str | None = None
    offset: str | None = None
    result_semantics: str | None = None

    def to_fields(self) -> dict[str, Any]:
        return _dataclass_fields(self)


def make_unsafe_stmt_semantics(
    *,
    stmt_id: int,
    operation: UnsafeStmtOperation,
    semantic_kind: UnsafeSemanticKind,
    semantic_hints: dict[str, Any],
    entity_id: int | None = None,
    source_snippet: str | None = None,
    related_symbols: list[str] | None = None,
    raw_gir: dict[str, Any] | None = None,
    programmatic_facts: dict[str, Any] | None = None,
    agent_missing_fields: list[str] | None = None,
) -> UnsafeStmtSemantics:


    record = UnsafeStmtSemantics(
        stmt_id=stmt_id,
        entity_id=entity_id,
        operation=operation,
        semantic_kind=semantic_kind,
        source_snippet=source_snippet,
        related_symbols=list(related_symbols or []),
        raw_gir=dict(raw_gir or {}),
        programmatic_facts=dict(programmatic_facts or {}),
        semantic_hints=semantic_hints,
        agent_missing_fields=list(agent_missing_fields or []),
    )
    record.needs_agent = bool(record.missing_fields())
    return record


def _dataclass_fields(value: Any) -> dict[str, Any]:
    return {
        field.name: _jsonify(getattr(value, field.name))
        for field in dataclasses.fields(value)
    }


def _jsonify(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value):
        return _dataclass_fields(value)
    if isinstance(value, list):
        return [_jsonify(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonify(item) for key, item in value.items()}
    return value


def _optional_int(value: Any) -> int | None:
    return None if value is None else int(value)


def _optional_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _reject_unknown_fields(
    value: dict[str, Any],
    allowed_fields: set[str],
    label: str,
) -> None:
    unknown_fields = set(value) - allowed_fields
    if unknown_fields:
        raise ValueError(
            f"{label} has unknown fields: "
            + ", ".join(sorted(unknown_fields))
        )
