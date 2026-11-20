from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from .semantic_hint_schemas import (
    ResourceCapability,
    ResourceHandleRole,
    ResourceHandleSemantics,
    ResourceKind,
    ResourceOpenMode,
    ResourceOperation,
    ResourceOperationEffect,
    ResourceOperationOrigin,
    ResourceSemantics,
    ResourceStateRequirement,
)

_CALL_EFFECTS: dict[str, ResourceOperationEffect] = {
    "fopen": ResourceOperationEffect.OPEN,
    "fdopen": ResourceOperationEffect.OPEN,
    "freopen": ResourceOperationEffect.OPEN,
    "popen": ResourceOperationEffect.OPEN,
    "fread": ResourceOperationEffect.READ,
    "fscanf": ResourceOperationEffect.READ,
    "fgets": ResourceOperationEffect.READ,
    "fgetc": ResourceOperationEffect.READ,
    "getc": ResourceOperationEffect.READ,
    "fwrite": ResourceOperationEffect.WRITE,
    "fprintf": ResourceOperationEffect.WRITE,
    "fputs": ResourceOperationEffect.WRITE,
    "fputc": ResourceOperationEffect.WRITE,
    "putc": ResourceOperationEffect.WRITE,
    "fseek": ResourceOperationEffect.SEEK,
    "fseeko": ResourceOperationEffect.SEEK,
    "ftell": ResourceOperationEffect.TELL,
    "ftello": ResourceOperationEffect.TELL,
    "rewind": ResourceOperationEffect.REWIND,
    "fflush": ResourceOperationEffect.FLUSH,
    "fclose": ResourceOperationEffect.CLOSE,
    "pclose": ResourceOperationEffect.CLOSE,
    "feof": ResourceOperationEffect.TEST_EOF,
    "ferror": ResourceOperationEffect.TEST_ERROR,
    "ungetc": ResourceOperationEffect.PUSHBACK,
    "clearerr": ResourceOperationEffect.CLEAR_STATUS,
}
_CALL_PATTERN = re.compile(
    rf"\b({'|'.join(sorted(_CALL_EFFECTS, key=len, reverse=True))})\s*\("
)
_OPEN_MODE_PATTERN = re.compile(
    r'\b(?:fopen|fdopen|freopen)\s*\([^;]*?,\s*"([^"]+)"'
)
_STDIO_TYPE_QUALIFIERS = {
    "const",
    "volatile",
    "restrict",
    "__restrict",
    "__restrict__",
}
_STREAM_ARGUMENT_INDEX = {
    "fread": 3,
    "fscanf": 0,
    "fgets": 2,
    "fgetc": 0,
    "getc": 0,
    "fwrite": 3,
    "fprintf": 0,
    "fputs": 1,
    "fputc": 1,
    "putc": 1,
    "fseek": 0,
    "fseeko": 0,
    "ftell": 0,
    "ftello": 0,
    "rewind": 0,
    "fflush": 0,
    "fclose": 0,
    "pclose": 0,
    "feof": 0,
    "ferror": 0,
    "ungetc": 1,
    "clearerr": 0,
}
_CAPABILITY_BY_EFFECT: dict[ResourceOperationEffect, ResourceCapability] = {
    ResourceOperationEffect.READ: ResourceCapability.READ,
    ResourceOperationEffect.PUSHBACK: ResourceCapability.READ,
    ResourceOperationEffect.WRITE: ResourceCapability.WRITE,
    ResourceOperationEffect.SEEK: ResourceCapability.SEEK,
    ResourceOperationEffect.TELL: ResourceCapability.SEEK,
    ResourceOperationEffect.REWIND: ResourceCapability.SEEK,
    ResourceOperationEffect.FLUSH: ResourceCapability.FLUSH,
}
_CAPABILITY_ORDER = (
    ResourceCapability.READ,
    ResourceCapability.WRITE,
    ResourceCapability.SEEK,
    ResourceCapability.FLUSH,
)
_REQUIREMENT_ORDER = tuple(ResourceStateRequirement)


def parse_stdio_handle_type(c_type: str) -> int | None:


    text = str(c_type or "").strip()
    if not text or any(token in text for token in ("(", ")", "[", "]")):
        return None
    tokens = re.findall(r"[A-Za-z_]\w*|\*", text)
    tokens = [token for token in tokens if token not in _STDIO_TYPE_QUALIFIERS]
    if tokens[:1] == ["struct"]:
        tokens = tokens[1:]
    if not tokens or tokens[0] not in {"FILE", "_IO_FILE"}:
        return None
    pointer_tokens = tokens[1:]
    if not pointer_tokens or any(token != "*" for token in pointer_tokens):
        return None
    return len(pointer_tokens)


def infer_stdio_resource_semantics(
    *,
    resource_identity: str,
    handle: ResourceHandleSemantics,
    usage_path: Iterable[str],
    protocol_id: str | None = None,
) -> ResourceSemantics:


    operations: list[ResourceOperation] = []
    seen_operations: set[tuple[str, str, str, str, str]] = set()
    capabilities: set[ResourceCapability] = set()

    for raw_site in usage_path:
        site = str(raw_site).strip()
        if not site:
            continue
        parsed_mode = _open_mode_from_site(site)
        for callee, arguments in _iter_stdio_calls(site):
            effect = _CALL_EFFECTS[callee]
            operation_mode = (
                ResourceOpenMode.PROCESS_PIPE
                if callee == "popen"
                else parsed_mode if effect is ResourceOperationEffect.OPEN else None
            )
            target = _operation_target(
                callee,
                arguments,
                site=site,
                resource_identity=resource_identity,
            )
            key = (
                callee,
                effect.value,
                target,
                site,
                "" if operation_mode is None else operation_mode.value,
            )
            if key in seen_operations:
                continue
            seen_operations.add(key)
            operations.append(
                ResourceOperation(
                    callee=callee,
                    effect=effect,
                    origin=ResourceOperationOrigin.DIRECT,
                    target=target,
                    site=site,
                    open_mode=operation_mode,
                )
            )
            capability = _CAPABILITY_BY_EFFECT.get(effect)
            if capability is not None:
                capabilities.add(capability)

    open_operations = [
        operation
        for operation in operations
        if operation.effect is ResourceOperationEffect.OPEN
    ]
    close_operations = [
        operation
        for operation in operations
        if operation.effect is ResourceOperationEffect.CLOSE
    ]
    open_modes = {
        operation.open_mode
        for operation in open_operations
        if operation.open_mode is not None
    }
    unresolved_fields: list[str] = []
    if handle.role is ResourceHandleRole.UNKNOWN:
        unresolved_fields.append("handle.role")
    if handle.element_ownership is None:
        unresolved_fields.append("handle.element_ownership")
    if handle.element_nullability is None:
        unresolved_fields.append("handle.element_nullability")
    if not open_operations:
        unresolved_fields.extend(("creation_site", "open_mode"))
    elif any(operation.open_mode is None for operation in open_operations):
        unresolved_fields.append("open_mode")
    if not close_operations:
        unresolved_fields.append("end_site")
    if not capabilities:
        unresolved_fields.append("capabilities")

    return ResourceSemantics(
        resource_kind=ResourceKind.FILE_STREAM,
        resource_identity=resource_identity,
        capabilities=[
            capability for capability in _CAPABILITY_ORDER if capability in capabilities
        ],
        protocol_id=protocol_id or _local_protocol_id(resource_identity),
        handle=handle,
        operations=operations,
        flow_edges=[],
        state_requirements=derive_resource_state_requirements(operations),
        open_mode=next(iter(open_modes)) if len(open_modes) == 1 else None,
        creation_site=(open_operations[0].site if len(open_operations) == 1 else None),
        end_site=(close_operations[0].site if close_operations else None),
        unresolved_fields=unresolved_fields,
    )


def derive_resource_state_requirements(
    operations: Iterable[ResourceOperation],
) -> list[ResourceStateRequirement]:
    operations = tuple(operations)
    callees = {operation.callee for operation in operations}
    effects = {operation.effect for operation in operations}
    requirements: set[ResourceStateRequirement] = set()

    if ResourceOperationEffect.READ in effects:
        requirements.add(ResourceStateRequirement.EOF_IS_STICKY_AFTER_FAILED_READ)
        requirements.add(ResourceStateRequirement.ERROR_IS_STICKY_AFTER_FAILED_IO)
    if ResourceOperationEffect.TEST_ERROR in effects:
        requirements.add(ResourceStateRequirement.EOF_AND_ERROR_ARE_DISTINGUISHABLE)
    if ResourceOperationEffect.PUSHBACK in effects:
        requirements.update(
            {
                ResourceStateRequirement.PUSHBACK_SUPPORTS_AT_LEAST_ONE_BYTE,
                ResourceStateRequirement.SUCCESSFUL_PUSHBACK_CLEARS_EOF,
                ResourceStateRequirement.PUSHBACK_DOES_NOT_REQUIRE_SEEK,
            }
        )
    if ResourceOperationEffect.SEEK in effects:
        requirements.add(
            ResourceStateRequirement.SUCCESSFUL_SEEK_CLEARS_EOF_AND_PUSHBACK
        )
    if ResourceOperationEffect.REWIND in effects:
        requirements.add(ResourceStateRequirement.REWIND_CLEARS_EOF_AND_ERROR)
    if "fread" in callees:
        requirements.add(
            ResourceStateRequirement.FREAD_RETURNS_COMPLETE_ELEMENT_COUNT
        )
    if "fwrite" in callees:
        requirements.add(
            ResourceStateRequirement.FWRITE_RETURNS_COMPLETE_ELEMENT_COUNT
        )
    return [item for item in _REQUIREMENT_ORDER if item in requirements]


def _iter_stdio_calls(site: str) -> Iterable[tuple[str, list[str]]]:
    for match in _CALL_PATTERN.finditer(site):
        arguments_text = _balanced_call_contents(site, match.end() - 1)
        if arguments_text is not None:
            yield match.group(1), _split_arguments(arguments_text)


def _balanced_call_contents(text: str, opening_index: int) -> str | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening_index, len(text)):
        char = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[opening_index + 1 : index]
    return None


def _split_arguments(arguments: str) -> list[str]:
    result: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(arguments):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == "," and depth == 0:
            result.append(arguments[start:index].strip())
            start = index + 1
    tail = arguments[start:].strip()
    if tail or result:
        result.append(tail)
    return result


def _operation_target(
    callee: str,
    arguments: list[str],
    *,
    site: str,
    resource_identity: str,
) -> str:
    argument_index = _STREAM_ARGUMENT_INDEX.get(callee)
    if argument_index is not None and argument_index < len(arguments):
        return arguments[argument_index].strip()
    if callee in {"fopen", "fdopen", "freopen", "popen"}:
        assignment = re.search(
            rf"([^=;]+?)\s*=\s*{re.escape(callee)}\s*\(",
            site,
        )
        if assignment is not None:
            return assignment.group(1).strip()
    return resource_identity


def _local_protocol_id(resource_identity: str) -> str:
    digest = hashlib.sha256(resource_identity.encode("utf-8")).hexdigest()[:12]
    return f"stdio-local-{digest}"


def _open_mode_from_site(site: str) -> ResourceOpenMode | None:
    match = _OPEN_MODE_PATTERN.search(site)
    if match is None:
        return None
    normalized = match.group(1).replace("b", "").replace("t", "")
    return {
        "r": ResourceOpenMode.READ_EXISTING,
        "w": ResourceOpenMode.WRITE_TRUNCATE,
        "a": ResourceOpenMode.APPEND,
        "r+": ResourceOpenMode.READ_WRITE_EXISTING,
        "w+": ResourceOpenMode.READ_WRITE_TRUNCATE,
        "a+": ResourceOpenMode.READ_APPEND,
    }.get(normalized)
