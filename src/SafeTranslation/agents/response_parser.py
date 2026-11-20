from __future__ import annotations

import json
import re
from typing import Any

from SafeTranslation.models import (
    CargoDependencySpec,
    CheckerSummary,
    TranslatedEntity,
    TranslatedSignature,
)


class ResponseParseError(ValueError):
    pass


_RUST_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def parse_initial_translation(
    raw_response: str,
    *,
    expected_entity_id: int | None = None,
) -> TranslatedEntity:

    return _parse_translated_entity(
        raw_response,
        expected_entity_id=expected_entity_id,
    )


def parse_repair_rewrite(
    raw_response: str,
    *,
    expected_entity_id: int | None = None,
) -> TranslatedEntity:

    return _parse_translated_entity(
        raw_response,
        expected_entity_id=expected_entity_id,
    )


def parse_signature_translation(
    raw_response: str,
    *,
    expected_entity_id: int | None = None,
) -> TranslatedSignature:


    if _raw_metadata_contains_json_key(raw_response, "rust_signature"):
        raise ResponseParseError(
            "rust_signature must be emitted in a rust code block, not JSON"
        )

    data = _parse_json_object(raw_response)

    entity_id = _optional_int(data, "entity_id")
    if entity_id is not None and entity_id <= 0:
        entity_id = None
    if entity_id is None:
        entity_id = expected_entity_id
    if entity_id is None:
        raise ResponseParseError("entity_id is missing and no expected_entity_id provided")

    if "rust_signature" in data:
        raise ResponseParseError(
            "rust_signature must be emitted in a rust code block, not JSON"
        )

    rust_signature = _extract_rust_code_block(raw_response) or ""
    rust_signature = rust_signature.strip()
    if not rust_signature:
        raise ResponseParseError("rust_signature must not be empty")
    if "{" in rust_signature or "}" in rust_signature:
        raise ResponseParseError("rust_signature must not include a function body")
    rust_signature = rust_signature.rstrip(";").strip()
    if not rust_signature.startswith("pub fn "):
        raise ResponseParseError("rust_signature must start with 'pub fn '")

    exports = _optional_str_tuple(data, "exports")
    if not exports:
        raise ResponseParseError("exports must not be empty")
    for name in exports:
        if not _RUST_IDENTIFIER_RE.match(name):
            raise ResponseParseError(f"invalid exported Rust item name: {name!r}")

    support_exports = _parse_support_exports(data, exports=exports)
    cargo_dependencies = _parse_cargo_dependencies(data)

    return TranslatedSignature(
        entity_id=entity_id,
        rust_signature=rust_signature,
        exports=exports,
        summary=_optional_str(data, "summary", ""),
        raw_model_output=raw_response,
        resource_decisions=(),
        support_exports=support_exports,
        cargo_dependencies=cargo_dependencies,
    )


def parse_checker_summary(raw_response: str) -> CheckerSummary:

    data = _parse_json_object(raw_response)
    return CheckerSummary(
        summary=_optional_str(data, "summary", ""),
        root_causes=_optional_str_tuple(data, "root_causes"),
        repair_priority=_optional_str_tuple(data, "repair_priority"),
        raw_model_output=raw_response,
    )


def _parse_translated_entity(
    raw_response: str,
    *,
    expected_entity_id: int | None,
) -> TranslatedEntity:
    if _raw_metadata_contains_json_key(raw_response, "rust_code"):
        raise ResponseParseError("rust_code must be emitted in a rust code block, not JSON")

    data = _parse_json_object(raw_response)

    entity_id = _optional_int(data, "entity_id")
    if entity_id is not None and entity_id <= 0:
        entity_id = None
    if entity_id is None:
        entity_id = expected_entity_id
    if entity_id is None:
        raise ResponseParseError("entity_id is missing and no expected_entity_id provided")

    if "rust_code" in data:
        raise ResponseParseError("rust_code must be emitted in a rust code block, not JSON")

    rust_code = _extract_rust_code_block(raw_response) or ""
    if not rust_code.strip():
        raise ResponseParseError("rust_code must not be empty")

    exports = _optional_str_tuple(data, "exports")
    if not exports:
        raise ResponseParseError("exports must not be empty")
    for name in exports:
        if not _RUST_IDENTIFIER_RE.match(name):
            raise ResponseParseError(f"invalid exported Rust item name: {name!r}")

    support_exports = _parse_support_exports(data, exports=exports)
    cargo_dependencies = _parse_cargo_dependencies(data)

    return TranslatedEntity(
        entity_id=entity_id,
        rust_code=rust_code,
        exports=exports,
        summary=_optional_str(data, "summary", ""),
        raw_model_output=raw_response,
        resource_decisions=(),
        support_exports=support_exports,
        cargo_dependencies=cargo_dependencies,
    )


def _parse_support_exports(
    data: JsonDict,
    *,
    exports: tuple[str, ...],
) -> tuple[str, ...]:
    value = data.get("support_exports", [])
    if not isinstance(value, list):
        raise ResponseParseError("support_exports must be an array")
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not _RUST_IDENTIFIER_RE.fullmatch(item):
            raise ResponseParseError(
                f"support_exports[{index}] must be a valid Rust identifier"
            )
        if item in exports:
            raise ResponseParseError(
                f"support export {item!r} must be separate from required exports"
            )
        if item in result:
            raise ResponseParseError(f"duplicate support export: {item!r}")
        result.append(item)
    return tuple(result)


def _parse_cargo_dependencies(data: JsonDict) -> tuple[CargoDependencySpec, ...]:
    value = data.get("cargo_dependencies", [])
    if not isinstance(value, list):
        raise ResponseParseError("cargo_dependencies must be an array")
    if value:
        raise ResponseParseError(
            "Automatic Cargo dependency changes are disabled. "
            "cargo_dependencies must be empty; use only the Rust standard library "
            "or dependencies and features already configured in Cargo.toml."
        )
    return ()


def _parse_json_object(raw_response: str) -> JsonDict:
    text = _metadata_json_text(raw_response).strip()
    if not text:
        raise ResponseParseError("response is empty")
    try:
        value = json.loads(text)
    except json.JSONDecodeError:



        value = _extract_json_object(text)
        if value is None:
            raise ResponseParseError(
                f"response is not valid JSON and no JSON object could be "
                f"extracted from the response"
            ) from None
    if not isinstance(value, dict):
        raise ResponseParseError("response JSON must be an object")
    return value


def _metadata_json_text(raw_response: str) -> str:
    prefix = _metadata_prefix_before_rust_code(raw_response)
    return _strip_markdown_code_fence(prefix).strip()


def _extract_json_object(text: str) -> JsonDict | None:

    start = text.find("{")
    while start >= 0:
        depth = 0
        for index in range(start, len(text)):
            char = text[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : index + 1]
                    try:
                        value = json.loads(candidate)
                    except json.JSONDecodeError:
                        break
                    if isinstance(value, dict):
                        return value
                    break
        start = text.find("{", start + 1)
    return None


_CODE_FENCE_RE = re.compile(r"```([A-Za-z0-9_-]*)\s*(.*?)\s*```", re.DOTALL)
_RUST_CODE_FENCE_RE = re.compile(r"```(?:rust|rs)\s*(.*?)\s*```", re.DOTALL)


def _strip_markdown_code_fence(text: str) -> str:

    stripped = text.strip()
    match = re.fullmatch(_CODE_FENCE_RE, stripped)
    if match and _is_json_fence(match.group(1), match.group(2)):
        return match.group(2)
    matches = [
        match
        for match in _CODE_FENCE_RE.finditer(stripped)
        if _is_json_fence(match.group(1), match.group(2))
    ]
    if matches:
        return matches[-1].group(2)
    return stripped


def _is_json_fence(language: str, body: str) -> bool:
    language = language.strip().lower()
    if language == "json":
        return True
    if language:
        return False
    return body.lstrip().startswith("{")


def _extract_rust_code_block(text: str) -> str | None:
    matches = list(_RUST_CODE_FENCE_RE.finditer(text.strip()))
    if not matches:
        return None
    return matches[-1].group(1).strip()


def _raw_metadata_contains_json_key(raw_response: str, key: str) -> bool:
    metadata_prefix = _metadata_prefix_before_rust_code(raw_response)
    return re.search(rf'(?<!\\)"{re.escape(key)}"\s*:', metadata_prefix) is not None


def _metadata_prefix_before_rust_code(raw_response: str) -> str:
    matches = list(_RUST_CODE_FENCE_RE.finditer(raw_response))
    if not matches:
        return raw_response
    return raw_response[: matches[-1].start()]




def _require_str(data: JsonDict, key: str) -> str:
    if key not in data:
        raise ResponseParseError(f"missing required field {key!r}")
    value = data[key]
    if not isinstance(value, str):
        raise ResponseParseError(f"field {key!r} must be a string")
    return value




def _optional_str(data: JsonDict, key: str, default: str) -> str:
    value = data.get(key)
    if value is None or value == "":
        return default
    if not isinstance(value, str):
        return default
    return value


def _optional_int(data: JsonDict, key: str) -> int | None:
    value = data.get(key)
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        try:
            return int(stripped)
        except (ValueError, TypeError):
            pass
    return None


def _optional_str_tuple(data: JsonDict, key: str) -> tuple[str, ...]:
    value = data.get(key)
    if not isinstance(value, list):
        return ()
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if text:
            result.append(text)
    return tuple(result)
