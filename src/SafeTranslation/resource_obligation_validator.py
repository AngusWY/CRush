from __future__ import annotations

import dataclasses
from TranslationOrientedAnalysis.semantic_hint_schemas import ResourceStateRequirement


@dataclasses.dataclass(frozen=True)
class ResourceObligationVerdict:
    protocol_id: str
    requirement: ResourceStateRequirement
    satisfied: bool
    evidence: str


@dataclasses.dataclass(frozen=True)
class ResourceValidationResult:
    passed: bool
    verdicts: tuple[ResourceObligationVerdict, ...]
    errors: tuple[str, ...]
