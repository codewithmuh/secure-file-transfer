"""A tenant detector's definition, sealed for `dlp_detectors.definition_ct` (#218, #233; data
model 2.7; encryption and keys 3.3).

Keyword lists and patterns are JSON, encrypted with the tenant's DLP data key (`dlp-dek`,
`sft.service.fields`), bound to the detector's ID, so the scan worker can read them to send to
the inspector and nothing else can. A definition of a detector made before #233 is still format
0 (not encrypted) until the field key job's backfill reseals it; it is read the same way.

The keys are the caller's tenant's, never the row's, as for every sealed field. Nothing here logs
a definition: keyword lists hold a company's confidential terms.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID

from sft.data.models import DlpDetectorKind
from sft.dlp.protocol import KeywordListSpec, PatternSpec
from sft.dlp.units import KeywordList, Pattern, TenantDetector
from sft.service.fields import DETECTOR_DEFINITION, SealedValueError, TenantKeys


@dataclass(frozen=True, slots=True)
class Keywords:
    """A keyword list (FR-38): 1 to 1,000 terms of 1 to 100 characters (detectors 5)."""

    terms: tuple[str, ...]

    kind = DlpDetectorKind.KEYWORDS


@dataclass(frozen=True, slots=True)
class PatternDefinition:
    """An RE2 pattern (FR-39, #221): stored as the contract names its fields."""

    pattern: str
    context_keywords: tuple[str, ...] = ()
    case_insensitive: bool = True
    min_length: int | None = None

    kind = DlpDetectorKind.PATTERN


Definition = Keywords | PatternDefinition


def seal_definition(keys: TenantKeys, detector_id: UUID, definition: Definition) -> bytes:
    """`definition` as stored in `definition_ct` of the detector's rows, under the DLP key."""
    if isinstance(definition, Keywords):
        body: dict[str, object] = {"kind": "keywords", "terms": list(definition.terms)}
    else:
        body = {
            "kind": "pattern",
            "pattern": definition.pattern,
            "context_keywords": list(definition.context_keywords),
            "case_insensitive": definition.case_insensitive,
            "min_length": definition.min_length,
        }
    text = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
    return keys.seal(DETECTOR_DEFINITION, detector_id, text)


def open_definition(keys: TenantKeys, detector_id: UUID, value: bytes) -> Definition:
    """The definition in a detector's `definition_ct` value, with the caller's tenant's keys."""
    text = keys.open(DETECTOR_DEFINITION, detector_id, value)
    try:
        body = json.loads(text)
        if body["kind"] == "keywords":
            return Keywords(tuple(str(t) for t in body["terms"]))
        if body["kind"] == "pattern":
            min_length = body.get("min_length")
            return PatternDefinition(
                pattern=str(body["pattern"]),
                context_keywords=tuple(str(k) for k in body.get("context_keywords", ())),
                case_insensitive=bool(body.get("case_insensitive", True)),
                min_length=None if min_length is None else int(min_length),
            )
    except (ValueError, KeyError, TypeError) as exc:
        raise SealedValueError("unreadable detector definition") from exc
    raise SealedValueError("unknown detector kind")


def detector_unit(detector_id: UUID, definition: Definition) -> TenantDetector:
    """The definition as the detector library takes it, named by the detector's ID: its findings
    are `custom:<id>` (`sft.dlp.units.CUSTOM_PREFIX`)."""
    if isinstance(definition, Keywords):
        return KeywordList(id=str(detector_id), terms=definition.terms)
    return Pattern(
        id=str(detector_id),
        expression=definition.pattern,
        context_keywords=definition.context_keywords,
        min_length=definition.min_length or 0,
        case_insensitive=definition.case_insensitive,
    )


def inspector_spec(detector_id: UUID, definition: Definition) -> KeywordListSpec | PatternSpec:
    """The definition as the scan worker sends it to the inspector (`sft.dlp.protocol`)."""
    if isinstance(definition, Keywords):
        return KeywordListSpec(kind="keywords", id=str(detector_id), terms=list(definition.terms))
    return PatternSpec(
        kind="pattern",
        id=str(detector_id),
        expression=definition.pattern,
        context_keywords=list(definition.context_keywords),
        min_length=definition.min_length or 0,
        case_insensitive=definition.case_insensitive,
    )
