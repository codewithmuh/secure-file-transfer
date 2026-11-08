"""A tenant detector's definition, sealed for `dlp_detectors.definition_ct` (#218; data model 2.7;
encryption and keys 3.3).

The design stores keyword lists and patterns encrypted with the tenant's DLP data key, which
arrives with DLP-8 (M6). Until then this module is the one place a definition passes through on
its way to and from the column, so DLP-8 changes this module and a data migration, not its
callers. The definition is JSON, sealed with the stand-in of M2 (`sft.service.fields.seal`,
format 0, **not encrypted**); `dlp_key_version` stays empty.

The tenant is the caller's scope, never the row's, as for every sealed field. Nothing here logs a
definition: keyword lists hold a company's confidential terms.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from uuid import UUID

from sft.data.models import DlpDetectorKind
from sft.dlp.protocol import KeywordListSpec, PatternSpec
from sft.dlp.units import KeywordList, Pattern, TenantDetector
from sft.service.fields import SealedValueError, open_sealed, seal


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


def seal_definition(tenant_id: UUID, definition: Definition) -> bytes:
    """`definition` as stored in `definition_ct` of `tenant_id`'s row."""
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
    return seal(tenant_id, json.dumps(body, ensure_ascii=False, separators=(",", ":")))


def open_definition(tenant_id: UUID, value: bytes) -> Definition:
    """The definition in a `definition_ct` value, read in `tenant_id`'s scope."""
    try:
        body = json.loads(open_sealed(tenant_id, value))
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
