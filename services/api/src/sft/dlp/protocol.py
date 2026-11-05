"""The DLP inspector's wire protocol and its strict schema (ADR-0022, architecture 4.6).

One connection inspects one file:

1. The scan worker sends a request frame: the file's size and the tenant's own detectors.
2. It sends the first `prefix_bytes` of the file (all of it if the file is smaller), raw.
3. The inspector answers with a decision frame: read the rest, or stop. It stops for a type it
   can't extract, such as an image; then only clamd gets the rest of the bytes. Instead of a
   decision it may answer with a result or an error frame at once.
4. On "read the rest", the worker sends the remaining bytes, raw.
5. The inspector answers with a result frame, or an error frame.

A frame is a 4-byte big-endian length and that many bytes of JSON in UTF-8. Raw file bytes are not
framed: the request gives their count.

The scan worker treats the answer as hostile input (T-92): `parse_answer` checks it against a
strict schema, with known detector IDs only, bounded counts and bounded lengths, and raises
`MalformedAnswerError` for anything else, which the worker counts as an engine error. No model
here has a free-text field, so nothing extracted can travel back in an answer except through
location hints and masked previews, which the detectors bound (T-99).
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from typing import Annotated, Final, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    TypeAdapter,
    ValidationError,
    model_validator,
)

from sft.dlp.units import CUSTOM_PREFIX, Finding, KeywordList, Pattern, TenantDetector

PROTOCOL_VERSION: Final = 1

MAX_REQUEST_FRAME: Final = 16 * 1024 * 1024
"""50 keyword lists of 1,000 terms of 100 characters fit, at up to 3 bytes a character."""

MAX_ANSWER_FRAME: Final = 1024 * 1024
"""Far above the largest valid result: 70 detectors, 10 hints of 256 and 3 previews of 64."""

Reason = Literal[
    "encrypted", "no_text", "unsupported_type", "too_large", "limit_exceeded", "parse_error"
]
"""Why content wasn't inspected ([detectors] 1)."""

State = Literal["inspected", "partial", "not_inspected"]
"""What the inspector says about a file. `failed` and `skipped` are the scan worker's own states."""

ErrorCode = Literal["bad_request", "engine_error", "sandbox_unavailable"]
"""Why the inspector couldn't answer. Each is a failed attempt for the worker, never a pass."""

MAX_LOCATIONS: Final = 10
MAX_PREVIEWS: Final = 3
MAX_LOCATION_CHARS: Final = 256
MAX_PREVIEW_CHARS: Final = 64
MAX_COUNT: Final = 2**31 - 1

# No C0 or C1 control characters and no DEL in anything the answer carries.
_PRINTABLE = r"^[^\x00-\x1f\x7f-\x9f]*$"
_DETECTOR_ID = r"^[A-Za-z0-9_-]{1,64}$"

TenantId = Annotated[str, StringConstraints(pattern=_DETECTOR_ID)]
Location = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_LOCATION_CHARS, pattern=_PRINTABLE)
]
Preview = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_PREVIEW_CHARS, pattern=_PRINTABLE)
]
Count = Annotated[int, Field(ge=0, le=MAX_COUNT)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


# ---- worker -> inspector ----


class KeywordListSpec(_Strict):
    """A tenant keyword list as sent ([detectors] 5, FR-38)."""

    kind: Literal["keywords"]
    id: TenantId
    terms: Annotated[
        list[Annotated[str, StringConstraints(min_length=1, max_length=100)]],
        Field(min_length=1, max_length=1000),
    ]


class PatternSpec(_Strict):
    """A tenant pattern as sent ([detectors] 5, FR-39). The detectors compile and check it."""

    kind: Literal["pattern"]
    id: TenantId
    expression: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    context_keywords: Annotated[
        list[Annotated[str, StringConstraints(min_length=1, max_length=100)]],
        Field(max_length=1000),
    ] = []
    min_length: Annotated[int, Field(ge=0, le=512)] = 0
    case_insensitive: bool = False


TenantDetectorSpec = Annotated[KeywordListSpec | PatternSpec, Field(discriminator="kind")]


class Request(_Strict):
    """The first frame of a connection."""

    type: Literal["inspect"]
    version: Literal[1]
    size: Annotated[int, Field(ge=0, le=2**62)]
    tenant_detectors: Annotated[list[TenantDetectorSpec], Field(max_length=50)] = []

    @model_validator(mode="after")
    def _bounded(self) -> Self:
        ids = [spec.id for spec in self.tenant_detectors]
        if len(set(ids)) != len(ids):
            raise ValueError("tenant detector IDs must be unique")
        if sum(isinstance(spec, PatternSpec) for spec in self.tenant_detectors) > 20:
            raise ValueError("at most 20 patterns")
        return self

    def detectors(self) -> tuple[TenantDetector, ...]:
        """The tenant's detectors as the detector library takes them."""
        out: list[TenantDetector] = []
        for spec in self.tenant_detectors:
            if isinstance(spec, KeywordListSpec):
                out.append(KeywordList(id=spec.id, terms=tuple(spec.terms)))
            else:
                out.append(
                    Pattern(
                        id=spec.id,
                        expression=spec.expression,
                        context_keywords=tuple(spec.context_keywords),
                        min_length=spec.min_length,
                        case_insensitive=spec.case_insensitive,
                    )
                )
        return tuple(out)

    def custom_detector_ids(self) -> frozenset[str]:
        return frozenset(CUSTOM_PREFIX + spec.id for spec in self.tenant_detectors)


# ---- inspector -> worker ----


class Counts(_Strict):
    low: Count
    medium: Count
    high: Count


BudgetDetector = Annotated[str, StringConstraints(pattern=r"^custom:[A-Za-z0-9_-]{1,64}$")]
"""A tenant pattern's detector ID: only tenant patterns have a scan-time budget."""


class FindingModel(_Strict):
    detector: Annotated[str, StringConstraints(min_length=1, max_length=72)]
    counts: Counts
    locations: Annotated[list[Location], Field(max_length=MAX_LOCATIONS)]
    previews: Annotated[list[Preview], Field(max_length=MAX_PREVIEWS)]


class Decision(_Strict):
    """The answer to the prefix: read the rest of the file, or stop sending it."""

    type: Literal["decision"]
    read_rest: bool


class Result(_Strict):
    """The inspector's result for one file."""

    type: Literal["result"]
    version: Literal[1]
    engine_version: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._+-]{1,64}$")]
    state: State
    reasons: Annotated[list[Reason], Field(max_length=6)]
    findings: Annotated[list[FindingModel], Field(max_length=200)]
    budget_exceeded: Annotated[list[BudgetDetector], Field(max_length=20)] = []
    """The tenant patterns stopped on this file for spending their scan-time budget ([DLP] 5,
    #147): IDs only, never a match. The file's state doesn't depend on it."""

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.reasons)) != len(self.reasons):
            raise ValueError("reasons repeat")
        if (self.state == "inspected") != (not self.reasons):
            raise ValueError("a file is inspected exactly when it has no reasons")
        if self.state == "not_inspected" and self.findings:
            raise ValueError("a file not inspected has no findings")
        if "too_large" in self.reasons and self.state != "not_inspected":
            raise ValueError("too_large means not_inspected")
        if len(set(self.budget_exceeded)) != len(self.budget_exceeded):
            raise ValueError("a stopped pattern repeats")
        detectors = [finding.detector for finding in self.findings]
        if len(set(detectors)) != len(detectors):
            raise ValueError("a detector repeats")
        for finding in self.findings:
            counts = finding.counts
            if counts.low + counts.medium + counts.high == 0:
                raise ValueError("a finding counts nothing")
        return self


class Error(_Strict):
    type: Literal["error"]
    code: ErrorCode


Answer = Decision | Result | Error

_ANSWER: TypeAdapter[Answer] = TypeAdapter(
    Annotated[Decision | Result | Error, Field(discriminator="type")]
)


class MalformedAnswerError(Exception):
    """The inspector's answer broke the protocol or the schema: an engine error (T-92).

    The message names the rule broken, never the content of the answer.
    """


class ProtocolError(Exception):
    """A peer broke the framing: a frame too long, or the stream ended early."""


def encode_frame(model: BaseModel) -> bytes:
    payload = model.model_dump_json().encode()
    return struct.pack(">I", len(payload)) + payload


def frame_length(header: bytes, limit: int) -> int:
    """The length a 4-byte frame header gives, or ProtocolError if it is over `limit`."""
    if len(header) != 4:
        raise ProtocolError("the stream ended inside a frame header")
    (length,) = struct.unpack(">I", header)
    if length > limit:
        raise ProtocolError("frame too long")
    return int(length)


def parse_request(payload: bytes) -> Request:
    """The request frame, or ValidationError."""
    return Request.model_validate_json(payload)


def parse_answer(
    payload: bytes,
    *,
    builtin_detectors: frozenset[str] | None,
    custom_detectors: frozenset[str] = frozenset(),
) -> Answer:
    """Check one answer frame from the inspector against the schema, or raise MalformedAnswerError.

    `builtin_detectors` is the detector library's `BUILTIN_DETECTORS`; `custom_detectors` the
    `custom:` IDs of the tenant detectors sent with the request. Any other detector ID fails.
    None skips that check: the inspector's parent checks the child's answers for shape only, and
    the worker checks them again in full.
    """
    try:
        answer = _ANSWER.validate_json(payload)
    except ValidationError as exc:
        # Only the location and the kind of each error: never the input.
        rules = sorted({f"{'.'.join(map(str, e['loc']))}: {e['type']}" for e in exc.errors()})
        raise MalformedAnswerError("; ".join(rules)[:500]) from None
    if isinstance(answer, Result) and builtin_detectors is not None:
        known = builtin_detectors | custom_detectors
        if any(finding.detector not in known for finding in answer.findings):
            raise MalformedAnswerError("unknown detector")
    return answer


def finding_model(finding: Finding) -> FindingModel:
    """A detector library finding as the answer carries it, cut to the schema's bounds."""
    return FindingModel(
        detector=finding.detector,
        counts=Counts(
            low=min(int(finding.counts.get("low", 0)), MAX_COUNT),
            medium=min(int(finding.counts.get("medium", 0)), MAX_COUNT),
            high=min(int(finding.counts.get("high", 0)), MAX_COUNT),
        ),
        locations=[_clean(text, MAX_LOCATION_CHARS) for text in finding.locations[:MAX_LOCATIONS]],
        previews=[_clean(text, MAX_PREVIEW_CHARS) for text in finding.previews[:MAX_PREVIEWS]],
    )


def _clean(text: str, limit: int) -> str:
    cleaned = "".join(" " if _is_control(char) else char for char in text)[:limit]
    return cleaned or "-"


def _is_control(char: str) -> bool:
    code = ord(char)
    return code < 0x20 or 0x7F <= code <= 0x9F


def result(
    *,
    engine_version: str,
    state: State,
    reasons: Sequence[Reason],
    findings: Sequence[FindingModel] = (),
    budget_exceeded: Sequence[str] = (),
) -> Result:
    return Result(
        type="result",
        version=PROTOCOL_VERSION,
        engine_version=engine_version,
        state=state,
        reasons=list(reasons),
        findings=list(findings),
        budget_exceeded=list(budget_exceeded),
    )
