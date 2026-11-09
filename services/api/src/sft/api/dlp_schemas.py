"""The request and response bodies of the DLP policy operations, as the contract defines them
(docs/api/openapi.yaml: `DlpPolicy`, `DlpPolicyUpdate`, `DlpRule`, `DlpRuleCreate`,
`DlpRuleUpdate`, `DlpRuleList`, `DlpDetector`, `DlpDetectorCreate`, `DlpDetectorUpdate`,
`DlpDetectorList`; #218); a transfer's decision (`TransferDlp`, `DlpDecision`, `DlpMatchedRule`,
`DlpRecipientCheck`, `TransferDlpFile`, `TransferConfirmation`, and `ApprovalRequestSummary`,
which #220 fills; #219). The approval bodies (#220) are `sft.api.approval_schemas`.

The generated-spec check compares these with the contract (API README 11.1), with the patterns
of `sft.api.transfer_schemas`: an optional request field that may not be null is `X | None` with
`WithJsonSchema` giving the contract's schema, and a response field that is optional but never
null is set only when it has a value, the routes answering with `response_model_exclude_unset`.
`uniqueItems` is checked here, since Pydantic doesn't.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any, Final, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, WithJsonSchema, model_validator
from pydantic.json_schema import SkipJsonSchema

from sft.api.transfer_schemas import (
    _DETECTOR_PATTERN,
    _DOMAINS_SCHEMA,
    DlpFinding,
    FileInspectionSummary,
    Hostname,
    InspectionReason,
    _duration,
)
from sft.data.dlp_decisions import Decision
from sft.data.models import (
    DlpAction,
    DlpCondition,
    DlpConfidence,
    DlpDetectorKind,
    DlpDirection,
    DlpMode,
    DlpRecipientScope,
    DlpRule,
)
from sft.data.models import InspectionReason as Reason
from sft.service import dlp_policy
from sft.service.approval_requests import ApprovalSummaryView
from sft.service.dlp_definitions import Keywords, PatternDefinition
from sft.service.file_reads import FindingView
from sft.service.transfer_dlp import TransferDlpView, threshold_of

NIL: Final = UUID(int=0)
"""`created_by` of a default rule made for a tenant with no user (revision 0024): the contract's
`DlpRule.created_by` is a required ID, and no tenant made by `createTenant` is without its admin."""

_DETECTOR_ID: Final[dict[str, Any]] = {
    "type": "string",
    "maxLength": 71,
    "pattern": _DETECTOR_PATTERN,
}
_TERM: Final[dict[str, Any]] = {"type": "string", "minLength": 1, "maxLength": 100}
_REASON: Final[dict[str, Any]] = {
    "type": "string",
    "enum": [r.value for r in Reason],
}

DetectorId = Annotated[str, Field(max_length=71, pattern=_DETECTOR_PATTERN)]
Term = Annotated[str, Field(min_length=1, max_length=100)]


def _unique[T](values: list[T] | None) -> list[T] | None:
    if values is not None and len(set(values)) != len(values):
        raise ValueError("the items must be unique")
    return values


def _optional(schema: dict[str, Any]) -> WithJsonSchema:
    return WithJsonSchema(schema, mode="validation")


def _sent_fields_not_null(model: BaseModel) -> None:
    if not model.model_fields_set:
        raise ValueError("send at least one field")
    for name in model.model_fields_set:
        if getattr(model, name) is None:
            raise ValueError(f"{name} can't be null")


_VERSION_SCHEMA: Final = {"type": "integer", "minimum": 1}
ExpectedVersion = Annotated[int | None, _optional(_VERSION_SCHEMA)]


# ---- the policy ----


class DlpPolicyOut(BaseModel):
    """The contract's `DlpPolicy`."""

    model_config = ConfigDict(title="DlpPolicy")

    mode: DlpMode
    version: int = Field(ge=1)
    trusted_domains: list[Hostname] = Field(max_length=500, json_schema_extra={"uniqueItems": True})
    approval_timeout: Annotated[str, WithJsonSchema({"type": "string", "format": "duration"})]
    active_approvers: int = Field(ge=0)
    updated_at: datetime
    updated_by: UUID | None

    @classmethod
    def of(cls, view: dlp_policy.PolicyView) -> DlpPolicyOut:
        return cls(
            mode=view.mode,
            version=view.version,
            trusted_domains=list(view.trusted_domains),
            approval_timeout=_duration(view.approval_timeout),
            active_approvers=view.active_approvers,
            updated_at=view.updated_at,
            updated_by=view.updated_by,
        )


class DlpPolicyUpdate(BaseModel):
    """The contract's `DlpPolicyUpdate`: only the fields sent are changed."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"minProperties": 1})

    expected_version: ExpectedVersion = Field(default=None, ge=1)
    mode: DlpMode | SkipJsonSchema[None] = None
    trusted_domains: Annotated[
        list[str] | None, _optional(_DOMAINS_SCHEMA), AfterValidator(_unique)
    ] = Field(default=None, max_length=500)
    approval_timeout: Annotated[
        timedelta | None, _optional({"type": "string", "format": "duration"})
    ] = None

    @model_validator(mode="after")
    def _something_to_change(self) -> DlpPolicyUpdate:
        _sent_fields_not_null(self)
        return self

    def change(self) -> dlp_policy.PolicyUpdate:
        return dlp_policy.PolicyUpdate(
            expected_version=self.expected_version,
            mode=self.mode,
            trusted_domains=self.trusted_domains,
            approval_timeout=self.approval_timeout,
        )


# ---- rules ----

_DETECTORS_SCHEMA: Final = {
    "type": "array",
    "maxItems": 64,
    "uniqueItems": True,
    "items": _DETECTOR_ID,
}
_REASONS_SCHEMA: Final = {"type": "array", "maxItems": 6, "uniqueItems": True, "items": _REASON}

Detectors = Annotated[
    list[DetectorId] | None, _optional(_DETECTORS_SCHEMA), AfterValidator(_unique)
]
Reasons = Annotated[
    list[InspectionReason] | None, _optional(_REASONS_SCHEMA), AfterValidator(_unique)
]
Name = Annotated[str, Field(min_length=1, max_length=100)]
OptionalName = Annotated[
    str | None, _optional({"type": "string", "minLength": 1, "maxLength": 100})
]
Threshold = Annotated[int | None, _optional({"type": "integer", "minimum": 1, "maximum": 100000})]
ApprovalsRequired = Annotated[
    int | None, _optional({"type": "integer", "minimum": 1, "maximum": 2})
]


class DlpRuleOut(BaseModel):
    """The contract's `DlpRule`."""

    model_config = ConfigDict(title="DlpRule")

    id: UUID
    revision: int = Field(ge=1)
    name: str = Field(max_length=100)
    enabled: bool
    direction: Literal["sent", "received"]
    condition: DlpCondition
    detectors: list[DetectorId] = Field(max_length=64, json_schema_extra={"uniqueItems": True})
    min_confidence: DlpConfidence
    threshold: int = Field(ge=1, le=100000)
    reasons: list[InspectionReason] = Field(max_length=6, json_schema_extra={"uniqueItems": True})
    include_sender_24h: bool
    recipient_scope: Literal["any", "untrusted"]
    action: DlpAction
    approvals_required: int = Field(ge=1, le=2)
    created_by: UUID
    created_at: datetime

    @classmethod
    def of(cls, rule: DlpRule) -> DlpRuleOut:
        return cls(
            id=rule.id,
            revision=rule.revision,
            name=rule.name,
            enabled=rule.enabled,
            direction=rule.direction,  # type: ignore[arg-type] # the table's CHECK allows these
            condition=DlpCondition(rule.condition),
            detectors=list(rule.detectors),
            min_confidence=DlpConfidence(rule.min_confidence),
            threshold=rule.threshold,
            reasons=list(rule.reasons),  # type: ignore[arg-type]
            include_sender_24h=rule.include_sender_24h,
            recipient_scope=rule.recipient_scope,  # type: ignore[arg-type]
            action=DlpAction(rule.action),
            approvals_required=rule.approvals_required,
            created_by=rule.created_by or NIL,
            created_at=rule.created_at,
        )


class DlpRuleList(BaseModel):
    """The contract's `DlpRuleList`."""

    policy_version: int = Field(ge=1)
    items: list[DlpRuleOut] = Field(max_length=50)


class DlpRuleCreate(BaseModel):
    """The contract's `DlpRuleCreate`, with its defaults."""

    model_config = ConfigDict(extra="forbid")

    expected_version: ExpectedVersion = Field(default=None, ge=1)
    name: Name
    enabled: bool = True
    direction: Literal["sent", "received"]
    condition: DlpCondition
    detectors: Detectors = Field(default=None, max_length=64)
    min_confidence: DlpConfidence = DlpConfidence.MEDIUM
    threshold: int = Field(default=1, ge=1, le=100000)
    reasons: Reasons = Field(default=None, max_length=6)
    include_sender_24h: bool = False
    recipient_scope: Literal["any", "untrusted"] = "any"
    action: DlpAction
    approvals_required: int = Field(default=1, ge=1, le=2)

    def rule(self) -> dlp_policy.RuleCreate:
        return dlp_policy.RuleCreate(
            expected_version=self.expected_version,
            name=self.name,
            enabled=self.enabled,
            direction=DlpDirection(self.direction),
            condition=self.condition,
            detectors=tuple(self.detectors or ()),
            min_confidence=self.min_confidence,
            threshold=self.threshold,
            reasons=tuple(Reason(r) for r in self.reasons or ()),
            include_sender_24h=self.include_sender_24h,
            recipient_scope=DlpRecipientScope(self.recipient_scope),
            action=self.action,
            approvals_required=self.approvals_required,
        )


class DlpRuleUpdate(BaseModel):
    """The contract's `DlpRuleUpdate`: only the fields sent are changed."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"minProperties": 1})

    expected_version: ExpectedVersion = Field(default=None, ge=1)
    name: OptionalName = Field(default=None, min_length=1, max_length=100)
    enabled: bool | SkipJsonSchema[None] = None
    condition: DlpCondition | SkipJsonSchema[None] = None
    detectors: Detectors = Field(default=None, max_length=64)
    min_confidence: DlpConfidence | SkipJsonSchema[None] = None
    threshold: Threshold = Field(default=None, ge=1, le=100000)
    reasons: Reasons = Field(default=None, max_length=6)
    include_sender_24h: bool | SkipJsonSchema[None] = None
    recipient_scope: Annotated[
        Literal["any", "untrusted"] | None,
        _optional({"type": "string", "enum": ["any", "untrusted"]}),
    ] = None
    action: DlpAction | SkipJsonSchema[None] = None
    approvals_required: ApprovalsRequired = Field(default=None, ge=1, le=2)

    @model_validator(mode="after")
    def _something_to_change(self) -> DlpRuleUpdate:
        _sent_fields_not_null(self)
        return self

    def change(self) -> dlp_policy.RuleUpdate:
        return dlp_policy.RuleUpdate(
            expected_version=self.expected_version,
            name=self.name,
            enabled=self.enabled,
            condition=self.condition,
            detectors=None if self.detectors is None else tuple(self.detectors),
            min_confidence=self.min_confidence,
            threshold=self.threshold,
            reasons=None if self.reasons is None else tuple(Reason(r) for r in self.reasons),
            include_sender_24h=self.include_sender_24h,
            recipient_scope=(
                None if self.recipient_scope is None else DlpRecipientScope(self.recipient_scope)
            ),
            action=self.action,
            approvals_required=self.approvals_required,
        )


# ---- detectors ----

_KEYWORDS_SCHEMA: Final = {
    "type": "array",
    "minItems": 1,
    "maxItems": 1000,
    "uniqueItems": True,
    "items": _TERM,
}
_CONTEXT_SCHEMA: Final = {"type": "array", "maxItems": 50, "uniqueItems": True, "items": _TERM}
_PATTERN_SCHEMA: Final = {"type": "string", "minLength": 1, "maxLength": 512}
_MIN_LENGTH_SCHEMA: Final = {"type": "integer", "minimum": 1, "maximum": 1000}

KeywordsIn = Annotated[list[Term] | None, _optional(_KEYWORDS_SCHEMA), AfterValidator(_unique)]
ContextIn = Annotated[list[Term] | None, _optional(_CONTEXT_SCHEMA), AfterValidator(_unique)]
PatternIn = Annotated[str | None, _optional(_PATTERN_SCHEMA)]
MinLengthIn = Annotated[int | None, _optional(_MIN_LENGTH_SCHEMA)]


def _out(schema: dict[str, Any]) -> WithJsonSchema:
    return WithJsonSchema(schema)


class DlpDetectorOut(BaseModel):
    """The contract's `DlpDetector`: a built-in detector, or one of the tenant's own with its
    definition. Optional fields are set only when they apply."""

    model_config = ConfigDict(title="DlpDetector")

    id: DetectorId
    kind: Literal["built_in", "keywords", "pattern"]
    name: str = Field(max_length=100)
    description: str | SkipJsonSchema[None] = None
    enabled: bool
    revision: Annotated[int | None, _out(_VERSION_SCHEMA)] = None
    keywords: Annotated[
        list[str] | None, _out({"type": "array", "maxItems": 1000, "items": _TERM})
    ] = None
    pattern: Annotated[str | None, _out({"type": "string", "maxLength": 512})] = None
    context_keywords: Annotated[
        list[str] | None, _out({"type": "array", "maxItems": 50, "items": _TERM})
    ] = None
    case_insensitive: bool | SkipJsonSchema[None] = None
    min_length: Annotated[int | None, _out(_MIN_LENGTH_SCHEMA)] = None
    created_at: datetime | SkipJsonSchema[None] = None
    budget_exceeded_files: Annotated[int | None, _out({"type": "integer", "minimum": 0})] = None
    budget_exceeded_last_at: datetime | None = None

    @classmethod
    def of(cls, view: dlp_policy.DetectorView) -> DlpDetectorOut:
        fields: dict[str, Any] = {
            "id": view.id,
            "kind": view.kind,
            "name": view.name,
            "enabled": view.enabled,
        }
        if view.description is not None:
            fields["description"] = view.description
        if view.revision is not None:
            fields["revision"] = view.revision
        if view.created_at is not None:
            fields["created_at"] = view.created_at
        if view.budget_stops is not None:
            # A pattern in getDlpDetector (#164): set, the time null if none ever stopped it.
            fields["budget_exceeded_files"] = view.budget_stops
            fields["budget_exceeded_last_at"] = view.last_budget_stop_at
        definition = view.definition
        if isinstance(definition, Keywords):
            fields["keywords"] = list(definition.terms)
        elif isinstance(definition, PatternDefinition):
            fields["pattern"] = definition.pattern
            fields["context_keywords"] = list(definition.context_keywords)
            fields["case_insensitive"] = definition.case_insensitive
            if definition.min_length is not None:
                fields["min_length"] = definition.min_length
        return cls(**fields)


class DlpDetectorList(BaseModel):
    """The contract's `DlpDetectorList`."""

    engine_version: str
    items: list[DlpDetectorOut] = Field(max_length=100)


class DlpDetectorCreate(BaseModel):
    """The contract's `DlpDetectorCreate`, with its defaults."""

    model_config = ConfigDict(extra="forbid")

    expected_version: ExpectedVersion = Field(default=None, ge=1)
    name: Name
    kind: Literal["keywords", "pattern"]
    enabled: bool = True
    keywords: KeywordsIn = Field(default=None, min_length=1, max_length=1000)
    pattern: PatternIn = Field(default=None, min_length=1, max_length=512)
    context_keywords: ContextIn = Field(default=None, max_length=50)
    case_insensitive: bool = True
    min_length: MinLengthIn = Field(default=None, ge=1, le=1000)

    def detector(self) -> dlp_policy.DetectorCreate:
        return dlp_policy.DetectorCreate(
            expected_version=self.expected_version,
            name=self.name,
            kind=DlpDetectorKind(self.kind),
            enabled=self.enabled,
            keywords=self.keywords,
            pattern=self.pattern,
            context_keywords=self.context_keywords,
            min_length=self.min_length,
            case_insensitive=self.case_insensitive,
        )


class DlpDetectorUpdate(BaseModel):
    """The contract's `DlpDetectorUpdate`: only the fields sent are changed."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"minProperties": 1})

    expected_version: ExpectedVersion = Field(default=None, ge=1)
    name: OptionalName = Field(default=None, min_length=1, max_length=100)
    enabled: bool | SkipJsonSchema[None] = None
    keywords: KeywordsIn = Field(default=None, min_length=1, max_length=1000)
    pattern: PatternIn = Field(default=None, min_length=1, max_length=512)
    context_keywords: ContextIn = Field(default=None, max_length=50)
    case_insensitive: bool | SkipJsonSchema[None] = None
    min_length: MinLengthIn = Field(default=None, ge=1, le=1000)

    @model_validator(mode="after")
    def _something_to_change(self) -> DlpDetectorUpdate:
        _sent_fields_not_null(self)
        return self

    def change(self) -> dlp_policy.DetectorUpdate:
        return dlp_policy.DetectorUpdate(
            expected_version=self.expected_version,
            name=self.name,
            enabled=self.enabled,
            keywords=self.keywords,
            pattern=self.pattern,
            context_keywords=self.context_keywords,
            case_insensitive=self.case_insensitive,
            min_length=self.min_length,
        )


def sent(model: BaseModel) -> frozenset[str]:
    """The body's fields the client sent, for the pointer of a service refusal."""
    return frozenset(model.model_fields_set)


# ---- testDlpDetectors (FR-56, #221) ----

_TEST_TEXT_SCHEMA: Final = {
    "type": "string",
    "minLength": 1,
    "maxLength": dlp_policy.MAX_TEST_TEXT,
    "description": "Sample text, processed in memory and never stored or logged.",
}


class DlpDetectorTest(BaseModel):
    """The contract's `DlpDetectorTest`. The text's 16,384 characters are checked by the service,
    which answers `413 request_too_large` past them (abuse 2.2, K), not a `422`."""

    model_config = ConfigDict(extra="forbid")

    text: Annotated[str, WithJsonSchema(_TEST_TEXT_SCHEMA), Field(min_length=1, repr=False)]
    detectors: Annotated[
        list[DetectorId] | None,
        _optional(
            {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": True,
                "items": _DETECTOR_ID,
                "description": "Existing detectors to run. Leave out to run only `draft`, or "
                "every detector if there is no draft.",
            }
        ),
        AfterValidator(_unique),
    ] = Field(default=None, max_length=64)
    draft: DlpDetectorCreate | SkipJsonSchema[None] = None

    def test(self) -> dlp_policy.DetectorTest:
        return dlp_policy.DetectorTest(
            text=self.text,
            detectors=self.detectors,
            draft=None if self.draft is None else self.draft.detector(),
        )


class DlpDetectorTestMatch(BaseModel):
    detector: str
    confidence: DlpConfidence
    line: int = Field(ge=1)
    preview: str = Field(max_length=64)


class DlpDetectorTestResult(BaseModel):
    """The contract's `DlpDetectorTestResult`: the matches, masked as findings are."""

    matches: list[DlpDetectorTestMatch] = Field(max_length=100)
    truncated: bool

    @classmethod
    def of(cls, result: dlp_policy.TestResult) -> DlpDetectorTestResult:
        return cls(
            matches=[
                DlpDetectorTestMatch(
                    detector=m.detector,
                    confidence=DlpConfidence(m.confidence),
                    line=m.line,
                    preview=m.preview,
                )
                for m in result.matches
            ],
            truncated=result.truncated,
        )


# ---- a transfer's DLP decision (#219): getTransferDlp, confirmTransfer ----

DlpOutcomeName = Literal["none", "allow_and_record", "warn", "require_approval", "block"]
TransferStateName = Literal[
    "draft",
    "submitted",
    "awaiting_confirmation",
    "pending_approval",
    "sent",
    "held",
    "revoked",
    "expired",
    "cancelled",
]


class DlpMatchedRuleOut(BaseModel):
    model_config = ConfigDict(title="DlpMatchedRule")

    rule_id: UUID
    revision: int = Field(ge=1)
    name: str
    condition: DlpCondition
    action: DlpAction
    matched_count: int = Field(ge=0)
    threshold: int | None = Field(ge=1)


class DlpDecisionOut(BaseModel):
    model_config = ConfigDict(title="DlpDecision")

    id: UUID
    transfer_id: UUID | None
    file_id: UUID | None
    policy_version: int = Field(ge=1)
    mode: DlpMode
    outcome: DlpOutcomeName
    enforced: bool
    untrusted_recipients: int = Field(ge=0)
    new_domains: int = Field(ge=0)
    matched_rules: list[DlpMatchedRuleOut] = Field(max_length=50)
    decided_at: datetime

    @classmethod
    def of(cls, decision: Decision) -> DlpDecisionOut:
        return cls(
            id=decision.id,
            transfer_id=decision.transfer_id,
            file_id=decision.file_id,
            policy_version=decision.policy_version,
            mode=DlpMode(decision.mode),
            outcome=decision.outcome,  # type: ignore[arg-type]
            enforced=decision.enforced,
            untrusted_recipients=decision.untrusted_recipients,
            new_domains=decision.new_domains,
            matched_rules=[
                DlpMatchedRuleOut(
                    rule_id=rule.rule_id,
                    revision=rule.revision,
                    name=rule.name,
                    condition=DlpCondition(rule.condition),
                    action=DlpAction(rule.action),
                    matched_count=rule.matched_count,
                    threshold=threshold_of(rule.condition, rule.threshold),
                )
                for rule in decision.rules
            ],
            decided_at=decision.decided_at,
        )


class DlpRecipientCheckOut(BaseModel):
    model_config = ConfigDict(title="DlpRecipientCheck")

    recipient_id: UUID
    email: Annotated[str, Field(max_length=254, json_schema_extra={"format": "email"})]
    trusted: bool
    new_domain: bool


class TransferDlpFileOut(BaseModel):
    model_config = ConfigDict(title="TransferDlpFile")

    file_id: UUID
    display_name: str
    inspection: FileInspectionSummary
    findings: list[DlpFinding] = Field(max_length=70)


class ApprovalRequestSummaryOut(BaseModel):
    """A transfer's approval request in brief (FR-43, #220); shared with the approval reads."""

    model_config = ConfigDict(title="ApprovalRequestSummary")

    id: UUID
    transfer_id: UUID
    state: Literal["pending", "approved", "rejected", "expired", "withdrawn"]
    requested_by: UUID
    requested_at: datetime
    expires_at: datetime
    approvals_required: int = Field(ge=1, le=2)
    approvals: int = Field(ge=0, le=2)
    rule_names: list[str] = Field(max_length=50)

    @classmethod
    def of(cls, view: ApprovalSummaryView) -> ApprovalRequestSummaryOut:
        return cls(
            id=view.id,
            transfer_id=view.transfer_id,
            state=view.state.value,
            requested_by=view.requested_by,
            requested_at=view.requested_at,
            expires_at=view.expires_at,
            approvals_required=view.approvals_required,
            approvals=view.approvals,
            rule_names=list(view.rule_names),
        )


def _finding(view: FindingView) -> DlpFinding:
    return DlpFinding.of(view)


class TransferDlpOut(BaseModel):
    model_config = ConfigDict(title="TransferDlp")

    transfer_id: UUID
    state: TransferStateName
    decision: DlpDecisionOut | None
    recipients: list[DlpRecipientCheckOut] = Field(max_length=50)
    files: list[TransferDlpFileOut] = Field(max_length=50)
    message_findings: list[DlpFinding] = Field(max_length=70)
    approval_request: ApprovalRequestSummaryOut | None

    @classmethod
    def of(cls, view: TransferDlpView) -> TransferDlpOut:
        return cls(
            transfer_id=view.transfer_id,
            state=view.state.value,
            decision=None if view.decision is None else DlpDecisionOut.of(view.decision),
            recipients=[
                DlpRecipientCheckOut(
                    recipient_id=r.recipient_id,
                    email=r.email,
                    trusted=r.trusted,
                    new_domain=r.new_domain,
                )
                for r in view.recipients
            ],
            files=[
                TransferDlpFileOut(
                    file_id=f.file_id,
                    display_name=f.display_name,
                    inspection=FileInspectionSummary(
                        state=f.inspection_state.value,
                        reasons=[r.value for r in f.reasons],
                        dlp_blocked=False,  # received files only (FR-51)
                        detectors=[finding.detector for finding in f.findings],
                    ),
                    findings=[_finding(finding) for finding in f.findings],
                )
                for f in view.files
            ],
            message_findings=[_finding(finding) for finding in view.message_findings],
            approval_request=(
                None
                if view.approval_request is None
                else ApprovalRequestSummaryOut.of(view.approval_request)
            ),
        )


class TransferConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision_id: UUID
    justification: Annotated[
        str | None, _optional({"type": "string", "minLength": 1, "maxLength": 1000})
    ] = Field(default=None, min_length=1, max_length=1000)
