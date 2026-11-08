"""The request and response bodies of the transfer and upload operations, as the contract defines
them (docs/api/openapi.yaml: `TransferCreate`, `Transfer`, `TransferPage`, `FileCreate`, `File`,
`FileInspection`, `PartUrlRequest`, `PartUrlList`, `UploadedParts`, `TenantPolicy`,
`TenantPolicyUpdate`, `ExpiryExtension` and the schemas they use).

The generated-spec check compares the schemas FastAPI builds from these with the contract (API
README 11.1), so a field here is written to produce exactly the contract's schema. Two patterns
recur:

- **An optional request field that may not be null** is `X | None` in Python, with
  `WithJsonSchema` giving the contract's schema, so the code can tell "left out" from a value.
- **A response field that is optional but never null** (`File.upload`) is set only when it has
  a value, and the routes answer with `response_model_exclude_unset`, so it is left out otherwise.
  Every other field is always set.
"""

from __future__ import annotations

import unicodedata
from datetime import datetime, timedelta
from typing import Annotated, Any, Final, Literal
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    WithJsonSchema,
    model_validator,
)
from pydantic.json_schema import SkipJsonSchema

from sft.core.addresses import is_plain_address
from sft.data.models import UnscannablePolicy
from sft.data.tenants import Policy
from sft.service.file_reads import InspectionView
from sft.service.tenant_policy import PolicyChange
from sft.service.transfers import FileView, SummaryView, TransferPage, TransferView
from sft.service.uploads import PartUrl as PartUrlResult
from sft.service.uploads import UploadedParts as UploadedPartsResult

Locale = Literal["en", "ja"]
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
FileStateName = Literal[
    "uploading",
    "completing",
    "scanning",
    "clean",
    "infected",
    "unscannable",
    "scan_failed",
    "rejected",
    "deleted",
]
HoldReason = Literal["file_blocked", "dlp_blocked", "approval_rejected"]
InspectionState = Literal["pending", "inspected", "partial", "not_inspected", "failed", "skipped"]
InspectionReason = Literal[
    "encrypted", "no_text", "unsupported_type", "too_large", "limit_exceeded", "parse_error"
]
ScanDetailName = Literal[
    "encrypted",
    "limit_exceeded",
    "engine_error",
    "deadline_passed",
    "large_file_scanning_unavailable",
]

_DETECTOR_PATTERN: Final = (
    r"^([a-z][a-z0-9_]{1,63}|custom:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)


def _email(value: str) -> str:
    # As `inviteUser` checks one (sft.api.members): the mail adapter's rule (sft.core.addresses),
    # so a link email can always be sent, and the shape `format: email` asks for. Deliverability
    # is the notification worker's to find out (data model 2.2).
    local, _, domain = value.rpartition("@")
    if not (is_plain_address(value) and len(local) <= 64 and "." in domain.strip(".")):
        raise ValueError("not an email address")
    return value


def _display_name(value: str) -> str:
    """File names with path separators or control characters are refused (contract `FileCreate`)."""
    if "/" in value or "\\" in value:
        raise ValueError("a file name has no path separators")
    if any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in value):
        raise ValueError("a file name has no control characters")
    if value.strip() in ("", ".", ".."):
        raise ValueError("not a file name")
    return value


EmailAddress = Annotated[
    str, Field(max_length=254, json_schema_extra={"format": "email"}), AfterValidator(_email)
]


def _optional(schema: dict[str, Any]) -> WithJsonSchema:
    return WithJsonSchema(schema, mode="validation")


# ---- requests ----


class RecipientInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailAddress
    locale: Annotated[Locale | None, _optional({"type": "string", "enum": ["en", "ja"]})] = None


class TransferCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    recipients: list[RecipientInput] = Field(min_length=1, max_length=50)
    expires_in: Annotated[timedelta | None, _optional({"type": "string", "format": "duration"})] = (
        None
    )
    message: Annotated[str | None, _optional({"type": "string", "maxLength": 2000})] = Field(
        default=None, max_length=2000
    )
    download_limit: int | None = Field(default=None, ge=1, le=100)
    notify_on_first_download: bool = False


class ExpiryExtension(BaseModel):
    """`extendTransferExpiry`'s body (#214): the new expiry, with its offset."""

    model_config = ConfigDict(extra="forbid")

    expires_at: AwareDatetime


class FileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: Annotated[str, AfterValidator(_display_name)] = Field(
        min_length=1, max_length=255
    )
    content_type: str = Field(default="application/octet-stream", max_length=255)
    size: int = Field(ge=1, le=5_000_000_000)


class PartUrlRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    part_numbers: list[Annotated[int, Field(ge=1, le=1000)]] = Field(
        min_length=1, max_length=100, json_schema_extra={"uniqueItems": True}
    )


# ---- responses ----


class UploadPlan(BaseModel):
    part_size: int = Field(ge=5_242_880)
    part_count: int = Field(ge=1, le=1000)


_UPLOAD_PLAN_SCHEMA: Final = {
    "type": "object",
    "required": ["part_size", "part_count"],
    "properties": {
        "part_size": {"type": "integer", "minimum": 5_242_880},
        "part_count": {"type": "integer", "minimum": 1, "maximum": 1000},
    },
}


class FileInspectionSummary(BaseModel):
    state: InspectionState
    reasons: list[InspectionReason] = Field(max_length=6, json_schema_extra={"uniqueItems": True})
    dlp_blocked: bool
    detectors: list[Annotated[str, Field(max_length=71, pattern=_DETECTOR_PATTERN)]] = Field(
        max_length=70, json_schema_extra={"uniqueItems": True}
    )


class File(BaseModel):
    id: UUID
    transfer_id: UUID | None
    upload_request_id: UUID | None
    display_name: str
    content_type: str
    declared_size: int = Field(ge=1, le=5_000_000_000)
    actual_size: int | None = Field(ge=1)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    state: FileStateName
    shareable: bool
    inspection: FileInspectionSummary
    scanned_at: datetime | None = None
    scan_engine: Literal["clamav", "guardduty"] | None = None
    scan_detail: ScanDetailName | None = None
    retention_until: datetime | None = None
    created_at: datetime
    upload: Annotated[UploadPlan | None, WithJsonSchema(_UPLOAD_PLAN_SCHEMA)] = None
    """Present only while the file is `uploading`."""

    @classmethod
    def of(cls, view: FileView) -> File:
        file = cls(
            id=view.id,
            transfer_id=view.transfer_id,
            upload_request_id=view.upload_request_id,
            display_name=view.display_name,
            content_type=view.content_type,
            declared_size=view.declared_size,
            actual_size=view.actual_size,
            sha256=view.sha256,
            state=view.state.value,
            shareable=view.shareable,
            inspection=FileInspectionSummary(
                state=view.inspection_state.value,
                reasons=[r.value for r in view.inspection_reasons],
                dlp_blocked=view.dlp_blocked,  # received files only (FR-51, #221)
                detectors=list(view.detectors),
            ),
            scanned_at=view.scanned_at,
            scan_engine=None if view.scan_engine is None else view.scan_engine.value,
            scan_detail=None if view.scan_detail is None else view.scan_detail.value,
            created_at=view.created_at,
        )
        if view.retention_until is not None:
            file.retention_until = view.retention_until
        if view.state.value == "uploading":
            # Set only while uploading: routes answer with `response_model_exclude_unset`, so it is
            # left out otherwise, as the contract has it, rather than sent as null.
            file.upload = UploadPlan(part_size=view.part_size, part_count=view.part_count)
        return file


class TransferRecipient(BaseModel):
    id: UUID
    email: Annotated[str, Field(max_length=254, json_schema_extra={"format": "email"})]
    locale: Locale
    access_state: Literal["invited", "verified", "locked"]


class TransferDlpSummary(BaseModel):
    outcome: Literal["none", "allow_and_record", "warn", "require_approval", "block"]
    mode: Literal["monitor", "enforce"]
    enforced: bool
    approval_request_id: UUID | None


class Transfer(BaseModel):
    id: UUID
    state: TransferStateName
    created_by: UUID
    created_at: datetime
    expires_in: timedelta
    expires_at: datetime | None
    message: str | None
    download_limit: int | None = Field(ge=1, le=100)
    notify_on_first_download: bool
    submitted_at: datetime | None
    sent_at: datetime | None
    revoked_at: datetime | None
    revoked_by: UUID | None
    total_size: int = Field(ge=0)
    hold_reason: HoldReason | None
    dlp: TransferDlpSummary | None
    files: list[File] = Field(max_length=50)
    recipients: list[TransferRecipient] = Field(max_length=50)

    @classmethod
    def of(cls, view: TransferView) -> Transfer:
        return cls(
            id=view.id,
            state=view.state.value,
            created_by=view.created_by,
            created_at=view.created_at,
            expires_in=view.expires_in,
            expires_at=view.expires_at,
            message=view.message,
            download_limit=view.download_limit,
            notify_on_first_download=view.notify_on_first_download,
            submitted_at=view.submitted_at,
            sent_at=view.sent_at,
            revoked_at=view.revoked_at,
            revoked_by=view.revoked_by,
            total_size=view.total_size,
            hold_reason=view.hold_reason,  # type: ignore[arg-type]
            dlp=None
            if view.dlp is None
            else TransferDlpSummary(
                outcome=view.dlp.outcome,  # type: ignore[arg-type]
                mode=view.dlp.mode,  # type: ignore[arg-type]
                enforced=view.dlp.enforced,
                approval_request_id=view.dlp.approval_request_id,
            ),
            files=[File.of(f) for f in view.files],
            # Nobody is invited before the transfer is sent; `invited` is the state until then.
            recipients=[
                TransferRecipient(
                    id=r.id,
                    email=r.email,
                    locale=r.locale,  # type: ignore[arg-type]
                    access_state="invited",
                )
                for r in view.recipients
            ],
        )


class PartUrl(BaseModel):
    part_number: int = Field(ge=1, le=1000)
    size: int = Field(ge=1)
    method: Literal["PUT"]
    url: Annotated[str, Field(json_schema_extra={"format": "uri"})]
    headers: dict[str, str] = Field(default_factory=dict)
    expires_at: datetime

    @classmethod
    def of(cls, result: PartUrlResult) -> PartUrl:
        return cls(
            part_number=result.part_number,
            size=result.size,
            method="PUT",
            url=result.url,
            expires_at=result.expires_at,
        )


class PartUrlList(BaseModel):
    parts: list[PartUrl]


class UploadedPart(BaseModel):
    part_number: int = Field(ge=1, le=1000)
    size: int = Field(ge=1)


class UploadedParts(BaseModel):
    part_size: int = Field(ge=5_242_880)
    part_count: int = Field(ge=1, le=1000)
    parts: list[UploadedPart] = Field(max_length=1000)

    @classmethod
    def of(cls, result: UploadedPartsResult) -> UploadedParts:
        return cls(
            part_size=result.part_size,
            part_count=result.part_count,
            parts=[UploadedPart(part_number=n, size=size) for n, size in result.parts],
        )


class TransferSummary(BaseModel):
    id: UUID
    state: TransferStateName
    created_by: UUID
    created_at: datetime
    expires_at: datetime | None
    sent_at: datetime | None
    revoked_at: datetime | None
    file_count: int = Field(ge=0, le=50)
    recipient_count: int = Field(ge=1, le=50)
    total_size: int = Field(ge=0)
    dlp_outcome: Literal["none", "allow_and_record", "warn", "require_approval", "block"] | None = (
        None
    )

    @classmethod
    def of(cls, view: SummaryView) -> TransferSummary:
        return cls(
            id=view.id,
            state=view.state.value,
            created_by=view.created_by,
            created_at=view.created_at,
            expires_at=view.expires_at,
            sent_at=view.sent_at,
            revoked_at=view.revoked_at,
            file_count=view.file_count,
            recipient_count=view.recipient_count,
            total_size=view.total_size,
            dlp_outcome=view.dlp_outcome,  # type: ignore[arg-type]
        )


class TransferPageOut(BaseModel):
    model_config = ConfigDict(title="TransferPage")

    items: list[TransferSummary]
    next_cursor: str | None

    @classmethod
    def of(cls, page: TransferPage) -> TransferPageOut:
        return cls(
            items=[TransferSummary.of(item) for item in page.items], next_cursor=page.next_cursor
        )


# ---- DLP inspection (getFileInspection) ----


class DlpLocation(BaseModel):
    """Where a match is (detectors 7). None are returned before DLP-8 encrypts them."""

    model_config = ConfigDict(extra="forbid")

    member: Annotated[str, Field(max_length=1024)] | SkipJsonSchema[None] = None
    page: Annotated[int, Field(ge=1)] | SkipJsonSchema[None] = None
    sheet: Annotated[str, Field(max_length=255)] | SkipJsonSchema[None] = None
    row: Annotated[int, Field(ge=1)] | SkipJsonSchema[None] = None
    slide: Annotated[int, Field(ge=1)] | SkipJsonSchema[None] = None
    line: Annotated[int, Field(ge=1)] | SkipJsonSchema[None] = None
    paragraph: Annotated[int, Field(ge=1)] | SkipJsonSchema[None] = None
    part: (
        Literal[
            "body", "header", "footer", "footnotes", "comments", "notes", "properties", "message"
        ]
        | SkipJsonSchema[None]
    ) = None


class DlpFinding(BaseModel):
    detector: Annotated[str, Field(max_length=71, pattern=_DETECTOR_PATTERN)]
    detector_name: str
    count_low: int = Field(ge=0)
    count_medium: int = Field(ge=0)
    count_high: int = Field(ge=0)
    details_visible: bool
    locations: Annotated[list[DlpLocation], Field(max_length=10)] | SkipJsonSchema[None] = None
    """Only with details (DLP-8); left out, never null, until then."""
    previews: (
        Annotated[list[Annotated[str, Field(max_length=64)]], Field(max_length=3)]
        | SkipJsonSchema[None]
    ) = None


class FileInspection(BaseModel):
    file_id: UUID
    state: InspectionState
    reasons: list[InspectionReason] = Field(max_length=6, json_schema_extra={"uniqueItems": True})
    dlp_blocked: bool
    engine_version: str | None
    policy_version: int | None
    inspected_at: datetime | None
    findings: list[DlpFinding] = Field(max_length=70)

    @classmethod
    def of(cls, view: InspectionView) -> FileInspection:
        return cls(
            file_id=view.file_id,
            state=view.state.value,
            reasons=[r.value for r in view.reasons],
            dlp_blocked=view.dlp_blocked,
            engine_version=view.engine_version,
            policy_version=view.policy_version,
            inspected_at=view.inspected_at,
            findings=[
                DlpFinding(
                    detector=f.detector,
                    detector_name=f.detector_name,
                    count_low=f.count_low,
                    count_medium=f.count_medium,
                    count_high=f.count_high,
                    details_visible=f.details_visible,
                )
                for f in view.findings
            ],
        )


# ---- the tenant's policy ----

Hostname = Annotated[str, Field(json_schema_extra={"format": "hostname"})]
_DOMAINS_SCHEMA: Final = {
    "type": "array",
    "maxItems": 500,
    "uniqueItems": True,
    "items": {"type": "string", "format": "hostname"},
}


def _duration(value: timedelta) -> str:
    """An ISO 8601 duration such as `P30D` or `PT12H`, as the contract's examples write them."""
    seconds = int(value.total_seconds())
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes, secs = divmod(rest, 60)
    time = "".join(f"{n}{unit}" for n, unit in ((hours, "H"), (minutes, "M"), (secs, "S")) if n)
    return ("P" + (f"{days}D" if days else "") + (f"T{time}" if time else "")) or "PT0S"


class TenantPolicyOut(BaseModel):
    model_config = ConfigDict(title="TenantPolicy")

    max_expiry: Annotated[str, WithJsonSchema({"type": "string", "format": "duration"})]
    unscannable_policy: UnscannablePolicy
    received_file_retention_days: int = Field(ge=1, le=90)
    allowed_domains: list[Hostname] = Field(max_length=500, json_schema_extra={"uniqueItems": True})
    blocked_domains: list[Hostname] = Field(max_length=500, json_schema_extra={"uniqueItems": True})
    default_locale: Locale
    updated_at: datetime

    @classmethod
    def of(cls, policy: Policy, *, now: datetime) -> TenantPolicyOut:
        return cls(
            max_expiry=_duration(policy.max_expiry),
            unscannable_policy=policy.unscannable_policy,
            received_file_retention_days=policy.received_file_retention_days,
            allowed_domains=list(policy.allowed_domains),  # FR-24 (#217)
            blocked_domains=list(policy.blocked_domains),
            default_locale=policy.default_locale,  # type: ignore[arg-type]
            # A tenant made before revision 0005 has no row, so no change time: now stands in.
            updated_at=policy.updated_at or now,
        )


class TenantPolicyUpdate(BaseModel):
    """The contract's `TenantPolicyUpdate`: only the fields sent are changed."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"minProperties": 1})

    max_expiry: Annotated[
        timedelta | SkipJsonSchema[None], _optional({"type": "string", "format": "duration"})
    ] = None
    unscannable_policy: UnscannablePolicy | SkipJsonSchema[None] = None
    received_file_retention_days: Annotated[
        int | None, _optional({"type": "integer", "minimum": 1, "maximum": 90})
    ] = Field(default=None, ge=1, le=90)
    allowed_domains: Annotated[list[str] | None, _optional(_DOMAINS_SCHEMA)] = Field(
        default=None, max_length=500
    )
    blocked_domains: Annotated[list[str] | None, _optional(_DOMAINS_SCHEMA)] = Field(
        default=None, max_length=500
    )
    default_locale: Locale | SkipJsonSchema[None] = None

    @model_validator(mode="after")
    def _something_to_change(self) -> TenantPolicyUpdate:
        if not self.model_fields_set:
            raise ValueError("send at least one field")
        for name in self.model_fields_set:
            if getattr(self, name) is None:
                raise ValueError(f"{name} can't be null")
        return self

    def change(self) -> PolicyChange:
        return PolicyChange(
            max_expiry=self.max_expiry,
            unscannable_policy=self.unscannable_policy,
            received_file_retention_days=self.received_file_retention_days,
            default_locale=self.default_locale,
            allowed_domains=self.allowed_domains,
            blocked_domains=self.blocked_domains,
        )
