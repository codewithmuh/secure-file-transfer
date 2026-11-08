"""The request and response bodies of the link, session and recipient-status operations, as the
contract defines them (docs/api/openapi.yaml: `LinkTokenRequest`, `LinkSessionCreate`,
`LinkResolution`, `VerificationCodeRequested`, `LinkSession`, `SessionFileList`,
`RecipientStatusList`, `RecipientStatus` and the schemas they use; #178, #179).

As in `sft.api.transfer_schemas`, each field is written to produce exactly the contract's schema
(API README 11.1). A response field that is optional but never null is
`X | SkipJsonSchema[None]`, set only when it has a value, and the routes answer with
`response_model_exclude_unset`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from pydantic.json_schema import SkipJsonSchema

from sft.api.auth import CsrfToken
from sft.api.transfer_schemas import EmailAddress, FileStateName, Locale, UploadPlan
from sft.data.recipients import RecipientStatus as RecipientStatusRow
from sft.service.links import Resolution, SessionFile, SessionView

LinkToken = Annotated[str, Field(min_length=22, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
Code = Annotated[str, Field(pattern=r"^[0-9]{6,10}$")]
LinkKind = Literal["transfer", "upload_request"]
DeliveryStateName = Literal["pending", "queued", "sent", "bounced", "suppressed"]


# ---- requests ----


class LinkTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: LinkToken


class LinkSessionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: LinkToken
    code: Code


# ---- responses ----


class LinkResolution(BaseModel):
    kind: LinkKind
    access_state: Literal["verification_required", "verified", "locked"]
    link_session_id: UUID | SkipJsonSchema[None] = None
    locale: Locale

    @classmethod
    def of(cls, resolution: Resolution) -> LinkResolution:
        out = cls(
            kind=resolution.kind,
            access_state=resolution.access_state,
            locale=resolution.locale,  # type: ignore[arg-type]
        )
        if resolution.link_session_id is not None:
            out.link_session_id = resolution.link_session_id
        return out


class VerificationCodeRequested(BaseModel):
    code_valid_for_seconds: int = Field(ge=1, le=600)
    max_attempts: int = Field(ge=1, le=5)


class LinkSessionTransfer(BaseModel):
    tenant_name: str
    sender_email: EmailAddress
    message: str | None
    expires_at: datetime
    download_limit: int | None = Field(ge=1, le=100)


class LinkSessionUploadRequest(BaseModel):
    """An upload request's session (#212): the request, its limits and what has arrived."""

    tenant_name: str
    requester_email: EmailAddress
    message: str | None
    expires_at: datetime
    max_files: int = Field(ge=1, le=50)
    max_file_size: int = Field(ge=1, le=5_000_000_000)
    max_total_size: int = Field(ge=1, le=20_000_000_000)
    files_received: int = Field(ge=0, le=50)
    bytes_received: int = Field(ge=0)


class LinkSession(BaseModel):
    id: UUID
    csrf_token: CsrfToken
    kind: LinkKind
    email: EmailAddress
    locale: Locale
    expires_at: datetime
    transfer: LinkSessionTransfer | SkipJsonSchema[None] = None
    upload_request: LinkSessionUploadRequest | SkipJsonSchema[None] = None

    @classmethod
    def of(cls, view: SessionView) -> LinkSession:
        out = cls(
            id=view.id,
            csrf_token=view.csrf_token,
            kind=view.kind,
            email=view.email,
            locale=view.locale,  # type: ignore[arg-type] # the table's CHECK allows only these
            expires_at=view.expires_at,
        )
        # Exactly one of the two, set so it isn't left out (`response_model_exclude_unset`).
        if view.transfer is not None:
            part = view.transfer
            out.transfer = LinkSessionTransfer(
                tenant_name=part.tenant_name,
                sender_email=part.sender_email,
                message=part.message,
                expires_at=part.expires_at,
                download_limit=part.download_limit,
            )
        if view.upload_request is not None:
            asked = view.upload_request
            out.upload_request = LinkSessionUploadRequest(
                tenant_name=asked.tenant_name,
                requester_email=asked.requester_email,
                message=asked.message,
                expires_at=asked.expires_at,
                max_files=asked.max_files,
                max_file_size=asked.max_file_size,
                max_total_size=asked.max_total_size,
                files_received=asked.files_received,
                bytes_received=asked.bytes_received,
            )
        return out


class SessionFileOut(BaseModel):
    model_config = ConfigDict(title="SessionFile")

    id: UUID
    display_name: str
    content_type: str
    size: int = Field(ge=1, le=5_000_000_000)
    state: FileStateName
    warning: Literal["unscannable"] | SkipJsonSchema[None] = None
    download_limit: int | None = Field(default=None, ge=1, le=100)
    downloads_used: Annotated[int, Field(ge=0)] | SkipJsonSchema[None] = None
    upload: UploadPlan | SkipJsonSchema[None] = None
    blocked: bool | SkipJsonSchema[None] = None

    @classmethod
    def of(cls, file: SessionFile) -> SessionFileOut:
        if file.uploader:
            # An uploader's file (#213): its state, and its plan while uploading; no download
            # count, which is a recipient's. An unscannable file the policy allowed carries the
            # warning, which the uploader's page words as accepted (#229).
            mine = cls(
                id=file.id,
                display_name=file.display_name,
                content_type=file.content_type,
                size=file.size,
                state=file.state.value,
                blocked=file.blocked,
            )
            if file.unscannable:
                mine.warning = "unscannable"
            if file.state.value == "uploading":
                mine.upload = UploadPlan(part_size=file.part_size, part_count=file.part_count)
            return mine
        out = cls(
            id=file.id,
            display_name=file.display_name,
            content_type=file.content_type,
            size=file.size,
            state=file.state.value,
            download_limit=file.download_limit,
            downloads_used=file.downloads_used,
        )
        if file.unscannable:
            out.warning = "unscannable"
        return out


class SessionFileList(BaseModel):
    items: list[SessionFileOut] = Field(max_length=50)


class RecipientDownload(BaseModel):
    file_id: UUID
    count: int = Field(ge=1)
    first_downloaded_at: datetime
    last_downloaded_at: datetime


class RecipientStatus(BaseModel):
    id: UUID
    email: EmailAddress
    locale: Locale
    access_state: Literal["invited", "verified", "locked"]
    delivery_state: DeliveryStateName
    notified_at: datetime | None
    first_verified_at: datetime | None
    last_verified_at: datetime | None
    failed_attempts: int = Field(ge=0, le=20)
    locked_at: datetime | None
    downloads: list[RecipientDownload]

    @classmethod
    def of(cls, row: RecipientStatusRow) -> RecipientStatus:
        access: Literal["invited", "verified", "locked"]
        if row.locked_at is not None:
            access = "locked"
        elif row.verified:
            access = "verified"
        else:
            access = "invited"
        return cls(
            id=row.id,
            email=row.email,
            locale=row.locale,  # type: ignore[arg-type]
            access_state=access,
            delivery_state=row.delivery_state.value,
            notified_at=row.notified_at,
            first_verified_at=row.first_verified_at,
            last_verified_at=row.last_verified_at,
            failed_attempts=row.failed_attempts,
            locked_at=row.locked_at,
            downloads=[
                RecipientDownload(
                    file_id=d.file_id,
                    count=d.count,
                    first_downloaded_at=d.first_downloaded_at,
                    last_downloaded_at=d.last_downloaded_at,
                )
                for d in row.downloads
            ],
        )


class RecipientStatusList(BaseModel):
    items: list[RecipientStatus] = Field(max_length=50)
