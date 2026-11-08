"""The request and response bodies of the upload-request operations, as the contract defines them
(docs/api/openapi.yaml: `UploadRequestCreate`, `UploadRequest`, `UploadRequestPage` and the
schemas they use; #212).

As in `sft.api.transfer_schemas`, each field is written to produce exactly the contract's schema
(API README 11.1): an optional request field that may not be null is `X | None` with
`WithJsonSchema` giving the contract's schema, so the code can tell "left out" from a value.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, WithJsonSchema

from sft.api.link_schemas import DeliveryStateName
from sft.api.transfer_schemas import EmailAddress, Locale
from sft.service.upload_requests import UploadRequestPage, UploadRequestView

UploadRequestStateName = Literal["open", "revoked", "expired"]
AccessStateName = Literal["invited", "verified", "locked"]


def _optional(schema: dict[str, Any]) -> WithJsonSchema:
    return WithJsonSchema(schema, mode="validation")


# ---- requests ----


class UploadRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    uploader_email: EmailAddress
    locale: Annotated[Locale | None, _optional({"type": "string", "enum": ["en", "ja"]})] = None
    expires_at: Annotated[
        AwareDatetime | None, _optional({"type": "string", "format": "date-time"})
    ] = None
    message: Annotated[str | None, _optional({"type": "string", "maxLength": 2000})] = Field(
        default=None, max_length=2000
    )


# ---- responses ----


class UploadRequestOut(BaseModel):
    model_config = ConfigDict(title="UploadRequest")

    id: UUID
    state: UploadRequestStateName
    created_by: UUID
    created_at: datetime
    uploader_email: EmailAddress
    locale: Locale
    message: str | None
    expires_at: datetime
    revoked_at: datetime | None
    revoked_by: UUID | None
    uploader_access_state: AccessStateName
    delivery_state: DeliveryStateName
    notified_at: datetime | None
    failed_attempts: int = Field(ge=0, le=20)
    locked_at: datetime | None
    file_count: int = Field(ge=0, le=50)
    total_size: int = Field(ge=0)

    @classmethod
    def of(cls, view: UploadRequestView) -> UploadRequestOut:
        return cls(
            id=view.id,
            state=view.state.value,
            created_by=view.created_by,
            created_at=view.created_at,
            uploader_email=view.uploader_email,
            locale=view.locale,  # type: ignore[arg-type] # the table's CHECK allows only these
            message=view.message,
            expires_at=view.expires_at,
            revoked_at=view.revoked_at,
            revoked_by=view.revoked_by,
            uploader_access_state=view.access_state,
            delivery_state=view.delivery_state.value,
            notified_at=view.notified_at,
            failed_attempts=view.failed_attempts,
            locked_at=view.locked_at,
            file_count=view.file_count,
            total_size=view.total_size,
        )


class UploadRequestPageOut(BaseModel):
    model_config = ConfigDict(title="UploadRequestPage")

    items: list[UploadRequestOut]
    next_cursor: str | None

    @classmethod
    def of(cls, page: UploadRequestPage) -> UploadRequestPageOut:
        return cls(
            items=[UploadRequestOut.of(item) for item in page.items], next_cursor=page.next_cursor
        )
