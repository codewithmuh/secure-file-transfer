"""The operator API's request and response bodies, as the contract defines them (docs/api).

The generated-spec check compares the schemas FastAPI builds from these with the contract's, so a
constraint here is the contract's constraint (docs/api/README.md 11.1).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

from sft.core.addresses import is_plain_address
from sft.data.models import Tenant as TenantRow
from sft.data.models import User as UserRow

TenantStatus = Literal["active", "suspended"]
Locale = Literal["en", "ja"]
Role = Literal["admin", "member"]
UserStatus = Literal["invited", "active", "deactivated"]


def _email_shape(value: str) -> str:
    """The rule `inviteUser` and the mail adapter apply (`sft.core.addresses`), so the first admin's
    invitation can always be sent; and the contract's `format: email`: a local part of at most 64
    characters, and a domain with a dot. Delivery is the real check."""
    local, _, domain = value.rpartition("@")
    if not (is_plain_address(value) and len(local) <= 64 and "." in domain.strip(".")):
        raise ValueError("not an email address")
    return value


EmailAddress = Annotated[
    str, Field(max_length=254, json_schema_extra={"format": "email"}), AfterValidator(_email_shape)
]


class TenantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=200)]
    first_admin_email: EmailAddress
    recovery_contact: Annotated[str, Field(min_length=1, max_length=320)]
    default_locale: Locale = "en"


class Tenant(BaseModel):
    id: UUID
    name: str
    status: TenantStatus
    created_at: datetime

    @classmethod
    def of(cls, row: TenantRow) -> Tenant:
        return cls(id=row.id, name=row.name, status=row.status, created_at=row.created_at)  # type: ignore[arg-type]


class User(BaseModel):
    id: UUID
    email: Annotated[str, Field(max_length=254, json_schema_extra={"format": "email"})]
    role: Role
    status: UserStatus
    sso_fallback: bool
    dlp_approver: bool
    created_at: datetime

    @classmethod
    def of(cls, row: UserRow) -> User:
        return cls(
            id=row.id,
            email=row.email,
            role=row.role,  # type: ignore[arg-type]
            status=row.status,  # type: ignore[arg-type]
            sso_fallback=row.sso_fallback,
            dlp_approver=row.dlp_approver,
            created_at=row.created_at,
        )


class TenantCreated(BaseModel):
    tenant: Tenant
    first_admin: User


class TenantPage(BaseModel):
    items: list[Tenant]
    next_cursor: str | None


class SignedStsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    headers: Annotated[dict[str, Annotated[str, Field(max_length=4096)]], Field(max_length=20)]
    # sft.service.operator_auth.GET_CALLER_IDENTITY; a test checks they agree.
    body: Literal["Action=GetCallerIdentity&Version=2011-06-15"]


class OperatorTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sts_request: SignedStsRequest


class OperatorToken(BaseModel):
    token: Annotated[str, Field(min_length=43, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
    expires_at: datetime
    aws_account_id: Annotated[str, Field(pattern=r"^[0-9]{12}$")]
    operator_name: Annotated[str, Field(max_length=128)]
