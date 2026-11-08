"""The operator API's request and response bodies, as the contract defines them (docs/api).

The generated-spec check compares the schemas FastAPI builds from these with the contract's, so a
constraint here is the contract's constraint (docs/api/README.md 11.1).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field
from pydantic.json_schema import SkipJsonSchema

from sft.core.addresses import is_plain_address
from sft.data.models import BreakGlassGrant
from sft.data.models import Tenant as TenantRow
from sft.data.models import User as UserRow
from sft.service.sso import RecordedSso

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


# ---- tenant SSO (#231) ----

Hostname = Annotated[str, Field(json_schema_extra={"format": "hostname"})]


class TenantSsoUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["oidc", "saml"]
    provider_name: Annotated[str, Field(min_length=1, max_length=32)]
    issuer: Annotated[str, Field(max_length=1024)] | SkipJsonSchema[None] = None
    status: Literal["active", "inactive"]
    domains: Annotated[
        list[Hostname], Field(min_length=1, max_length=20, json_schema_extra={"uniqueItems": True})
    ]
    sso_required: bool
    sso_mfa_confirmed_by: UUID | SkipJsonSchema[None] = None


class TenantSsoDomain(BaseModel):
    domain: Hostname
    verified_at: datetime


class TenantSso(BaseModel):
    tenant_id: UUID
    idp_connection_id: UUID
    kind: Literal["oidc", "saml"]
    provider_name: str
    issuer: str | None
    status: Literal["active", "inactive"]
    domains: Annotated[list[TenantSsoDomain], Field(max_length=20)]
    sso_required: bool
    sso_mfa_confirmed_by: UUID | None
    sso_mfa_confirmed_at: datetime | None
    updated_at: datetime

    @classmethod
    def of(cls, recorded: RecordedSso) -> TenantSso:
        tenant, connection = recorded.tenant, recorded.connection
        return cls(
            tenant_id=tenant.id,
            idp_connection_id=connection.id,
            kind=connection.kind,  # type: ignore[arg-type] # the table's CHECK allows only these
            provider_name=connection.provider_name,
            issuer=connection.issuer or None,
            status=connection.status,  # type: ignore[arg-type]
            domains=[
                TenantSsoDomain(domain=d.domain, verified_at=d.verified_at)
                for d in recorded.domains
                if d.verified_at is not None
            ],
            sso_required=tenant.sso_required,
            sso_mfa_confirmed_by=tenant.sso_mfa_confirmed_by,
            sso_mfa_confirmed_at=tenant.sso_mfa_confirmed_at,
            updated_at=max(tenant.updated_at, connection.updated_at),
        )


# ---- break-glass (#232) ----

BreakGlassState = Literal["requested", "active", "ended", "expired", "lapsed", "withdrawn"]


class BreakGlassRequestCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: Annotated[str, Field(min_length=1, max_length=64)]
    reason: Annotated[str, Field(min_length=1, max_length=1000)]
    tenant_ids: Annotated[
        list[UUID], Field(min_length=1, max_length=100, json_schema_extra={"uniqueItems": True})
    ]
    duration_minutes: Annotated[int, Field(ge=1, le=60)]


class BreakGlassRequest(BaseModel):
    id: UUID
    incident_id: str
    reason: str
    tenant_ids: list[UUID]
    duration_minutes: int
    state: BreakGlassState
    requester: str
    approver: str | None
    self_approved: bool
    requested_at: datetime
    approved_at: datetime | None
    starts_at: datetime | None
    ends_at: datetime | None
    ended_at: datetime | None
    ended_by: str | None

    @classmethod
    def of(cls, row: BreakGlassGrant) -> BreakGlassRequest:
        return cls(
            id=row.id,
            incident_id=row.incident_id,
            reason=row.reason,
            tenant_ids=list(row.tenant_ids),
            duration_minutes=row.duration_minutes,
            state=row.state,  # type: ignore[arg-type] # the table's CHECK allows only these
            requester=row.requester,
            approver=row.approver,
            self_approved=row.self_approved,
            requested_at=row.requested_at,
            approved_at=row.approved_at,
            starts_at=row.starts_at,
            ends_at=row.ends_at,
            ended_at=row.ended_at,
            ended_by=row.ended_by,
        )


class BreakGlassRequestList(BaseModel):
    items: Annotated[list[BreakGlassRequest], Field(max_length=100)]
