"""The tenant admin's SSO operations of the contract: `getTenantSso`, `updateTenantSso`,
`claimSsoDomain`, `verifySsoDomain` and `deleteSsoDomain` (#231; FR-26; docs/api/openapi.yaml, tag
"Tenant admin").

Routes only parse the request and shape the response; `sft.service.sso` checks the caller and
applies the rules. All are group H (`TENANT_OPERATION`, abuse and rate limits 2.2). The TXT
resolver is the app's (`app.state.txt_resolver`): DNS, or the local stack's and the tests'
stand-in (`SSO_DNS_OVERRIDES`).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic.json_schema import SkipJsonSchema

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database
from sft.api.errors import problem_responses
from sft.api.rate_limits import rate_limit
from sft.core.settings import Settings
from sft.data.database import Database
from sft.data.models import IdpConnection, Role, SsoDomain
from sft.service import sso
from sft.service.caller import Caller
from sft.service.rate_limits.limits import TENANT_OPERATION

PREFIX: Final = "/v1"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)

router = APIRouter(prefix=PREFIX, tags=["Tenant admin"])

Hostname = Annotated[str, Field(json_schema_extra={"format": "hostname"})]


def _now() -> datetime:
    return datetime.now(UTC)


# ---- schemas, as the contract's ----


class TenantSsoConnection(BaseModel):
    id: UUID
    kind: Literal["oidc", "saml"]
    provider_name: str
    issuer: str | None
    status: Literal["active", "inactive"]

    @classmethod
    def of(cls, row: IdpConnection) -> TenantSsoConnection:
        return cls(
            id=row.id,
            kind=row.kind,  # type: ignore[arg-type] # the table's CHECK allows only these
            provider_name=row.provider_name,
            issuer=row.issuer or None,
            status=row.status,  # type: ignore[arg-type]
        )


class SsoGroupRole(BaseModel):
    model_config = ConfigDict(extra="forbid")

    group: str = Field(min_length=1, max_length=256)
    role: Role


class SsoDomainOut(BaseModel):
    model_config = ConfigDict(title="SsoDomain")

    id: UUID
    domain: Hostname
    status: Literal["pending", "verified"]
    txt_record_name: str
    txt_record_value: str
    idp_connection_id: UUID | None
    verified_at: datetime | None
    created_at: datetime

    @classmethod
    def of(cls, row: SsoDomain) -> SsoDomainOut:
        return cls(
            id=row.id,
            domain=row.domain,
            status="pending" if row.verified_at is None else "verified",
            txt_record_name=sso.record_name(row.domain),
            txt_record_value=sso.record_value(row.verification_token),
            idp_connection_id=row.idp_connection_id,
            verified_at=row.verified_at,
            created_at=row.created_at,
        )


class TenantSsoSettings(BaseModel):
    connection: TenantSsoConnection | None
    sso_required: bool
    sso_mfa_confirmed_by: UUID | None
    sso_mfa_confirmed_at: datetime | None
    jit_provisioning: bool
    group_roles: list[SsoGroupRole] = Field(max_length=50)
    domains: list[SsoDomainOut] = Field(max_length=20)

    @classmethod
    def of(cls, view: sso.SsoSettings) -> TenantSsoSettings:
        tenant = view.tenant
        return cls(
            connection=None if view.connection is None else TenantSsoConnection.of(view.connection),
            sso_required=tenant.sso_required,
            sso_mfa_confirmed_by=tenant.sso_mfa_confirmed_by,
            sso_mfa_confirmed_at=tenant.sso_mfa_confirmed_at,
            jit_provisioning=tenant.sso_jit,
            group_roles=[
                SsoGroupRole(group=g.group_name, role=Role(g.role)) for g in view.group_roles
            ],
            domains=[SsoDomainOut.of(d) for d in view.domains],
        )


class TenantSsoSettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", json_schema_extra={"minProperties": 1})

    sso_required: bool | SkipJsonSchema[None] = None
    confirm_idp_mfa: Literal[True] | SkipJsonSchema[None] = None
    jit_provisioning: bool | SkipJsonSchema[None] = None
    group_roles: (
        Annotated[list[SsoGroupRole], Field(max_length=50, json_schema_extra={"uniqueItems": True})]
        | SkipJsonSchema[None]
    ) = None

    @model_validator(mode="after")
    def _something_to_change(self) -> TenantSsoSettingsUpdate:
        if not self.model_fields_set:
            raise ValueError("send at least one field")
        for name in self.model_fields_set:
            if getattr(self, name) is None:
                raise ValueError(f"{name} can't be null")
        return self

    def change(self) -> sso.SsoChange:
        return sso.SsoChange(
            sso_required=self.sso_required,
            confirm_idp_mfa=bool(self.confirm_idp_mfa),
            jit_provisioning=self.jit_provisioning,
            group_roles=None
            if self.group_roles is None
            else [(g.group, g.role) for g in self.group_roles],
        )


class SsoDomainClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: Hostname = Field(max_length=253)


# ---- routes ----


def _resolver(request: Request) -> sso.TxtResolver:
    resolver = getattr(request.app.state, "txt_resolver", None)
    if resolver is None:
        raise RuntimeError("this app was created without settings, so it has no TXT resolver")
    return resolver  # type: ignore[no-any-return]


@router.get(
    "/tenant/sso",
    operation_id="getTenantSso",
    response_model=TenantSsoSettings,
    summary="Get the tenant's single sign-on settings",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 429),
)
async def get_tenant_sso(caller: CallerDep, database: DatabaseDep) -> TenantSsoSettings:
    """The tenant's SSO settings (FR-26)."""
    return TenantSsoSettings.of(await sso.get_settings(database, caller, now=_now()))


@router.patch(
    "/tenant/sso",
    operation_id="updateTenantSso",
    response_model=TenantSsoSettings,
    summary="Change the tenant's single sign-on settings",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 422, 429),
)
async def update_tenant_sso(
    body: TenantSsoSettingsUpdate, request: Request, caller: CallerDep, database: DatabaseDep
) -> TenantSsoSettings:
    """Change the fields sent, audited (FR-26, FR-27)."""
    view = await sso.update_settings(
        database, caller, body.change(), origin=origin_of(request), now=_now()
    )
    return TenantSsoSettings.of(view)


@router.post(
    "/tenant/sso/domains",
    operation_id="claimSsoDomain",
    response_model=SsoDomainOut,
    status_code=201,
    summary="Claim an email domain for single sign-on",
    dependencies=[TENANT_LIMITS],
    responses={
        200: {"model": SsoDomainOut, "description": "The claim as it is."},
        **problem_responses(400, 401, 403, 422, 429),
    },
)
async def claim_sso_domain(
    body: SsoDomainClaim,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
) -> SsoDomainOut:
    """A new claim with its TXT record, or the claim the tenant already has."""
    row, created = await sso.claim_domain(
        database, caller, body.domain, origin=origin_of(request), now=_now()
    )
    if not created:
        response.status_code = 200
    return SsoDomainOut.of(row)


@router.post(
    "/tenant/sso/domains/{sso_domain_id}/verify",
    operation_id="verifySsoDomain",
    response_model=SsoDomainOut,
    summary="Check a claimed domain's DNS TXT record",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 422, 429, 503),
)
async def verify_sso_domain(
    sso_domain_id: UUID, request: Request, caller: CallerDep, database: DatabaseDep
) -> SsoDomainOut:
    """Prove the domain by its TXT record (FR-26, FR-45)."""
    row = await sso.verify_domain(
        database,
        caller,
        sso_domain_id,
        _resolver(request),
        origin=origin_of(request),
        now=_now(),
    )
    return SsoDomainOut.of(row)


@router.delete(
    "/tenant/sso/domains/{sso_domain_id}",
    operation_id="deleteSsoDomain",
    status_code=204,
    response_class=Response,
    summary="Give up a domain",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 404, 429),
)
async def delete_sso_domain(
    sso_domain_id: UUID, request: Request, caller: CallerDep, database: DatabaseDep
) -> Response:
    """Remove the claim, audited."""
    await sso.delete_domain(database, caller, sso_domain_id, origin=origin_of(request), now=_now())
    return Response(status_code=204)


def txt_resolver(settings: Settings | None) -> sso.TxtResolver:
    """DNS, or the stand-in that `SSO_DNS_OVERRIDES` names (local and test only)."""
    if settings is not None and settings.sso_dns_overrides is not None:
        return sso.StaticTxtResolver.from_json(settings.sso_dns_overrides)
    nameservers = (
        ()
        if settings is None or not settings.sso_dns_nameservers
        else (tuple(settings.sso_dns_nameservers.split(",")))
    )
    return sso.DnsTxtResolver(nameservers)


def register(app: FastAPI, settings: Settings | None) -> None:
    """Add the SSO routes, and the TXT resolver they prove domains with."""
    app.state.txt_resolver = txt_resolver(settings)
    app.include_router(router)
