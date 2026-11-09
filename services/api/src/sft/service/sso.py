"""Tenant single sign-on through the customer's identity provider (#231; FR-26; authn and authz
2.4, 2.5; data model 2.1).

**Who does what.** A tenant admin claims and proves the tenant's email domains and sets its SSO
rules (`getTenantSso`, `updateTenantSso`, `claimSsoDomain`, `verifySsoDomain`, `deleteSsoDomain`).
An operator creates the identity provider in both user pools with their own AWS credentials
(`sft.runtime.sso_providers`, no Terraform), then records it with `configureTenantSso`, which
links the tenant's proven domains to it. The API role never manages providers.

**Proving a domain.** A claim gets 128 random bits as 32 URL-safe characters, which the tenant
publishes at `_sft-verification.<domain>` as `sft-domain-verification=<token>`. Verifying reads
that TXT record (`TxtResolver`) and compares in constant time. The token is no secret: DNS
publishes it. A proven domain belongs to one tenant at most (the unique index of revision 0029), so
another tenant's proof of it first is `409 invalid_state` (the claim stays pending); a record
that isn't there yet is `422 validation_failed`. Both are existing codes, each with a `detail`, so
the contract's problem codes stay as they were. Domain text never goes into an
audit event's details (data model 2.5): events name the domain's row.

**Rules.** `sso_required` needs an active connection and the MFA confirmation, because Cognito's
MFA doesn't apply to federated users (authn and authz 9.1). Group roles apply when a sign-in
creates a member (`sft.service.signin`). Every write needs a step-up and the admin role (the
permission registry).

**Trusted domains.** Proven domains are trusted recipient domains in the DLP decision (FR-45,
#219): `sft.data.dlp_decisions.decision_policy` and `sft.service.transfer_dlp` add them.
"""

from __future__ import annotations

import hmac
import json
import logging
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Protocol
from uuid import UUID

import dns.asyncresolver
import dns.exception
import dns.resolver
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import (
    Conflict,
    FieldError,
    NotFound,
    ServiceUnavailable,
    Unprocessable,
    json_pointer,
)
from sft.data import audit, sso, tenants, users
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import IdpConnection, Role, SsoDomain, SsoGroupRole, Tenant, UserStatus
from sft.data.scope import Scope
from sft.service.caller import Caller
from sft.service.domain_rules import DomainError, normalize_domain
from sft.service.operator_auth import Operator
from sft.service.permissions import authorize
from sft.service.transfers import tenant_scope

log = logging.getLogger(__name__)

TXT_PREFIX: Final = "_sft-verification."
TXT_VALUE_PREFIX: Final = "sft-domain-verification="
TOKEN_CHARACTERS: Final = 32
MAX_DOMAINS: Final = 20
MAX_GROUP_ROLES: Final = 50
DNS_TIMEOUT_SECONDS: Final = 5.0
DOMAIN_TARGET: Final = "sso_domain"
SSO_TARGET: Final = "tenant_sso"


class ConnectionKind(StrEnum):
    OIDC = "oidc"
    SAML = "saml"


class ConnectionStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


# ---- DNS ----


class DnsUnavailableError(Exception):
    """DNS didn't answer: `503`, so the admin tries again."""


class TxtResolver(Protocol):
    async def txt(self, name: str) -> tuple[str, ...]:
        """The TXT strings at `name`: empty when there are none; `DnsUnavailableError` when DNS
        can't answer."""
        ...


class DnsTxtResolver:
    """TXT records from DNS, through the system's resolver or the ones named (in AWS, the VPC's)."""

    def __init__(self, nameservers: Sequence[str] = ()) -> None:
        self._nameservers = tuple(nameservers)

    async def txt(self, name: str) -> tuple[str, ...]:
        resolver = dns.asyncresolver.Resolver(configure=not self._nameservers)
        if self._nameservers:
            resolver.nameservers = list(self._nameservers)
        resolver.lifetime = DNS_TIMEOUT_SECONDS
        try:
            answer = await resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return ()
        except dns.exception.DNSException as exc:
            log.warning("dns lookup failed", extra={"error": type(exc).__name__})
            raise DnsUnavailableError from exc
        values = []
        for record in answer:
            strings = getattr(record, "strings", ())
            values.append(b"".join(strings).decode("utf-8", "replace"))
        return tuple(values)


class StaticTxtResolver:
    """TXT records from a JSON object, for the local stack and the tests (`SSO_DNS_OVERRIDES`,
    which settings refuse outside ENVIRONMENT=local or test)."""

    def __init__(self, records: Mapping[str, Sequence[str]]) -> None:
        self._records = {name.lower().rstrip("."): tuple(v) for name, v in records.items()}

    @classmethod
    def from_json(cls, raw: str) -> StaticTxtResolver:
        loaded = json.loads(raw)
        if not isinstance(loaded, dict) or not all(
            isinstance(v, list) and all(isinstance(s, str) for s in v) for v in loaded.values()
        ):
            raise ValueError("SSO_DNS_OVERRIDES is a JSON object of names to lists of strings")
        return cls(loaded)

    async def txt(self, name: str) -> tuple[str, ...]:
        return self._records.get(name.lower().rstrip("."), ())


def record_name(domain: str) -> str:
    return f"{TXT_PREFIX}{domain}"


def record_value(token: str) -> str:
    return f"{TXT_VALUE_PREFIX}{token}"


# ---- views ----


@dataclass(frozen=True, slots=True)
class SsoSettings:
    """What `getTenantSso` shows."""

    tenant: Tenant
    connection: IdpConnection | None
    group_roles: Sequence[SsoGroupRole]
    domains: Sequence[SsoDomain]


@dataclass(frozen=True, slots=True)
class SsoChange:
    """The fields of `TenantSsoSettingsUpdate` that were sent."""

    sso_required: bool | None = None
    confirm_idp_mfa: bool = False
    jit_provisioning: bool | None = None
    group_roles: Sequence[tuple[str, Role]] | None = None


def _invalid(field: str, detail: str) -> Unprocessable:
    return Unprocessable(
        "validation_failed", detail, errors=[FieldError(detail, pointer=json_pointer(field))]
    )


async def _read(session: AsyncSession, tenant_id: UUID) -> SsoSettings:
    tenant = await tenants.get_tenant(session, tenant_id)
    if tenant is None:
        raise NotFound()
    return SsoSettings(
        tenant=tenant,
        connection=await sso.get_connection(session),
        group_roles=await sso.group_roles(session),
        domains=await sso.list_domains(session),
    )


# ---- the tenant admin's operations ----


async def get_settings(database: Database, caller: Caller, *, now: datetime) -> SsoSettings:
    """`getTenantSso`."""
    authorize(caller, "getTenantSso", now=now)
    scope = tenant_scope(caller)
    assert scope.tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        return await _read(session, scope.tenant_id)


async def update_settings(
    database: Database, caller: Caller, change: SsoChange, *, origin: Origin, now: datetime
) -> SsoSettings:
    """`updateTenantSso`: the fields sent, audited with flags and counts."""
    authorize(caller, "updateTenantSso", now=now)
    mapping = None if change.group_roles is None else _group_roles(change.group_roles)
    scope = tenant_scope(caller)
    assert scope.tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    assert caller.user_id is not None  # noqa: S101 - and a member's caller
    async with database.transaction(scope) as session:
        before = await _read(session, scope.tenant_id)
        confirmed = before.tenant.sso_mfa_confirmed_by is not None or change.confirm_idp_mfa
        if change.sso_required:
            connection = before.connection
            if connection is None or connection.status != ConnectionStatus.ACTIVE:
                raise _invalid("sso_required", "SSO can be required only with an active provider.")
            if not confirmed:
                raise _invalid(
                    "sso_required",
                    "Confirm that the identity provider enforces MFA before requiring SSO.",
                )
        await sso.update_tenant_sso(
            session,
            sso_required=change.sso_required,
            mfa_confirmed_by=caller.user_id if change.confirm_idp_mfa else None,
            jit=change.jit_provisioning,
        )
        details: dict[str, audit.Detail] = {}
        if change.sso_required is not None:
            details["sso_required"] = change.sso_required
        if change.jit_provisioning is not None:
            details["jit_provisioning"] = change.jit_provisioning
        if change.confirm_idp_mfa:
            details["idp_mfa_confirmed"] = True
        if mapping is not None:
            removed, added = await sso.replace_group_roles(session, mapping)
            details["group_roles_before"] = removed
            details["group_roles_count"] = added
            details["group_roles_admin"] = sum(1 for _, role in mapping if role is Role.ADMIN)
        await audit.record(
            session,
            action="tenant_sso.updated",
            actor=caller.actor(),
            target=Target(SSO_TARGET, scope.tenant_id),
            origin=origin,
            details=details,
        )
        return await _read(session, scope.tenant_id)


def _group_roles(items: Sequence[tuple[str, Role]]) -> tuple[tuple[str, Role], ...]:
    if len(items) > MAX_GROUP_ROLES:
        raise _invalid("group_roles", f"At most {MAX_GROUP_ROLES} groups.")
    seen: set[str] = set()
    out = []
    for index, (group, role) in enumerate(items):
        name = group.strip()
        if not 1 <= len(name) <= 256:
            raise _invalid(f"group_roles/{index}/group", "A group name is 1 to 256 characters.")
        if name in seen:
            raise _invalid(f"group_roles/{index}/group", "Each group appears once.")
        seen.add(name)
        out.append((name, Role(role)))
    return tuple(out)


async def claim_domain(
    database: Database, caller: Caller, raw_domain: str, *, origin: Origin, now: datetime
) -> tuple[SsoDomain, bool]:
    """`claimSsoDomain`: the claim and whether it is new."""
    authorize(caller, "claimSsoDomain", now=now)
    try:
        domain = normalize_domain(raw_domain)
    except DomainError as exc:
        raise _invalid("domain", str(exc)) from exc
    scope = tenant_scope(caller)
    assert caller.user_id is not None  # noqa: S101 - a member's caller
    async with database.transaction(scope) as session:
        if await sso.count_domains(session) >= MAX_DOMAINS:
            # A claim already made is returned below, even at the limit.
            existing = [d for d in await sso.list_domains(session) if d.domain == domain]
            if existing:
                return existing[0], False
            raise _invalid("domain", f"A tenant holds at most {MAX_DOMAINS} domains.")
        row, created = await sso.claim_domain(
            session,
            domain=domain,
            token=secrets.token_urlsafe(24)[:TOKEN_CHARACTERS],
            created_by=caller.user_id,
        )
        if created:
            await audit.record(
                session,
                action="sso_domain.claimed",
                actor=caller.actor(),
                target=Target(DOMAIN_TARGET, row.id),
                origin=origin,
            )
        return row, created


async def verify_domain(
    database: Database,
    caller: Caller,
    domain_id: UUID,
    resolver: TxtResolver,
    *,
    origin: Origin,
    now: datetime,
) -> SsoDomain:
    """`verifySsoDomain`: look the TXT record up, and prove the domain if it holds the token."""
    authorize(caller, "verifySsoDomain", now=now)
    scope = tenant_scope(caller)
    async with database.transaction(scope) as session:
        row = await sso.get_domain(session, domain_id)
    if row is None:
        raise NotFound()
    if row.verified_at is not None:
        return row
    try:
        values = await resolver.txt(record_name(row.domain))
    except DnsUnavailableError as exc:
        raise ServiceUnavailable(10, "DNS didn't answer. Try again shortly.") from exc
    expected = record_value(row.verification_token)
    if not any(hmac.compare_digest(v.strip().encode(), expected.encode()) for v in values):
        detail = f"No TXT record at {record_name(row.domain)} holds the claim's value yet."
        raise Unprocessable("validation_failed", detail, errors=[FieldError(detail)])
    try:
        async with database.transaction(scope) as session:
            locked = await sso.get_domain(session, domain_id, for_update=True)
            if locked is None:
                raise NotFound()
            if locked.verified_at is not None:
                return locked
            proven = await sso.mark_verified(session, domain_id)
            await audit.record(
                session,
                action="sso_domain.verified",
                actor=caller.actor(),
                target=Target(DOMAIN_TARGET, domain_id),
                origin=origin,
            )
            return proven
    except IntegrityError as exc:
        # The unique index on proven domains: another tenant proved it first.
        raise Conflict(
            "invalid_state",
            "Another organisation has proven this domain, so this claim stays pending.",
            current_state="pending",
        ) from exc


async def delete_domain(
    database: Database, caller: Caller, domain_id: UUID, *, origin: Origin, now: datetime
) -> None:
    """`deleteSsoDomain`."""
    authorize(caller, "deleteSsoDomain", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        row = await sso.get_domain(session, domain_id, for_update=True)
        if row is None or not await sso.delete_domain(session, domain_id):
            raise NotFound()
        await audit.record(
            session,
            action="sso_domain.deleted",
            actor=caller.actor(),
            target=Target(DOMAIN_TARGET, domain_id),
            origin=origin,
            details={"was_verified": row.verified_at is not None},
        )


# ---- the operator's record ----


@dataclass(frozen=True, slots=True)
class SsoConfiguration:
    """`TenantSsoUpdate`, as the operator CLI sends it."""

    kind: ConnectionKind
    provider_name: str
    issuer: str | None
    status: ConnectionStatus
    domains: Sequence[str]
    sso_required: bool
    sso_mfa_confirmed_by: UUID | None


@dataclass(frozen=True, slots=True)
class RecordedSso:
    tenant: Tenant
    connection: IdpConnection
    domains: Sequence[SsoDomain]


def provider_name_for(tenant_id: UUID) -> str:
    """A tenant's provider name in both pools: its ID without dashes (32 characters)."""
    return tenant_id.hex


async def configure_tenant_sso(
    database: Database,
    operator: Operator,
    tenant_id: UUID,
    config: SsoConfiguration,
    *,
    origin: Origin,
) -> RecordedSso:
    """`configureTenantSso`: record the connection and link the tenant's proven domains to it."""
    authorize(operator.caller, "configureTenantSso", now=datetime.now(UTC))
    if config.provider_name != provider_name_for(tenant_id):
        raise _invalid("provider_name", "The provider name is the tenant ID without dashes.")
    domains: list[str] = []
    for index, raw in enumerate(config.domains):
        try:
            domains.append(normalize_domain(raw))
        except DomainError as exc:
            raise _invalid(f"domains/{index}", str(exc)) from exc
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        tenant = await tenants.get_tenant(session, tenant_id)
        if tenant is None:
            raise NotFound()
        proven = {d.domain for d in await sso.list_domains(session) if d.verified_at is not None}
        for index, domain in enumerate(domains):
            if domain not in proven:
                raise _invalid(f"domains/{index}", "The tenant hasn't proven this domain.")
        confirmer = config.sso_mfa_confirmed_by
        if confirmer is not None:
            user = await users.get_user(session, confirmer)
            if user is None or user.role != Role.ADMIN or user.status != UserStatus.ACTIVE:
                raise _invalid("sso_mfa_confirmed_by", "Not an active admin of the tenant.")
        if config.status is ConnectionStatus.ACTIVE and (
            confirmer is None and tenant.sso_mfa_confirmed_by is None
        ):
            raise _invalid(
                "sso_mfa_confirmed_by", "An active connection needs an admin's MFA confirmation."
            )
        connection, changed = await sso.put_connection(
            session,
            kind=config.kind.value,
            provider_name=config.provider_name,
            issuer=config.issuer or "",
            status=config.status.value,
        )
        linked, unlinked = await sso.link_domains(session, connection.id, domains)
        mfa_change = confirmer is not None and confirmer != tenant.sso_mfa_confirmed_by
        required_change = config.sso_required != tenant.sso_required
        if mfa_change or required_change:
            tenant = await sso.update_tenant_sso(
                session,
                sso_required=config.sso_required if required_change else None,
                mfa_confirmed_by=confirmer if mfa_change else None,
            )
        if changed or linked or unlinked or mfa_change or required_change:
            await audit.record(
                session,
                action="tenant_sso.configured",
                actor=operator.actor,
                target=Target(SSO_TARGET, tenant_id),
                origin=origin,
                details={
                    **operator.details(),
                    "idp_connection_id": connection.id,
                    "kind": config.kind,
                    "status": config.status,
                    "domains_linked": linked,
                    "domains_unlinked": unlinked,
                    "sso_required": config.sso_required,
                },
            )
        recorded = RecordedSso(
            tenant=tenant,
            connection=connection,
            domains=[d for d in await sso.list_domains(session) if d.domain in set(domains)],
        )
    await _platform_event(database, operator, "tenant_sso.configured", origin, tenant_id)
    return recorded


async def _platform_event(
    database: Database, operator: Operator, action: str, origin: Origin, tenant_id: UUID
) -> None:
    """The platform record of the operator's call. The change and its tenant record stand if it
    fails, and a retry with the same configuration writes it again: `503`."""
    try:
        async with database.transaction(Scope.platform()) as session:
            await audit.record(
                session,
                action=action,
                actor=operator.actor,
                target=Target("tenant", tenant_id),
                origin=origin,
                details=operator.details(),
            )
    except (SQLAlchemyError, OSError) as exc:
        log.exception("the platform audit event of an operator call wasn't written")
        raise ServiceUnavailable(5, "The change is recorded; retry to complete it.") from exc


__all__ = [
    "ConnectionKind",
    "ConnectionStatus",
    "DnsTxtResolver",
    "DnsUnavailableError",
    "RecordedSso",
    "SsoChange",
    "SsoConfiguration",
    "SsoSettings",
    "StaticTxtResolver",
    "TxtResolver",
    "claim_domain",
    "configure_tenant_sso",
    "delete_domain",
    "get_settings",
    "provider_name_for",
    "record_name",
    "record_value",
    "update_settings",
    "verify_domain",
]
