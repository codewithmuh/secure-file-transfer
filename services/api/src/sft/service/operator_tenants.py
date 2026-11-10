"""Tenant provisioning by a platform operator (FR-34): create, list, get and suspend.

Every call is audited as a platform event, and a call that acts on a tenant in that tenant's audit
log too (authn and authz 8.2), with actor type `operator`, the operator session's ID and the
operator's Identity Center user name.

The two records are written in turn. A tenant's events are written in its scope and platform
events in platform scope, and a transaction runs in one scope (ADR-0020). So a change commits in
the tenant's scope with the tenant's event, which the database requires (`audit_required`); then
the platform event follows in a transaction of its own. If that second write fails, the change
stands, with its record in the tenant's log, and the error is logged:

- `suspendTenant` answers `503`. A retry is safe: it finds the tenant suspended, changes nothing
  and writes the platform event.
- `createTenant` answers `201` with the tenant anyway. The tenant's own log holds the record;
  `CreatedTenant.platform_recorded` is False, and the operator API counts the miss in a metric
  that alerts. A retry with the same `Idempotency-Key` gets the first tenant back, with no second
  tenant, invitation or email (#160, `sft.service.idempotency`); without a key it makes a second
  tenant, so an operator always sends one.

Reads go through the tenant directory (`sft.data.tenants`), in platform scope: the tenant rows
only, never a tenant's users, transfers, files or audit log.

Each function checks the operator against the permission registry first (`authorize`, authn and
authz 6.1), as the member operations do. The operator app resolves only operator tokens, so the
check passes; it keeps the registry the one place that says who may call an operation.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from sft.core.errors import Conflict, NotFound, ServiceUnavailable
from sft.core.ids import uuid7
from sft.data import audit, dlp_policy, member_sessions, tenants
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import Role, Tenant, User
from sft.data.scope import Scope
from sft.data.users import UserExistsError, create_invitation, list_users
from sft.service.idempotency import OperatorKey, operator_claim, operator_replay
from sft.service.members import decode_cursor, encode_cursor
from sft.service.operator_auth import Operator
from sft.service.permissions import authorize
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import CREATE_TENANT

log = logging.getLogger(__name__)

TARGET: Final = "tenant"


class TenantStatus(StrEnum):
    ACTIVE = tenants.ACTIVE
    SUSPENDED = tenants.SUSPENDED


@dataclass(frozen=True, slots=True)
class NewTenant:
    name: str
    first_admin_email: str
    recovery_contact: str
    default_locale: str = "en"


@dataclass(frozen=True, slots=True)
class CreatedTenant:
    tenant: Tenant
    first_admin: User
    platform_recorded: bool = True
    """False when the platform audit event failed after the commit (the module docstring)."""
    replayed: bool = False
    """A retry with the first request's `Idempotency-Key`: nothing was made this time."""


@dataclass(frozen=True, slots=True)
class TenantPage:
    items: Sequence[Tenant]
    next_cursor: str | None


async def platform_event(
    database: Database,
    operator: Operator,
    action: str,
    origin: Origin,
    tenant_id: UUID | None = None,
    *,
    retry_safe: bool = True,
) -> bool:
    """The platform record of an operator call; whether it was written.

    A failure is logged. After a change whose retry is safe it is a `503`, so the operator retries;
    with `retry_safe=False` (a creation) it returns False instead, and the caller answers success.
    """
    target = None if tenant_id is None else Target(TARGET, tenant_id)
    try:
        async with database.transaction(Scope.platform()) as session:
            await audit.record(
                session,
                action=action,
                actor=operator.actor,
                target=target,
                origin=origin,
                details=operator.details(),
            )
    except (SQLAlchemyError, OSError):
        log.exception(
            "the platform audit event of an operator call wasn't written",
            extra={"action": action, "tenant_id": str(tenant_id) if tenant_id else None},
        )
        if not retry_safe:
            return False
        raise ServiceUnavailable(
            retry_after=5, detail="The change was made; its platform record wasn't. Retry."
        ) from None
    return True


async def create_tenant(
    database: Database,
    operator: Operator,
    new: NewTenant,
    origin: Origin,
    *,
    limiter: RateLimiter,
    key: OperatorKey | None = None,
) -> CreatedTenant:
    """`createTenant`: the tenant, its policy, its first admin's invitation and its default DLP
    policy, in one commit, with the operator's `Idempotency-Key` if they sent one (`key`): a
    retry gets the first tenant and its first admin as they are now.

    The invitation writes its own audit event and its email's outbox message (`MEMBER_INVITED`).
    The operator's limit (abuse and rate limits 2.2, J: 30 new tenants an hour) counts only a
    tenant that is made: inside the transaction, after the writes, so a refusal writes nothing.
    The member invitation limits of group G need no check here: the tenant is new, and so is the
    address in it.
    """
    authorize(operator.caller, "createTenant", now=datetime.now(UTC))
    replay = await operator_replay(database, key, resource_type=TARGET)
    if replay is not None:
        return await _created(database, replay.resource_id)
    tenant_id = uuid7()
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        tenant = await tenants.insert_tenant(
            session,
            name=new.name,
            recovery_contact=new.recovery_contact,
            default_locale=new.default_locale,
        )
        if tenant is None:  # pragma: no cover - a fresh UUIDv7 is never taken
            raise RuntimeError("the new tenant's ID is taken")
        # The key's row names the tenant, so it follows the tenant's row; before any other work.
        await operator_claim(session, key, status=201, resource_type=TARGET, resource_id=tenant_id)
        await audit.record(
            session,
            action="tenant.created",
            actor=operator.actor,
            target=Target(TARGET, tenant_id),
            origin=origin,
            details=operator.details(),
        )
        try:
            first_admin = await create_invitation(
                session,
                email=new.first_admin_email,
                role=Role.ADMIN,
                actor=operator.actor,
                origin=origin,
            )
        except UserExistsError:  # pragma: no cover - the tenant was made in this transaction
            raise Conflict("user_exists") from None
        # The default DLP policy of detectors 6 at version 1, its rules made by the first admin
        # and named in the tenant's language (#218). The tenant's event above covers it.
        await dlp_policy.insert_default_policy(
            session, created_by=first_admin.id, locale=new.default_locale
        )
        await limiter.check(CREATE_TENANT, operator.rate_limit_keys())
    recorded = await platform_event(
        database, operator, "tenant.created", origin, tenant_id, retry_safe=False
    )
    return CreatedTenant(tenant, first_admin, platform_recorded=recorded)


async def _created(database: Database, tenant_id: UUID) -> CreatedTenant:
    """A replayed `createTenant`: the tenant and its first admin, the tenant's oldest user, as
    they are now. Nothing is written or audited again, as for `inviteUser`."""
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        tenant = await tenants.get_tenant(session, tenant_id)
        oldest = await list_users(session, limit=1)
    if tenant is None or not oldest:  # pragma: no cover - a tenant is never deleted with its key
        raise NotFound()
    return CreatedTenant(tenant, oldest[0], replayed=True)


async def get_tenant(
    database: Database, operator: Operator, tenant_id: UUID, origin: Origin
) -> Tenant:
    """`getTenant`, from the directory; `404` for a tenant that doesn't exist."""
    authorize(operator.caller, "getTenant", now=datetime.now(UTC))
    async with database.transaction(Scope.platform()) as session:
        tenant = await tenants.directory_tenant(session, tenant_id)
        if tenant is None:
            raise NotFound()
        await audit.record(
            session,
            action="tenant.read",
            actor=operator.actor,
            target=Target(TARGET, tenant_id),
            origin=origin,
            details=operator.details(),
        )
    return tenant


async def list_tenants(
    database: Database,
    operator: Operator,
    origin: Origin,
    *,
    status: TenantStatus | None = None,
    cursor: str | None = None,
    limit: int = 25,
) -> TenantPage:
    """`listTenants`: newest first, a page at a time, with the member lists' opaque cursor."""
    authorize(operator.caller, "listTenants", now=datetime.now(UTC))
    before = None if cursor is None else decode_cursor(cursor)
    async with database.transaction(Scope.platform()) as session:
        rows = await tenants.list_directory(
            session,
            limit=limit + 1,
            status=None if status is None else status.value,
            before=before,
        )
        await audit.record(
            session,
            action="tenant.listed",
            actor=operator.actor,
            origin=origin,
            details={**operator.details(), "status": status, "count": min(len(rows), limit)},
        )
    page = rows[:limit]
    more = len(rows) > limit
    return TenantPage(page, encode_cursor(page[-1].id) if more else None)


async def suspend_tenant(
    database: Database, operator: Operator, tenant_id: UUID, origin: Origin
) -> Tenant:
    """`suspendTenant`: safe to retry; a tenant already suspended is returned as it is.

    Access ends at once: every member request and sign-in checks that its tenant is active (authn
    and authz 3.2), and every session of the tenant is revoked in the same transaction, so none
    comes back if the tenant is ever reactivated (data model 2.4).
    """
    authorize(operator.caller, "suspendTenant", now=datetime.now(UTC))
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        tenant = await tenants.get_tenant(session, tenant_id)
        if tenant is None:
            raise NotFound()
        if tenant.status == TenantStatus.ACTIVE:
            suspended = await tenants.suspend_tenant(session)
            if suspended is not None:
                tenant = suspended
                await member_sessions.revoke_tenant_sessions(
                    session, reason=member_sessions.RevokedReason.TENANT_SUSPENDED
                )
                await audit.record(
                    session,
                    action="tenant.suspended",
                    actor=operator.actor,
                    target=Target(TARGET, tenant_id),
                    origin=origin,
                    details=operator.details(),
                )
    await platform_event(database, operator, "tenant.suspended", origin, tenant_id)
    return tenant
