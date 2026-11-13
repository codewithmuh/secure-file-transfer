"""Operator-assisted recovery of a tenant admin: `recoverTenantAdmin` (#239; authn and authz 2.5).

For a tenant whose last admin has lost their factor, or an SSO tenant whose identity provider is
down with no fallback admin available. The operator confirms the request through the tenant's
recovery contact first, and records how (`confirmed_via`).

**What it does**, in one transaction of the tenant's scope, as `sft_operator`:

- **A local admin** (`sign_in_reset`): what `resetUserSignIn` does. Every session ends, their pool
  identities are deleted, a new sign-in reset starts and its outbox message asks the notification
  worker for a new pool user and a new invitation (`sft.service.members.reset_user_sign_in`).
- **An admin of a tenant with an active SSO connection** who isn't one of its fallback admins
  (`temporary_local_sign_in`): the same reset, and the identity the worker records for it
  expires 72 hours later (`sft.data.identities.record_identity`). Sign-in lets that identity in
  although the tenant requires SSO, as a security-critical record, and refuses it once it has
  expired; the daily `cleanup` job then deletes it (`end_temporary_sign_ins`). A fallback admin
  already has a local sign-in, so theirs is reset. Each ended sign-in's message asks the
  notification worker to delete the admin's pool user too (`member.temporary_sign_in_ended`), if
  it is still the one made for the recovery (#273).

The recovery is an `admin_recoveries` row, which keeps `confirmed_via` (free text, never in an
audit event), and a security-critical `user.sign_in_reset` event in the tenant's log, by the
operator, naming the recovery and its kind. It is the event a reset writes, so the failover and
restore runbooks re-apply it as they do a reset (`sft.service.recovery_replay`).

**A security-critical record** (architecture 5.2): it commits first and takes effect at once; the
`202` comes only after its record is in both regions' audit archive, `503` otherwise. A retry with
the same `Idempotency-Key` (`sft.service.idempotency`, #160) finds the recovery, writes the archive
record if it is still missing and answers `202`; it never starts a second recovery. The platform
audit event follows, as for every operator call (`sft.service.operator_tenants`).

**Every admin is told** (#273): the recovery's `tenant.admin_recovered` message, in the same
transaction, has the notification worker email every active admin of the tenant, the recovered one
included, which admin it was, when, and the kind (`tenant_admin_recovered`).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final
from uuid import UUID

from sft.core.errors import Conflict, NotFound
from sft.core.ids import uuid7
from sft.data import admin_recoveries, audit, identities, member_sessions, sso, tenants, users
from sft.data.audit import Actor, ActorType, Origin, Target
from sft.data.database import Database
from sft.data.models import AdminRecovery, AdminRecoveryKind, Role, UserStatus
from sft.data.outbox import (
    MEMBER_SIGN_IN_RESET,
    MEMBER_TEMPORARY_SIGN_IN_ENDED,
    TENANT_ADMIN_RECOVERED,
    enqueue,
)
from sft.data.scope import Scope
from sft.service.audit_archive import DONE_NOT_CONFIRMED, AuditArchive, RecordNotConfirmed
from sft.service.idempotency import OperatorKey, operator_claim, operator_replay
from sft.service.members import SIGN_IN_RESET
from sft.service.operator_auth import Operator
from sft.service.operator_tenants import platform_event
from sft.service.permissions import authorize

log = logging.getLogger(__name__)

TARGET: Final = "admin_recovery"
TEMPORARY_SIGN_IN: Final = timedelta(hours=72)
"""How long an SSO tenant's admin keeps the temporary local sign-in (authn and authz 2.5)."""
JOB_BATCH: Final = 1000


@dataclass(frozen=True, slots=True)
class NewRecovery:
    user_id: UUID
    confirmed_via: str


async def recover_tenant_admin(
    database: Database,
    operator: Operator,
    tenant_id: UUID,
    new: NewRecovery,
    *,
    archive: AuditArchive | None,
    origin: Origin,
    key: OperatorKey | None = None,
) -> AdminRecovery:
    """`recoverTenantAdmin` (the module docstring). Without an archive (an environment that names
    no bucket), the recovery takes effect and the answer is `503`, as for a failed write."""
    authorize(operator.caller, "recoverTenantAdmin", now=datetime.now(UTC))
    replay = await operator_replay(database, key, resource_type=TARGET)
    if replay is not None:
        recovery, event = await _replayed(database, replay.tenant_id, replay.resource_id)
    else:
        recovery, event = await _recover(database, operator, tenant_id, new, origin, key)
    if archive is None:
        log.error("no audit archive: a recovery's record can't be confirmed")
        raise RecordNotConfirmed(DONE_NOT_CONFIRMED)
    await archive.confirm([event] if event is not None else [])
    await platform_event(database, operator, "tenant.admin_recovered", origin, tenant_id)
    return recovery


async def _recover(
    database: Database,
    operator: Operator,
    tenant_id: UUID,
    new: NewRecovery,
    origin: Origin,
    key: OperatorKey | None,
) -> tuple[AdminRecovery, audit.ArchivedEvent | None]:
    recovery_id = uuid7()
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        if await tenants.get_tenant(session, tenant_id) is None:
            raise NotFound()
        await operator_claim(
            session, key, status=202, resource_type=TARGET, resource_id=recovery_id
        )
        user = await users.get_user(session, new.user_id, for_update=True)
        if user is None:
            raise NotFound()
        if user.role != Role.ADMIN or user.status != UserStatus.ACTIVE:
            raise Conflict(
                "invalid_state", "Only an active admin is recovered.", current_state=user.status
            )
        connection = await sso.get_connection(session)
        temporary = (
            connection is not None and connection.status == "active" and not user.sso_fallback
        )
        kind = (
            AdminRecoveryKind.TEMPORARY_LOCAL_SIGN_IN
            if temporary
            else AdminRecoveryKind.SIGN_IN_RESET
        )
        ended = await member_sessions.revoke_user_sessions(
            session, user.id, reason=member_sessions.RevokedReason.SIGN_IN_RESET
        )
        removed = await identities.delete_pool_identities(session, user.id)
        user, reset_id = await users.start_sign_in_reset(session, user.id)
        recovery = await admin_recoveries.insert_recovery(
            session,
            recovery_id=recovery_id,
            user_id=user.id,
            kind=kind,
            confirmed_via=new.confirmed_via,
            operator_name=str(operator.name),
            sign_in_reset_id=reset_id,
            lasts=TEMPORARY_SIGN_IN if temporary else None,
        )
        details: dict[str, audit.Detail] = {
            **operator.details(),
            "sessions_ended": ended,
            "identities_removed": removed,
            "reset_id": reset_id,
            "admin_recovery_id": recovery.id,
            "admin_recovery_kind": kind,
        }
        if recovery.temporary_sign_in_expires_at is not None:
            details["temporary_sign_in_expires_at"] = recovery.temporary_sign_in_expires_at
        event_id = await audit.record(
            session,
            action=SIGN_IN_RESET,
            actor=operator.actor,
            target=Target(users.TARGET, user.id),
            origin=origin,
            details=details,
            security_critical=True,
        )
        await enqueue(session, MEMBER_SIGN_IN_RESET, {"user_id": user.id, "reset_id": reset_id})
        await enqueue(
            session,
            TENANT_ADMIN_RECOVERED,
            {"user_id": user.id, "admin_recovery_id": recovery.id},
        )
        event = await audit.archived_event(session, event_id)
    return recovery, event


async def _replayed(
    database: Database, tenant_id: UUID, recovery_id: UUID
) -> tuple[AdminRecovery, audit.ArchivedEvent | None]:
    """A retry: the recovery as it is, and its record, for the archive if it is still missing."""
    async with database.transaction(Scope.tenant(tenant_id)) as session:
        recovery = await admin_recoveries.get_recovery(session, recovery_id)
        if recovery is None:  # pragma: no cover - a recovery is never deleted with its key
            raise NotFound()
        event = await audit.latest_critical_event(
            session, action=SIGN_IN_RESET, target=Target(users.TARGET, recovery.user_id)
        )
    return recovery, event


async def end_temporary_sign_ins(
    database: Database, *, now: datetime, job: Mapping[str, audit.Detail]
) -> int:
    """The daily job's step (`sft_jobs`): delete the identities of temporary sign-ins past their
    end, each with its event naming the job (`job`) and its message for the notification worker,
    which deletes the pool user (#273); how many sign-ins it ended. Find across, act within
    (ADR-0020)."""
    system = Actor(ActorType.SYSTEM)
    total = 0
    while True:
        async with database.transaction(Scope.system()) as session:
            tenant_ids = await admin_recoveries.tenants_with_ended(
                session, before=now, limit=JOB_BATCH
            )
        before_pass = total
        for tenant_id in tenant_ids:
            async with database.transaction(Scope.tenant(tenant_id)) as session:
                ended = await admin_recoveries.end_temporary(session, before=now, limit=JOB_BATCH)
                for item in ended:
                    await audit.record(
                        session,
                        action="user.temporary_sign_in_ended",
                        actor=system,
                        target=Target(users.TARGET, item.user_id),
                        details={
                            **job,
                            "admin_recovery_id": item.recovery_id,
                            "identities_removed": item.identities_deleted,
                        },
                    )
                    await enqueue(
                        session,
                        MEMBER_TEMPORARY_SIGN_IN_ENDED,
                        {"user_id": item.user_id, "admin_recovery_id": item.recovery_id},
                    )
            total += len(ended)
        if not tenant_ids or total == before_pass:
            break  # what the find saw, the tenant's scope keeps: never loop on it
    if total:
        log.info("temporary sign-ins ended", extra={"count": total})
    return total


__all__ = ["NewRecovery", "end_temporary_sign_ins", "recover_tenant_admin"]
