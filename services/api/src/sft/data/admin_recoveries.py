"""Data access for `admin_recoveries`: operator-assisted recovery of a tenant admin (#239;
revision 0037; authn and authz 2.5).

- `insert_recovery` writes the row, in the tenant's scope, as `sft_operator`; the caller writes the
  recovery's audit event in the same transaction (the trigger requires one).
- `get_recovery` reads one back, for a retry with the same `Idempotency-Key`.
- `tenants_with_ended` and `end_temporary` are the daily job's (`sft_jobs`): find the temporary
  sign-ins past their end across tenants in system scope, then, in each tenant's scope, delete the
  identities that expired with them and mark the recoveries ended. The identity stopped working
  at its `expires_at` already; this removes it.

Every function filters with `in_scope` and writes the scope's tenant, like every data-access
function.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import func, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import AdminRecovery, AdminRecoveryKind
from sft.data.scope import ScopeKind


@dataclass(frozen=True, slots=True)
class EndedSignIn:
    """A temporary local sign-in the job ended: its recovery, its admin and how many identities
    went with it."""

    recovery_id: UUID
    user_id: UUID
    identities_deleted: int


async def insert_recovery(
    session: AsyncSession,
    *,
    recovery_id: UUID,
    user_id: UUID,
    kind: AdminRecoveryKind,
    confirmed_via: str,
    operator_name: str,
    sign_in_reset_id: UUID,
    lasts: timedelta | None,
) -> AdminRecovery:
    """The recovery's row; `lasts` is a temporary sign-in's lifetime, from the transaction's
    time, and None for a reset."""
    require_scope(session, ScopeKind.TENANT)
    row: AdminRecovery = (
        await session.scalars(
            insert(AdminRecovery)
            .values(
                id=recovery_id,
                tenant_id=tenant_of(session),
                user_id=user_id,
                kind=AdminRecoveryKind(kind).value,
                confirmed_via=confirmed_via,
                operator_name=operator_name,
                sign_in_reset_id=sign_in_reset_id,
                temporary_sign_in_expires_at=None if lasts is None else func.now() + lasts,
            )
            .returning(AdminRecovery),
            execution_options={"populate_existing": True},
        )
    ).one()
    return row


async def get_recovery(session: AsyncSession, recovery_id: UUID) -> AdminRecovery | None:
    require_scope(session, ScopeKind.TENANT)
    found: AdminRecovery | None = await session.scalar(
        select(AdminRecovery).where(
            AdminRecovery.id == recovery_id, in_scope(AdminRecovery, session)
        )
    )
    return found


# ---- the daily job ----


async def tenants_with_ended(
    session: AsyncSession, *, before: datetime, limit: int = 1000
) -> list[UUID]:
    """The tenants with a temporary sign-in past its end and not yet ended: system scope."""
    require_scope(session, ScopeKind.SYSTEM)
    statement = (
        select(AdminRecovery.tenant_id)
        .where(
            AdminRecovery.temporary_sign_in_expires_at <= before,
            AdminRecovery.ended_at.is_(None),
            in_scope(AdminRecovery, session),
        )
        .group_by(AdminRecovery.tenant_id)
        .order_by(AdminRecovery.tenant_id)
        .limit(limit)
    )
    return list((await session.scalars(statement)).all())


async def end_temporary(
    session: AsyncSession, *, before: datetime, limit: int = 1000
) -> Sequence[EndedSignIn]:
    """End up to `limit` of the scope's tenant's temporary sign-ins past their end: delete the
    admin's identities that expired by then and mark the recovery ended. The caller writes an
    event per sign-in in the same transaction."""
    require_scope(session, ScopeKind.TENANT)
    due = (
        await session.execute(
            select(AdminRecovery.id, AdminRecovery.user_id)
            .where(
                AdminRecovery.temporary_sign_in_expires_at <= before,
                AdminRecovery.ended_at.is_(None),
                in_scope(AdminRecovery, session),
            )
            .order_by(AdminRecovery.temporary_sign_in_expires_at)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    ).all()
    ended: list[EndedSignIn] = []
    for recovery_id, user_id in due:
        deleted = await session.execute(
            text(
                "DELETE FROM user_identities WHERE tenant_id = :tenant AND user_id = :user "
                "AND expires_at IS NOT NULL AND expires_at <= :before"
            ),
            {"tenant": tenant_of(session), "user": user_id, "before": before},
        )
        await session.execute(
            update(AdminRecovery)
            .where(AdminRecovery.id == recovery_id, in_scope(AdminRecovery, session))
            .values(ended_at=func.now())
            .execution_options(synchronize_session=False)
        )
        ended.append(EndedSignIn(recovery_id, user_id, int(deleted.rowcount)))  # type: ignore[attr-defined]
    return ended
