"""Data access for break-glass requests and grants (#232; data model 2.6; authn and authz 8.3).

`break_glass_grants` is a platform table: no tenant and no row-level security, granted to
`sft_operator` alone, read and written in platform scope only. A request becomes a grant when a
second operator approves it; the grant's `starts_at` and `ends_at` are the transaction's time and
that plus its duration, so the database's clock, the one `break_glass_tenants()` compares with,
decides when access ends. The sweep records what time has already ended: an `active` grant past
`ends_at` is `expired`, and a request nobody approved within `REQUEST_LIFETIME` is `lapsed`.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import func, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import require_scope
from sft.data.models import BreakGlassGrant, BreakGlassState
from sft.data.scope import ScopeKind

REQUEST_LIFETIME: Final = timedelta(hours=1)
"""How long a request waits for a second operator before it lapses."""

MAX_LIST: Final = 100


def _platform(session: AsyncSession) -> None:
    require_scope(session, ScopeKind.PLATFORM)


async def insert_request(
    session: AsyncSession,
    *,
    incident_id: str,
    reason: str,
    tenant_ids: Sequence[UUID],
    duration_minutes: int,
    requester: str,
) -> BreakGlassGrant:
    _platform(session)
    row: BreakGlassGrant = (
        await session.scalars(
            insert(BreakGlassGrant)
            .values(
                id=uuid7(),
                incident_id=incident_id,
                reason=reason,
                tenant_ids=list(tenant_ids),
                duration_minutes=duration_minutes,
                state=BreakGlassState.REQUESTED.value,
                requester=requester,
            )
            .returning(BreakGlassGrant),
            execution_options={"populate_existing": True},
        )
    ).one()
    return row


async def get_grant(
    session: AsyncSession, grant_id: UUID, *, for_update: bool = False
) -> BreakGlassGrant | None:
    _platform(session)
    statement = select(BreakGlassGrant).where(BreakGlassGrant.id == grant_id)
    if for_update:
        statement = statement.with_for_update().execution_options(populate_existing=True)
    found: BreakGlassGrant | None = await session.scalar(statement)
    return found


async def list_grants(
    session: AsyncSession, *, state: BreakGlassState | None = None, limit: int = 25
) -> Sequence[BreakGlassGrant]:
    """The newest `limit` requests, optionally in one state."""
    _platform(session)
    if not 1 <= limit <= MAX_LIST:
        raise ValueError(f"a list holds 1 to {MAX_LIST} requests")
    statement = select(BreakGlassGrant)
    if state is not None:
        statement = statement.where(BreakGlassGrant.state == BreakGlassState(state).value)
    statement = statement.order_by(
        BreakGlassGrant.requested_at.desc(), BreakGlassGrant.id.desc()
    ).limit(limit)
    return (await session.scalars(statement)).all()


async def lapsed(session: AsyncSession, grant: BreakGlassGrant) -> bool:
    """Whether the request is older than `REQUEST_LIFETIME`, by the database's clock."""
    _platform(session)
    old = await session.scalar(
        select(func.now() - BreakGlassGrant.requested_at >= REQUEST_LIFETIME).where(
            BreakGlassGrant.id == grant.id
        )
    )
    return bool(old)


async def approve(
    session: AsyncSession, grant_id: UUID, *, approver: str, self_approved: bool
) -> BreakGlassGrant:
    """Start the grant now, for its duration. The caller has locked a `requested` row."""
    _platform(session)
    row: BreakGlassGrant = (
        await session.scalars(
            update(BreakGlassGrant)
            .where(
                BreakGlassGrant.id == grant_id,
                BreakGlassGrant.state == BreakGlassState.REQUESTED.value,
            )
            .values(
                state=BreakGlassState.ACTIVE.value,
                approver=approver,
                self_approved=self_approved,
                approved_at=func.now(),
                starts_at=func.now(),
                ends_at=func.now()
                + func.make_interval(0, 0, 0, 0, 0, BreakGlassGrant.duration_minutes),
            )
            .returning(BreakGlassGrant),
            execution_options={"populate_existing": True},
        )
    ).one()
    return row


async def end(
    session: AsyncSession, grant_id: UUID, *, state: BreakGlassState, ended_by: str | None
) -> BreakGlassGrant:
    """End an `active` grant (`ended`) or a `requested` one (`withdrawn`) now."""
    _platform(session)
    row: BreakGlassGrant = (
        await session.scalars(
            update(BreakGlassGrant)
            .where(BreakGlassGrant.id == grant_id)
            .values(state=BreakGlassState(state).value, ended_at=func.now(), ended_by=ended_by)
            .returning(BreakGlassGrant),
            execution_options={"populate_existing": True},
        )
    ).one()
    return row


async def expire_due(session: AsyncSession) -> Sequence[BreakGlassGrant]:
    """Mark every active grant past its `ends_at` expired, at that time; the rows marked."""
    _platform(session)
    statement = (
        update(BreakGlassGrant)
        .where(
            BreakGlassGrant.state == BreakGlassState.ACTIVE.value,
            BreakGlassGrant.ends_at <= func.now(),
        )
        .values(state=BreakGlassState.EXPIRED.value, ended_at=BreakGlassGrant.ends_at)
        .returning(BreakGlassGrant)
    )
    return (await session.scalars(statement, execution_options={"populate_existing": True})).all()


async def lapse_due(session: AsyncSession) -> Sequence[BreakGlassGrant]:
    """Mark every request nobody approved within `REQUEST_LIFETIME` lapsed; the rows marked."""
    _platform(session)
    statement = (
        update(BreakGlassGrant)
        .where(
            BreakGlassGrant.state == BreakGlassState.REQUESTED.value,
            BreakGlassGrant.requested_at <= func.now() - REQUEST_LIFETIME,
        )
        .values(state=BreakGlassState.LAPSED.value, ended_at=func.now())
        .returning(BreakGlassGrant)
    )
    return (await session.scalars(statement, execution_options={"populate_existing": True})).all()


async def active_counts(session: AsyncSession) -> dict[bool, int]:
    """How many grants give access now, by whether they were self-approved."""
    _platform(session)
    rows = await session.execute(
        text(
            "SELECT self_approved, count(*) FROM break_glass_grants "
            "WHERE state = 'active' AND starts_at <= now() AND ends_at > now() "
            "GROUP BY self_approved"
        )
    )
    counts = {False: 0, True: 0}
    for self_approved, count in rows.all():
        counts[bool(self_approved)] = int(count)
    return counts
