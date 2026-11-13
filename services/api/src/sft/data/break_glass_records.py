"""Data access for the service's copy of Identity Center break-glass grants (#239; data model 2.6;
authn and authz 8.3).

The Identity Center path of 8.3 is recorded in `break_glass_grants`, the table break-glass in the
service writes (#232), with `recorded_by` `tool` (`recordBreakGlassGrant`) or `reconciliation`
(the job that reads CloudTrail) and the assignment's request ID, which is unique: one grant, one
row, however many times the tool retries or the job runs. Platform scope only, as `sft_operator`.

A recorded grant is `active` until its `ends_at`, then the sweep marks it `expired` like any
other, so the break-glass alerts and the tenants' logs see it. It never opens the database to
`sft_breakglass`: `break_glass_tenants()` matches grants the service made only (revision 0038),
since the Identity Center path has its own access.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import require_scope
from sft.data.models import BreakGlassGrant, BreakGlassState
from sft.data.scope import ScopeKind


@dataclass(frozen=True, slots=True)
class RecordedGrant:
    """An Identity Center grant as the service records it."""

    assignment_request_id: str
    requester: str
    approver: str
    incident_id: str
    reason: str
    tenant_ids: Sequence[UUID]
    starts_at: datetime
    ends_at: datetime
    duration_minutes: int
    recorded_by: str
    """`tool` or `reconciliation`."""
    review_due_at: datetime
    expired: bool
    """Whether `ends_at` has passed already: the row is then `expired`, not `active`."""


async def find_by_assignment(
    session: AsyncSession, assignment_request_id: str
) -> BreakGlassGrant | None:
    require_scope(session, ScopeKind.PLATFORM)
    found: BreakGlassGrant | None = await session.scalar(
        select(BreakGlassGrant).where(
            BreakGlassGrant.assignment_request_id == assignment_request_id
        )
    )
    return found


async def recorded_assignments(session: AsyncSession, ids: Collection[str]) -> set[str]:
    """Which of these assignment request IDs have a row already."""
    require_scope(session, ScopeKind.PLATFORM)
    if not ids:
        return set()
    rows = await session.scalars(
        select(BreakGlassGrant.assignment_request_id).where(
            BreakGlassGrant.assignment_request_id.in_(list(ids))
        )
    )
    return {row for row in rows if row is not None}


async def insert_recorded(session: AsyncSession, grant: RecordedGrant) -> BreakGlassGrant | None:
    """The new row, or None if the assignment has one already: a retry, or the tool and the job
    at once. One statement, so two writers can't both make a row."""
    require_scope(session, ScopeKind.PLATFORM)
    state = BreakGlassState.EXPIRED if grant.expired else BreakGlassState.ACTIVE
    statement = (
        insert(BreakGlassGrant)
        .values(
            id=uuid7(),
            incident_id=grant.incident_id,
            reason=grant.reason,
            tenant_ids=list(grant.tenant_ids),
            duration_minutes=grant.duration_minutes,
            state=state.value,
            requester=grant.requester,
            approver=grant.approver,
            self_approved=grant.requester == grant.approver,
            approved_at=grant.starts_at,
            starts_at=grant.starts_at,
            ends_at=grant.ends_at,
            ended_at=grant.ends_at if grant.expired else None,
            assignment_request_id=grant.assignment_request_id,
            recorded_by=grant.recorded_by,
            review_due_at=grant.review_due_at,
        )
        .on_conflict_do_nothing(index_elements=[BreakGlassGrant.assignment_request_id])
        .returning(BreakGlassGrant)
    )
    row: BreakGlassGrant | None = await session.scalar(
        statement, execution_options={"populate_existing": True}
    )
    return row


__all__ = ["RecordedGrant", "find_by_assignment", "insert_recorded", "recorded_assignments"]
