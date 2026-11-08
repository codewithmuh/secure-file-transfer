"""Data access for `notice_windows`: the notification worker's windows of coalesced and capped
notices (#230, revision 0028; abuse and rate limits 7.1).

A row is one tenant's window of one kind of notice (`NoticeKind`), and for the approvers' digest
one approver's. Only the notification worker (`sft_notify`) reads and writes them, in its tenant's
scope; the rules (how long a window is, how many emails it allows, when a notice is due) are the
service's (`sft.service.notice_windows`), and these functions only read and write rows.

- `lock` makes the rows it names (with defaults) if they aren't there yet, then reads them under
  their row locks, in one order (by user), so two messages at once queue rather than both pass a
  cap, and never deadlock.
- `save` writes a window back, in the same transaction.
- `pending_approvals` counts what a digest names: the approval requests still pending that the
  approver could decide (not of their own transfers, T-100).

Not audited (`sft.data.audit_required.NOT_AUDITED`): the emails a window sends are audited, and so
are the changes they report.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import ColumnElement, func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import (
    ApprovalState,
    DlpApprovalRequest,
    NoticeKind,
    NoticeWindow,
    Transfer,
)
from sft.data.scope import ScopeKind

UNIQUE = "notice_windows_tenant_id_notice_user_id_key"
"""The constraint a new row conflicts on: one row per tenant, kind and approver."""


@dataclass(frozen=True, slots=True)
class Window:
    """One window as its row holds it."""

    user_id: UUID | None
    window_started_at: datetime
    sent: int
    changes: tuple[str, ...]
    changed_at: datetime | None
    due_at: datetime | None


async def lock(
    session: AsyncSession, notice: NoticeKind, user_ids: Sequence[UUID | None]
) -> dict[UUID | None, Window]:
    """The windows of `notice` for `user_ids` (None for the tenant's own), made if missing, under
    their row locks until the transaction ends."""
    require_scope(session, ScopeKind.TENANT)
    keys = sorted(set(user_ids), key=lambda u: (u is not None, str(u)))
    if not keys:
        return {}
    tenant_id = tenant_of(session)
    await session.execute(
        pg_insert(NoticeWindow)
        .values(
            [
                {"id": uuid7(), "tenant_id": tenant_id, "notice": notice.value, "user_id": key}
                for key in keys
            ]
        )
        .on_conflict_do_nothing(constraint=UNIQUE)
    )
    wanted = [k for k in keys if k is not None]
    condition: ColumnElement[bool] = NoticeWindow.user_id.in_(wanted)
    if None in keys:
        condition = or_(condition, NoticeWindow.user_id.is_(None))
    rows = await session.scalars(
        select(NoticeWindow)
        .where(NoticeWindow.notice == notice.value, condition, in_scope(NoticeWindow, session))
        .order_by(NoticeWindow.user_id.nulls_first())
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    return {
        row.user_id: Window(
            row.user_id,
            row.window_started_at,
            row.sent,
            tuple(row.changes),
            row.changed_at,
            row.due_at,
        )
        for row in rows
    }


async def save(
    session: AsyncSession,
    notice: NoticeKind,
    user_id: UUID | None,
    *,
    window_started_at: datetime,
    sent: int,
    changes: Sequence[str] = (),
    changed_at: datetime | None = None,
    due_at: datetime | None = None,
) -> None:
    """Write the window of `notice` for `user_id` back; the caller locked it (`lock`)."""
    require_scope(session, ScopeKind.TENANT)
    who = NoticeWindow.user_id.is_(None) if user_id is None else NoticeWindow.user_id == user_id
    await session.execute(
        update(NoticeWindow)
        .where(NoticeWindow.notice == notice.value, who, in_scope(NoticeWindow, session))
        .values(
            window_started_at=window_started_at,
            sent=sent,
            changes=list(changes),
            changed_at=changed_at,
            due_at=due_at,
            updated_at=func.now(),
        )
        .execution_options(synchronize_session=False)
    )


async def pending_approvals(session: AsyncSession, approver_id: UUID) -> int:
    """How many approval requests of the tenant are pending that `approver_id` could decide: every
    pending request but those of their own transfers (T-100)."""
    require_scope(session, ScopeKind.TENANT)
    count = await session.scalar(
        select(func.count())
        .select_from(DlpApprovalRequest)
        .join(
            Transfer,
            (Transfer.id == DlpApprovalRequest.transfer_id)
            & (Transfer.tenant_id == DlpApprovalRequest.tenant_id),
        )
        .where(
            DlpApprovalRequest.state == ApprovalState.PENDING.value,
            Transfer.created_by != approver_id,
            in_scope(DlpApprovalRequest, session),
            in_scope(Transfer, session),
        )
    )
    return int(count or 0)
