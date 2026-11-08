"""The windows of the admins' and approvers' DLP notices: what is coalesced, digested or capped, and
when (#230; FR-43, FR-54; abuse and rate limits 7.1).

The notification worker (`sft.service.notifications`) asks these in the transaction that prepares
an email, under the window's row lock (`sft.data.notice_windows.lock`), so two messages at once
queue rather than both pass a cap:

- **Policy changes are coalesced per tenant over 10 minutes** (`note_policy_change`). The first
  change with no notice due makes one due in 10 minutes, with one `dlp_policy.notice_due` message
  delayed that long; every change meanwhile only adds its kind. The notice then lists every kind
  (`policy_notice`), one email per admin, and once it is out the window is cleared
  (`settle_policy_notice`); a change recorded while it was going out makes the next notice due,
  listing the kinds again, so a notice may repeat a kind, never miss one. A notice due for more
  than 15 minutes lost its message (a suspended tenant's, say): the next change makes it due again.
- **Approval requests are digested per approver past 20 an hour** (`split_approvers`). Each
  approver's window counts the request emails sent in the hour since it began; up to 20 go out one
  by one (`count_approver_emails`, after the send), and past that the approver's digest is made due
  when the hour ends, with one `dlp_approval.digest_due` message. A delay past SQS's 15 minutes is
  the message sent again, delayed (`digest_due`). The digest counts every request the approver
  could still decide then, not only the held ones, so it is right however many were decided
  meanwhile; a new hour starts with the next request.
- **"No eligible approver" emails are capped per tenant** (`reserve_no_approver_email`): 3 a day,
  counted when the email is prepared, so a redelivery can never pass the cap. The admins already
  know after the first; the refusals stay in the audit log.

Times come from the worker's clock, so the tests move them.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import notice_windows
from sft.data.models import NoticeKind
from sft.data.outbox import (
    DLP_APPROVAL_DIGEST_DUE,
    DLP_POLICY_NOTICE_DUE,
    MAX_DELAY,
    enqueue,
)

POLICY_WINDOW: Final = timedelta(minutes=10)
"""At most one DLP policy notice per tenant in this long (abuse 7.1)."""
APPROVER_WINDOW: Final = timedelta(hours=1)
"""An approver's request emails are counted over this long."""
APPROVER_EMAILS: Final = 20
"""Request emails an approver gets one by one in a window; past it, the window's digest."""
NO_APPROVER_WINDOW: Final = timedelta(days=1)
NO_APPROVER_EMAILS: Final = 3
""""No eligible approver" emails to a tenant's admins in a window."""
STALE: Final = timedelta(minutes=15)
"""A notice due this long ago lost its message: the next event makes it due again."""

POLICY: Final = NoticeKind.DLP_POLICY_CHANGED
DIGEST: Final = NoticeKind.DLP_APPROVAL_DIGEST
NO_APPROVER: Final = NoticeKind.DLP_NO_ELIGIBLE_APPROVER


# ---- policy changes ----


async def note_policy_change(session: AsyncSession, change: str, *, now: datetime) -> bool:
    """Record one kind of change in the tenant's window; when no notice was due, make one due and
    write its delayed message. True when this call made it due."""
    window = (await notice_windows.lock(session, POLICY, [None]))[None]
    changes = window.changes if change in window.changes else (*window.changes, change)
    due = window.due_at
    made = due is None or due < now - STALE
    if made:
        due = now + POLICY_WINDOW
    await notice_windows.save(
        session,
        POLICY,
        None,
        window_started_at=window.window_started_at,
        sent=window.sent,
        changes=changes,
        changed_at=now,
        due_at=due,
    )
    if made:
        await enqueue(session, DLP_POLICY_NOTICE_DUE, {}, delay=POLICY_WINDOW)
    return made


@dataclass(frozen=True, slots=True)
class PolicyNotice:
    """What the coalesced notice lists, and the latest change it covers."""

    changes: tuple[str, ...]
    changed_at: datetime | None


async def policy_notice(session: AsyncSession) -> PolicyNotice | None:
    """The tenant's waiting changes, under the window's lock; None when there are none (a copy of
    a notice that went out already)."""
    window = (await notice_windows.lock(session, POLICY, [None]))[None]
    if not window.changes:
        return None
    return PolicyNotice(window.changes, window.changed_at)


async def settle_policy_notice(session: AsyncSession, sent: PolicyNotice, *, now: datetime) -> bool:
    """The notice of `sent` went out (or never can): clear the window, unless a change was
    recorded meanwhile, which makes the next notice due with its message. True when it did."""
    window = (await notice_windows.lock(session, POLICY, [None]))[None]
    more = (
        window.changed_at is not None
        and sent.changed_at is not None
        and window.changed_at > sent.changed_at
    )
    await notice_windows.save(
        session,
        POLICY,
        None,
        window_started_at=window.window_started_at,
        sent=window.sent + 1,
        changes=window.changes if more else (),
        changed_at=window.changed_at if more else None,
        due_at=now + POLICY_WINDOW if more else None,
    )
    if more:
        await enqueue(session, DLP_POLICY_NOTICE_DUE, {}, delay=POLICY_WINDOW)
    return more


# ---- the approvers' digest ----


def _fresh(window: notice_windows.Window, length: timedelta, now: datetime) -> bool:
    return window.window_started_at <= now - length


def _delay(due: datetime, now: datetime) -> timedelta:
    return max(timedelta(0), min(due - now, MAX_DELAY))


async def split_approvers(
    session: AsyncSession, approver_ids: Sequence[UUID], *, now: datetime
) -> tuple[list[UUID], list[UUID]]:
    """Which approvers get this request's email now, and which are past 20 this hour: their digest
    is made due when their hour ends, with its message, unless one is due already."""
    windows = await notice_windows.lock(session, DIGEST, list(approver_ids))
    now_ones: list[UUID] = []
    held: list[UUID] = []
    for approver_id in approver_ids:
        window = windows[approver_id]
        if _fresh(window, APPROVER_WINDOW, now) or window.sent < APPROVER_EMAILS:
            now_ones.append(approver_id)
            continue
        held.append(approver_id)
        if window.due_at is not None and window.due_at >= now - STALE:
            continue  # its digest is due already, and its message carries this request too
        due = window.window_started_at + APPROVER_WINDOW
        await notice_windows.save(
            session,
            DIGEST,
            approver_id,
            window_started_at=window.window_started_at,
            sent=window.sent,
            due_at=due,
        )
        await enqueue(
            session, DLP_APPROVAL_DIGEST_DUE, {"user_id": approver_id}, delay=_delay(due, now)
        )
    return now_ones, held


async def count_approver_emails(
    session: AsyncSession, approver_ids: Sequence[UUID], *, now: datetime
) -> None:
    """The request emails to `approver_ids` went out: count each in its window, starting a new hour
    for one whose window has ended."""
    windows = await notice_windows.lock(session, DIGEST, list(approver_ids))
    for approver_id in approver_ids:
        window = windows[approver_id]
        fresh = _fresh(window, APPROVER_WINDOW, now)
        await notice_windows.save(
            session,
            DIGEST,
            approver_id,
            window_started_at=now if fresh else window.window_started_at,
            sent=1 if fresh else window.sent + 1,
            due_at=window.due_at,
        )


@dataclass(frozen=True, slots=True)
class Digest:
    """Whether an approver's digest goes out now, and how many requests it counts."""

    due: bool
    request_count: int = 0


async def digest_due(session: AsyncSession, approver_id: UUID, *, now: datetime) -> Digest:
    """An approver's `dlp_approval.digest_due` arrived: not due yet (its message is sent again,
    delayed), nothing to send (a copy, or every request decided: the window is cleared), or due,
    with the requests the approver could decide now. The caller clears it once sent
    (`clear_digest`)."""
    window = (await notice_windows.lock(session, DIGEST, [approver_id]))[approver_id]
    if window.due_at is None:
        return Digest(due=False)
    if window.due_at > now:
        delay = _delay(window.due_at, now)
        await enqueue(session, DLP_APPROVAL_DIGEST_DUE, {"user_id": approver_id}, delay=delay)
        return Digest(due=False)
    count = await notice_windows.pending_approvals(session, approver_id)
    if count == 0:
        await clear_digest(session, approver_id)
        return Digest(due=False)
    return Digest(due=True, request_count=count)


async def clear_digest(session: AsyncSession, approver_id: UUID) -> None:
    """No digest is due for the approver any more; their next request starts a new hour."""
    window = (await notice_windows.lock(session, DIGEST, [approver_id]))[approver_id]
    await notice_windows.save(
        session,
        DIGEST,
        approver_id,
        window_started_at=window.window_started_at,
        sent=window.sent,
        due_at=None,
    )


# ---- "no eligible approver" ----


async def reserve_no_approver_email(session: AsyncSession, *, now: datetime) -> bool:
    """Count one more "no eligible approver" notice in the tenant's window: True while the cap
    allows it, False once the window holds `NO_APPROVER_EMAILS`."""
    window = (await notice_windows.lock(session, NO_APPROVER, [None]))[None]
    fresh = _fresh(window, NO_APPROVER_WINDOW, now)
    sent = 0 if fresh else window.sent
    if sent >= NO_APPROVER_EMAILS:
        return False
    await notice_windows.save(
        session,
        NO_APPROVER,
        None,
        window_started_at=now if fresh else window.window_started_at,
        sent=sent + 1,
    )
    return True
