"""The transfer evaluation: one locked decision of what a submitted or held transfer becomes
(data model 3.2, architecture 4.1, FR-5).

`sendTransfer`, every scan result (a scan deadline passing included), every removal of a file from
a transfer that isn't a draft and every rejection of one of its files run it, in their own
transaction, under the transfer's row lock (`SELECT … FOR UPDATE`). Two scans that finish together
queue on the lock, so exactly one of them moves the transfer on, and the notification is written
once. The API runs it as the member or key that called; the scan worker and the scan sweep run it
as named system actors (authn and authz 6.1), whose roles read only the columns it needs.

It counts the files that aren't `rejected` and haven't been removed, and the first row that
matches decides:

| Situation | Result |
|---|---|
| The transfer is neither `submitted` nor `held` | No change |
| `expires_at` has passed | No change: the transfer is expired, and the lifecycle job records it |
| No counted file | `draft`, `submitted_at` and `expires_at` cleared; an outbox notice |
| A counted file is blocked | `held` (`file_blocked`), an outbox notice; unless held already |
| A counted file is still uploading, completing or scanning | `submitted`; a held one goes back |
| Every counted file is shareable | `sent` (below) |

**No DLP gate yet.** Until DLP-4 (M5) every shareable transfer is sent: findings are recorded with
each file's scan (DLP-3) and shown, but no rule acts on them, no `dlp_decisions` row is written and
no transfer is ever `awaiting_confirmation` or held for `dlp_blocked`. An inspection that `failed`
still blocks its file: that is a shareability rule (FR-16, FR-47), not a DLP decision.

**Moving to `sent`**, in the same transaction: a download counter per recipient per counted file
with the transfer's limit copied, every recipient `queued`, and one outbox message for the
notification worker (#178). Every change writes its audit event.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import audit, files, transfers
from sft.data.audit import Actor, Origin, Target
from sft.data.files import CountedFile
from sft.data.models import FileState, InspectionState, TransferState
from sft.data.outbox import TRANSFER_HELD, TRANSFER_RETURNED_TO_DRAFT, TRANSFER_SENT, enqueue

TRANSFER: Final = "transfer"

IN_PROGRESS: Final = frozenset({FileState.UPLOADING, FileState.COMPLETING, FileState.SCANNING})
INSPECTION_DONE: Final = frozenset(
    {InspectionState.INSPECTED, InspectionState.PARTIAL, InspectionState.NOT_INSPECTED}
)
"""Inspections that let a file be shared (FR-16): `failed` blocks it, and `pending` and `skipped`
mean it isn't shareable yet or ever."""


class Outcome(StrEnum):
    """What one evaluation did."""

    UNCHANGED = "unchanged"
    EXPIRED = "expired"
    DRAFT = "draft"
    HELD = "held"
    SUBMITTED = "submitted"
    SENT = "sent"


class HoldReason(StrEnum):
    FILE_BLOCKED = "file_blocked"


def is_shareable(
    state: FileState, unscannable_allowed: bool, inspection_state: InspectionState
) -> bool:
    """Data model 3.1: `clean`, or `unscannable` with the policy's allowance recorded at scan
    time, and an inspection that finished and didn't fail. Received files' `dlp_blocked` joins
    with upload requests."""
    scanned_ok = state is FileState.CLEAN or (
        state is FileState.UNSCANNABLE and unscannable_allowed
    )
    return scanned_ok and inspection_state in INSPECTION_DONE


def is_blocked(
    state: FileState, unscannable_allowed: bool, inspection_state: InspectionState
) -> bool:
    """Data model 3.1: `infected`, `scan_failed`, `unscannable` without the allowance, or an
    inspection that `failed`."""
    if state in (FileState.INFECTED, FileState.SCAN_FAILED):
        return True
    if state is FileState.UNSCANNABLE and not unscannable_allowed:
        return True
    return state not in IN_PROGRESS and inspection_state is InspectionState.FAILED


def _blocked(file: CountedFile) -> bool:
    return is_blocked(file.state, file.unscannable_allowed, file.inspection_state)


def _shareable(file: CountedFile) -> bool:
    return is_shareable(file.state, file.unscannable_allowed, file.inspection_state)


async def evaluate(
    session: AsyncSession,
    transfer_id: UUID,
    *,
    actor: Actor,
    now: datetime,
    origin: Origin | None = None,
    details: Mapping[str, audit.Detail] | None = None,
) -> Outcome:
    """Lock the transfer and apply the first matching row of the table above.

    `details` go into every audit event it writes, such as a system actor's name or an API key's
    owner. Raises `NotFoundError` if the scope doesn't reach the transfer.
    """
    locked = await transfers.lock_for_evaluation(session, transfer_id)
    if locked.state not in (TransferState.SUBMITTED, TransferState.HELD):
        return Outcome.UNCHANGED
    if locked.expires_at is not None and locked.expires_at <= now:
        return Outcome.EXPIRED
    counted = await files.counted_states(session, transfer_id)
    extra = dict(details or {})

    async def record(action: str, **more: audit.Detail) -> None:
        await audit.record(
            session,
            action=action,
            actor=actor,
            target=Target(TRANSFER, transfer_id),
            origin=origin,
            details={**extra, "from_state": locked.state, **more},
        )

    if not counted:
        await transfers.change_state(
            session,
            transfer_id,
            from_states=(locked.state,),
            to=TransferState.DRAFT,
            submitted_at=None,
            expires_at=None,
            hold_reason=None,
            last_activity_at=func.now(),
        )
        await enqueue(session, TRANSFER_RETURNED_TO_DRAFT, {"transfer_id": transfer_id})
        await record("transfer.returned_to_draft")
        return Outcome.DRAFT
    if any(_blocked(f) for f in counted):
        if locked.state is TransferState.HELD:
            return Outcome.UNCHANGED
        await transfers.change_state(
            session,
            transfer_id,
            from_states=(TransferState.SUBMITTED,),
            to=TransferState.HELD,
            hold_reason=HoldReason.FILE_BLOCKED.value,
        )
        await enqueue(session, TRANSFER_HELD, {"transfer_id": transfer_id})
        blocked = sum(1 for f in counted if _blocked(f))
        await record("transfer.held", hold_reason=HoldReason.FILE_BLOCKED, blocked_files=blocked)
        return Outcome.HELD
    if not all(_shareable(f) for f in counted):
        if locked.state is TransferState.SUBMITTED:
            return Outcome.UNCHANGED
        await transfers.change_state(
            session,
            transfer_id,
            from_states=(TransferState.HELD,),
            to=TransferState.SUBMITTED,
            hold_reason=None,
        )
        await record("transfer.submitted")
        return Outcome.SUBMITTED
    await _send(session, locked, [f.id for f in counted])
    await record("transfer.sent", files=len(counted))
    return Outcome.SENT


async def _send(session: AsyncSession, locked: transfers.Locked, file_ids: Sequence[UUID]) -> None:
    await transfers.change_state(
        session,
        locked.id,
        from_states=(locked.state,),
        to=TransferState.SENT,
        sent_at=func.now(),
        hold_reason=None,
    )
    recipients = await transfers.recipient_ids(session, locked.id)
    await transfers.insert_download_counters(
        session,
        recipient_ids=recipients,
        file_ids=file_ids,
        download_limit=locked.download_limit,
    )
    await transfers.queue_recipients(session, locked.id)
    await enqueue(session, TRANSFER_SENT, {"transfer_id": locked.id})
