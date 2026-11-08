"""The transfer evaluation: one locked decision of what a submitted or held transfer becomes
(data model 3.2, architecture 4.1, 4.6; FR-5, FR-41).

`sendTransfer`, every scan result (a scan deadline passing included), every removal of a file from
a transfer that isn't a draft and every rejection of one of its files run it, in their own
transaction, under the transfer's row lock (`SELECT … FOR UPDATE`). Two scans that finish together
queue on the lock, so exactly one of them moves the transfer on, and the notification is written
once. The API runs it as the member or key that called; the scan worker and the jobs run it as
named system actors (authn and authz 6.1), whose roles read only the columns it needs.

**A file removal** from an `awaiting_confirmation` or `pending_approval` transfer first sets it
back to `submitted`, withdrawing its pending approval request in the same transaction
(`withdraw_approval_request`, #220, data model 3.6), so the evaluation below makes a new decision
on the files left (data model 3.2). Cancelling and revoking withdraw it the same way.

It counts the files that aren't `rejected` and haven't been removed, and the first row that
matches decides:

| Situation | Result |
|---|---|
| The transfer is neither `submitted` nor `held` | No change |
| `expires_at` has passed | No change: the transfer is expired, and the lifecycle job records it |
| Held by a DLP rule or a rejected approval, and no file was removed | No change: it stands |
| No counted file | `draft`; `submitted_at`, `expires_at`, the decision cleared; an outbox notice |
| A counted file is blocked | `held` (`file_blocked`), an outbox notice; unless held already |
| A counted file is still uploading, completing or scanning | `submitted`; a held one goes back |
| Every counted file is shareable | The DLP decision (`sft.service.dlp_decision`), then below |

**The DLP decision** is written with its matched rules, `transfers.dlp_decision_id` points at it,
and `dlp.decided` (with one `dlp.rule_matched` per rule) records it, with IDs, enums and counts
only, never a value, a name or a domain. Then, in enforce mode:

- `none` or `allow_and_record`: `sent` (below);
- `warn` or `require_approval`: `awaiting_confirmation`, with an outbox notice that sends the
  member `dlp_confirmation_needed`; the member confirms or requests approval
  (`sft.service.transfer_dlp`);
- `block`: `held` with `hold_reason = dlp_blocked` and the `transfer_held` notice, unless it was
  held for that already. Removing a file evaluates again and makes a new decision.

In monitor mode (#221) the transfer is sent whatever the outcome. A decision is never recomputed
when the policy changes; only a change to the counted files makes a new one.

**Moving to `sent`** (`send`), here or from a confirmation, in the same transaction: a download
counter per recipient per counted file with the transfer's limit copied, every recipient
`queued`, each recipient domain recorded as known to the tenant (FR-46), and one outbox message
for the notification worker (#178). No recipient email is written before that. Every change writes
its audit event.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import audit, dlp_approvals, dlp_decisions, files, transfers
from sft.data.audit import Actor, Origin, Target
from sft.data.files import CountedFile
from sft.data.models import (
    ApprovalState,
    DlpAction,
    DlpOutcome,
    FileState,
    InspectionState,
    TransferState,
)
from sft.data.outbox import (
    TRANSFER_AWAITING_CONFIRMATION,
    TRANSFER_HELD,
    TRANSFER_RETURNED_TO_DRAFT,
    TRANSFER_SENT,
    enqueue,
)
from sft.service import dlp_decision
from sft.service.dlp_decision import Decided

TRANSFER: Final = "transfer"
DLP_RULE: Final = "dlp_rule"
APPROVAL_REQUEST: Final = "dlp_approval_request"
"""The audit target of an approval request (#220)."""

IN_PROGRESS: Final = frozenset({FileState.UPLOADING, FileState.COMPLETING, FileState.SCANNING})
INSPECTION_DONE: Final = frozenset(
    {InspectionState.INSPECTED, InspectionState.PARTIAL, InspectionState.NOT_INSPECTED}
)
"""Inspections that let a file be shared (FR-16): `failed` blocks it, and `pending` and `skipped`
mean it isn't shareable yet or ever."""

REOPENED_BY_REMOVAL: Final = frozenset(
    {TransferState.AWAITING_CONFIRMATION, TransferState.PENDING_APPROVAL}
)
"""States a file removal sets back to `submitted` before the evaluation (data model 3.2)."""


class Outcome(StrEnum):
    """What one evaluation did."""

    UNCHANGED = "unchanged"
    EXPIRED = "expired"
    DRAFT = "draft"
    HELD = "held"
    SUBMITTED = "submitted"
    SENT = "sent"
    AWAITING_CONFIRMATION = "awaiting_confirmation"


class HoldReason(StrEnum):
    FILE_BLOCKED = "file_blocked"
    DLP_BLOCKED = "dlp_blocked"
    APPROVAL_REJECTED = "approval_rejected"


DECISION_HOLDS: Final = frozenset({HoldReason.DLP_BLOCKED, HoldReason.APPROVAL_REJECTED})
"""Holds that stand for the files a decision saw: only a file removal decides again."""


class WithdrawReason(StrEnum):
    """Why a pending approval request was withdrawn, in `dlp_approval.withdrawn` (data model
    3.6)."""

    FILE_REMOVED = "file_removed"
    CANCELLED = "cancelled"
    REVOKED = "revoked"


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
    file_removed: bool = False,
) -> Outcome:
    """Lock the transfer and apply the first matching row of the table above.

    `details` go into every audit event it writes, such as a system actor's name or an API key's
    owner. `file_removed` says a file was just removed (`deleteFile`): only that reopens a
    transfer awaiting confirmation or approval, or one a DLP rule holds. Raises `NotFoundError` if
    the scope doesn't reach the transfer.
    """
    locked = await transfers.lock_for_evaluation(session, transfer_id)
    expired = locked.expires_at is not None and locked.expires_at <= now
    extra = dict(details or {})

    async def record(
        action: str,
        /,
        listed: Mapping[str, audit.Detail] | None = None,
        *,
        target: Target | None = None,
        **more: audit.Detail,
    ) -> None:
        await audit.record(
            session,
            action=action,
            actor=actor,
            target=target or Target(TRANSFER, transfer_id),
            origin=origin,
            details={**extra, "from_state": locked.state, **(listed or {}), **more},
        )

    if file_removed and locked.state in REOPENED_BY_REMOVAL and not expired:
        await withdraw_approval_request(
            session,
            transfer_id,
            reason=WithdrawReason.FILE_REMOVED,
            actor=actor,
            origin=origin,
            details=extra,
            now=now,
        )
        await transfers.change_state(
            session, transfer_id, from_states=(locked.state,), to=TransferState.SUBMITTED
        )
        await record("transfer.submitted", file_removed=True)
        locked = replace(locked, state=TransferState.SUBMITTED)
    if locked.state not in (TransferState.SUBMITTED, TransferState.HELD):
        return Outcome.UNCHANGED
    if expired:
        return Outcome.EXPIRED
    if locked.hold_reason in DECISION_HOLDS and not file_removed:
        return Outcome.UNCHANGED  # a decision stands for the files it saw (data model 3.2)
    counted = await files.counted_states(session, transfer_id)

    if not counted:
        await transfers.change_state(
            session,
            transfer_id,
            from_states=(locked.state,),
            to=TransferState.DRAFT,
            submitted_at=None,
            expires_at=None,
            hold_reason=None,
            dlp_decision_id=None,
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

    decided = await dlp_decision.decide(session, transfer_id, counted, now=now)
    await record("dlp.decided", _decision_details(decided))
    for match in decided.matches:
        await record(
            "dlp.rule_matched",
            {
                "decision_id": decided.id,
                "transfer_id": transfer_id,
                "rule_revision": match.rule.revision,
                "action": DlpAction(match.rule.action),
                "matched_count": match.count,
            },
            target=Target(DLP_RULE, match.rule.id),
        )
    if decided.sends:
        await send(session, locked, [f.id for f in counted], decision_id=decided.id)
        await record("transfer.sent", files=len(counted), decision_id=decided.id)
        return Outcome.SENT
    if decided.outcome is not DlpOutcome.BLOCK:
        await transfers.change_state(
            session,
            transfer_id,
            from_states=(locked.state,),
            to=TransferState.AWAITING_CONFIRMATION,
            hold_reason=None,
            dlp_decision_id=decided.id,
        )
        await enqueue(session, TRANSFER_AWAITING_CONFIRMATION, {"transfer_id": transfer_id})
        await record(
            "transfer.awaiting_confirmation", decision_id=decided.id, outcome=decided.outcome
        )
        return Outcome.AWAITING_CONFIRMATION
    held_already = locked.hold_reason == HoldReason.DLP_BLOCKED
    await transfers.change_state(
        session,
        transfer_id,
        from_states=(locked.state,),
        to=TransferState.HELD,
        hold_reason=HoldReason.DLP_BLOCKED.value,
        dlp_decision_id=decided.id,
    )
    if not held_already:
        await enqueue(session, TRANSFER_HELD, {"transfer_id": transfer_id})
    await record("transfer.held", hold_reason=HoldReason.DLP_BLOCKED, decision_id=decided.id)
    return Outcome.HELD


def _decision_details(decided: Decided) -> dict[str, audit.Detail]:
    """`dlp.decided`: IDs, enums and counts (FR-54). Never a value, a rule's name or a domain; the
    rules matched each have their own `dlp.rule_matched` event, since details hold no lists."""
    return {
        "decision_id": decided.id,
        "outcome": decided.outcome,
        "mode": decided.mode,
        "enforced": decided.enforced,
        "policy_version": decided.policy_version,
        "matched_rules": len(decided.matches),
        "untrusted_recipients": decided.untrusted_recipients,
        "new_domains": decided.new_domains,
    }


async def withdraw_approval_request(
    session: AsyncSession,
    transfer_id: UUID,
    *,
    reason: WithdrawReason,
    actor: Actor,
    origin: Origin | None,
    details: Mapping[str, audit.Detail],
    now: datetime,
) -> UUID | None:
    """Withdraw the transfer's pending approval request, if it has one, in the caller's
    transaction, under the transfer's row lock the caller holds (data model 3.6): a file removal,
    a cancellation or a revocation (#220). Writes `dlp_approval.withdrawn`; returns the request's
    ID, or None when nothing was pending."""
    withdrawn = await dlp_approvals.end_pending(
        session, transfer_id, to=ApprovalState.WITHDRAWN, ended_at=now
    )
    if withdrawn is not None:
        await audit.record(
            session,
            action="dlp_approval.withdrawn",
            actor=actor,
            target=Target(APPROVAL_REQUEST, withdrawn),
            origin=origin,
            details={**details, "transfer_id": transfer_id, "reason": reason},
        )
    return withdrawn


async def send(
    session: AsyncSession,
    locked: transfers.Locked,
    file_ids: Sequence[UUID],
    *,
    decision_id: UUID | None = None,
) -> None:
    """Move the locked transfer to `sent` (module docstring): from the evaluation, a confirmation
    (`sft.service.transfer_dlp`) or an approval (`sft.service.approvals`, #220). `decision_id` is
    the decision that allowed it, recorded as the transfer's current one; None keeps the one it
    has. The caller writes the audit events."""
    values: dict[str, object] = {"sent_at": func.now(), "hold_reason": None}
    if decision_id is not None:
        values["dlp_decision_id"] = decision_id
    await transfers.change_state(
        session, locked.id, from_states=(locked.state,), to=TransferState.SENT, **values
    )
    recipients = await transfers.recipient_ids(session, locked.id)
    await transfers.insert_download_counters(
        session,
        recipient_ids=recipients,
        file_ids=file_ids,
        download_limit=locked.download_limit,
    )
    await transfers.queue_recipients(session, locked.id)
    domains = await dlp_decision.recipient_domains(session, locked.id)
    await dlp_decisions.record_known_domains(session, domains)
    await enqueue(session, TRANSFER_SENT, {"transfer_id": locked.id})
