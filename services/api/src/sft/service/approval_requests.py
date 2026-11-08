"""A sender's DLP approval request: how `confirmTransfer` makes one, and the request in brief
(#220; FR-43, FR-54; architecture 4.6; data model 2.7, 3.2, 3.6; threat model T-100, T-104).

`sft.service.transfer_dlp.confirm_transfer` calls `request_approval` for a decision that needs
approval, in its transaction and under the transfer's row lock, once it has checked the caller,
the state and the decision. In order:

1. A justification is required: `422 justification_required`, pointing at it.
2. At most 3 requests per transfer, in any state (FR-43): a fourth is `409 approval_limit_reached`.
   One pending at a time: the transfer is `awaiting_confirmation`, so none is pending; the
   partial unique index refuses a second one anyway, which is the same 409.
3. Enough eligible approvers (data model 2.7): active users with the designation other than the
   transfer's `created_by` (for an API key's transfer, its owner), at least as many as the
   decision's approval rules need. Otherwise `409 no_eligible_approver` (`NoEligibleApprover`),
   and nothing changes; `confirm_transfer` then tells the tenant's admins in a transaction of its
   own (`tell_admins`), so the refusal changes nothing else but the notice is sent.
4. The confirmation with the sealed justification (`dlp_confirmations`), the pending request,
   whose `expires_at` is the earlier of now plus the tenant's `approval_timeout` and the
   transfer's own `expires_at`, the transfer to `pending_approval`, `transfer.confirmed` and
   `dlp_approval.requested` (IDs, counts and a flag, never the justification), and the outbox
   message that emails each eligible approver `dlp_approval_requested` (no file name, no approve
   link).

`summary` is the request in brief that `getTransferDlp` (`approval_request`), the approval queue
and `Transfer.dlp.approval_request_id` show: the transfer's latest request, in whatever state.
A pending request past `expires_at` shows as `expired` before the expiry job records it, as a
transfer does.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import Conflict, FieldError, Unprocessable
from sft.core.ids import uuid7
from sft.data import audit, dlp_approvals, dlp_decisions, dlp_policy, transfers, users
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.dlp_approvals import Request
from sft.data.dlp_decisions import Decision
from sft.data.models import (
    ApprovalState,
    DlpOutcome,
    Outcome,
    Transfer,
    TransferState,
    UserStatus,
)
from sft.data.outbox import DLP_APPROVAL_REQUESTED, DLP_NO_ELIGIBLE_APPROVER, enqueue
from sft.data.scope import Scope
from sft.service import fields
from sft.service.caller import Caller
from sft.service.evaluation import APPROVAL_REQUEST, TRANSFER

MAX_REQUESTS: Final = 3
"""Approval requests per transfer, in any state (FR-43, abuse 2.2 K)."""
DEFAULT_TIMEOUT: Final = timedelta(hours=72)
"""The policy's default `approval_timeout`, for a tenant without a policy, which can't happen."""


class NoEligibleApprover(Conflict):
    """`409 no_eligible_approver`: nobody but the sender could approve (data model 2.7). Raised
    inside the confirmation's transaction, which it rolls back; `confirm_transfer` then tells the
    admins (`tell_admins`)."""

    def __init__(self, transfer_id: UUID, decision_id: UUID) -> None:
        super().__init__(
            "no_eligible_approver",
            "Nobody but you can approve this transfer. The tenant's admins have been told.",
            current_state=TransferState.AWAITING_CONFIRMATION.value,
        )
        self.transfer_id = transfer_id
        self.decision_id = decision_id


class RefusalReason(StrEnum):
    """Why a request was refused, in a failed `dlp_approval.requested`."""

    NO_ELIGIBLE_APPROVER = "no_eligible_approver"


@dataclass(frozen=True, slots=True)
class ApprovalSummaryView:
    """An approval request in brief (the contract's `ApprovalRequestSummary`)."""

    id: UUID
    transfer_id: UUID
    state: ApprovalState
    requested_by: UUID
    requested_at: datetime
    expires_at: datetime
    approvals_required: int
    approvals: int
    rule_names: tuple[str, ...]


def shown_state(request: Request, now: datetime) -> ApprovalState:
    """The state as the API shows it: `expired` once a pending request's `expires_at` has passed,
    before the expiry job records it."""
    if request.state is ApprovalState.PENDING and request.expires_at <= now:
        return ApprovalState.EXPIRED
    return request.state


async def summaries(
    session: AsyncSession, requests: list[Request], now: datetime
) -> list[ApprovalSummaryView]:
    """Each request in brief, with its approvals and the names of the rules that asked."""
    counts = await dlp_approvals.approvals(session, [r.id for r in requests])
    names = await dlp_approvals.rule_names(session, sorted({r.decision_id for r in requests}))
    return [
        ApprovalSummaryView(
            id=r.id,
            transfer_id=r.transfer_id,
            state=shown_state(r, now),
            requested_by=r.requested_by,
            requested_at=r.created_at,
            expires_at=r.expires_at,
            approvals_required=r.approvals_required,
            approvals=counts.get(r.id, 0),
            rule_names=tuple(names.get(r.decision_id, ())),
        )
        for r in requests
    ]


async def summary(
    session: AsyncSession, transfer_id: UUID, now: datetime
) -> ApprovalSummaryView | None:
    """The transfer's latest request in brief, in whatever state; None if it has none."""
    latest = await dlp_approvals.latest_request(session, transfer_id)
    if latest is None:
        return None
    [view] = await summaries(session, [latest], now)
    return view


async def active_approver(session: AsyncSession, user_id: UUID | None) -> bool:
    """Whether the user is an active user with the DLP approver designation, as `users` says
    now (data model 2.7), not as a session remembers it."""
    if user_id is None:
        return False
    user = await users.get_user(session, user_id)
    return user is not None and user.dlp_approver and user.status == UserStatus.ACTIVE.value


async def request_approval(
    session: AsyncSession,
    caller: Caller,
    transfer: Transfer,
    decision: Decision,
    justification: str | None,
    origin: Origin,
    now: datetime,
) -> UUID:
    """`confirmTransfer` for a decision that needs approval (module docstring); the new request's
    ID. The caller holds the transfer's row lock."""
    tenant_id, user_id = caller.tenant_id, caller.user_id
    assert tenant_id is not None  # noqa: S101 - checked by tenant_scope
    assert user_id is not None  # noqa: S101 - checked by tenant_scope
    if DlpOutcome(decision.outcome) is not DlpOutcome.REQUIRE_APPROVAL:  # pragma: no cover
        raise RuntimeError("only a decision that needs approval asks for one")
    if justification is None:
        detail = "A transfer that needs approval needs a justification for the approvers."
        raise Unprocessable(
            "justification_required",
            detail,
            errors=[FieldError(detail, pointer="#/justification")],
        )
    earlier = await dlp_approvals.count_requests(session, transfer.id)
    if earlier >= MAX_REQUESTS:
        raise _limit_reached()
    needed = await dlp_approvals.approvals_required(session, decision.id)
    approvers = await dlp_approvals.eligible_approvers(session, sender=transfer.created_by)
    if len(approvers) < needed:
        raise NoEligibleApprover(transfer.id, decision.id)

    policy = await dlp_policy.get_policy(session)
    timeout = DEFAULT_TIMEOUT if policy is None else policy.approval_timeout
    expires_at = now + timeout
    if transfer.expires_at is not None:
        expires_at = min(expires_at, transfer.expires_at)
    confirmation_id, request_id = uuid7(), uuid7()
    await dlp_decisions.insert_confirmation(
        session,
        confirmation_id=confirmation_id,
        transfer_id=transfer.id,
        decision_id=decision.id,
        confirmed_by=user_id,
        justification_ct=(await fields.tenant_keys(session, tenant_id, write=True)).seal(
            fields.JUSTIFICATION, confirmation_id, justification
        ),
    )
    try:
        await dlp_approvals.insert_request(
            session,
            request_id=request_id,
            transfer_id=transfer.id,
            decision_id=decision.id,
            confirmation_id=confirmation_id,
            requested_by=user_id,
            approvals_required=needed,
            expires_at=expires_at,
        )
    except IntegrityError:  # pragma: no cover - the row lock keeps a second one from starting
        raise _limit_reached() from None
    await transfers.change_state(
        session,
        transfer.id,
        from_states=(TransferState.AWAITING_CONFIRMATION,),
        to=TransferState.PENDING_APPROVAL,
    )
    await audit.record(
        session,
        action="transfer.confirmed",
        actor=caller.actor(),
        target=Target(TRANSFER, transfer.id),
        origin=origin,
        details={
            "decision_id": decision.id,
            "confirmation_id": confirmation_id,
            "outcome": DlpOutcome.REQUIRE_APPROVAL,
            "justification_given": True,
            "approval_request_id": request_id,
        },
    )
    await audit.record(
        session,
        action="dlp_approval.requested",
        actor=caller.actor(),
        target=Target(APPROVAL_REQUEST, request_id),
        origin=origin,
        details={
            "transfer_id": transfer.id,
            "decision_id": decision.id,
            "confirmation_id": confirmation_id,
            "approvals_required": needed,
            "eligible_approvers": len(approvers),
            "request_number": earlier + 1,
            "expires_at": expires_at,
        },
    )
    await enqueue(session, DLP_APPROVAL_REQUESTED, {"approval_request_id": request_id})
    return request_id


def _limit_reached() -> Conflict:
    return Conflict(
        "approval_limit_reached",
        f"A transfer can have at most {MAX_REQUESTS} approval requests, one pending at a time.",
        current_state=TransferState.AWAITING_CONFIRMATION.value,
    )


async def tell_admins(
    database: Database, caller: Caller, refused: NoEligibleApprover, origin: Origin
) -> None:
    """After a request refused for want of an approver: the outbox message that emails every
    active admin `dlp_no_eligible_approver` (architecture 4.6), and the refusal's record, in a
    transaction of their own, since the refused one rolled back."""
    assert caller.tenant_id is not None  # noqa: S101 - confirm_transfer checked it
    async with database.transaction(Scope.tenant(caller.tenant_id)) as session:
        await enqueue(session, DLP_NO_ELIGIBLE_APPROVER, {"transfer_id": refused.transfer_id})
        await audit.record(
            session,
            action="dlp_approval.requested",
            actor=caller.actor(),
            target=Target(TRANSFER, refused.transfer_id),
            origin=origin,
            outcome=Outcome.FAILURE,
            details={
                "decision_id": refused.decision_id,
                "reason": RefusalReason.NO_ELIGIBLE_APPROVER,
            },
        )
