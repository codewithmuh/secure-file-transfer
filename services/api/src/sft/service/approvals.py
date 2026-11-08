"""DLP approvals: `listApprovalRequests`, `getApprovalRequest`, `approveTransfer` and
`rejectTransfer` (#220; FR-43, FR-44, FR-54; architecture 4.6; data model 2.7, 3.2, 3.6; authn and
authz 3.3, 5.3, 6.3; threat model T-100, T-101, T-106).

Who may do what (authn and authz 6.3, `dlp_approval.read` and `dlp_approval.decide`). API keys get
`403` on all four (`DLP_PEOPLE_ONLY`): every DLP decision on record is a person's. "Approver"
means an active user with the `dlp_approver` designation as `users` says now, never as a session
remembers it.

- **`listApprovalRequests`**, newest first, with a cursor like `listTransfers`. `scope=queue`, the
  default for an approver, is the tenant's pending requests for transfers the caller didn't make;
  anyone else gets `403 permission_denied`. `scope=own` (the default for others) is the requests for
  the caller's own transfers. `scope=tenant` is every request and needs the admin role: a member
  gets `403 permission_denied`, a local admin without a passkey `403 passkey_required`. `state`
  filters; a pending request past `expires_at` shows as `expired`, as a transfer does.
- **`getApprovalRequest`**: approvers see every request of the tenant, the sender their own, an
  admin acting as one every request; anyone else gets 404, so a request's existence isn't told.
  It holds what the approver needs to decide (FR-43): the recipients with their trust and
  new-domain flags, the files with names, sizes and inspection summary, the message, the matched
  rules, the justification, the decisions with their comments, and `can_decide`. Never a way to
  download a file.
- **`approveTransfer`** (step-up, authn and authz 3.3) and **`rejectTransfer`** (a comment, no
  step-up). In order, under the transfer's row lock: 404 for a request the scope doesn't reach;
  `403 permission_denied` for a caller who isn't an approver; `403 self_approval_forbidden` for the
  transfer's `created_by`, who for an API key's transfer is the key's owner (T-100); the same
  decision by the same approver again returns the request unchanged, a different one is
  `409 invalid_state`; then `409 transfer_revoked`, `409 transfer_expired` and `409 invalid_state`
  for a request that isn't pending. Then the decision (`dlp_approval_decisions`, the comment sealed
  with `sft.service.fields`, one per approver):
  - an approval that gives the request its `approvals_required` (one, or two, FR-44) makes it
    `approved` and sends the transfer as the evaluation does (`sft.service.evaluation.send`:
    counters, recipients queued, domains known, `transfer.sent`, the recipients' emails); the
    sender is emailed `dlp_approval_decided`. Short of that, it stays `pending`;
  - a rejection makes it `rejected` and holds the transfer (`approval_rejected`), which stays held
    until the sender removes files or cancels; the sender is emailed.

Every step is audited: `dlp_approval.approved` or `.rejected` (the transfer, approvals so far,
whether a comment was given, never its text), then `transfer.sent` or `transfer.held`.

Rate limits (abuse 2.2, `sft.api.approvals`): reads and `approveTransfer` count against the
caller's and the tenant's budget (group H); both decisions against the approver's 120 an hour
(group K); `rejectTransfer`, a safety action, against nothing else.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import Conflict, FieldError, Forbidden, NotFound, Unprocessable
from sft.core.ids import uuid7
from sft.data import audit, dlp_approvals, dlp_decisions, files, findings, transfers
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.dlp_approvals import Request
from sft.data.dlp_decisions import DecisionRule
from sft.data.models import (
    ApprovalDecisionKind,
    ApprovalState,
    FileState,
    InspectionReason,
    InspectionState,
    Transfer,
    TransferState,
)
from sft.data.outbox import DLP_APPROVAL_DECIDED, enqueue
from sft.service import fields
from sft.service.approval_requests import (
    ApprovalSummaryView,
    active_approver,
    shown_state,
    summaries,
)
from sft.service.caller import Caller, CallerKind
from sft.service.evaluation import APPROVAL_REQUEST, TRANSFER, HoldReason, send
from sft.service.permissions import Reach, authorize
from sft.service.transfer_dlp import RecipientFlags, recipient_flags
from sft.service.transfers import (
    decode_cursor,
    effective_state,
    encode_cursor,
    tenant_scope,
)

MAX_PAGE: Final = 100
"""`listApprovalRequests` returns at most this many per page (the contract's `Limit`)."""


class ApprovalScope(StrEnum):
    """`listApprovalRequests`'s `scope`."""

    QUEUE = "queue"
    OWN = "own"
    TENANT = "tenant"


@dataclass(frozen=True, slots=True)
class ApprovalPage:
    items: tuple[ApprovalSummaryView, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class ApprovalFileView:
    id: UUID
    display_name: str
    size: int
    inspection_state: InspectionState
    reasons: tuple[InspectionReason, ...]
    detectors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ApprovalTransferView:
    """What an approver sees of the transfer: never a way to download its files."""

    created_by: UUID
    message: str | None
    expires_at: datetime | None
    recipients: tuple[RecipientFlags, ...]
    files: tuple[ApprovalFileView, ...]


@dataclass(frozen=True, slots=True)
class ApprovalDecisionView:
    approver_id: UUID
    decision: ApprovalDecisionKind
    comment: str | None
    decided_at: datetime


@dataclass(frozen=True, slots=True)
class ApprovalRequestView:
    """An approval request with what an approver needs to decide (the contract's
    `ApprovalRequest`)."""

    summary: ApprovalSummaryView
    justification: str
    matched_rules: tuple[DecisionRule, ...]
    transfer: ApprovalTransferView
    decisions: tuple[ApprovalDecisionView, ...]
    can_decide: bool


# ---- listApprovalRequests ----


async def list_approval_requests(
    database: Database,
    caller: Caller,
    *,
    scope: ApprovalScope | None = None,
    states: Collection[ApprovalState] = (),
    cursor: str | None = None,
    limit: int = 25,
    now: datetime,
) -> ApprovalPage:
    """`listApprovalRequests` (module docstring)."""
    reach = authorize(caller, "listApprovalRequests", now=now)
    if scope is ApprovalScope.TENANT and reach is not Reach.TENANT:
        if caller.is_admin and caller.kind is CallerKind.MEMBER:
            raise Forbidden("passkey_required", "The admin role needs a passkey sign-in.")
        raise Forbidden("permission_denied", "scope=tenant needs the admin role.")
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError("a page holds 1 to 100 approval requests")
    before = None if cursor is None else decode_cursor(cursor)
    wanted = set(states)
    async with database.transaction(tenant_scope(caller)) as session:
        approver = await active_approver(session, caller.user_id)
        chosen = scope or (ApprovalScope.QUEUE if approver else ApprovalScope.OWN)
        sent_by = not_sent_by = None
        if chosen is ApprovalScope.QUEUE:
            if not approver:
                raise Forbidden("permission_denied", "The queue is for DLP approvers.")
            # Pending requests the caller may decide: never for the caller's own transfers.
            wanted = (wanted or {ApprovalState.PENDING}) & {ApprovalState.PENDING}
            if not wanted:
                return ApprovalPage((), None)
            not_sent_by = caller.user_id
        elif chosen is ApprovalScope.OWN:
            sent_by = caller.user_id
        found = await dlp_approvals.list_requests(
            session,
            now=now,
            sent_by=sent_by,
            not_sent_by=not_sent_by,
            states=wanted,
            before=before,
            limit=limit + 1,
        )
        items = await summaries(session, found, now)
    more = len(items) > limit
    page = tuple(items[:limit])
    return ApprovalPage(page, encode_cursor(page[-1].id) if more else None)


# ---- getApprovalRequest ----


async def get_approval_request(
    database: Database, caller: Caller, request_id: UUID, *, now: datetime
) -> ApprovalRequestView:
    """`getApprovalRequest` (module docstring)."""
    reach = authorize(caller, "getApprovalRequest", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        request = await dlp_approvals.get_request(session, request_id)
        if request is None:
            raise NotFound
        transfer = await transfers.get_transfer(session, request.transfer_id)
        approver = await active_approver(session, caller.user_id)
        if not (reach is Reach.TENANT or approver or transfer.created_by == caller.user_id):
            raise NotFound
        return await _view(session, caller, request, transfer, approver=approver, now=now)


async def _view(
    session: AsyncSession,
    caller: Caller,
    request: Request,
    transfer: Transfer,
    *,
    approver: bool,
    now: datetime,
) -> ApprovalRequestView:
    tenant_id = caller.tenant_id
    assert tenant_id is not None  # noqa: S101 - checked by tenant_scope
    [brief] = await summaries(session, [request], now)
    decision = await dlp_decisions.get_decision(session, request.decision_id)
    justification = await dlp_approvals.justification(session, request.confirmation_id)
    decided = await dlp_approvals.list_decisions(session, request.id)
    listed = [
        f
        for f in await files.list_transfer_files(session, transfer.id)
        if f.state != FileState.REJECTED.value
    ]
    detectors = await findings.detectors_by_file(session, [f.id for f in listed])
    keys = await fields.tenant_keys(session, tenant_id)
    can_decide = (
        approver
        and transfer.created_by != caller.user_id
        and all(d.approver_id != caller.user_id for d in decided)
        and brief.state is ApprovalState.PENDING
    )
    return ApprovalRequestView(
        summary=brief,
        justification=(
            ""
            if justification is None
            else keys.open(fields.JUSTIFICATION, request.confirmation_id, justification)
        ),
        matched_rules=() if decision is None else decision.rules,
        transfer=ApprovalTransferView(
            created_by=transfer.created_by,
            message=keys.open_optional(fields.TRANSFER_MESSAGE, transfer.id, transfer.message_ct),
            expires_at=transfer.expires_at,
            recipients=await recipient_flags(session, transfer.id, decision, now),
            files=tuple(
                ApprovalFileView(
                    id=f.id,
                    display_name=keys.open(fields.FILE_NAME, f.id, f.display_name_ct),
                    size=f.declared_size,
                    inspection_state=InspectionState(f.inspection_state),
                    reasons=tuple(InspectionReason(r) for r in f.inspection_reasons),
                    detectors=tuple(detectors.get(f.id, ())),
                )
                for f in listed
            ),
        ),
        decisions=tuple(
            ApprovalDecisionView(
                approver_id=d.approver_id,
                decision=d.decision,
                comment=None
                if d.comment_ct is None or d.id is None
                else keys.open(fields.APPROVAL_COMMENT, d.id, d.comment_ct),
                decided_at=d.decided_at,
            )
            for d in decided
        ),
        can_decide=can_decide,
    )


# ---- approveTransfer, rejectTransfer ----


async def approve_transfer(
    database: Database,
    caller: Caller,
    request_id: UUID,
    *,
    comment: str | None,
    origin: Origin,
    now: datetime,
) -> ApprovalRequestView:
    """`approveTransfer` (module docstring)."""
    authorize(caller, "approveTransfer", now=now)
    return await _decide(
        database, caller, request_id, ApprovalDecisionKind.APPROVE, comment, origin, now
    )


async def reject_transfer(
    database: Database,
    caller: Caller,
    request_id: UUID,
    *,
    comment: str | None,
    origin: Origin,
    now: datetime,
) -> ApprovalRequestView:
    """`rejectTransfer` (module docstring)."""
    authorize(caller, "rejectTransfer", now=now)
    if not comment:
        detail = "A rejection needs a comment for the sender."
        raise Unprocessable(
            "validation_failed", detail, errors=[FieldError(detail, pointer="#/comment")]
        )
    return await _decide(
        database, caller, request_id, ApprovalDecisionKind.REJECT, comment, origin, now
    )


async def _decide(
    database: Database,
    caller: Caller,
    request_id: UUID,
    kind: ApprovalDecisionKind,
    comment: str | None,
    origin: Origin,
    now: datetime,
) -> ApprovalRequestView:
    """The checks and the decision of both operations, in the order of the module docstring."""
    tenant_id, user_id = caller.tenant_id, caller.user_id
    assert tenant_id is not None  # noqa: S101 - authorize admits only members
    assert user_id is not None  # noqa: S101 - authorize admits only members
    async with database.transaction(tenant_scope(caller)) as session:
        found = await dlp_approvals.get_request(session, request_id)
        if found is None:
            raise NotFound
        try:
            locked = await transfers.lock_for_evaluation(session, found.transfer_id)
        except NotFoundError:  # pragma: no cover - the request's key names the transfer
            raise NotFound from None
        # Read again under the row lock: an approver, the sender or the expiry job may have
        # ended it since.
        request = await dlp_approvals.get_request(session, request_id)
        assert request is not None  # noqa: S101 - it goes only with its transfer
        if not await active_approver(session, user_id):
            raise Forbidden("permission_denied", "Only an active DLP approver decides.")
        if locked.created_by == user_id:
            raise Forbidden(
                "self_approval_forbidden",
                "You sent this transfer, so someone else must decide it.",
            )
        decided = await dlp_approvals.list_decisions(session, request.id)
        mine = [d for d in decided if d.approver_id == user_id]
        if not mine:
            _check_decidable(request, locked, now)
            await _record(session, caller, request, locked, kind, comment, origin, now)
        elif mine[0].decision is not kind:
            raise Conflict(
                "invalid_state",
                "You have decided this request already.",
                current_state=shown_state(request, now).value,
            )
        ended = await dlp_approvals.get_request(session, request_id)
        transfer = await transfers.get_transfer(session, locked.id)
        assert ended is not None  # noqa: S101 - read in this transaction
        return await _view(session, caller, ended, transfer, approver=True, now=now)


def _check_decidable(request: Request, locked: transfers.Locked, now: datetime) -> None:
    state = effective_state(locked.state, locked.expires_at, now)
    if state is TransferState.REVOKED:
        raise Conflict("transfer_revoked", current_state=state.value)
    if state is TransferState.EXPIRED:
        raise Conflict("transfer_expired", current_state=state.value)
    shown = shown_state(request, now)
    if shown is not ApprovalState.PENDING or state is not TransferState.PENDING_APPROVAL:
        raise Conflict(
            "invalid_state",
            "Only a pending approval request can be decided.",
            current_state=shown.value,
        )


async def _record(
    session: AsyncSession,
    caller: Caller,
    request: Request,
    locked: transfers.Locked,
    kind: ApprovalDecisionKind,
    comment: str | None,
    origin: Origin,
    now: datetime,
) -> None:
    """The decision, its consequence for the request and the transfer, and their records."""
    tenant_id, user_id = caller.tenant_id, caller.user_id
    assert tenant_id is not None  # noqa: S101 - checked by the caller
    assert user_id is not None  # noqa: S101 - checked by the caller
    decision_id = uuid7()
    comment_ct = None
    if comment is not None:
        keys = await fields.tenant_keys(session, tenant_id, write=True)
        comment_ct = keys.seal(fields.APPROVAL_COMMENT, decision_id, comment)
    await dlp_approvals.insert_decision(
        session,
        decision_id=decision_id,
        request_id=request.id,
        approver_id=user_id,
        decision=kind,
        comment_ct=comment_ct,
    )
    target = Target(APPROVAL_REQUEST, request.id)
    actor = caller.actor()
    if kind is ApprovalDecisionKind.REJECT:
        await dlp_approvals.end_request(
            session, request.id, to=ApprovalState.REJECTED, ended_at=now
        )
        await transfers.change_state(
            session,
            locked.id,
            from_states=(TransferState.PENDING_APPROVAL,),
            to=TransferState.HELD,
            hold_reason=HoldReason.APPROVAL_REJECTED.value,
        )
        await audit.record(
            session,
            action="dlp_approval.rejected",
            actor=actor,
            target=target,
            origin=origin,
            details={"transfer_id": locked.id, "comment_given": True},
        )
        await audit.record(
            session,
            action="transfer.held",
            actor=actor,
            target=Target(TRANSFER, locked.id),
            origin=origin,
            details={
                "from_state": locked.state,
                "hold_reason": HoldReason.APPROVAL_REJECTED,
                "approval_request_id": request.id,
            },
        )
        await enqueue(session, DLP_APPROVAL_DECIDED, {"approval_request_id": request.id})
        return
    approvals = (await dlp_approvals.approvals(session, [request.id])).get(request.id, 0)
    complete = approvals >= request.approvals_required
    await audit.record(
        session,
        action="dlp_approval.approved",
        actor=actor,
        target=target,
        origin=origin,
        details={
            "transfer_id": locked.id,
            "approvals": approvals,
            "approvals_required": request.approvals_required,
            "complete": complete,
            "comment_given": comment is not None,
        },
    )
    if not complete:
        return  # a rule that needs two approvers waits for the second (FR-44)
    await dlp_approvals.end_request(session, request.id, to=ApprovalState.APPROVED, ended_at=now)
    counted = await files.counted_states(session, locked.id)
    await send(session, locked, [f.id for f in counted])
    await audit.record(
        session,
        action="transfer.sent",
        actor=actor,
        target=Target(TRANSFER, locked.id),
        origin=origin,
        details={
            "from_state": locked.state,
            "files": len(counted),
            "decision_id": locked.dlp_decision_id,
            "approval_request_id": request.id,
        },
    )
    await enqueue(session, DLP_APPROVAL_DECIDED, {"approval_request_id": request.id})
