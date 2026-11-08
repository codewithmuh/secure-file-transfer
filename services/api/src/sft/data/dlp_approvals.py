"""Data access for DLP approvals: `dlp_approval_requests` and `dlp_approval_decisions` (#220;
data model 2.7, 3.2, 3.6, 5, 6; revision 0026).

- **The API** (`sft.service.approvals`, `sft.service.transfer_dlp`, the withdrawals of
  `sft.service.evaluation`) writes a request with its confirmation, the approvers' decisions, and
  ends a request, always under the transfer's row lock, which the caller holds. It reads requests
  for the queue and the request page, with the approvals so far and the names of the rules that
  asked for approval, and the tenant's eligible approvers.
- **The expiry job** (`sft_jobs`) finds pending requests past `expires_at` across tenants, in
  system scope, and ends each in its tenant's scope; it also ends the pending request of a
  transfer that expires. It reads only the columns revision 0026 grants it, never a
  justification, comment or decision.
- **The notification worker** (`sft_notify`) reads a request's transfer and state (`notice`).

Every function filters with `in_scope`, and every write takes its tenant from the scope.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import ColumnElement, and_, func, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import (
    ApprovalDecisionKind,
    ApprovalState,
    DlpAction,
    DlpApprovalDecision,
    DlpApprovalRequest,
    DlpConfirmation,
    DlpDecisionRule,
    DlpRule,
    Transfer,
    User,
    UserStatus,
)
from sft.data.scope import ScopeKind

_TENANT = (ScopeKind.TENANT,)
_PENDING = ApprovalState.PENDING.value


@dataclass(frozen=True, slots=True)
class Request:
    """An approval request as the API reads it."""

    id: UUID
    transfer_id: UUID
    decision_id: UUID
    confirmation_id: UUID
    requested_by: UUID
    approvals_required: int
    state: ApprovalState
    created_at: datetime
    expires_at: datetime
    ended_at: datetime | None


def _request(row: DlpApprovalRequest) -> Request:
    return Request(
        id=row.id,
        transfer_id=row.transfer_id,
        decision_id=row.decision_id,
        confirmation_id=row.confirmation_id,
        requested_by=row.requested_by,
        approvals_required=row.approvals_required,
        state=ApprovalState(row.state),
        created_at=row.created_at,
        expires_at=row.expires_at,
        ended_at=row.ended_at,
    )


# ---- requests (sft_api, under the transfer's row lock) ----


async def insert_request(
    session: AsyncSession,
    *,
    request_id: UUID,
    transfer_id: UUID,
    decision_id: UUID,
    confirmation_id: UUID,
    requested_by: UUID,
    approvals_required: int,
    expires_at: datetime,
) -> None:
    """A pending request of the scope's tenant. A second pending request for the transfer breaks
    the partial unique index (`IntegrityError`); commits only with its audit event."""
    require_scope(session, *_TENANT)
    await session.execute(
        insert(DlpApprovalRequest).values(
            id=request_id,
            tenant_id=tenant_of(session),
            transfer_id=transfer_id,
            decision_id=decision_id,
            confirmation_id=confirmation_id,
            requested_by=requested_by,
            approvals_required=approvals_required,
            expires_at=expires_at,
        )
    )


async def count_requests(session: AsyncSession, transfer_id: UUID) -> int:
    """How many requests the transfer has had, in any state: at most 3 (FR-43)."""
    require_scope(session, *_TENANT)
    count = await session.scalar(
        select(func.count()).where(
            DlpApprovalRequest.transfer_id == transfer_id, in_scope(DlpApprovalRequest, session)
        )
    )
    return int(count or 0)


async def get_request(session: AsyncSession, request_id: UUID) -> Request | None:
    """The request, read again from the database; None if the scope doesn't reach it."""
    require_scope(session, *_TENANT)
    row: DlpApprovalRequest | None = await session.scalar(
        select(DlpApprovalRequest)
        .where(DlpApprovalRequest.id == request_id, in_scope(DlpApprovalRequest, session))
        .execution_options(populate_existing=True)
    )
    return None if row is None else _request(row)


async def latest_request(session: AsyncSession, transfer_id: UUID) -> Request | None:
    """The transfer's latest request, in whatever state, or None (the contract's
    `TransferDlp.approval_request`)."""
    require_scope(session, *_TENANT)
    row: DlpApprovalRequest | None = await session.scalar(
        select(DlpApprovalRequest)
        .where(DlpApprovalRequest.transfer_id == transfer_id, in_scope(DlpApprovalRequest, session))
        .order_by(DlpApprovalRequest.created_at.desc(), DlpApprovalRequest.id.desc())
        .limit(1)
        .execution_options(populate_existing=True)
    )
    return None if row is None else _request(row)


async def end_request(
    session: AsyncSession,
    request_id: UUID,
    *,
    to: ApprovalState,
    ended_at: datetime,
    due_by: datetime | None = None,
) -> bool:
    """End the request in state `to` if it is still pending (and, with `due_by`, past its
    `expires_at` then); False if it wasn't. The caller holds the transfer's row lock and writes the
    audit event. Runs as `sft_api` and as `sft_jobs`."""
    require_scope(session, *_TENANT)
    if to is ApprovalState.PENDING:
        raise ValueError("a request ends in a state other than pending")
    statement = update(DlpApprovalRequest).where(
        DlpApprovalRequest.id == request_id,
        DlpApprovalRequest.state == _PENDING,
        in_scope(DlpApprovalRequest, session),
    )
    if due_by is not None:
        statement = statement.where(DlpApprovalRequest.expires_at <= due_by)
    result = await session.execute(
        statement.values(state=to.value, ended_at=ended_at)
        .returning(DlpApprovalRequest.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def end_pending(
    session: AsyncSession, transfer_id: UUID, *, to: ApprovalState, ended_at: datetime
) -> UUID | None:
    """End the transfer's pending request, if it has one, in state `to` (withdrawn when a file is
    removed or the transfer cancelled or revoked, expired when the transfer expires); its ID, or
    None. Runs as `sft_api` and as `sft_jobs`, under the transfer's row lock."""
    require_scope(session, *_TENANT)
    if to is ApprovalState.PENDING:
        raise ValueError("a request ends in a state other than pending")
    result = await session.execute(
        update(DlpApprovalRequest)
        .where(
            DlpApprovalRequest.transfer_id == transfer_id,
            DlpApprovalRequest.state == _PENDING,
            in_scope(DlpApprovalRequest, session),
        )
        .values(state=to.value, ended_at=ended_at)
        .returning(DlpApprovalRequest.id)
        .execution_options(synchronize_session=False)
    )
    row = result.first()
    return None if row is None else row[0]


def _shows_as(state: ApprovalState, now: datetime) -> ColumnElement[bool]:
    """Requests the API shows in `state` at `now`: a pending request past `expires_at` shows as
    expired before the expiry job records it, as a transfer does (data model 3.2)."""
    past = and_(DlpApprovalRequest.state == _PENDING, DlpApprovalRequest.expires_at <= now)
    if state is ApprovalState.EXPIRED:
        return or_(DlpApprovalRequest.state == state.value, past)
    if state is ApprovalState.PENDING:
        return and_(DlpApprovalRequest.state == _PENDING, DlpApprovalRequest.expires_at > now)
    return DlpApprovalRequest.state == state.value


async def list_requests(
    session: AsyncSession,
    *,
    now: datetime,
    sent_by: UUID | None = None,
    not_sent_by: UUID | None = None,
    states: Collection[ApprovalState] = (),
    before: UUID | None = None,
    limit: int,
) -> list[Request]:
    """Up to `limit` requests of the scope's tenant, newest first, before the request `before`:
    only those for transfers `sent_by` made, or not made by `not_sent_by`, if given, and only
    those that show in one of `states` at `now`."""
    require_scope(session, *_TENANT)
    statement = select(DlpApprovalRequest).where(in_scope(DlpApprovalRequest, session))
    if sent_by is not None or not_sent_by is not None:
        statement = statement.join(
            Transfer,
            and_(Transfer.id == DlpApprovalRequest.transfer_id, in_scope(Transfer, session)),
        )
        if sent_by is not None:
            statement = statement.where(Transfer.created_by == sent_by)
        if not_sent_by is not None:
            statement = statement.where(Transfer.created_by != not_sent_by)
    if states:
        statement = statement.where(or_(*(_shows_as(state, now) for state in states)))
    if before is not None:
        statement = statement.where(DlpApprovalRequest.id < before)
    rows = await session.scalars(statement.order_by(DlpApprovalRequest.id.desc()).limit(limit))
    return [_request(row) for row in rows]


# ---- what a request shows ----


async def approvals(session: AsyncSession, request_ids: Sequence[UUID]) -> dict[UUID, int]:
    """Each request's approvals so far."""
    require_scope(session, *_TENANT)
    if not request_ids:
        return {}
    rows = await session.execute(
        select(DlpApprovalDecision.approval_request_id, func.count())
        .where(
            DlpApprovalDecision.approval_request_id.in_(list(request_ids)),
            DlpApprovalDecision.decision == ApprovalDecisionKind.APPROVE.value,
            in_scope(DlpApprovalDecision, session),
        )
        .group_by(DlpApprovalDecision.approval_request_id)
    )
    return {request_id: int(count) for request_id, count in rows.tuples()}


def _approval_rules(session: AsyncSession) -> ColumnElement[bool]:
    """The decision's matched rules that asked for approval, joined to their revisions."""
    return and_(
        DlpRule.tenant_id == DlpDecisionRule.tenant_id,
        DlpRule.id == DlpDecisionRule.rule_id,
        DlpRule.revision == DlpDecisionRule.rule_revision,
        DlpDecisionRule.action == DlpAction.REQUIRE_APPROVAL.value,
        in_scope(DlpRule, session),
    )


async def rule_names(session: AsyncSession, decision_ids: Sequence[UUID]) -> dict[UUID, list[str]]:
    """For each decision, the names of the rules that asked for approval, as their revisions
    were (the contract's `ApprovalRequestSummary.rule_names`)."""
    require_scope(session, *_TENANT)
    if not decision_ids:
        return {}
    rows = await session.execute(
        select(DlpDecisionRule.decision_id, DlpRule.name)
        .join(DlpRule, _approval_rules(session))
        .where(
            DlpDecisionRule.decision_id.in_(list(decision_ids)),
            in_scope(DlpDecisionRule, session),
        )
        .order_by(DlpDecisionRule.decision_id, DlpDecisionRule.rule_id)
    )
    found: dict[UUID, list[str]] = {}
    for decision_id, name in rows.tuples():
        found.setdefault(decision_id, []).append(name)
    return found


async def approvals_required(session: AsyncSession, decision_id: UUID) -> int:
    """The approvals a decision needs: the most any of its approval rules asks, one or two
    (FR-44); 1 if none says."""
    require_scope(session, *_TENANT)
    found = await session.scalar(
        select(func.max(DlpRule.approvals_required))
        .select_from(DlpDecisionRule)
        .join(DlpRule, _approval_rules(session))
        .where(DlpDecisionRule.decision_id == decision_id, in_scope(DlpDecisionRule, session))
    )
    return int(found or 1)


async def justification(session: AsyncSession, confirmation_id: UUID) -> bytes | None:
    """The sealed justification of a request's confirmation (FR-43), for the API to open."""
    require_scope(session, *_TENANT)
    found: bytes | None = await session.scalar(
        select(DlpConfirmation.justification_ct).where(
            DlpConfirmation.id == confirmation_id, in_scope(DlpConfirmation, session)
        )
    )
    return found


# ---- decisions ----


@dataclass(frozen=True, slots=True)
class ApproverDecision:
    approver_id: UUID
    decision: ApprovalDecisionKind
    comment_ct: bytes | None
    decided_at: datetime


async def insert_decision(
    session: AsyncSession,
    *,
    decision_id: UUID,
    request_id: UUID,
    approver_id: UUID,
    decision: ApprovalDecisionKind,
    comment_ct: bytes | None,
) -> None:
    """One approver's decision on a request of the scope's tenant; the comment arrives sealed
    (`sft.service.fields`). A second one by the same approver breaks the unique key."""
    require_scope(session, *_TENANT)
    await session.execute(
        insert(DlpApprovalDecision).values(
            id=decision_id,
            tenant_id=tenant_of(session),
            approval_request_id=request_id,
            approver_id=approver_id,
            decision=decision.value,
            comment_ct=comment_ct,
        )
    )


async def list_decisions(session: AsyncSession, request_id: UUID) -> list[ApproverDecision]:
    """The request's decisions, oldest first."""
    require_scope(session, *_TENANT)
    rows = await session.scalars(
        select(DlpApprovalDecision)
        .where(
            DlpApprovalDecision.approval_request_id == request_id,
            in_scope(DlpApprovalDecision, session),
        )
        .order_by(DlpApprovalDecision.decided_at, DlpApprovalDecision.id)
    )
    return [
        ApproverDecision(
            approver_id=row.approver_id,
            decision=ApprovalDecisionKind(row.decision),
            comment_ct=row.comment_ct,
            decided_at=row.decided_at,
        )
        for row in rows
    ]


# ---- approvers ----


async def eligible_approvers(session: AsyncSession, *, sender: UUID) -> list[UUID]:
    """The tenant's active approvers other than the transfer's sender (data model 2.7), oldest
    first."""
    require_scope(session, *_TENANT)
    rows = await session.scalars(
        select(User.id)
        .where(
            User.dlp_approver.is_(True),
            User.status == UserStatus.ACTIVE.value,
            User.id != sender,
            in_scope(User, session),
        )
        .order_by(User.id)
    )
    return list(rows)


# ---- the expiry job (sft_jobs, data model 6) ----


@dataclass(frozen=True, slots=True)
class Due:
    tenant_id: UUID
    request_id: UUID
    transfer_id: UUID


async def due_for_expiry(session: AsyncSession, *, now: datetime, limit: int) -> list[Due]:
    """Pending requests past `expires_at`, across tenants: the expiry job's find step, in system
    scope (data model 3.6, 6)."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.execute(
        select(DlpApprovalRequest.tenant_id, DlpApprovalRequest.id, DlpApprovalRequest.transfer_id)
        .where(
            DlpApprovalRequest.state == _PENDING,
            DlpApprovalRequest.expires_at <= now,
            in_scope(DlpApprovalRequest, session),
        )
        .order_by(DlpApprovalRequest.expires_at)
        .limit(limit)
    )
    return [Due(r.tenant_id, r.id, r.transfer_id) for r in rows]


# ---- the notification worker (sft_notify) ----


@dataclass(frozen=True, slots=True)
class Notice:
    """What a notice about a request needs: its transfer and state, nothing the sender wrote."""

    id: UUID
    transfer_id: UUID
    state: ApprovalState


async def notice(session: AsyncSession, request_id: UUID) -> Notice | None:
    """The request as a notice sees it, reading only the columns the notification worker may
    read (revision 0026); None if the scope doesn't reach it."""
    require_scope(session, *_TENANT)
    row = (
        await session.execute(
            select(
                DlpApprovalRequest.id, DlpApprovalRequest.transfer_id, DlpApprovalRequest.state
            ).where(DlpApprovalRequest.id == request_id, in_scope(DlpApprovalRequest, session))
        )
    ).first()
    return None if row is None else Notice(row[0], row[1], ApprovalState(row[2]))
