"""Data access for the DLP reports: `listDlpDecisions` and `getDlpReport` (#222, DLP-7; FR-55;
data model 2.7, 5).

Every query is the API's (`sft_api`), in the caller's tenant scope, filtered with `in_scope`, over
a range of `decided_at` (or of the approval decision's or the file's own time), using the indexes
of data model 5: `dlp_decisions (tenant_id, decided_at DESC)`, the decision rules' primary key,
`dlp_findings (tenant_id, file_id, detector)` and `(tenant_id, transfer_id, detector)`,
`dlp_approval_decisions (tenant_id, approver_id, decided_at)` and `transfer_recipients (tenant_id,
transfer_id, …)`.

Nothing here reads a finding's details, a justification, a comment or an address: decisions are
IDs, enums and counts. **Recipient domains** are looked up at read time from the transfers'
recipients (data model 2.7 keeps only the counts on a decision), so a purged transfer's decisions
drop out of that one breakdown; the others still count them.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, datetime
from typing import Final
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    Date,
    and_,
    cast,
    distinct,
    func,
    literal,
    select,
    union_all,
)
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope
from sft.data.dlp_decisions import Decision, DecisionRule
from sft.data.models import (
    DlpApprovalDecision,
    DlpApprovalRequest,
    DlpDecision,
    DlpDecisionRule,
    DlpFinding,
    DlpRule,
    File,
    FileState,
    InspectionState,
    Transfer,
    TransferRecipient,
)
from sft.data.scope import ScopeKind

_TENANT = (ScopeKind.TENANT,)
TOP: Final = 50
"""The largest of the sender and recipient-domain breakdowns (the contract's `maxItems`)."""


# ---- listDlpDecisions ----


@dataclass(frozen=True, slots=True)
class DecisionQuery:
    """The filters of `listDlpDecisions`: outcomes, a rule that matched, the transfer's owner, and
    `[since, until)` of `decided_at`."""

    since: datetime
    until: datetime
    outcomes: tuple[str, ...] = ()
    rule_id: UUID | None = None
    sender_id: UUID | None = None


def _in_range(session: AsyncSession, query: DecisionQuery) -> list[ColumnElement[bool]]:
    conditions = [
        DlpDecision.decided_at >= query.since,
        DlpDecision.decided_at < query.until,
        in_scope(DlpDecision, session),
    ]
    if query.outcomes:
        conditions.append(DlpDecision.outcome.in_(list(query.outcomes)))
    if query.rule_id is not None:
        conditions.append(
            select(literal(1))
            .where(
                DlpDecisionRule.decision_id == DlpDecision.id,
                DlpDecisionRule.rule_id == query.rule_id,
                in_scope(DlpDecisionRule, session),
            )
            .exists()
        )
    if query.sender_id is not None:
        conditions.append(
            DlpDecision.transfer_id.in_(
                select(Transfer.id).where(
                    Transfer.created_by == query.sender_id, in_scope(Transfer, session)
                )
            )
        )
    return conditions


async def list_decisions(
    session: AsyncSession, query: DecisionQuery, *, before: UUID | None, limit: int
) -> list[Decision]:
    """Up to `limit` decisions that match, newest first (their IDs are time-ordered UUIDv7s),
    older than `before`, each with the rules it matched as their revisions were."""
    require_scope(session, *_TENANT)
    conditions = _in_range(session, query)
    if before is not None:
        conditions.append(DlpDecision.id < before)
    found = list(
        await session.scalars(
            select(DlpDecision)
            .where(and_(*conditions))
            .order_by(DlpDecision.id.desc())
            .limit(limit)
        )
    )
    rules: dict[UUID, list[DecisionRule]] = defaultdict(list)
    if found:
        rows = await session.execute(
            select(
                DlpDecisionRule.decision_id,
                DlpDecisionRule.rule_id,
                DlpDecisionRule.rule_revision,
                DlpRule.name,
                DlpRule.condition,
                DlpDecisionRule.action,
                DlpDecisionRule.matched_count,
                DlpRule.threshold,
            )
            .join(
                DlpRule,
                and_(
                    DlpRule.tenant_id == DlpDecisionRule.tenant_id,
                    DlpRule.id == DlpDecisionRule.rule_id,
                    DlpRule.revision == DlpDecisionRule.rule_revision,
                    in_scope(DlpRule, session),
                ),
            )
            .where(
                DlpDecisionRule.decision_id.in_([d.id for d in found]),
                in_scope(DlpDecisionRule, session),
            )
            .order_by(DlpDecisionRule.decision_id, DlpDecisionRule.rule_id)
        )
        for row in rows.tuples():
            rules[row[0]].append(DecisionRule(*row[1:]))
    return [
        Decision(
            id=d.id,
            transfer_id=d.transfer_id,
            file_id=d.file_id,
            policy_version=d.policy_version,
            mode=d.mode,
            outcome=d.outcome,
            enforced=d.enforced,
            untrusted_recipients=d.untrusted_recipients,
            new_domains=d.new_domains,
            decided_at=d.decided_at,
            rules=tuple(rules.get(d.id, ())),
        )
        for d in found
    ]


# ---- getDlpReport ----


@dataclass(frozen=True, slots=True)
class ApproverTotals:
    approver_id: UUID
    approved: int
    rejected: int
    median_seconds: int | None


@dataclass(frozen=True, slots=True)
class Report:
    """Every breakdown of FR-55 for one range, as (key, count) pairs, largest first."""

    by_outcome: list[tuple[str, int]]
    by_day: list[tuple[date, str, int]]
    by_rule: list[tuple[UUID, int]]
    by_detector: list[tuple[str, int]]
    by_sender: list[tuple[UUID, int]]
    by_recipient_domain: list[tuple[str, int]]
    approvers: list[ApproverTotals]
    not_inspected: list[tuple[str, int]]


def _range(session: AsyncSession, since: datetime, until: datetime) -> list[ColumnElement[bool]]:
    return _in_range(session, DecisionQuery(since=since, until=until))


async def report(session: AsyncSession, *, since: datetime, until: datetime) -> Report:
    """The report's breakdowns over decisions made in `[since, until)` (module docstring).

    - **By outcome and by day** (the day in UTC): every decision, for transfers and received
      files.
    - **By rule**: the decisions each rule matched in, at any revision.
    - **By detector**: the decisions whose subject a detector matched in: a transfer's counted
      files and message, or a received file.
    - **By sender** (transfers only) and **by recipient domain** (each domain once per decision):
      the 50 largest.
    - **Approvals by approver**: the approvals and rejections each approver made in the range,
      with the median time from the request to their decision.
    - **Not fully inspected, by reason**: the files scanned in the range whose inspection was
      `partial` or `not_inspected`, each reason counted once per file.
    """
    require_scope(session, *_TENANT)
    in_range = _range(session, since, until)

    by_outcome = [
        (row[0], int(row[1]))
        for row in (
            await session.execute(
                select(DlpDecision.outcome, func.count())
                .where(*in_range)
                .group_by(DlpDecision.outcome)
                .order_by(func.count().desc(), DlpDecision.outcome)
            )
        ).tuples()
    ]
    day = cast(func.timezone("UTC", DlpDecision.decided_at), Date)
    by_day = [
        (row[0], row[1], int(row[2]))
        for row in (
            await session.execute(
                select(day, DlpDecision.outcome, func.count())
                .where(*in_range)
                .group_by(day, DlpDecision.outcome)
                .order_by(day, DlpDecision.outcome)
            )
        ).tuples()
    ]
    by_rule = [
        (row[0], int(row[1]))
        for row in (
            await session.execute(
                select(DlpDecisionRule.rule_id, func.count())
                .join(
                    DlpDecision,
                    and_(
                        DlpDecision.tenant_id == DlpDecisionRule.tenant_id,
                        DlpDecision.id == DlpDecisionRule.decision_id,
                    ),
                )
                .where(*in_range, in_scope(DlpDecisionRule, session))
                .group_by(DlpDecisionRule.rule_id)
                .order_by(func.count().desc(), DlpDecisionRule.rule_id)
                .limit(TOP)
            )
        ).tuples()
    ]
    by_detector = await _by_detector(session, in_range)
    by_sender = [
        (row[0], int(row[1]))
        for row in (
            await session.execute(
                select(Transfer.created_by, func.count())
                .join(
                    DlpDecision,
                    and_(
                        DlpDecision.tenant_id == Transfer.tenant_id,
                        DlpDecision.transfer_id == Transfer.id,
                    ),
                )
                .where(*in_range, in_scope(Transfer, session))
                .group_by(Transfer.created_by)
                .order_by(func.count().desc(), Transfer.created_by)
                .limit(TOP)
            )
        ).tuples()
    ]
    domains = (
        select(
            DlpDecision.id.label("decision_id"),
            TransferRecipient.domain.label("domain"),
        )
        .join(
            TransferRecipient,
            and_(
                TransferRecipient.tenant_id == DlpDecision.tenant_id,
                TransferRecipient.transfer_id == DlpDecision.transfer_id,
            ),
        )
        .where(
            *in_range, TransferRecipient.domain.is_not(None), in_scope(TransferRecipient, session)
        )
        .distinct()
        .subquery()
    )
    by_recipient_domain = [
        (row[0], int(row[1]))
        for row in (
            await session.execute(
                select(domains.c.domain, func.count())
                .group_by(domains.c.domain)
                .order_by(func.count().desc(), domains.c.domain)
                .limit(TOP)
            )
        ).tuples()
    ]
    return Report(
        by_outcome=by_outcome,
        by_day=by_day,
        by_rule=by_rule,
        by_detector=by_detector,
        by_sender=by_sender,
        by_recipient_domain=by_recipient_domain,
        approvers=await _approvers(session, since, until),
        not_inspected=await _not_inspected(session, since, until),
    )


async def _by_detector(
    session: AsyncSession, in_range: Sequence[ColumnElement[bool]]
) -> list[tuple[str, int]]:
    """Per detector, the decisions in range whose subject it matched in."""
    # A transfer's decision: its files' findings and its message's.
    transfer_files = (
        select(DlpDecision.id.label("decision_id"), DlpFinding.detector.label("detector"))
        .join(
            File,
            and_(
                File.tenant_id == DlpDecision.tenant_id, File.transfer_id == DlpDecision.transfer_id
            ),
        )
        .join(
            DlpFinding, and_(DlpFinding.tenant_id == File.tenant_id, DlpFinding.file_id == File.id)
        )
        .where(
            *in_range,
            File.removed_at.is_(None),
            File.state != FileState.REJECTED.value,
            in_scope(File, session),
            in_scope(DlpFinding, session),
        )
    )
    messages = (
        select(DlpDecision.id.label("decision_id"), DlpFinding.detector.label("detector"))
        .join(
            DlpFinding,
            and_(
                DlpFinding.tenant_id == DlpDecision.tenant_id,
                DlpFinding.transfer_id == DlpDecision.transfer_id,
            ),
        )
        .where(*in_range, in_scope(DlpFinding, session))
    )
    received = (
        select(DlpDecision.id.label("decision_id"), DlpFinding.detector.label("detector"))
        .join(
            DlpFinding,
            and_(
                DlpFinding.tenant_id == DlpDecision.tenant_id,
                DlpFinding.file_id == DlpDecision.file_id,
            ),
        )
        .where(*in_range, in_scope(DlpFinding, session))
    )
    matched = union_all(transfer_files, messages, received).subquery()
    rows = await session.execute(
        select(matched.c.detector, func.count(distinct(matched.c.decision_id)))
        .group_by(matched.c.detector)
        .order_by(func.count(distinct(matched.c.decision_id)).desc(), matched.c.detector)
        .limit(70)
    )
    return [(row[0], int(row[1])) for row in rows.tuples()]


async def _approvers(
    session: AsyncSession, since: datetime, until: datetime
) -> list[ApproverTotals]:
    seconds = func.extract("epoch", DlpApprovalDecision.decided_at - DlpApprovalRequest.created_at)
    rows = await session.execute(
        select(
            DlpApprovalDecision.approver_id,
            func.count().filter(DlpApprovalDecision.decision == "approve"),
            func.count().filter(DlpApprovalDecision.decision == "reject"),
            func.percentile_cont(0.5).within_group(seconds),
        )
        .join(
            DlpApprovalRequest,
            and_(
                DlpApprovalRequest.tenant_id == DlpApprovalDecision.tenant_id,
                DlpApprovalRequest.id == DlpApprovalDecision.approval_request_id,
            ),
        )
        .where(
            DlpApprovalDecision.decided_at >= since,
            DlpApprovalDecision.decided_at < until,
            in_scope(DlpApprovalDecision, session),
            in_scope(DlpApprovalRequest, session),
        )
        .group_by(DlpApprovalDecision.approver_id)
        .order_by(func.count().desc(), DlpApprovalDecision.approver_id)
        .limit(100)
    )
    return [
        ApproverTotals(
            approver_id=row[0],
            approved=int(row[1]),
            rejected=int(row[2]),
            median_seconds=None if row[3] is None else max(0, round(float(row[3]))),
        )
        for row in rows.tuples()
    ]


NOT_FULLY: Final = (InspectionState.PARTIAL.value, InspectionState.NOT_INSPECTED.value)


async def _not_inspected(
    session: AsyncSession, since: datetime, until: datetime
) -> list[tuple[str, int]]:
    reason = func.unnest(File.inspection_reasons).table_valued("reason").render_derived()
    rows = await session.execute(
        select(reason.c.reason, func.count(distinct(File.id)))
        .select_from(File)
        .join(reason, literal(True))
        .where(
            File.scanned_at >= since,
            File.scanned_at < until,
            File.inspection_state.in_(NOT_FULLY),
            in_scope(File, session),
        )
        .group_by(reason.c.reason)
        .order_by(func.count(distinct(File.id)).desc(), reason.c.reason)
    )
    return [(row[0], int(row[1])) for row in rows.tuples()]
