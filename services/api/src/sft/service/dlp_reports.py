"""DLP reports: `listDlpDecisions` and `getDlpReport` (#222, DLP-7; FR-54, FR-55, UC-4; authn and
authz 6.3; abuse and rate limits 2.2, K; data model 2.7).

**Who** (`dlp_report.read`): a tenant admin acting as one (a local admin needs a passkey), and an
API key with `audit:read`. A member gets `403`, as does a key without the scope. Every read is in
the caller's tenant scope (`sft.data.dlp_reports`), so another tenant's decisions never appear.

**The range** is `[from, to)`: `to` defaults to now and `from` to 30 days before `to`. `from` must
be before `to` (`422 validation_failed`), and the report covers at most 92 days (`422` beyond).

- **`listDlpDecisions`**: decisions for transfers and received files, newest first, 1 to 100 a
  page, filtered by outcome, a rule that matched, the transfer's owner (`sender_id`, transfers
  only) and time, with an opaque cursor (the last decision's ID, `400 invalid_cursor`). An API
  key's read is recorded by `api_key.used`, as every key's request is.
- **`getDlpReport`**: the breakdowns of `sft.data.dlp_reports.report`, and the number of policy
  changes in the range, counted from the audit log (the `dlp_policy.updated`, `dlp_rule.*` and
  `dlp_detector.*` events). Viewing it writes `dlp.report_viewed` with the range only.

**Exporting decisions** (FR-29): each decision is an audit event (`dlp.decided`, one
`dlp.rule_matched` per rule), so `exportAuditEvents` with `actions: [dlp.decided]` and the same
range exports exactly the decisions the report counts; the report page links to it.

Group K's 60 report and list reads a minute per tenant are the routes'. Nothing here holds an
address, a name, a finding's detail or free text: IDs, domains, enums and counts.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Collection
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Final
from uuid import UUID

from sft.core.errors import FieldError, InvalidRequest, Unprocessable
from sft.data import audit, audit_reads, dlp_reports
from sft.data.audit import Origin, Target
from sft.data.audit_reads import EventFilter
from sft.data.database import Database
from sft.data.dlp_decisions import Decision
from sft.data.dlp_reports import ApproverTotals, DecisionQuery
from sft.data.models import DlpOutcome
from sft.service.caller import Caller
from sft.service.permissions import authorize
from sft.service.transfers import tenant_scope

MAX_PAGE: Final = 100
DEFAULT_RANGE: Final = timedelta(days=30)
MAX_REPORT_RANGE: Final = timedelta(days=92)
REPORT_TARGET: Final = "dlp_report"
POLICY_CHANGE_ACTIONS: Final = (
    "dlp_policy.updated",
    "dlp_rule.created",
    "dlp_rule.changed",
    "dlp_rule.deleted",
    "dlp_detector.created",
    "dlp_detector.changed",
    "dlp_detector.deleted",
)
"""The audit events of a policy change (FR-54): what the report's `policy_changes` counts."""
MAX_POLICY_CHANGES: Final = 1_000_000


def _invalid(detail: str, name: str) -> Unprocessable:
    return Unprocessable("validation_failed", detail, errors=[FieldError(detail, parameter=name)])


@dataclass(frozen=True, slots=True)
class Range:
    since: datetime
    until: datetime


def resolve_range(
    since: datetime | None, until: datetime | None, *, now: datetime, cap: timedelta | None
) -> Range:
    """`[from, to)` with its defaults (module docstring); `422` if it's empty or past `cap`."""
    for name, value in (("from", since), ("to", until)):
        if value is not None and value.tzinfo is None:
            raise _invalid("A time needs its offset, such as Z.", name)
    end = now if until is None else until
    start = end - DEFAULT_RANGE if since is None else since
    if start >= end:
        raise _invalid("`from` is before `to`.", "from")
    if cap is not None and end - start > cap:
        raise _invalid("The report covers at most 92 days.", "from")
    return Range(start, end)


# ---- listDlpDecisions ----


@dataclass(frozen=True, slots=True)
class DecisionPage:
    items: tuple[Decision, ...]
    next_cursor: str | None


def encode_cursor(decision_id: UUID) -> str:
    """An opaque cursor: the last decision of the page."""
    return base64.urlsafe_b64encode(decision_id.bytes).decode().rstrip("=")


def decode_cursor(cursor: str) -> UUID:
    try:
        return UUID(bytes=base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (binascii.Error, ValueError) as exc:
        raise InvalidRequest("invalid_cursor") from exc


async def list_dlp_decisions(
    database: Database,
    caller: Caller,
    *,
    outcomes: Collection[DlpOutcome] = (),
    rule_id: UUID | None = None,
    sender_id: UUID | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    cursor: str | None = None,
    limit: int = 25,
    now: datetime,
) -> DecisionPage:
    """`listDlpDecisions` (module docstring)."""
    authorize(caller, "listDlpDecisions", now=now)
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError("a page holds 1 to 100 decisions")
    window = resolve_range(since, until, now=now, cap=None)
    before = None if cursor is None else decode_cursor(cursor)
    query = DecisionQuery(
        since=window.since,
        until=window.until,
        outcomes=tuple(sorted({o.value for o in outcomes})),
        rule_id=rule_id,
        sender_id=sender_id,
    )
    async with database.transaction(tenant_scope(caller)) as session:
        found = await dlp_reports.list_decisions(session, query, before=before, limit=limit + 1)
    page = found[:limit]
    more = len(found) > limit
    return DecisionPage(tuple(page), encode_cursor(page[-1].id) if more and page else None)


# ---- getDlpReport ----


@dataclass(frozen=True, slots=True)
class ReportView:
    since: datetime
    until: datetime
    policy_changes: int
    by_outcome: tuple[tuple[str, int], ...]
    by_day: tuple[tuple[date, tuple[tuple[str, int], ...]], ...]
    by_rule: tuple[tuple[str, int], ...]
    by_detector: tuple[tuple[str, int], ...]
    by_sender: tuple[tuple[str, int], ...]
    by_recipient_domain: tuple[tuple[str, int], ...]
    approvers: tuple[ApproverTotals, ...]
    not_inspected: tuple[tuple[str, int], ...]


async def get_dlp_report(
    database: Database,
    caller: Caller,
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    origin: Origin,
    now: datetime,
) -> ReportView:
    """`getDlpReport` (module docstring)."""
    authorize(caller, "getDlpReport", now=now)
    window = resolve_range(since, until, now=now, cap=MAX_REPORT_RANGE)
    scope = tenant_scope(caller)
    assert scope.tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        found = await dlp_reports.report(session, since=window.since, until=window.until)
        changes = await audit_reads.count_events(
            session,
            EventFilter(
                occurred_after=window.since,
                occurred_before=window.until,
                actions=POLICY_CHANGE_ACTIONS,
            ),
            until=now,
            cap=MAX_POLICY_CHANGES,
        )
        await audit.record(
            session,
            action="dlp.report_viewed",
            actor=caller.actor(),
            target=Target(REPORT_TARGET, scope.tenant_id),
            origin=origin,
            details={"from": window.since, "to": window.until},
        )
    days: dict[date, list[tuple[str, int]]] = {}
    for day, outcome, count in found.by_day:
        days.setdefault(day, []).append((outcome, count))
    return ReportView(
        since=window.since,
        until=window.until,
        policy_changes=changes,
        by_outcome=tuple(found.by_outcome),
        by_day=tuple((day, tuple(counts)) for day, counts in sorted(days.items())),
        by_rule=tuple((str(rule), count) for rule, count in found.by_rule),
        by_detector=tuple(found.by_detector),
        by_sender=tuple((str(sender), count) for sender, count in found.by_sender),
        by_recipient_domain=tuple(found.by_recipient_domain),
        approvers=tuple(found.approvers),
        not_inspected=tuple(found.not_inspected),
    )
