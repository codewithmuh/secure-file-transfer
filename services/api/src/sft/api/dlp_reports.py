"""The DLP report operations of the contract (#222, DLP-7; docs/api/openapi.yaml, tag "Data loss
prevention"): `listDlpDecisions` and `getDlpReport`.

Routes only parse the request and shape the response; `sft.service.dlp_reports` checks the caller
and the range. Both count against the caller's and the tenant's budget (`TENANT_OPERATION`, group
H) and the tenant's 60 report and list reads a minute (group K).
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database
from sft.api.dlp_schemas import DlpDecisionOut, DlpOutcomeName
from sft.api.errors import problem_responses
from sft.api.rate_limits import rate_limit
from sft.data.database import Database
from sft.data.models import DlpOutcome
from sft.service import dlp_reports
from sft.service.caller import Caller
from sft.service.rate_limits.limits import DLP_REPORT_READ, TENANT_OPERATION

PREFIX: Final = "/v1"
TAG: Final = "Data loss prevention"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)
REPORT_LIMITS: Final = rate_limit(DLP_REPORT_READ, caller=get_tenant_caller)

router = APIRouter(prefix=PREFIX, tags=[TAG], dependencies=[TENANT_LIMITS, REPORT_LIMITS])

FromQuery = Annotated[datetime | None, Query(alias="from")]
ToQuery = Annotated[datetime | None, Query(alias="to")]


def _now() -> datetime:
    return datetime.now(UTC)


# ---- bodies (the contract's schemas) ----


class DlpDecisionPage(BaseModel):
    """The contract's `DlpDecisionPage`."""

    items: list[DlpDecisionOut]
    next_cursor: str | None

    @classmethod
    def of(cls, page: dlp_reports.DecisionPage) -> DlpDecisionPage:
        return cls(items=[DlpDecisionOut.of(d) for d in page.items], next_cursor=page.next_cursor)


class DlpCount(BaseModel):
    """One row of a report breakdown: an outcome, rule ID, detector ID, user ID, domain or
    reason, with its count."""

    key: str
    count: int = Field(ge=0)


def _counts(pairs: tuple[tuple[str, int], ...]) -> list[DlpCount]:
    return [DlpCount(key=key, count=count) for key, count in pairs]


class DlpReportDay(BaseModel):
    model_config = ConfigDict(title="DlpReportDay")

    date: date
    by_outcome: list[DlpCount] = Field(max_length=5)


class DlpReportApprover(BaseModel):
    model_config = ConfigDict(title="DlpReportApprover")

    approver_id: UUID
    approved: int = Field(ge=0)
    rejected: int = Field(ge=0)
    median_seconds_to_decide: int | None = Field(ge=0)


class DlpReport(BaseModel):
    """The contract's `DlpReport` (FR-55)."""

    model_config = ConfigDict(validate_by_name=True)

    from_: datetime = Field(alias="from")
    to: datetime
    policy_changes: int = Field(ge=0)
    decisions_by_outcome: list[DlpCount] = Field(max_length=5)
    decisions_by_day: list[DlpReportDay] = Field(max_length=92)
    matches_by_rule: list[DlpCount] = Field(max_length=50)
    matches_by_detector: list[DlpCount] = Field(max_length=70)
    decisions_by_sender: list[DlpCount] = Field(max_length=50)
    decisions_by_recipient_domain: list[DlpCount] = Field(max_length=50)
    approvals_by_approver: list[DlpReportApprover] = Field(max_length=100)
    not_inspected_by_reason: list[DlpCount] = Field(max_length=6)

    @classmethod
    def of(cls, view: dlp_reports.ReportView) -> DlpReport:
        return cls.model_validate(
            {
                "from": view.since,
                "to": view.until,
                "policy_changes": view.policy_changes,
                "decisions_by_outcome": _counts(view.by_outcome),
                "decisions_by_day": [
                    DlpReportDay(date=day, by_outcome=_counts(counts))
                    for day, counts in view.by_day
                ],
                "matches_by_rule": _counts(view.by_rule),
                "matches_by_detector": _counts(view.by_detector),
                "decisions_by_sender": _counts(view.by_sender),
                "decisions_by_recipient_domain": _counts(view.by_recipient_domain),
                "approvals_by_approver": [
                    DlpReportApprover(
                        approver_id=a.approver_id,
                        approved=a.approved,
                        rejected=a.rejected,
                        median_seconds_to_decide=a.median_seconds,
                    )
                    for a in view.approvers
                ],
                "not_inspected_by_reason": _counts(view.not_inspected),
            }
        )


# ---- routes ----


@router.get(
    "/dlp/decisions",
    operation_id="listDlpDecisions",
    response_model=DlpDecisionPage,
    summary="List DLP decisions",
    responses=problem_responses(400, 401, 403, 422, 429),
)
async def list_dlp_decisions(
    caller: CallerDep,
    database: DatabaseDep,
    outcome: Annotated[
        list[DlpOutcomeName] | None,
        Query(max_length=5, json_schema_extra={"uniqueItems": True}),
    ] = None,
    rule_id: UUID | None = None,
    sender_id: UUID | None = None,
    from_: FromQuery = None,
    to: ToQuery = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=dlp_reports.MAX_PAGE)] = 25,
) -> DlpDecisionPage:
    page = await dlp_reports.list_dlp_decisions(
        database,
        caller,
        outcomes=[DlpOutcome(o) for o in outcome or ()],
        rule_id=rule_id,
        sender_id=sender_id,
        since=from_,
        until=to,
        cursor=cursor,
        limit=limit,
        now=_now(),
    )
    return DlpDecisionPage.of(page)


@router.get(
    "/dlp/report",
    operation_id="getDlpReport",
    response_model=DlpReport,
    response_model_by_alias=True,
    summary="Get the DLP report",
    responses=problem_responses(400, 401, 403, 422, 429),
)
async def get_dlp_report(
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    from_: FromQuery = None,
    to: ToQuery = None,
) -> DlpReport:
    view = await dlp_reports.get_dlp_report(
        database, caller, since=from_, until=to, origin=origin_of(request), now=_now()
    )
    return DlpReport.of(view)


def register(app: FastAPI) -> None:
    """Add the DLP report routes to the public app."""
    app.include_router(router)
