"""The DLP approval operations of the contract (#220; docs/api/openapi.yaml, tag "Data loss
prevention"): `listApprovalRequests`, `getApprovalRequest`, `approveTransfer` and `rejectTransfer`
(`sft.service.approvals`). `confirmTransfer`, which makes a request, is `sft.api.dlp`'s.

Routes only parse the request and shape the response; the service layer checks the caller and
applies the rules. Rate limits (abuse 2.2): the reads and `approveTransfer` count against the
caller's and the tenant's budget (`TENANT_OPERATION`, group H); both decisions against the
approver's 120 an hour (group K). `rejectTransfer` only stops sharing, so, like a revocation, it
counts only against the caller's own limit (`SAFETY_ACTION`) and never the tenant's.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Query, Request

from sft.api.approval_schemas import (
    ApprovalApprove,
    ApprovalReject,
    ApprovalRequestOut,
    ApprovalRequestPageOut,
    ApprovalStateName,
)
from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database
from sft.api.errors import problem_responses
from sft.api.rate_limits import rate_limit
from sft.data.database import Database
from sft.data.models import ApprovalState
from sft.service import approvals
from sft.service.approvals import ApprovalScope
from sft.service.caller import Caller
from sft.service.rate_limits.limits import APPROVAL_DECISION, SAFETY_ACTION, TENANT_OPERATION

PREFIX: Final = "/v1"
TAG: Final = "Data loss prevention"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)
SAFETY_LIMITS: Final = rate_limit(SAFETY_ACTION, caller=get_tenant_caller)
DECISION_LIMITS: Final = rate_limit(APPROVAL_DECISION, caller=get_tenant_caller)

router = APIRouter(prefix=PREFIX, tags=[TAG])


def _now() -> datetime:
    return datetime.now(UTC)


@router.get(
    "/dlp/approval-requests",
    operation_id="listApprovalRequests",
    response_model=ApprovalRequestPageOut,
    summary="List DLP approval requests",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 429),
)
async def list_approval_requests(
    caller: CallerDep,
    database: DatabaseDep,
    scope: Annotated[ApprovalScope | None, Query()] = None,
    state: Annotated[
        list[ApprovalStateName] | None,
        Query(max_length=5, json_schema_extra={"uniqueItems": True}),
    ] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=approvals.MAX_PAGE)] = 25,
) -> ApprovalRequestPageOut:
    """One page of approval requests, newest first (FR-43, FR-55)."""
    page = await approvals.list_approval_requests(
        database,
        caller,
        scope=scope,
        states=[ApprovalState(s) for s in state or ()],
        cursor=cursor,
        limit=limit,
        now=_now(),
    )
    return ApprovalRequestPageOut.of(page)


@router.get(
    "/dlp/approval-requests/{approval_request_id}",
    operation_id="getApprovalRequest",
    response_model=ApprovalRequestOut,
    summary="Get a DLP approval request",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 404, 429),
)
async def get_approval_request(
    approval_request_id: UUID, caller: CallerDep, database: DatabaseDep
) -> ApprovalRequestOut:
    view = await approvals.get_approval_request(database, caller, approval_request_id, now=_now())
    return ApprovalRequestOut.of(view)


@router.post(
    "/dlp/approval-requests/{approval_request_id}/approve",
    operation_id="approveTransfer",
    response_model=ApprovalRequestOut,
    summary="Approve a transfer",
    dependencies=[TENANT_LIMITS, DECISION_LIMITS],
    responses=problem_responses(400, 401, 403, 404, 409, 422, 429),
)
async def approve_transfer(
    approval_request_id: UUID,
    body: ApprovalApprove,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
) -> ApprovalRequestOut:
    view = await approvals.approve_transfer(
        database,
        caller,
        approval_request_id,
        comment=body.comment,
        origin=origin_of(request),
        now=_now(),
    )
    return ApprovalRequestOut.of(view)


@router.post(
    "/dlp/approval-requests/{approval_request_id}/reject",
    operation_id="rejectTransfer",
    response_model=ApprovalRequestOut,
    summary="Reject a transfer",
    dependencies=[SAFETY_LIMITS, DECISION_LIMITS],
    responses=problem_responses(400, 401, 403, 404, 409, 422, 429),
)
async def reject_transfer(
    approval_request_id: UUID,
    body: ApprovalReject,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
) -> ApprovalRequestOut:
    view = await approvals.reject_transfer(
        database,
        caller,
        approval_request_id,
        comment=body.comment,
        origin=origin_of(request),
        now=_now(),
    )
    return ApprovalRequestOut.of(view)


def register(app: FastAPI) -> None:
    """Add the approval routes to the public app."""
    app.include_router(router)
