"""The DLP policy operations of the contract (#218; docs/api/openapi.yaml, tag "Data loss
prevention"): `getDlpPolicy`, `updateDlpPolicy`, `listDlpRules`, `createDlpRule`, `getDlpRule`,
`updateDlpRule`, `deleteDlpRule`, `listDlpDetectors`, `createDlpDetector`, `getDlpDetector`,
`updateDlpDetector` and `deleteDlpDetector`; a transfer's decision, `getTransferDlp` and
`confirmTransfer` (#219, `sft.service.transfer_dlp`). The approval operations (#220) are
`sft.api.approvals`, whose `rejectTransfer` mustn't count against the tenant's budget.

Routes only parse the request and shape the response; the service layer (`sft.service.dlp_policy`)
checks the caller and applies the rules. Every route counts against the caller's and the tenant's
budget (`TENANT_OPERATION`, group H); a write that is made also counts against the tenant's 100
policy changes a day (group K), in the service. The two creating operations take
`Idempotency-Key` (`sft.api.idempotency`). `getTransferDlp` also counts against the caller's 600
reads an hour and `confirmTransfer` against its 30 confirmations a minute (group K).

Built-in detectors are named in the caller's language: Japanese when `Accept-Language` starts
with `ja`, English when it starts with `en`, otherwise the tenant's default language.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Path, Request, Response

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database
from sft.api.dlp_schemas import (
    DlpDetectorCreate,
    DlpDetectorList,
    DlpDetectorOut,
    DlpDetectorUpdate,
    DlpPolicyOut,
    DlpPolicyUpdate,
    DlpRuleCreate,
    DlpRuleList,
    DlpRuleOut,
    DlpRuleUpdate,
    TransferConfirmation,
    TransferDlpOut,
    sent,
)
from sft.api.errors import problem_responses
from sft.api.idempotency import IdempotencyDep
from sft.api.rate_limits import get_rate_limiter, rate_limit
from sft.api.transfer_schemas import _DETECTOR_PATTERN, Transfer
from sft.data.database import Database
from sft.service import dlp_policy, transfer_dlp
from sft.service.caller import Caller
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import (
    CONFIRM_TRANSFER,
    TENANT_OPERATION,
    TRANSFER_DLP_READ,
)

PREFIX: Final = "/v1"
TAG: Final = "Data loss prevention"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)
DLP_READ_LIMITS: Final = rate_limit(TRANSFER_DLP_READ, caller=get_tenant_caller)
CONFIRM_LIMITS: Final = rate_limit(CONFIRM_TRANSFER, caller=get_tenant_caller)
DetectorIdPath = Annotated[str, Path(max_length=71, pattern=_DETECTOR_PATTERN)]

router = APIRouter(prefix=PREFIX, tags=[TAG], dependencies=[TENANT_LIMITS])


def _now() -> datetime:
    return datetime.now(UTC)


def language_of(request: Request) -> str | None:
    """`ja` or `en` from the first language `Accept-Language` names; None for any other."""
    first = request.headers.get("accept-language", "").split(",")[0].strip().lower()
    for language in ("ja", "en"):
        if first == language or first.startswith(f"{language}-"):
            return language
    return None


# ---- the policy's settings ----


@router.get(
    "/dlp/policy",
    operation_id="getDlpPolicy",
    response_model=DlpPolicyOut,
    summary="Get the DLP policy settings",
    responses=problem_responses(401, 403, 429),
)
async def get_dlp_policy(caller: CallerDep, database: DatabaseDep) -> DlpPolicyOut:
    return DlpPolicyOut.of(await dlp_policy.get_dlp_policy(database, caller, now=_now()))


@router.patch(
    "/dlp/policy",
    operation_id="updateDlpPolicy",
    response_model=DlpPolicyOut,
    summary="Update the DLP policy settings",
    responses=problem_responses(400, 401, 403, 409, 422, 429),
)
async def update_dlp_policy(
    body: DlpPolicyUpdate,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
) -> DlpPolicyOut:
    view = await dlp_policy.update_dlp_policy(
        database, caller, body.change(), limiter=limiter, origin=origin_of(request), now=_now()
    )
    return DlpPolicyOut.of(view)


# ---- rules ----


@router.get(
    "/dlp/rules",
    operation_id="listDlpRules",
    response_model=DlpRuleList,
    summary="List the DLP rules",
    responses=problem_responses(401, 403, 429),
)
async def list_dlp_rules(caller: CallerDep, database: DatabaseDep) -> DlpRuleList:
    found = await dlp_policy.list_dlp_rules(database, caller, now=_now())
    return DlpRuleList(
        policy_version=found.policy_version, items=[DlpRuleOut.of(r) for r in found.items]
    )


@router.post(
    "/dlp/rules",
    operation_id="createDlpRule",
    status_code=201,
    response_model=DlpRuleOut,
    summary="Create a DLP rule",
    responses=problem_responses(400, 401, 403, 409, 422, 429),
)
async def create_dlp_rule(
    body: DlpRuleCreate,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
    idempotency: IdempotencyDep,
) -> DlpRuleOut:
    outcome = await dlp_policy.create_dlp_rule(
        database,
        caller,
        body.rule(),
        sent=sent(body),
        limiter=limiter,
        origin=origin_of(request),
        now=_now(),
        idempotency=idempotency,
    )
    response.status_code = outcome.status
    response.headers["Location"] = f"{PREFIX}/dlp/rules/{outcome.value.id}"
    return DlpRuleOut.of(outcome.value)


@router.get(
    "/dlp/rules/{rule_id}",
    operation_id="getDlpRule",
    response_model=DlpRuleOut,
    summary="Get a DLP rule",
    responses=problem_responses(401, 403, 404, 429),
)
async def get_dlp_rule(rule_id: UUID, caller: CallerDep, database: DatabaseDep) -> DlpRuleOut:
    return DlpRuleOut.of(await dlp_policy.get_dlp_rule(database, caller, rule_id, now=_now()))


@router.patch(
    "/dlp/rules/{rule_id}",
    operation_id="updateDlpRule",
    response_model=DlpRuleOut,
    summary="Change a DLP rule",
    responses=problem_responses(400, 401, 403, 404, 409, 422, 429),
)
async def update_dlp_rule(
    rule_id: UUID,
    body: DlpRuleUpdate,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
) -> DlpRuleOut:
    rule = await dlp_policy.update_dlp_rule(
        database,
        caller,
        rule_id,
        body.change(),
        sent=sent(body),
        limiter=limiter,
        origin=origin_of(request),
        now=_now(),
    )
    return DlpRuleOut.of(rule)


@router.delete(
    "/dlp/rules/{rule_id}",
    operation_id="deleteDlpRule",
    status_code=204,
    response_class=Response,
    summary="Delete a DLP rule",
    responses=problem_responses(401, 403, 404, 409, 429),
)
async def delete_dlp_rule(
    rule_id: UUID, request: Request, caller: CallerDep, database: DatabaseDep, limiter: LimiterDep
) -> Response:
    await dlp_policy.delete_dlp_rule(
        database, caller, rule_id, limiter=limiter, origin=origin_of(request), now=_now()
    )
    return Response(status_code=204)


# ---- detectors ----


@router.get(
    "/dlp/detectors",
    operation_id="listDlpDetectors",
    response_model=DlpDetectorList,
    response_model_exclude_unset=True,
    summary="List the DLP detectors",
    responses=problem_responses(401, 403, 429),
)
async def list_dlp_detectors(
    request: Request, caller: CallerDep, database: DatabaseDep
) -> DlpDetectorList:
    found = await dlp_policy.list_dlp_detectors(
        database, caller, language=language_of(request), now=_now()
    )
    return DlpDetectorList(
        engine_version=found.engine_version, items=[DlpDetectorOut.of(d) for d in found.items]
    )


@router.post(
    "/dlp/detectors",
    operation_id="createDlpDetector",
    status_code=201,
    response_model=DlpDetectorOut,
    response_model_exclude_unset=True,
    summary="Add a keyword list or a pattern",
    responses=problem_responses(400, 401, 403, 409, 413, 422, 429),
)
async def create_dlp_detector(
    body: DlpDetectorCreate,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
    idempotency: IdempotencyDep,
) -> DlpDetectorOut:
    outcome = await dlp_policy.create_dlp_detector(
        database,
        caller,
        body.detector(),
        limiter=limiter,
        origin=origin_of(request),
        now=_now(),
        idempotency=idempotency,
    )
    response.status_code = outcome.status
    response.headers["Location"] = f"{PREFIX}/dlp/detectors/{outcome.value.id}"
    return DlpDetectorOut.of(outcome.value)


@router.get(
    "/dlp/detectors/{detector_id}",
    operation_id="getDlpDetector",
    response_model=DlpDetectorOut,
    response_model_exclude_unset=True,
    summary="Get a DLP detector",
    responses=problem_responses(401, 403, 404, 429),
)
async def get_dlp_detector(
    detector_id: DetectorIdPath, request: Request, caller: CallerDep, database: DatabaseDep
) -> DlpDetectorOut:
    view = await dlp_policy.get_dlp_detector(
        database, caller, detector_id, language=language_of(request), now=_now()
    )
    return DlpDetectorOut.of(view)


@router.patch(
    "/dlp/detectors/{detector_id}",
    operation_id="updateDlpDetector",
    response_model=DlpDetectorOut,
    response_model_exclude_unset=True,
    summary="Change a keyword list or a pattern",
    responses=problem_responses(400, 401, 403, 404, 409, 413, 422, 429),
)
async def update_dlp_detector(
    detector_id: DetectorIdPath,
    body: DlpDetectorUpdate,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
) -> DlpDetectorOut:
    view = await dlp_policy.update_dlp_detector(
        database,
        caller,
        detector_id,
        body.change(),
        limiter=limiter,
        origin=origin_of(request),
        now=_now(),
    )
    return DlpDetectorOut.of(view)


@router.delete(
    "/dlp/detectors/{detector_id}",
    operation_id="deleteDlpDetector",
    status_code=204,
    response_class=Response,
    summary="Delete a keyword list or a pattern",
    responses=problem_responses(401, 403, 404, 409, 429),
)
async def delete_dlp_detector(
    detector_id: DetectorIdPath,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
) -> Response:
    await dlp_policy.delete_dlp_detector(
        database, caller, detector_id, limiter=limiter, origin=origin_of(request), now=_now()
    )
    return Response(status_code=204)


# ---- a transfer's decision (#219) ----


@router.get(
    "/transfers/{transfer_id}/dlp",
    operation_id="getTransferDlp",
    response_model=TransferDlpOut,
    response_model_exclude_unset=True,
    summary="Get a transfer's DLP decision and findings",
    dependencies=[DLP_READ_LIMITS],
    responses=problem_responses(401, 403, 404, 429),
)
async def get_transfer_dlp(
    transfer_id: UUID, request: Request, caller: CallerDep, database: DatabaseDep
) -> TransferDlpOut:
    view = await transfer_dlp.get_transfer_dlp(
        database, caller, transfer_id, language=language_of(request), now=_now()
    )
    return TransferDlpOut.of(view)


@router.post(
    "/transfers/{transfer_id}/confirm",
    operation_id="confirmTransfer",
    response_model=Transfer,
    response_model_exclude_unset=True,
    summary="Confirm a DLP warning, or request approval",
    dependencies=[CONFIRM_LIMITS],
    responses=problem_responses(400, 401, 403, 404, 409, 422, 429),
)
async def confirm_transfer(
    transfer_id: UUID,
    body: TransferConfirmation,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
) -> Transfer:
    view = await transfer_dlp.confirm_transfer(
        database,
        caller,
        transfer_id,
        decision_id=body.decision_id,
        justification=body.justification,
        origin=origin_of(request),
        now=_now(),
    )
    return Transfer.of(view)


def register(app: FastAPI) -> None:
    """Add the DLP routes to the public app."""
    app.include_router(router)
