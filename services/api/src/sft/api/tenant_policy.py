"""The tenant policy operations of the contract: `getTenantPolicy` and `updateTenantPolicy` (#174;
FR-23; docs/api/openapi.yaml, tag "Tenant admin").

Routes only parse the request and shape the response; the service layer
(`sft.service.tenant_policy`) checks the caller and applies the rules. Both are group H
(`TENANT_OPERATION`, abuse and rate limits 2.2).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, FastAPI, Request

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database
from sft.api.errors import problem_responses
from sft.api.rate_limits import rate_limit
from sft.api.transfer_schemas import TenantPolicyOut, TenantPolicyUpdate
from sft.data.database import Database
from sft.service import tenant_policy
from sft.service.caller import Caller
from sft.service.rate_limits.limits import TENANT_OPERATION

PREFIX: Final = "/v1"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)

router = APIRouter(prefix=PREFIX, tags=["Tenant admin"])


def _now() -> datetime:
    return datetime.now(UTC)


@router.get(
    "/tenant/policy",
    operation_id="getTenantPolicy",
    response_model=TenantPolicyOut,
    summary="Get the tenant policy",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 429),
)
async def get_tenant_policy(caller: CallerDep, database: DatabaseDep) -> TenantPolicyOut:
    """The tenant policy, for every member (FR-23, FR-24, FR-3)."""
    now = _now()
    policy = await tenant_policy.get_tenant_policy(database, caller, now=now)
    return TenantPolicyOut.of(policy, now=now)


@router.patch(
    "/tenant/policy",
    operation_id="updateTenantPolicy",
    response_model=TenantPolicyOut,
    summary="Update the tenant policy",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 422, 429),
)
async def update_tenant_policy(
    body: TenantPolicyUpdate, request: Request, caller: CallerDep, database: DatabaseDep
) -> TenantPolicyOut:
    """Change the fields sent, audited (FR-23, FR-24, FR-18, FR-13)."""
    now = _now()
    policy = await tenant_policy.update_tenant_policy(
        database, caller, body.change(), origin=origin_of(request), now=now
    )
    return TenantPolicyOut.of(policy, now=now)


def register(app: FastAPI) -> None:
    """Add the tenant policy routes to the public app."""
    app.include_router(router)
