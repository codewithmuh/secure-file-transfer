"""The tenant policy operations of the contract: `getTenantPolicy` and `updateTenantPolicy` (#174;
FR-23, FR-24), and `clearEmailSuppression` (#217; FR-7) (docs/api/openapi.yaml, tag "Tenant
admin").

Routes only parse the request and shape the response; the service layer
(`sft.service.tenant_policy`, `sft.service.email_suppressions`) checks the caller and applies the
rules. All are group H (`TENANT_OPERATION`, abuse and rate limits 2.2). The address to clear
travels in the body, never the URL, and the answer is `204` whether or not it was suppressed.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Final

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database, get_email_keyring
from sft.api.errors import problem_responses
from sft.api.members import UserInvite
from sft.api.rate_limits import rate_limit
from sft.api.transfer_schemas import TenantPolicyOut, TenantPolicyUpdate
from sft.core.pseudonyms import EmailKeyring
from sft.data.database import Database
from sft.service import email_suppressions, tenant_policy
from sft.service.caller import Caller
from sft.service.rate_limits.limits import TENANT_OPERATION

PREFIX: Final = "/v1"

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
EmailKeyringDep = Annotated[EmailKeyring, Depends(get_email_keyring)]
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


class EmailSuppressionClear(BaseModel):
    """The contract's `EmailSuppressionClear`: the address, as entered; compared lower-case."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=254, json_schema_extra={"format": "email"})

    @field_validator("email")
    @classmethod
    def _an_address(cls, value: str) -> str:
        return UserInvite._an_address(value)  # the same check as an invitation's


@router.post(
    "/email-suppressions/clear",
    operation_id="clearEmailSuppression",
    status_code=204,
    response_class=Response,
    summary="Clear an address from the tenant's suppression list",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 422, 429),
)
async def clear_email_suppression(
    body: EmailSuppressionClear,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    emails: EmailKeyringDep,
) -> Response:
    """Let this tenant email the address again (FR-7, abuse 7.4); `204` either way."""
    await email_suppressions.clear_email_suppression(
        database, caller, body.email, emails=emails, origin=origin_of(request), now=_now()
    )
    return Response(status_code=204)


def register(app: FastAPI) -> None:
    """Add the tenant policy routes to the public app."""
    app.include_router(router)
