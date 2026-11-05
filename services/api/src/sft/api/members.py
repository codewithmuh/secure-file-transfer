"""The member operations of the contract: `inviteUser`, `listUsers`, `getUser`, `updateUser` and
`deactivateUser` (docs/api/openapi.yaml, tag "Tenant admin"; FR-22).

Routes only parse the request and shape the response; the service layer (`sft.service.members`)
checks the caller's permission and applies the rules. Its refusals are `sft.core.errors`
exceptions, which `sft.api.errors` answers as problem documents; each route declares the error
answers the contract gives it (`problem_responses`).

Rate limits (abuse and rate limits 2.2): every route counts against the caller's and the tenant's
budget (`TENANT_OPERATION`, group H), except `deactivateUser`, a safety action that only the
caller's own limit applies to (`SAFETY_ACTION`). `inviteUser` also applies group G's invitation
limits, in the service once the caller may invite (`sft.service.members.INVITE_LIMITS`).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Annotated, Any, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.json_schema import SkipJsonSchema

from sft.api import app as app_module
from sft.api.caller import get_tenant_caller
from sft.api.client_ip import client_address
from sft.api.errors import problem_responses
from sft.api.rate_limits import get_rate_limiter, rate_limit
from sft.data.audit import Origin
from sft.data.database import Database
from sft.data.models import Role, User, UserStatus
from sft.service import members
from sft.service.caller import Caller
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import SAFETY_ACTION, TENANT_OPERATION

PREFIX: Final = "/v1"
TAG: Final = "Tenant admin"

# One address: a local part and a domain with a dot, no spaces, no control characters. The mail
# system is the final judge; this only refuses what can't be an address (contract: format email).
_EMAIL = re.compile(r"[^@\s\x00-\x1f\x7f]{1,64}@[^@\s\x00-\x1f\x7f]+\.[^@\s\x00-\x1f\x7f.]+")
_EMAIL_SCHEMA: Final[dict[str, Any]] = {"format": "email"}
_IDEMPOTENCY_KEY = r"^[\x21-\x7E]+$"


def _database(request: Request) -> Database:
    return app_module.get_database(request)


def _origin(request: Request) -> Origin:
    """FR-27's source IP and user agent: the client's address by ADR-0002's rule, as rate limits
    read it."""
    source = client_address(request, request.app.state.trusted_proxies)
    return Origin(source_ip=source, user_agent=request.headers.get("user-agent"))


def _now() -> datetime:
    return datetime.now(UTC)


# The caller comes first, so a request without a credential gets 401 before anything else runs;
# the rate limit next, before the handler. FastAPI resolves the caller once for both.
CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(_database)]
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)
SAFETY_LIMITS: Final = rate_limit(SAFETY_ACTION, caller=get_tenant_caller)


# ---- request and response bodies (the contract's schemas) ----


class UserOut(BaseModel):
    """The contract's `User`."""

    model_config = ConfigDict(title="User")

    id: UUID
    email: str = Field(max_length=254, json_schema_extra=_EMAIL_SCHEMA)
    role: Role
    status: UserStatus
    sso_fallback: bool
    dlp_approver: bool
    created_at: datetime

    @classmethod
    def of(cls, user: User) -> UserOut:
        return cls(
            id=user.id,
            email=user.email,
            role=Role(user.role),
            status=UserStatus(user.status),
            sso_fallback=user.sso_fallback,
            dlp_approver=user.dlp_approver,
            created_at=user.created_at,
        )


class UserPageOut(BaseModel):
    """The contract's `UserPage`."""

    model_config = ConfigDict(title="UserPage")

    items: list[UserOut]
    next_cursor: str | None


class UserInvite(BaseModel):
    """The contract's `UserInvite`."""

    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=254, json_schema_extra=_EMAIL_SCHEMA)
    role: Role = Role.MEMBER

    @field_validator("email")
    @classmethod
    def _an_address(cls, value: str) -> str:
        if not _EMAIL.fullmatch(value):
            raise ValueError("not an email address")
        return value


class UserUpdate(BaseModel):
    """The contract's `UserUpdate`: only the fields sent are changed."""

    model_config = ConfigDict(extra="forbid", json_schema_extra={"minProperties": 1})

    role: Role | SkipJsonSchema[None] = None
    sso_fallback: bool | SkipJsonSchema[None] = None
    dlp_approver: bool | SkipJsonSchema[None] = None

    @model_validator(mode="after")
    def _something_to_change(self) -> UserUpdate:
        if not self.model_fields_set:
            raise ValueError("send at least one field")
        for name in self.model_fields_set:
            if getattr(self, name) is None:
                raise ValueError(f"{name} can't be null")
        return self


# ---- the routes ----

router = APIRouter(prefix=PREFIX, tags=[TAG])


@router.post(
    "/users",
    operation_id="inviteUser",
    status_code=201,
    response_model=UserOut,
    summary="Invite a member or admin",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 409, 429),
)
async def invite_user(
    body: UserInvite,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key", min_length=1, max_length=255, pattern=_IDEMPOTENCY_KEY),
    ] = None,
) -> UserOut:
    user = await members.invite_user(
        database,
        caller,
        email=body.email,
        role=body.role,
        limiter=limiter,
        origin=_origin(request),
        now=_now(),
    )
    response.headers["Location"] = f"{PREFIX}/users/{user.id}"
    return UserOut.of(user)


@router.get(
    "/users",
    operation_id="listUsers",
    response_model=UserPageOut,
    summary="List members and admins",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 429),
)
async def list_users(
    caller: CallerDep,
    database: DatabaseDep,
    role: Role | None = None,
    status: UserStatus | None = None,
    dlp_approver: bool | None = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 25,
) -> UserPageOut:
    page = await members.list_users(
        database,
        caller,
        role=role,
        status=status,
        dlp_approver=dlp_approver,
        cursor=cursor,
        limit=limit,
        now=_now(),
    )
    return UserPageOut(items=[UserOut.of(u) for u in page.items], next_cursor=page.next_cursor)


@router.get(
    "/users/{user_id}",
    operation_id="getUser",
    response_model=UserOut,
    summary="Get a member or admin",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(401, 403, 404, 429),
)
async def get_user(user_id: UUID, caller: CallerDep, database: DatabaseDep) -> UserOut:
    return UserOut.of(await members.get_user(database, caller, user_id, now=_now()))


@router.patch(
    "/users/{user_id}",
    operation_id="updateUser",
    response_model=UserOut,
    summary="Change a user's role, fallback or approver status",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 404, 409, 429, 503),
)
async def update_user(
    user_id: UUID, body: UserUpdate, request: Request, caller: CallerDep, database: DatabaseDep
) -> UserOut:
    user = await members.update_user(
        database,
        caller,
        user_id,
        role=body.role,
        sso_fallback=body.sso_fallback,
        dlp_approver=body.dlp_approver,
        origin=_origin(request),
        now=_now(),
    )
    return UserOut.of(user)


@router.post(
    "/users/{user_id}/deactivate",
    operation_id="deactivateUser",
    response_model=UserOut,
    summary="Deactivate a user",
    dependencies=[SAFETY_LIMITS],
    responses=problem_responses(401, 403, 404, 409, 429, 503),
)
async def deactivate_user(
    user_id: UUID, request: Request, caller: CallerDep, database: DatabaseDep
) -> UserOut:
    user = await members.deactivate_user(
        database, caller, user_id, origin=_origin(request), now=_now()
    )
    return UserOut.of(user)


def register(app: FastAPI) -> None:
    """Add the member routes to the public app."""
    app.include_router(router)
