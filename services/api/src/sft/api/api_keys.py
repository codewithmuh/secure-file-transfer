"""The API key operations of the contract: `createApiKey`, `listApiKeys` and `revokeApiKey` (#215;
docs/api/openapi.yaml, tag "API keys"; authn and authz 5), and the record of every key's use.

Routes only parse the request and shape the response; the service layer (`sft.service.api_keys`)
checks the caller and applies the rules. The secret appears only in `createApiKey`'s `201`, with
`Cache-Control: no-store`, and never in a log, a trace or an error.

Rate limits (abuse and rate limits 2.2): `createApiKey` and `listApiKeys` count against the
caller's and the tenant's group H budget, and a creation also against group J's 20 a day, in the
service once the key can be made. `revokeApiKey` is a safety action: only the caller's own limit.

**Every use of a key is audited** (FR-27, authn and authz 5.2): `RecordKeyUse` writes one
`api_key.used` event per request a live key made, with its operation ID and status, after the
handler and before the answer's first byte. If the event can't be written, the answer is
`503 service_unavailable` instead (NFR-15): a request's own changes have committed with their own
audit events already, which name the key as the actor, so nothing goes unaudited either way.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated, Any, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.json_schema import SkipJsonSchema
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sft.api.caller import KEY_CALLER, get_tenant_caller, key_environment, origin_of
from sft.api.dependencies import get_audit_archive, get_database, now_of
from sft.api.errors import problem_for, problem_responses
from sft.api.rate_limits import get_rate_limiter, rate_limit
from sft.core.errors import ServiceUnavailable
from sft.data.database import Database
from sft.data.models import ApiKey, ApiKeyScope
from sft.service import api_keys
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import SAFETY_ACTION, TENANT_OPERATION

log = logging.getLogger(__name__)

PREFIX: Final = "/v1"
TAG: Final = "API keys"
NO_STORE: Final = {"Cache-Control": "no-store"}
USE_NOT_RECORDED_RETRY_AFTER: Final = 5

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
ArchiveDep = Annotated[AuditArchive, Depends(get_audit_archive)]
NowDep = Annotated[datetime, Depends(now_of)]
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)
SAFETY_LIMITS: Final = rate_limit(SAFETY_ACTION, caller=get_tenant_caller)

_PREFIX_PATTERN: Final = r"^sft_(dev|stg|prd)_[0-9A-Za-z]{8}$"
_SECRET_PATTERN: Final = r"^sft_(dev|stg|prd)_[0-9A-Za-z]{43}_[0-9A-Za-z]{6}$"  # noqa: S105 - a format


# ---- request and response bodies (the contract's schemas) ----


class ApiKeyCreate(BaseModel):
    """The contract's `ApiKeyCreate`."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    scopes: list[ApiKeyScope] = Field(min_length=1, json_schema_extra={"uniqueItems": True})
    expires_at: datetime | SkipJsonSchema[None] = None

    @field_validator("scopes")
    @classmethod
    def _unique(cls, value: list[ApiKeyScope]) -> list[ApiKeyScope]:
        if len(set(value)) != len(value):
            raise ValueError("a scope appears more than once")
        return value

    @field_validator("expires_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.utcoffset() is None:
            raise ValueError("a time with its offset, RFC 3339")
        return value


class ApiKeyOut(BaseModel):
    """The contract's `ApiKey`."""

    model_config = ConfigDict(title="ApiKey")

    id: UUID
    name: str
    key_prefix: str = Field(pattern=_PREFIX_PATTERN)
    scopes: list[ApiKeyScope]
    created_by: UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None

    @classmethod
    def of(cls, key: ApiKey) -> ApiKeyOut:
        return cls(**_fields(key))


def _fields(key: ApiKey) -> dict[str, Any]:
    return {
        "id": key.id,
        "name": key.name,
        "key_prefix": key.key_prefix,
        "scopes": [ApiKeyScope(s) for s in key.scopes],
        "created_by": key.created_by,
        "created_at": key.created_at,
        "expires_at": key.expires_at,
        "last_used_at": key.last_used_at,
        "revoked_at": key.revoked_at,
    }


class ApiKeyCreated(ApiKeyOut):
    """The contract's `ApiKeyCreated`: the key with its full value, shown only now."""

    model_config = ConfigDict(
        title="ApiKeyCreated",
        json_schema_extra={"description": "A new key, with its full value."},
    )

    secret: str = Field(pattern=_SECRET_PATTERN, repr=False)

    @classmethod
    def made(cls, created: api_keys.CreatedKey) -> ApiKeyCreated:
        return cls(**_fields(created.key), secret=created.secret)


class ApiKeyPageOut(BaseModel):
    """The contract's `ApiKeyPage`."""

    model_config = ConfigDict(title="ApiKeyPage")

    items: list[ApiKeyOut]
    next_cursor: str | None


# ---- the routes ----

router = APIRouter(prefix=PREFIX, tags=[TAG])


@router.post(
    "/api-keys",
    operation_id="createApiKey",
    status_code=201,
    response_model=ApiKeyCreated,
    summary="Create an API key",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 422, 429),
)
async def create_api_key(
    body: ApiKeyCreate,
    request: Request,
    response: Response,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
    now: NowDep,
) -> ApiKeyCreated:
    """A new key, shown once (FR-32)."""
    created = await api_keys.create_api_key(
        database,
        caller,
        name=body.name,
        scopes=body.scopes,
        expires_at=body.expires_at,
        environment=key_environment(request),
        limiter=limiter,
        origin=origin_of(request),
        now=now,
    )
    response.headers.update(NO_STORE)
    response.headers["Location"] = f"{PREFIX}/api-keys/{created.key.id}"
    return ApiKeyCreated.made(created)


@router.get(
    "/api-keys",
    operation_id="listApiKeys",
    response_model=ApiKeyPageOut,
    summary="List API keys",
    dependencies=[TENANT_LIMITS],
    responses=problem_responses(400, 401, 403, 429),
)
async def list_api_keys(
    caller: CallerDep,
    database: DatabaseDep,
    now: NowDep,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=api_keys.MAX_PAGE)] = 25,
) -> ApiKeyPageOut:
    page = await api_keys.list_api_keys(database, caller, cursor=cursor, limit=limit, now=now)
    return ApiKeyPageOut(items=[ApiKeyOut.of(k) for k in page.items], next_cursor=page.next_cursor)


@router.post(
    "/api-keys/{api_key_id}/revoke",
    operation_id="revokeApiKey",
    response_model=ApiKeyOut,
    summary="Revoke an API key",
    dependencies=[SAFETY_LIMITS],
    responses=problem_responses(401, 403, 404, 429, 503),
)
async def revoke_api_key(
    api_key_id: UUID,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    archive: ArchiveDep,
    now: NowDep,
) -> ApiKeyOut:
    """Revoked at once; `200` once both regions' archive hold the record (NFR-10)."""
    key = await api_keys.revoke_api_key(
        database, caller, api_key_id, archive=archive, origin=origin_of(request), now=now
    )
    return ApiKeyOut.of(key)


# ---- the record of every key's use ----


class _UseNotRecordedError(Exception):
    """The `503` went out instead of the handler's answer: stop the handler's response."""


class RecordKeyUse:
    """Writes `api_key.used` for each request a live key made, before the answer starts (module
    docstring). A pure ASGI middleware, so it sees the status of streamed answers too."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        state: dict[str, Any] = scope.setdefault("state", {})
        handled = refused = False

        async def watch(message: Message) -> None:
            nonlocal handled, refused
            caller = state.get(KEY_CALLER)
            if message["type"] == "http.response.start" and not handled and caller is not None:
                handled = True
                request = Request(scope)
                route = scope.get("route")
                try:
                    await api_keys.record_use(
                        request.app.state.database,
                        caller,
                        operation=getattr(route, "operation_id", None),
                        status=int(message["status"]),
                        origin=origin_of(request),
                    )
                except Exception:
                    log.exception("an API key's use could not be recorded")
                    unavailable = ServiceUnavailable(
                        USE_NOT_RECORDED_RETRY_AFTER, "The request couldn't be recorded. Retry."
                    )
                    refused = True
                    await problem_for(unavailable)(scope, receive, send)
                    raise _UseNotRecordedError from None
            if not refused:
                await send(message)

        try:
            await self.app(scope, receive, watch)
        except Exception:
            # The handler's answer was replaced by the 503: whatever its error handling made of
            # the stop is dropped. Any other error is the app's own.
            if not refused:
                raise


def register(app: FastAPI) -> None:
    """Add the API key routes to the public app, and the record of every key's use."""
    app.include_router(router)
    app.add_middleware(RecordKeyUse)
