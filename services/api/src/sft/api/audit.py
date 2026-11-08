"""The audit operations of the contract: `searchAuditEvents` and `exportAuditEvents` (#216;
docs/api/openapi.yaml, tag "Audit"; FR-28, FR-29, UC-4).

Routes only parse the request and shape the response; the service layer
(`sft.service.audit_search`) checks the caller, applies the limits and records each read. The
filter travels in the JSON body, never the URL, so an address or IP is never in an access log
(T-47). An export is streamed with `Content-Disposition: attachment`, which CORS exposes to the
web app (`sft.api.auth`).

Rate limits (abuse and rate limits 2.2): a search counts against the caller's group H budget, the
tenant's 60 searches a minute (group I) and the tenant's group H budget (`AUDIT_SEARCH`). An
export counts against group H at the route, then, in the service once its size is known, a key's
one export an hour, the tenant's 10 an hour, and the tenant's one export at a time.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from pydantic.json_schema import SkipJsonSchema

from sft.api.caller import get_tenant_caller, origin_of
from sft.api.dependencies import get_database, now_of
from sft.api.errors import problem_responses
from sft.api.rate_limits import get_rate_limiter, rate_limit
from sft.data.database import Database
from sft.data.models import ActorType
from sft.service import audit_search
from sft.service.audit_search import AuditQuery, EventView, ExportFormat, ExportLeases
from sft.service.caller import Caller
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import AUDIT_SEARCH, TENANT_OPERATION

PREFIX: Final = "/v1"
TAG: Final = "Audit"
NO_STORE: Final = {"Cache-Control": "no-store"}

CallerDep = Annotated[Caller, Depends(get_tenant_caller)]
DatabaseDep = Annotated[Database, Depends(get_database)]
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
NowDep = Annotated[datetime, Depends(now_of)]
SEARCH_LIMITS: Final = rate_limit(AUDIT_SEARCH, caller=get_tenant_caller)
TENANT_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)

_ACTION: Final = r"^[a-z_]+\.[a-z_]+$"


def get_export_leases(request: Request) -> ExportLeases:
    """The process's export leases (the counter store's, from the lifespan). An app made without
    settings, for tests, gets leases held in the process."""
    leases = getattr(request.app.state, "export_leases", None)
    if not isinstance(leases, ExportLeases):
        leases = request.app.state.export_leases = ExportLeases(None)
    return leases


LeasesDep = Annotated[ExportLeases, Depends(get_export_leases)]


# ---- request and response bodies (the contract's schemas) ----


class AuditFilter(BaseModel):
    """The contract's `AuditFilter`: every field optional, combined with AND."""

    model_config = ConfigDict(extra="forbid", title="AuditFilter")

    occurred_after: datetime | SkipJsonSchema[None] = None
    occurred_before: datetime | SkipJsonSchema[None] = None
    actor_type: ActorType | SkipJsonSchema[None] = None
    actor_id: UUID | SkipJsonSchema[None] = None
    email: (
        Annotated[str, Field(max_length=254, json_schema_extra={"format": "email"})]
        | SkipJsonSchema[None]
    ) = None
    actions: (
        Annotated[
            list[Annotated[str, Field(pattern=_ACTION)]],
            Field(max_length=20, json_schema_extra={"uniqueItems": True}),
        ]
        | SkipJsonSchema[None]
    ) = None
    target_type: Annotated[str, Field(max_length=64)] | SkipJsonSchema[None] = None
    target_id: UUID | SkipJsonSchema[None] = None
    source_ip: Annotated[str, Field(max_length=45)] | SkipJsonSchema[None] = None

    def query(self) -> AuditQuery:
        return AuditQuery(
            occurred_after=self.occurred_after,
            occurred_before=self.occurred_before,
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            email=self.email,
            actions=tuple(self.actions or ()),
            target_type=self.target_type,
            target_id=self.target_id,
            source_ip=self.source_ip,
        )


class AuditSearchRequest(BaseModel):
    """The contract's `AuditSearchRequest`."""

    model_config = ConfigDict(extra="forbid")

    filter: AuditFilter | SkipJsonSchema[None] = None
    cursor: Annotated[str, Field(max_length=512)] | SkipJsonSchema[None] = None
    limit: int = Field(default=25, ge=1, le=audit_search.MAX_PAGE)


class AuditExportRequest(BaseModel):
    """The contract's `AuditExportRequest`."""

    model_config = ConfigDict(extra="forbid")

    filter: AuditFilter | SkipJsonSchema[None] = None
    format: ExportFormat


class AuditEventOut(BaseModel):
    """The contract's `AuditEvent`."""

    model_config = ConfigDict(title="AuditEvent")

    id: UUID
    occurred_at: datetime
    actor_type: ActorType
    actor_id: UUID | None
    actor_email: Annotated[str, Field(json_schema_extra={"format": "email"})] | None
    action: str = Field(pattern=_ACTION)
    target_type: str | None
    target_id: UUID | None
    source_ip: str | None
    user_agent: str | None
    request_id: str | None
    security_critical: bool
    details: dict[str, Any]

    @classmethod
    def of(cls, view: EventView) -> AuditEventOut:
        return cls.model_validate(audit_search.event_json(view))


class AuditEventPage(BaseModel):
    """The contract's `AuditEventPage`."""

    model_config = ConfigDict(title="AuditEventPage")

    items: list[AuditEventOut]
    next_cursor: str | None


# ---- the routes ----

router = APIRouter(prefix=PREFIX, tags=[TAG])


@router.post(
    "/audit/events/search",
    operation_id="searchAuditEvents",
    response_model=AuditEventPage,
    summary="Search the audit log",
    dependencies=[SEARCH_LIMITS],
    responses=problem_responses(400, 401, 403, 422, 429),
)
async def search_audit_events(
    body: AuditSearchRequest,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    now: NowDep,
) -> AuditEventPage:
    """One page of the tenant's audit log, newest first (UC-4); the search is audited."""
    query = (body.filter or AuditFilter()).query()
    page = await audit_search.search_audit_events(
        database,
        caller,
        query,
        cursor=body.cursor,
        limit=body.limit,
        origin=origin_of(request),
        now=now,
    )
    return AuditEventPage(
        items=[AuditEventOut.of(v) for v in page.items], next_cursor=page.next_cursor
    )


_EXPORT_CONTENT: Final = {
    "text/csv": {"schema": {"type": "string"}},
    "application/json": {
        "schema": {"type": "array", "items": {"$ref": "#/components/schemas/AuditEventOut"}}
    },
}


@router.post(
    "/audit/exports",
    operation_id="exportAuditEvents",
    response_class=StreamingResponse,
    summary="Export audit log results",
    dependencies=[TENANT_LIMITS],
    responses={
        200: {
            "description": "The matching events, in the requested format.",
            "headers": {
                "Content-Disposition": {
                    "description": "`attachment` with a file name such as `audit-export.csv`.",
                    "schema": {"type": "string"},
                }
            },
            "content": _EXPORT_CONTENT,
        },
        **problem_responses(400, 401, 403, 422, 429),
    },
)
async def export_audit_events(
    body: AuditExportRequest,
    request: Request,
    caller: CallerDep,
    database: DatabaseDep,
    limiter: LimiterDep,
    leases: LeasesDep,
    now: NowDep,
) -> StreamingResponse:
    """Every matching event, streamed as CSV or JSON (FR-29); the export is audited."""
    query = (body.filter or AuditFilter()).query()
    export = await audit_search.export_audit_events(
        database,
        caller,
        query,
        body.format,
        limiter=limiter,
        leases=leases,
        origin=origin_of(request),
        now=now,
    )
    headers = {
        **NO_STORE,
        "Content-Disposition": f'attachment; filename="{export.filename}"',
    }
    return StreamingResponse(export.chunks, media_type=export.media_type, headers=headers)


def register(app: FastAPI) -> None:
    """Add the audit routes to the public app."""
    app.include_router(router)
