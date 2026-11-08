"""The operator API app: the contract's operator operations, and nothing else (FR-34).

A second FastAPI app from the same codebase, started with `python -m sft.api.operator`. It runs as
its own Deployment in the `sft-operator` namespace with its own IAM and database roles, on no load
balancer: operators reach it with `kubectl port-forward` (architecture 2, authn-authz 8.2). It
serves only the operations of the contract's operator server, and the public app serves none of
them; the generated-spec check holds each app to its own server (docs/api/README.md 11.1).

It never returns file names, messages or contents, and its database role, `sft_operator`, can't
read them. Every route but `createOperatorToken` needs an operator token, and every call is
audited (`sft.service.operator_tenants`).

It shares the public app's runtime pieces rather than copying them: problem errors
(`sft.api.errors`), the database dependency (`sft.api.dependencies`), the rate limiter
(`sft.api.rate_limits`, opened in the lifespan as the public app opens it) and the request's
trace, log line and metrics, which `RequestContextMiddleware` adds around it in `ApiServer`.
FastAPI's own telemetry is off, as in the public app. The one limit of abuse and rate limits 2.2
that applies here is group J's 30 new tenants an hour per operator, counted in the service; the
per-IP limits and the failed-authentication block don't apply, since every request comes through
the port-forward tunnel.

Not yet: `createTenant` accepts `Idempotency-Key`, as the contract has it, but doesn't keep it.
The shared helper (`sft.service.idempotency`, #144) keeps a key in the tenant's scope, and here the
tenant doesn't exist until the call has made it: a retry would have to find the key across tenants
first, which needs a platform-scope read for `sft_operator` and a key owner that outlives the
15-minute operator token. That is its own follow-up. Until then a retry creates a second tenant, so
an operator checks `listTenants` before retrying a `createTenant` whose answer was lost.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CollectorRegistry, Counter, Gauge
from sqlalchemy.engine import make_url

from sft.api.app import _NO_FASTAPI_TELEMETRY, API_TITLE, API_VERSION
from sft.api.client_ip import client_address
from sft.api.dependencies import get_database
from sft.api.errors import problem_responses, register_error_handlers
from sft.api.operator import schemas
from sft.api.operator.sts import HttpSts
from sft.api.rate_limits import get_rate_limiter
from sft.core.settings import OperatorSettings
from sft.data import roles
from sft.data.audit import Origin
from sft.data.counters import CounterMetrics, CounterStore, ValkeyIam
from sft.data.database import Database
from sft.data.models import BreakGlassState
from sft.service import break_glass, operator_auth, operator_tenants, sso
from sft.service.operator_auth import Operator, OperatorPolicy, Sts
from sft.service.rate_limits import RateLimiter

log = logging.getLogger(__name__)

PREFIX: Final = "/v1"

_bearer = HTTPBearer(auto_error=False, description="An operator token (createOperatorToken).")

IdempotencyKey = Annotated[
    str | None,
    Header(alias="Idempotency-Key", min_length=1, max_length=255, pattern=r"^[\x21-\x7E]+$"),
]


def policy_of(settings: OperatorSettings) -> OperatorPolicy:
    return OperatorPolicy(
        region=settings.aws_region,
        audience=settings.operator_audience,
        account_id=settings.operator_aws_account_id,
        role_name=settings.operator_role_name,
    )


def _lifespan(
    settings: OperatorSettings, sts: Sts | None, registry: CollectorRegistry
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    url = settings.database_url.get_secret_value()
    if make_url(url).username != roles.OPERATOR:
        # Its grants and policies are the operator API's; any other role is a deploy mistake.
        raise ValueError(f"the operator API logs in as {roles.OPERATOR} (authn-authz 7.3)")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # As in the public app: neither the pool nor the counter store connects yet.
        database = Database.connect(
            url,
            pool_size=settings.database_pool_size,
            iam_region=settings.aws_region if settings.database_iam_auth else None,
        )
        app.state.database = database
        metrics = CounterMetrics.create(registry)
        iam = ValkeyIam.of(settings.valkey_iam_cache, settings.aws_region)
        store = CounterStore.connect(settings.valkey_url.get_secret_value(), metrics, iam=iam)
        app.state.rate_limiter = RateLimiter(store, metrics)
        app.state.platform_audit_failures = Counter(
            "sft_operator_platform_audit_failures_total",
            "Operator calls whose change committed but whose platform audit event wasn't written; "
            "the change's own record is in the tenant's log. Any increase alerts.",
            ["action"],
            registry=registry,
        )
        app.state.sts = sts or HttpSts(settings.sts_endpoint)
        app.state.policy = policy_of(settings)
        app.state.break_glass_self_approval = settings.break_glass_self_approval
        # Break-glass (#232): record expiries and lapses, and keep the alert's gauges current.
        watch = asyncio.create_task(
            watch_break_glass(
                database, BreakGlassMetrics.create(registry), settings.break_glass_sweep_seconds
            )
        )
        try:
            yield
        finally:
            watch.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await watch
            await store.close()
            await database.dispose()

    return lifespan


@dataclass(frozen=True, slots=True)
class BreakGlassMetrics:
    """What the alerts of deploy/alerts/break-glass.rules.yaml read."""

    active: Gauge
    last_success: Gauge
    tenant_records_missed: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> BreakGlassMetrics:
        active = Gauge(
            "sft_break_glass_active_grants",
            "Break-glass grants giving access now (authn and authz 8.3); any pages.",
            ["self_approved"],
            registry=registry,
        )
        for label in ("true", "false"):
            active.labels(self_approved=label).set(0)
        return cls(
            active=active,
            last_success=Gauge(
                "sft_break_glass_sweep_last_success_timestamp_seconds",
                "When the break-glass sweep last ran to the end, as a Unix time.",
                registry=registry,
            ),
            tenant_records_missed=Counter(
                "sft_break_glass_tenant_records_missed_total",
                "Break-glass records not written to a tenant's audit log; any increase alerts.",
                registry=registry,
            ),
        )

    def observe(self, result: break_glass.SweepResult) -> None:
        for self_approved in (True, False):
            self.active.labels(self_approved=str(self_approved).lower()).set(
                result.active.get(self_approved, 0)
            )
        if result.tenant_records_missed:
            self.tenant_records_missed.inc(result.tenant_records_missed)
        self.last_success.set_to_current_time()


async def watch_break_glass(
    database: Database, metrics: BreakGlassMetrics, interval: float
) -> None:
    """Run the break-glass sweep every `interval` seconds until cancelled. A failed run is logged
    and tried again; the stalled-sweep alert fires if none succeeds for five minutes."""
    while True:
        try:
            metrics.observe(await break_glass.sweep(database))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("the break-glass sweep failed")
        await asyncio.sleep(interval)


def _origin(request: Request) -> Origin:
    # No proxy is trusted: through a port-forward the peer is the tunnel's end, recorded as it is.
    return Origin(
        source_ip=client_address(request, ()), user_agent=request.headers.get("user-agent")
    )


DatabaseDep = Annotated[Database, Depends(get_database)]
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]
OriginDep = Annotated[Origin, Depends(_origin)]


async def _operator(
    database: DatabaseDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Operator:
    return await operator_auth.authenticate(
        database, None if credentials is None else credentials.credentials
    )


OperatorDep = Annotated[Operator, Depends(_operator)]


def operator_router() -> APIRouter:
    router = APIRouter(prefix=PREFIX)

    @router.post(
        "/operator/token",
        operation_id="createOperatorToken",
        status_code=201,
        responses=problem_responses(400, 401, 422, 429, 503),
    )
    async def create_operator_token(
        body: schemas.OperatorTokenRequest,
        request: Request,
        response: Response,
        database: DatabaseDep,
        origin: OriginDep,
    ) -> schemas.OperatorToken:
        issued = await operator_auth.exchange_token(
            database,
            request.app.state.sts,
            request.app.state.policy,
            headers=body.sts_request.headers,
            body=body.sts_request.body,
            origin=origin,
        )
        response.headers["Cache-Control"] = "no-store"
        return schemas.OperatorToken(
            token=issued.token,
            expires_at=issued.expires_at,
            aws_account_id=issued.aws_account_id,
            operator_name=issued.operator_name,
        )

    @router.post(
        "/operator/tenants",
        operation_id="createTenant",
        status_code=201,
        responses=problem_responses(400, 401, 403, 409, 422, 429, 503),
    )
    async def create_tenant(
        body: schemas.TenantCreate,
        request: Request,
        response: Response,
        database: DatabaseDep,
        operator: OperatorDep,
        origin: OriginDep,
        limiter: LimiterDep,
        idempotency_key: IdempotencyKey = None,
    ) -> schemas.TenantCreated:
        # Idempotency-Key is accepted and validated, not yet kept (the module docstring).
        created = await operator_tenants.create_tenant(
            database,
            operator,
            operator_tenants.NewTenant(
                name=body.name,
                first_admin_email=body.first_admin_email,
                recovery_contact=body.recovery_contact,
                default_locale=body.default_locale,
            ),
            origin,
            limiter=limiter,
        )
        if not created.platform_recorded:
            # A 201 all the same: a retry would make a second tenant (operator_tenants).
            request.app.state.platform_audit_failures.labels(action="tenant.created").inc()
        response.headers["Location"] = f"{PREFIX}/operator/tenants/{created.tenant.id}"
        return schemas.TenantCreated(
            tenant=schemas.Tenant.of(created.tenant),
            first_admin=schemas.User.of(created.first_admin),
        )

    @router.get(
        "/operator/tenants",
        operation_id="listTenants",
        responses=problem_responses(400, 401, 429),
    )
    async def list_tenants(
        database: DatabaseDep,
        operator: OperatorDep,
        origin: OriginDep,
        status: schemas.TenantStatus | None = None,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> schemas.TenantPage:
        page = await operator_tenants.list_tenants(
            database,
            operator,
            origin,
            status=None if status is None else operator_tenants.TenantStatus(status),
            cursor=cursor,
            limit=limit,
        )
        return schemas.TenantPage(
            items=[schemas.Tenant.of(row) for row in page.items], next_cursor=page.next_cursor
        )

    @router.get(
        "/operator/tenants/{tenant_id}",
        operation_id="getTenant",
        responses=problem_responses(401, 404, 429),
    )
    async def get_tenant(
        tenant_id: UUID, database: DatabaseDep, operator: OperatorDep, origin: OriginDep
    ) -> schemas.Tenant:
        tenant = await operator_tenants.get_tenant(database, operator, tenant_id, origin)
        return schemas.Tenant.of(tenant)

    @router.put(
        "/operator/tenants/{tenant_id}/sso",
        operation_id="configureTenantSso",
        responses=problem_responses(400, 401, 403, 404, 422, 429),
    )
    async def configure_tenant_sso(
        tenant_id: UUID,
        body: schemas.TenantSsoUpdate,
        database: DatabaseDep,
        operator: OperatorDep,
        origin: OriginDep,
    ) -> schemas.TenantSso:
        recorded = await sso.configure_tenant_sso(
            database,
            operator,
            tenant_id,
            sso.SsoConfiguration(
                kind=sso.ConnectionKind(body.kind),
                provider_name=body.provider_name,
                issuer=body.issuer,
                status=sso.ConnectionStatus(body.status),
                domains=body.domains,
                sso_required=body.sso_required,
                sso_mfa_confirmed_by=body.sso_mfa_confirmed_by,
            ),
            origin=origin,
        )
        return schemas.TenantSso.of(recorded)

    @router.post(
        "/operator/break-glass-requests",
        operation_id="requestBreakGlass",
        status_code=201,
        responses=problem_responses(400, 401, 403, 422, 429),
    )
    async def request_break_glass(
        body: schemas.BreakGlassRequestCreate,
        database: DatabaseDep,
        operator: OperatorDep,
        origin: OriginDep,
    ) -> schemas.BreakGlassRequest:
        grant = await break_glass.request(
            database,
            operator,
            break_glass.NewRequest(
                incident_id=body.incident_id,
                reason=body.reason,
                tenant_ids=body.tenant_ids,
                duration_minutes=body.duration_minutes,
            ),
            origin=origin,
        )
        return schemas.BreakGlassRequest.of(grant)

    @router.get(
        "/operator/break-glass-requests",
        operation_id="listBreakGlassRequests",
        responses=problem_responses(400, 401, 403, 422, 429),
    )
    async def list_break_glass_requests(
        database: DatabaseDep,
        operator: OperatorDep,
        state: schemas.BreakGlassState | None = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> schemas.BreakGlassRequestList:
        rows = await break_glass.list_requests(
            database,
            operator,
            state=None if state is None else BreakGlassState(state),
            limit=limit,
        )
        return schemas.BreakGlassRequestList(
            items=[schemas.BreakGlassRequest.of(row) for row in rows]
        )

    @router.post(
        "/operator/break-glass-requests/{break_glass_request_id}/approve",
        operation_id="approveBreakGlass",
        responses=problem_responses(401, 403, 404, 409, 429),
    )
    async def approve_break_glass(
        break_glass_request_id: UUID,
        request: Request,
        database: DatabaseDep,
        operator: OperatorDep,
        origin: OriginDep,
    ) -> schemas.BreakGlassRequest:
        grant = await break_glass.approve(
            database,
            operator,
            break_glass_request_id,
            allow_self_approval=bool(
                getattr(request.app.state, "break_glass_self_approval", False)
            ),
            origin=origin,
        )
        return schemas.BreakGlassRequest.of(grant)

    @router.post(
        "/operator/break-glass-requests/{break_glass_request_id}/end",
        operation_id="endBreakGlass",
        responses=problem_responses(401, 403, 404, 429),
    )
    async def end_break_glass(
        break_glass_request_id: UUID,
        database: DatabaseDep,
        operator: OperatorDep,
        origin: OriginDep,
    ) -> schemas.BreakGlassRequest:
        grant = await break_glass.end(database, operator, break_glass_request_id, origin=origin)
        return schemas.BreakGlassRequest.of(grant)

    @router.post(
        "/operator/tenants/{tenant_id}/suspend",
        operation_id="suspendTenant",
        responses=problem_responses(401, 404, 429, 503),
    )
    async def suspend_tenant(
        tenant_id: UUID, database: DatabaseDep, operator: OperatorDep, origin: OriginDep
    ) -> schemas.Tenant:
        tenant = await operator_tenants.suspend_tenant(database, operator, tenant_id, origin)
        return schemas.Tenant.of(tenant)

    return router


def create_operator_app(
    settings: OperatorSettings | None = None,
    *,
    sts: Sts | None = None,
    registry: CollectorRegistry | None = None,
) -> FastAPI:
    """The operator API. Without settings it has no database or limiter: for the OpenAPI document
    and tests. `registry` is where its metrics go: the server passes the one /metrics serves."""
    app = FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=None
        if settings is None
        else _lifespan(settings, sts, registry or CollectorRegistry()),
        telemetry=_NO_FASTAPI_TELEMETRY,
    )
    register_error_handlers(app)
    app.include_router(operator_router())
    return app
