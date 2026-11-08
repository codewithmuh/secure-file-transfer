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

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Annotated, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Header, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CollectorRegistry, Counter
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
from sft.service import operator_auth, operator_tenants
from sft.service.operator_auth import Operator, OperatorPolicy, Sts
from sft.service.rate_limits import RateLimiter

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
        try:
            yield
        finally:
            await store.close()
            await database.dispose()

    return lifespan


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
