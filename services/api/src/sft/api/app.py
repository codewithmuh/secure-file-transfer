"""The public API app: the routes of the API contract, docs/api/openapi.yaml.

The member routes (#112) are the first; each feature registers its own. Probes and metrics live
on the internal port (internal.py). The interactive docs and the OpenAPI document aren't served
either: ADR-0002 keeps them off the public load balancer, and CI builds the document from
`create_app().openapi()`.

With settings, the app's lifespan opens the database pool and the rate-limit counter store at
startup, without connecting, and closes them at shutdown, after uvicorn has drained the requests. A
route reaches them through the `get_database` (dependencies.py) and `get_rate_limiter`
dependencies, or names its limits with `rate_limit` (rate_limits.py). Without settings there is
neither: that app is for generating the OpenAPI document and for tests of routes that don't need
them.

FastAPI's own OpenTelemetry support is off: `RequestContextMiddleware` makes the one SERVER span of
each request, outside FastAPI's error handling, from the attribute allowlist (sft.core.telemetry).
FastAPI's span would be a second root for the same request, record its path and query string,
which can hold a link token, and take `tracestate` and baggage from the caller; its OTel logs would
carry exception messages (ADR-0009, T-49).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI
from fastapi.telemetry import TelemetryConfig
from prometheus_client import CollectorRegistry

from sft.api import members
from sft.api.dependencies import get_database as get_database  # its home before dependencies.py
from sft.api.errors import register_error_handlers
from sft.api.rate_limits import install_rate_limits
from sft.core.settings import Settings
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.service.rate_limits import RateLimiter

_NO_FASTAPI_TELEMETRY: TelemetryConfig = {
    "tracing": False,
    "metrics": False,
    "logs": False,
    "operation_spans": False,
    "auto_configure": False,
}

# The contract's `info`, so the document generated from the code compares with it (ADR-0002).
API_TITLE = "secure-file-transfer API"
API_VERSION = "1.0.0-draft"


def _lifespan(
    settings: Settings, registry: CollectorRegistry
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # No connection yet: /readyz never depends on the database, so an outage can't take
        # every pod out of the load balancer at once.
        database = Database.connect(
            settings.database_url.get_secret_value(), pool_size=settings.database_pool_size
        )
        app.state.database = database
        # The same for the counters: an outage applies each limit's failure mode instead.
        metrics = CounterMetrics.create(registry)
        store = CounterStore.connect(settings.valkey_url.get_secret_value(), metrics)
        app.state.rate_limiter = RateLimiter(store, metrics)
        try:
            yield
        finally:
            await store.close()
            await database.dispose()

    return lifespan


def create_app(
    settings: Settings | None = None, *, registry: CollectorRegistry | None = None
) -> FastAPI:
    """The app. `registry` is where its metrics go: the server passes the one /metrics serves."""
    app = FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=None if settings is None else _lifespan(settings, registry or CollectorRegistry()),
        telemetry=_NO_FASTAPI_TELEMETRY,
    )
    app.state.trusted_proxies = () if settings is None else settings.trusted_proxies
    register_error_handlers(app)  # every error is a problem document (docs/api/README.md 3)
    install_rate_limits(app)
    members.register(app)  # members, roles and invitations (#112)
    return app
