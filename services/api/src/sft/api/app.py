"""The public API app: the routes of the API contract, docs/api/openapi.yaml.

It has no routes yet; the first arrive in M1. Probes and metrics live on the internal port
(internal.py). The interactive docs and the OpenAPI document aren't served either: ADR-0002 keeps
them off the public load balancer, and CI builds the document from `create_app().openapi()`.

With settings, the app's lifespan opens the database pool at startup, without connecting, and
closes it at shutdown, after uvicorn has drained the requests. A route reaches it through the
`get_database` dependency. Without settings there is no database: that app is for generating the
OpenAPI document and for tests of routes that don't need one.

FastAPI's own OpenTelemetry support is off: `RequestContextMiddleware` makes the one SERVER span of
each request, outside FastAPI's error handling, from the attribute allowlist (sft.core.telemetry).
FastAPI's span would be a second root for the same request, record its path and query string,
which can hold a link token, and take `tracestate` and baggage from the caller; its OTel logs would
carry exception messages (ADR-0009, T-49).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.telemetry import TelemetryConfig

from sft.core.settings import Settings
from sft.data.database import Database

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


def _lifespan(settings: Settings) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # No connection yet: /readyz never depends on the database, so an outage can't take
        # every pod out of the load balancer at once.
        database = Database.connect(
            settings.database_url.get_secret_value(), pool_size=settings.database_pool_size
        )
        app.state.database = database
        try:
            yield
        finally:
            await database.dispose()

    return lifespan


def get_database(request: Request) -> Database:
    """The FastAPI dependency for the process's database: `Depends(get_database)`."""
    database = getattr(request.app.state, "database", None)
    if not isinstance(database, Database):
        raise RuntimeError("this app was created without settings, so it has no database")
    return database


def create_app(settings: Settings | None = None) -> FastAPI:
    return FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=None if settings is None else _lifespan(settings),
        telemetry=_NO_FASTAPI_TELEMETRY,
    )
