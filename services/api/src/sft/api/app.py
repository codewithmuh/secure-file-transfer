"""The public API app: the routes of the API contract, docs/api/openapi.yaml.

It has no routes yet; the first arrive in M1. Probes and metrics live on the internal port
(internal.py). The interactive docs and the OpenAPI document aren't served either: ADR-0002 keeps
them off the public load balancer, and CI builds the document from `create_app().openapi()`.

With settings, the app's lifespan opens the database pool at startup, without connecting, and
closes it at shutdown, after uvicorn has drained the requests. A route reaches it through the
`get_database` dependency. Without settings there is no database: that app is for generating the
OpenAPI document and for tests of routes that don't need one.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI, Request

from sft.api.errors import register_error_handlers
from sft.core.settings import Settings
from sft.data.database import Database

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
    app = FastAPI(
        title=API_TITLE,
        version=API_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=None if settings is None else _lifespan(settings),
    )
    register_error_handlers(app)  # every error is a problem document (docs/api/README.md 3)
    return app
