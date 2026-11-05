"""The public API app: the routes of the API contract, docs/api/openapi.yaml.

Each feature registers its own routes: member sign-in, sign-out and `GET /me` (#113, auth.py),
the member routes (#112, members.py), and draft transfers and file uploads (#114, transfers.py).
Probes and metrics live on the internal port (sft.runtime.internal). The interactive docs and the
OpenAPI document aren't served either: ADR-0002 keeps them off the public load balancer, and CI
builds the document from `create_app().openapi()`.

With settings, the app's lifespan opens the database pool, the rate-limit counter store, the
sign-in service (its OIDC client and state store) and the files buckets' S3 client at startup,
without connecting, and closes them at shutdown, after uvicorn has drained the requests; it also
loads the `email-hmac` keyring and the upload policy. A route reaches them through the
`get_database`, `get_email_keyring`, `get_objects` and `get_upload_policy` (dependencies.py),
`get_rate_limiter` and `sign_in_service` (caller.py) dependencies, or names its limits with
`rate_limit` (rate_limits.py). Without settings there is none of them: that app is for generating
the OpenAPI document and for tests of routes that don't need them.

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

from sft.api import auth, members, transfers
from sft.api.dependencies import get_database as get_database  # its home before dependencies.py
from sft.api.errors import register_error_handlers
from sft.api.rate_limits import install_rate_limits
from sft.core.pseudonyms import EmailKeyring
from sft.core.settings import Settings
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.runtime.s3 import S3Objects
from sft.service.rate_limits import RateLimiter
from sft.service.uploads import UploadPolicy

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
        app.state.sign_in = auth.open_sign_in(settings, database)
        app.state.email_keyring = EmailKeyring.from_json(
            settings.email_hmac_keyring.get_secret_value()
        )
        # The files buckets (#114). Creating the client opens no connection either.
        objects = S3Objects.create(
            region=settings.aws_region,
            files_bucket=settings.s3_files_bucket,
            large_files_bucket=settings.s3_large_files_bucket,
            kms_key_id=settings.s3_files_kms_key_id,
            endpoint_url=settings.s3_endpoint_url,
        )
        app.state.objects = objects
        app.state.upload_policy = UploadPolicy(storage_quota=settings.tenant_storage_quota_bytes)
        try:
            yield
        finally:
            await objects.close()
            await app.state.sign_in.aclose()
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
    auth.register(app, settings)  # sign-in, sign-out, GET /me and CORS (#113)
    members.register(app)  # members, roles and invitations (#112)
    transfers.register(app)  # draft transfers and file uploads (#114)
    return app
