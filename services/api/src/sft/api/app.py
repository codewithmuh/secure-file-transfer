"""The public API app: the routes of the API contract, docs/api/openapi.yaml.

Each feature registers its own routes: member sign-in, sign-out and `GET /me` (#113, auth.py),
the member routes (#112, members.py), transfers and their files (#114, #174 to #176,
transfers.py), the tenant policy (#174, tenant_policy.py), recipients' status and unlock (#178,
#179, recipients.py), the link steps and link sessions (#179, links.py), downloads (#180,
downloads.py), upload requests (#212, upload_requests.py), API keys (#215, api_keys.py), audit
search and export (#216, audit.py), the DLP policy (#218, dlp.py) and DLP approvals (#220,
approvals.py).
Probes and metrics live on the internal port (sft.runtime.internal). The interactive docs and the
OpenAPI document aren't served either: ADR-0002 keeps them off the public load balancer, and CI
builds the document from `create_app().openapi()`.

With settings, the app's lifespan opens the database pool, the rate-limit counter store, the
sign-in service (its OIDC client and state store) and the files buckets' S3 client at startup,
without connecting, and closes them at shutdown, after uvicorn has drained the requests; it also
loads the `email-hmac` keyring and the upload policy, and opens the audit archive of both regions
(#177), the link steps' services: the `code-hmac` and `csrf-hmac` keyrings and their metrics
(#179), and the download services: the async content reader, the byte and stream caps and their
metrics (#180). The app's clock (`sft.core.clock`) is the wall clock, which only a local or test
environment may offset (#182). In AWS (#184) the keyrings come from Secrets Manager, read at startup
and every 5 minutes after (`sft.runtime.secrets`), and the database and Valkey connections sign in
with IAM tokens (`sft.data.iam_auth`). A route reaches them through the `get_database`,
`get_email_keyring`, `get_objects`, `get_upload_policy`, `get_audit_archive` and `now_of`
(dependencies.py), `get_rate_limiter` and `sign_in_service` (caller.py), `get_link_services`
(links.py) and `get_download_services` (downloads.py) dependencies, or names its limits
with `rate_limit` (rate_limits.py). Without settings there is none of them: that app is for
generating the OpenAPI document and for tests of routes that don't need them.

FastAPI's own OpenTelemetry support is off: `RequestContextMiddleware` makes the one SERVER span of
each request, outside FastAPI's error handling, from the attribute allowlist (sft.core.telemetry).
FastAPI's span would be a second root for the same request, record its path and query string,
which can hold a link token, and take `tracestate` and baggage from the caller; its OTel logs would
carry exception messages (ADR-0009, T-49).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager

from fastapi import FastAPI
from fastapi.telemetry import TelemetryConfig
from prometheus_client import CollectorRegistry

from sft.api import (
    api_keys,
    audit,
    auth,
    dlp,
    dlp_reports,
    downloads,
    links,
    members,
    received,
    recipients,
    tenant_policy,
    transfers,
    upload_requests,
)
from sft.api import approvals as approval_routes
from sft.api.dependencies import get_database as get_database  # its home before dependencies.py
from sft.api.errors import register_error_handlers
from sft.api.rate_limits import install_rate_limits
from sft.core.clock import Clock
from sft.core.hmac_keyrings import CodeKeyring
from sft.core.pseudonyms import EmailKeyring
from sft.core.settings import Settings
from sft.data.counters import CounterMetrics, CounterStore, ValkeyIam
from sft.data.database import Database
from sft.runtime.archive import S3AuditArchive
from sft.runtime.content import S3Content
from sft.runtime.s3 import S3Objects
from sft.runtime.secrets import Keyrings
from sft.service.audit_archive import ArchiveMetrics, AuditArchive, Region
from sft.service.audit_search import ExportLeases
from sft.service.csrf import CsrfKeyring
from sft.service.downloads import DownloadMetrics, DownloadServices
from sft.service.links import LinkMetrics, LinkServices
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.downloads import DownloadLimits
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
        # The keyrings first: one that names its secret is read now, and a missing or malformed
        # one stops the startup (encryption and keys 6.5). Then refreshed every 5 minutes.
        keyrings = Keyrings.create(region=settings.aws_region, registry=registry)
        email_keyring = await keyrings.load(
            settings.email_hmac_keyring, EmailKeyring.from_json, name="email"
        )
        code_keyring = await keyrings.load(
            settings.code_hmac_keyring, CodeKeyring.from_json, name="code"
        )
        csrf_keyring = await keyrings.load(
            settings.csrf_keyring, CsrfKeyring.from_json, name="CSRF"
        )
        database = Database.connect(
            settings.database_url.get_secret_value(),
            pool_size=settings.database_pool_size,
            iam_region=settings.aws_region if settings.database_iam_auth else None,
        )
        app.state.database = database
        # The same for the counters: an outage applies each limit's failure mode instead.
        metrics = CounterMetrics.create(registry)
        valkey_iam = ValkeyIam.of(settings.valkey_iam_cache, settings.aws_region)
        store = CounterStore.connect(
            settings.valkey_url.get_secret_value(), metrics, iam=valkey_iam
        )
        app.state.rate_limiter = RateLimiter(store, metrics)
        app.state.sign_in = auth.open_sign_in(settings, database, csrf_keyring, iam=valkey_iam)
        app.state.email_keyring = email_keyring
        # The files buckets (#114). Creating the client opens no connection either.
        objects = S3Objects.create(
            region=settings.aws_region,
            files_bucket=settings.s3_files_bucket,
            large_files_bucket=settings.s3_large_files_bucket,
            kms_key_id=settings.s3_files_kms_key_id,
            endpoint_url=settings.s3_endpoint_url,
            presign_endpoint_url=settings.s3_presign_endpoint_url,
        )
        app.state.objects = objects
        app.state.upload_policy = UploadPolicy(
            storage_quota=settings.tenant_storage_quota_bytes,
            small_pool_max=settings.scan_small_pool_max_bytes,
        )
        archive = AuditArchive(open_archive(settings), ArchiveMetrics.create(registry))
        app.state.audit_archive = archive
        app.state.link_services = LinkServices(
            limiter=app.state.rate_limiter,
            emails=app.state.email_keyring,
            codes=code_keyring,
            csrf=csrf_keyring,
            archive=archive,
            metrics=LinkMetrics.create(registry),
        )
        # Downloads (#180): the async reader of the scanned versions, and group D's byte caps and
        # group E's stream caps beside the rates.
        content = S3Content.create(
            region=settings.aws_region,
            files_bucket=settings.s3_files_bucket,
            large_files_bucket=settings.s3_large_files_bucket,
            endpoint_url=settings.s3_endpoint_url,
            max_streams=settings.download_streams_per_pod,
        )
        app.state.download_services = DownloadServices(
            limiter=app.state.rate_limiter,
            limits=DownloadLimits(store, metrics, pod_streams=settings.download_streams_per_pod),
            archive=archive,
            content=content,
            metrics=DownloadMetrics.create(registry),
            recheck_seconds=settings.download_recheck_seconds,
            clock=app.state.clock,
        )
        # Audit exports (#216): one at a time per tenant, a lease in the counter store.
        app.state.export_leases = ExportLeases(store)
        app.state.keyrings = keyrings
        refresh = asyncio.create_task(keyrings.run())
        try:
            yield
        finally:
            refresh.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await refresh
            await content.close()
            await archive.close()
            await objects.close()
            await app.state.sign_in.aclose()
            await store.close()
            await database.dispose()

    return lifespan


def open_archive(settings: Settings) -> S3AuditArchive:
    """Both regions' audit archive buckets (#177), or Tokyo's alone where there is no Osaka."""
    buckets = {Region.TOKYO: settings.audit_archive_tokyo_bucket}
    endpoints = {Region.TOKYO: settings.audit_archive_tokyo_endpoint_url}
    if settings.audit_archive_osaka_bucket is not None:
        buckets[Region.OSAKA] = settings.audit_archive_osaka_bucket
        endpoints[Region.OSAKA] = settings.audit_archive_osaka_endpoint_url
    return S3AuditArchive.create(buckets, endpoints)


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
    # What the routes read as now: the wall clock, offset only in a local or test environment.
    app.state.clock = (
        Clock() if settings is None else Clock.offset_by(settings.clock_offset_seconds)
    )
    app.state.web_origin = None if settings is None else settings.web_origin
    # The user pool's connection, whose identities a sign-in reset deletes (#197).
    app.state.pool_provider = None if settings is None else settings.oidc_provider_name
    # The environment of the API keys this API makes and takes (#215).
    app.state.api_key_environment = None if settings is None else settings.api_key_environment
    register_error_handlers(app)  # every error is a problem document (docs/api/README.md 3)
    install_rate_limits(app)
    auth.register(app, settings)  # sign-in, sign-out, GET /me and CORS (#113)
    members.register(app)  # members, roles and invitations (#112)
    transfers.register(app)  # transfers, file uploads and reads (#114, #174, #175, #176)
    tenant_policy.register(app)  # the tenant's policy (#174)
    recipients.register(app)  # recipients' status and unlock (#178, #179)
    links.register(app)  # the link steps and link sessions (#179)
    downloads.register(app)  # download grants and streamed content (#180)
    upload_requests.register(app)  # upload requests, revoke and unlock (#212)
    received.register(app)  # uploaders' uploads, received files and their downloads (#213)
    api_keys.register(app)  # API keys, and the record of every key's use (#215)
    audit.register(app)  # audit search and export (#216)
    dlp.register(app)  # the DLP policy, rules and detectors (#218)
    approval_routes.register(app)  # DLP approval requests and decisions (#220)
    dlp_reports.register(app)  # DLP decisions list and report (#222)
    return app
