"""The link and session world the link and download tests share (#179, #180): the real app over
ASGI (over https, so the browser-like client keeps `Secure` cookies) against the real database, a
real Valkey for the limits with a clock the test moves, the notification worker as `sft_notify`
(notify_fixtures.py), an in-memory audit archive and in-memory file contents.

Import the fixture `w` into a test module to use it: `from link_fixtures import w`.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any

import httpx2 as httpx
import pytest
from prometheus_client import CollectorRegistry

from api_settings import CODE_HMAC_KEYRING, CSRF_KEYRING, WEB_ORIGIN
from archive_fixtures import FakeArchiveStore, fake_archive
from member_fixtures import EMAIL_KEYRING, Tenant, seed_tenant
from notify_fixtures import Sent, drain, notifier
from object_fixtures import FakeContent
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.core.hmac_keyrings import CodeKeyring
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.data.roles import API, NOTIFY
from sft.service.csrf import CsrfKeyring
from sft.service.downloads import DownloadMetrics, DownloadServices
from sft.service.links import LinkMetrics, LinkServices
from sft.service.notifications import Notifier
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.downloads import DownloadLimits
from transfer_fixtures import seed_file, seed_transfer

COOKIE = "__Host-sft_link"
BASE = "https://api.sft.test"


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Browser:
    """One browser: its link cookie, kept as a browser keeps it."""

    http: httpx.AsyncClient
    cookie: str | None = None

    def headers(self, session_id: object | None = None, **more: str) -> dict[str, str]:
        # The test keeps the cookie itself, so it sends exactly what it means to: never the
        # client's own jar.
        self.http.cookies.clear()
        out = dict(more)
        if self.cookie:
            out["cookie"] = f"{COOKIE}={self.cookie}"
        if session_id is not None:
            out["x-link-session"] = str(session_id)
        return out

    async def post(self, path: str, body: dict[str, Any]) -> httpx.Response:
        response = await self.http.post(path, json=body, headers=self.headers())
        self.keep(response)
        return response

    async def get(self, path: str, session_id: object | None) -> httpx.Response:
        return await self.http.get(path, headers=self.headers(session_id))

    def keep(self, response: httpx.Response) -> None:
        raw = response.headers.get("set-cookie")
        if raw:
            jar: SimpleCookie = SimpleCookie()
            jar.load(raw)
            value = jar[COOKIE].value
            self.cookie = value or None


@dataclass
class World:
    db: ScratchDatabase
    api: Database
    notify: Database
    tenant: Tenant
    clock: Clock
    store: FakeArchiveStore
    sent: Sent
    worker: Notifier
    registry: CollectorRegistry
    app: Any
    browsers: list[httpx.AsyncClient] = field(default_factory=list)

    @property
    def downloads(self) -> DownloadServices:
        services: DownloadServices = self.app.state.download_services
        return services

    @property
    def content(self) -> FakeContent:
        content = self.downloads.content
        assert isinstance(content, FakeContent)
        return content

    async def browser(self) -> Browser:
        transport = httpx.ASGITransport(app=self.app)
        http = httpx.AsyncClient(transport=transport, base_url=BASE)
        self.browsers.append(http)
        return Browser(http)

    def transfer(
        self, *addresses: str, tenant: Tenant | None = None, files: tuple[str, ...] = ("clean",)
    ) -> tuple[uuid.UUID, list[uuid.UUID]]:
        """A sent transfer with its recipients `queued` and its files; message "hello"."""
        owner = tenant or self.tenant
        transfer_id, ids = seed_transfer(
            self.db, owner.id, owner.target, state="sent", recipients=addresses
        )
        self.db.sql(
            "UPDATE transfers SET message_ct = '\\x0068656c6c6f', sent_at = now() WHERE id = :id",
            id=transfer_id,
        )
        self.db.sql(
            "UPDATE transfer_recipients SET delivery_state = 'queued' WHERE transfer_id = :id",
            id=transfer_id,
        )
        # The evaluation's message to the notification worker (#174).
        self.db.sql(
            "INSERT INTO outbox (id, tenant_id, topic, payload) VALUES (:id, :tenant, "
            "'transfer.sent', jsonb_build_object('transfer_id', CAST(:transfer AS text)))",
            id=uuid.uuid4(),
            tenant=owner.id,
            transfer=str(transfer_id),
        )
        for state in files:
            file_id = seed_file(
                self.db,
                owner.id,
                transfer_id,
                state=state,
                unscannable_allowed=state == "unscannable",
            )
            for recipient_id in ids:
                self.db.sql(
                    "INSERT INTO download_counters (tenant_id, recipient_id, file_id) "
                    "VALUES (:t, :r, :f)",
                    t=owner.id,
                    r=recipient_id,
                    f=file_id,
                )
        return transfer_id, ids

    async def links(self, tenant: Tenant | None = None) -> None:
        """The worker sends every link and code that is due."""
        await drain(self.worker, self.db, (tenant or self.tenant).id)

    async def link_for(self, address: str, tenant: Tenant | None = None) -> str:
        await self.links(tenant)
        return self.sent.links(address)[-1]

    async def code(
        self, browser: Browser, token: str, address: str, tenant: Tenant | None = None
    ) -> str:
        self.clock.advance(31)  # past the 30 seconds between two codes for one link
        response = await browser.post("/v1/links/codes", {"token": token})
        assert response.status_code == 202, response.text
        await self.links(tenant)
        return self.sent.codes(address)[-1]

    async def verify(
        self, browser: Browser, address: str, tenant: Tenant | None = None
    ) -> tuple[str, dict[str, Any]]:
        token = await self.link_for(address, tenant)
        code = await self.code(browser, token, address, tenant)
        response = await browser.post("/v1/links/sessions", {"token": token, "code": code})
        assert response.status_code == 201, response.text
        return token, response.json()


def unique() -> str:
    return f"r-{uuid.uuid4().hex[:12]}@partner.example"


def build_app(
    db: ScratchDatabase, api: Database, limiter: RateLimiter, store: FakeArchiveStore
) -> tuple[Any, CollectorRegistry]:
    registry = CollectorRegistry()
    app = create_app()
    archive = fake_archive(store)
    app.state.database = api
    app.state.rate_limiter = limiter
    app.state.email_keyring = EMAIL_KEYRING
    app.state.audit_archive = archive
    app.state.web_origin = WEB_ORIGIN
    app.state.link_services = LinkServices(
        limiter=limiter,
        emails=EMAIL_KEYRING,
        codes=CodeKeyring.from_json(CODE_HMAC_KEYRING),
        csrf=CsrfKeyring.from_json(CSRF_KEYRING),
        archive=archive,
        metrics=LinkMetrics.create(registry),
    )
    # Downloads (#180): in-memory contents, and the byte and stream caps on the same store.
    store_of_counters: CounterStore = limiter._store  # the limiter's own store
    app.state.download_services = DownloadServices(
        limiter=limiter,
        limits=DownloadLimits(
            store_of_counters, CounterMetrics.create(CollectorRegistry()), clock=limiter._clock
        ),
        archive=archive,
        content=FakeContent(),
        metrics=DownloadMetrics.create(registry),
        recheck_seconds=0.2,
    )
    return app, registry


@pytest.fixture
async def w(migrated_db: ScratchDatabase, counter_store: CounterStore) -> AsyncIterator[World]:
    api = Database.connect(migrated_db.url(API), pool_size=4)
    notify = Database.connect(migrated_db.url(NOTIFY), pool_size=2)
    clock = Clock()
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()), clock=clock)
    store = FakeArchiveStore()
    app, registry = build_app(migrated_db, api, limiter, store)
    sent = Sent()
    world = World(
        migrated_db,
        api,
        notify,
        seed_tenant(migrated_db),
        clock,
        store,
        sent,
        notifier(notify, sent),
        registry,
        app,
    )
    yield world
    for http in world.browsers:
        await http.aclose()
    await api.dispose()
    await notify.dispose()
