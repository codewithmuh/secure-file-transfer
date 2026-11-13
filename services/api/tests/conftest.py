import io
import json
import logging
import os
import threading
from collections.abc import AsyncIterator, Callable, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from prometheus_client import CollectorRegistry
from sqlalchemy import URL

from isolation import Mode, World, world_database
from pg import ADMIN_URL_VARIABLE, ScratchDatabase, fresh_database
from sft.core.logs import JsonFormatter
from sft.core.telemetry import build_tracer_provider
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database, psycopg_url
from sft.data.migrate import run
from sft.data.roles import API, MIGRATE, OPERATOR
from sft.runtime.kms import LocalKms
from sft.service import fields


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# The process's tracer provider, as the service sets it up, exporting through the allowlist to
# memory as each span ends. A provider can be set only once per process, so it is set here.
_SPANS = InMemorySpanExporter()
trace.set_tracer_provider(build_tracer_provider("sft-test", "0.0.0", exporter=_SPANS, batch=False))


@pytest.fixture(autouse=True)
def spans() -> Iterator[InMemorySpanExporter]:
    """The spans exported during the test, as the collector would get them."""
    _SPANS.clear()
    yield _SPANS
    _SPANS.clear()


@pytest.fixture(autouse=True)
def field_keys() -> Iterator[fields.FieldKeys]:
    """The process's data keys, as the API installs them, on the KMS stand-in (#236): every test
    that seals or opens a name or message uses them. A test of a narrower workload installs its
    own (the scan worker's `dlp-dek` only)."""
    keys = fields.FieldKeys(LocalKms(), fields.FieldMetrics.create(CollectorRegistry()))
    previous = fields.install(keys)
    yield keys
    fields.install(previous)


class _Collector(BaseHTTPRequestHandler):
    received: list[tuple[str, bytes]]

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.received.append((self.path, body))
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture
def collector() -> Iterator[tuple[str, list[tuple[str, bytes]]]]:
    """A stand-in for the node's collector agent: it records what it is sent over OTLP/HTTP."""
    received: list[tuple[str, bytes]] = []
    handler = type("Handler", (_Collector,), {"received": received})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", received
    server.shutdown()
    server.server_close()


@pytest.fixture
def json_logs() -> Iterator[Callable[[], list[dict[str, object]]]]:
    """Capture what the root logger writes, as the service writes it: one JSON object per line."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)

    def lines() -> list[dict[str, object]]:
        return [json.loads(line) for line in stream.getvalue().splitlines()]

    yield lines
    root.removeHandler(handler)
    root.setLevel(old_level)


# ---- real PostgreSQL ----


@pytest.fixture(scope="session")
def admin_url() -> URL:
    raw = os.environ.get(ADMIN_URL_VARIABLE)
    if not raw:
        if os.environ.get("CI"):
            pytest.fail(f"{ADMIN_URL_VARIABLE} must be set in CI")
        pytest.skip(f"set {ADMIN_URL_VARIABLE} to a PostgreSQL 17 superuser URL")
    return psycopg_url(raw)


@pytest.fixture
def empty_db(admin_url: URL) -> Iterator[ScratchDatabase]:
    """A database of the test's own, bootstrapped but not migrated."""
    with fresh_database(admin_url) as db:
        yield db


@pytest.fixture(scope="session")
def migrated_db(admin_url: URL) -> Iterator[ScratchDatabase]:
    """One database for the session, migrated to head by the migration job as `sft_migrate`."""
    with fresh_database(admin_url) as db:
        run(db.url(MIGRATE))
        yield db


@pytest.fixture
async def api_db(migrated_db: ScratchDatabase) -> AsyncIterator[Database]:
    """The pool the API would have: `sft_api`, one connection, so tests see connection reuse."""
    database = Database.connect(migrated_db.url(API), pool_size=1)
    yield database
    await database.dispose()


@pytest.fixture
async def operator_db(migrated_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(migrated_db.url(OPERATOR), pool_size=1)
    yield database
    await database.dispose()


@pytest.fixture(scope="session")
def isolation_world(admin_url: URL) -> Iterator[World]:
    """The isolation suite's databases: one as built, one with row-level security off."""
    with (
        world_database(admin_url, rls=True) as as_built,
        world_database(admin_url, rls=False) as data_layer_alone,
    ):
        world = World({Mode.AS_BUILT: as_built, Mode.DATA_LAYER_ALONE: data_layer_alone})
        yield world
        world.close()


# ---- real Valkey ----

# A Valkey URL with credentials, e.g. redis://sft-test:…@127.0.0.1:6379/0. Tests flush its database
# 0 before each test that uses it, so never point it at a stack you care about.
VALKEY_URL_VARIABLE = "TEST_VALKEY_URL"


@pytest.fixture(scope="session")
def valkey_url() -> str:
    raw = os.environ.get(VALKEY_URL_VARIABLE)
    if not raw:
        if os.environ.get("CI"):
            pytest.fail(f"{VALKEY_URL_VARIABLE} must be set in CI")
        pytest.skip(f"set {VALKEY_URL_VARIABLE} to a Valkey 9 URL with credentials")
    return raw


@pytest.fixture
async def counter_store(valkey_url: str) -> AsyncIterator[CounterStore]:
    """A store on the test server, emptied first, with metrics of its own. Its calls have 1 s, not
    50 ms: the tests that use it check what the store answers, and one slow answer from a busy test
    runner mustn't fail them. The tests of the 50 ms set it themselves, or make their own store."""
    store = CounterStore.connect(valkey_url, CounterMetrics.create(CollectorRegistry()))
    store._timeout = 1.0
    await store._client.flushdb()  # read here only to start each test empty
    yield store
    await store.close()
