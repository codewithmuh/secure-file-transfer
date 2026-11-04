import io
import json
import logging
import os
from collections.abc import AsyncIterator, Callable, Iterator

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from sqlalchemy import URL

from pg import ADMIN_URL_VARIABLE, ScratchDatabase, fresh_database
from sft.core.logs import JsonFormatter
from sft.core.telemetry import build_tracer_provider
from sft.data.database import Database, psycopg_url
from sft.data.migrate import run
from sft.data.roles import API, MIGRATE, OPERATOR


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
