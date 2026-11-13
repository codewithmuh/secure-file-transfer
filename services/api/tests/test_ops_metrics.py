"""The remaining SLI and alert metrics of slos.md 6 (#260): NFR-7's send latency, the DLP approval
queue's age, and the age of the ClamAV signatures clamd scans with. The catalogue and label checks
of every metric are test_sli_metrics.py's; the alerts' promtool cases are deploy/alerts/tests.
"""

from __future__ import annotations

import asyncio
import math
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from prometheus_client import CollectorRegistry

import isolation_fixture
from isolation import seed_tenant
from pg import ScratchDatabase
from sft.core.ids import uuid7
from sft.data.database import Database
from sft.data.migrate import run
from sft.data.roles import JOBS, MIGRATE
from sft.service import lifecycle
from sft.service.email.catalog import EmailType
from sft.service.lifecycle import ApprovalBacklogMetrics, JobMetrics, Jobs
from sft.service.notifications import NotifyMetrics
from sft.workers.clamd import ClamdError, parse_version, signatures_built
from sft.workers.scan import Engines, SignatureMetrics, SignatureWatch

pytestmark = pytest.mark.anyio


# ---- NFR-7: from the message to the provider ----


def test_send_latency_runs_from_the_messages_id_to_the_send() -> None:
    registry = CollectorRegistry()
    metrics = NotifyMetrics.create(registry)
    for email_type in EmailType:  # every series exists at zero
        labels = {"type": email_type.value}
        assert registry.get_sample_value("send_latency_seconds_count", labels) == 0
    made = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
    message_id = uuid7(int(made.timestamp() * 1000))
    metrics.observe_send(message_id, EmailType.VERIFICATION_CODE, made + timedelta(seconds=3))
    labels = {"type": "verification_code"}
    assert registry.get_sample_value("send_latency_seconds_count", labels) == 1
    assert registry.get_sample_value("send_latency_seconds_sum", labels) == pytest.approx(3.0)
    # NFR-7's edge at 10 s is a bucket of its own.
    assert registry.get_sample_value("send_latency_seconds_bucket", labels | {"le": "10.0"}) == 1
    # Not a UUIDv7 (a message from before data model 1's IDs): nothing to measure from.
    metrics.observe_send(uuid.uuid4(), EmailType.VERIFICATION_CODE, made)
    assert registry.get_sample_value("send_latency_seconds_count", labels) == 1
    # A clock behind the message's never makes a negative time.
    metrics.observe_send(message_id, EmailType.TRANSFER_LINK, made - timedelta(seconds=1))
    assert registry.get_sample_value("send_latency_seconds_sum", {"type": "transfer_link"}) == 0


# ---- the DLP approval queue (abuse and rate limits 8.2, DlpApprovalBacklog) ----


@pytest.fixture
def own_db(empty_db: ScratchDatabase) -> ScratchDatabase:
    run(empty_db.url(MIGRATE))
    empty_db.as_owner(isolation_fixture.create)
    return empty_db


@pytest.fixture
async def jobs(own_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(own_db.url(JOBS), pool_size=1)
    yield database
    await database.dispose()


async def test_the_expiry_job_measures_the_oldest_request_and_its_share_of_the_timeout(
    jobs: Database, own_db: ScratchDatabase
) -> None:
    registry = CollectorRegistry()
    job = Jobs(database=jobs, metrics=JobMetrics.create(registry), now=lambda: datetime.now(UTC))
    job.approval_metrics = ApprovalBacklogMetrics.create(registry)
    empty = await lifecycle.measure_approval_backlog(job)
    assert (empty.oldest_seconds, empty.timeout_used) == (0, 0)

    seeded = seed_tenant(own_db, "approvals")
    # Waiting 30 hours of a 48-hour timeout: 62.5 % of it used.
    own_db.sql(
        "UPDATE dlp_approval_requests SET created_at = now() - interval '30 hours', "
        "expires_at = now() + interval '18 hours' WHERE id = :id",
        id=seeded.rows["dlp_approval_request"],
    )
    backlog = await lifecycle.measure_approval_backlog(job)
    assert backlog.oldest_seconds == pytest.approx(30 * 3600, abs=120)
    assert backlog.timeout_used == pytest.approx(0.625, abs=0.01)
    assert registry.get_sample_value("dlp_approval_oldest_pending_age_seconds") == pytest.approx(
        30 * 3600, abs=120
    )
    assert registry.get_sample_value("dlp_approval_pending_timeout_used_ratio") == pytest.approx(
        0.625, abs=0.01
    )

    # A decided request is no longer waiting.
    own_db.sql(
        "UPDATE dlp_approval_requests SET state = 'approved', ended_at = now() WHERE id = :id",
        id=seeded.rows["dlp_approval_request"],
    )
    assert (await lifecycle.measure_approval_backlog(job)).oldest_seconds == 0


# ---- ClamAV's signatures (threat model T-27) ----


def test_clamds_version_answer_gives_the_databases_build_time() -> None:
    built = parse_version(b"ClamAV 1.5.4/27820/Sun Nov  8 09:24:12 2026\0")
    assert built == datetime(2026, 11, 8, 9, 24, 12, tzinfo=UTC)
    for bad in (b"ClamAV 1.5.4\0", b"stream: OK\0", b"ClamAV 1.5.4/1/not a date\0"):
        with pytest.raises(ClamdError):
            parse_version(bad)


async def _clamd(answer: bytes) -> tuple[asyncio.Server, int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if await reader.readuntil(b"\0") == b"zVERSION\0":
            writer.write(answer)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_the_age_grows_from_the_last_build_time_clamd_gave() -> None:
    server, port = await _clamd(b"ClamAV 1.5.4/27820/Sun Nov  8 09:24:12 2026\0")
    registry = CollectorRegistry()
    now = datetime(2026, 11, 9, 9, 24, 12, tzinfo=UTC).timestamp()
    watch = SignatureWatch(
        Engines("127.0.0.1", port, "127.0.0.1", 9, connect_timeout=2),
        SignatureMetrics.create(registry),
        clock=lambda: now,
    )
    try:
        # Until clamd answers, the age is unknown, never 0.
        assert math.isnan(registry.get_sample_value("clamav_signature_age_seconds") or 0.0)
        await watch.check()
        assert registry.get_sample_value("clamav_signature_age_seconds") == 86400
    finally:
        server.close()
        await server.wait_closed()
    # clamd stops answering: the last build time stays, so the age keeps growing.
    await watch.check()
    now += 3600
    assert registry.get_sample_value("clamav_signature_age_seconds") == 90000


async def test_the_local_clamd_answers_its_version() -> None:
    url = os.environ.get("TEST_CLAMD_URL")
    if not url:
        pytest.skip("set TEST_CLAMD_URL to a clamd")
    host, port = url.removeprefix("tcp://").rsplit(":", 1)
    async with asyncio.timeout(10):
        built = await signatures_built(host, int(port))
    assert built < datetime.now(UTC)
