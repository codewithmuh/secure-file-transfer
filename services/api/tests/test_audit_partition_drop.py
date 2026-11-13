"""Audit events past their 365 days (#255; NFR-9; data model 6; revision 0040): the partition job
drops a month whose end is 365 days behind its clock, once every row of it is archived in both
regions, and leaves a newer month, an unarchived one and one waiting for its back-fill.

Each test gets a migrated database of its own, since it drops partitions and moves the archive
cursor. Past months are made as `sft_recovery` makes them before a re-import, so the owner owns
them; their events are inserted as the superuser, one transaction each, as a workload writes them.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, date, datetime, timedelta

import pytest
from prometheus_client import CollectorRegistry
from sqlalchemy import URL, text

from pg import ScratchDatabase, fresh_database
from sft.data import audit
from sft.data.database import Database
from sft.data.migrate import run
from sft.data.roles import JOBS, MIGRATE, RECOVERY
from sft.data.scope import Scope
from sft.service import lifecycle
from sft.service.audit_partitions import AuditPartitionMetrics, maintain_audit_partitions
from sft.service.lifecycle import JobMetrics, Jobs

pytestmark = pytest.mark.anyio

RETENTION = timedelta(days=365)


def month(offset: int) -> date:
    now = datetime.now(UTC)
    year, index = divmod(now.year * 12 + now.month - 1 + offset, 12)
    return date(year, index + 1, 1)


def name(offset: int) -> str:
    first = month(offset)
    return f"audit_events_y{first.year:04d}m{first.month:02d}"


def ends(offset: int) -> datetime:
    """The first instant after the month: when its newest possible row was written."""
    first = month(offset + 1)
    return datetime(first.year, first.month, 1, tzinfo=UTC)


def middle(offset: int) -> datetime:
    first = month(offset)
    return datetime(first.year, first.month, 15, 12, tzinfo=UTC)


@pytest.fixture
def own_db(admin_url: URL) -> Iterator[ScratchDatabase]:
    with fresh_database(admin_url) as db:
        run(db.url(MIGRATE))
        yield db


@pytest.fixture
async def jobs(own_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(own_db.url(JOBS), pool_size=1)
    yield database
    await database.dispose()


@pytest.fixture
async def recovery(own_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(own_db.url(RECOVERY), pool_size=1)
    yield database
    await database.dispose()


async def past_months(recovery: Database, back: int) -> None:
    async with recovery.transaction(Scope.recovery()) as session:
        await audit.create_partitions(session, 0, month(-back))


def add_event(db: ScratchDatabase, at: datetime) -> tuple[uuid.UUID, str]:
    """An event of `at`'s month in a transaction of its own; its ID and transaction."""
    event_id = uuid.uuid4()
    [(tx,)] = db.sql(
        "INSERT INTO audit_events (id, occurred_at, actor_type, action, outcome) "
        "VALUES (:id, :at, 'system', 'transfer.expired', 'success') RETURNING tx_id::text",
        id=event_id,
        at=at,
    )
    return event_id, str(tx)


def archive_up_to(db: ScratchDatabase, tx: str) -> None:
    """The archive job has archived, in both regions, every transaction before `tx`."""
    db.sql("UPDATE audit_archive_cursor SET archived_up_to_tx = CAST(:tx AS xid8)", tx=tx)


def partitions(db: ScratchDatabase) -> set[str]:
    return {
        str(n)
        for (n,) in db.sql(
            "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
            "WHERE i.inhparent = 'audit_events'::regclass"
        )
    }


def events(db: ScratchDatabase) -> set[uuid.UUID]:
    return {i for (i,) in db.sql("SELECT id FROM audit_events")}  # type: ignore[misc]


def expired_gauge(metrics: AuditPartitionMetrics) -> float | None:
    return metrics.registry.get_sample_value("sft_audit_expired_partitions")


async def test_an_expired_archived_month_goes_and_newer_or_unarchived_ones_stay(
    jobs: Database, recovery: Database, own_db: ScratchDatabase
) -> None:
    # Acceptance criterion 1, with the jobs' clock injected.
    await past_months(recovery, 18)
    newer, _ = add_event(own_db, middle(-16))
    old, _ = add_event(own_db, middle(-18))
    unarchived, unarchived_tx = add_event(own_db, middle(-17))
    archive_up_to(own_db, unarchived_tx)  # the first two are archived, the third isn't
    metrics = AuditPartitionMetrics.create()

    # An hour before the oldest month's 365 days are up, nothing has expired.
    early = ends(-18) + RETENTION - timedelta(hours=1)
    status = await maintain_audit_partitions(jobs, metrics, now=lambda: early)
    assert (status.expired, status.dropped, status.unarchived) == (0, (), ())
    assert expired_gauge(metrics) == 0

    # Once the two oldest months are past it: the archived one goes, the unarchived one stays and
    # is counted, and the newer one isn't touched.
    later = ends(-17) + RETENTION + timedelta(hours=1)
    status = await maintain_audit_partitions(jobs, metrics, now=lambda: later)
    assert status.dropped == (name(-18),)
    assert status.unarchived == (name(-17),)
    assert (status.expired, status.drop_failed) == (1, ())
    assert expired_gauge(metrics) == 1
    left = partitions(own_db)
    assert name(-18) not in left
    assert {name(-17), name(-16), "audit_events_default"} <= left
    assert events(own_db) >= {newer, unarchived}
    assert old not in events(own_db)

    # The archive job catches up; the next run drops the month.
    archive_up_to(own_db, str(int(unarchived_tx) + 1))
    status = await maintain_audit_partitions(jobs, metrics, now=lambda: later)
    assert (status.dropped, status.expired) == ((name(-17),), 0)
    assert expired_gauge(metrics) == 0
    assert metrics.registry.get_sample_value("sft_audit_partition_last_success_timestamp_seconds")


async def test_a_clock_ahead_of_the_databases_drops_nothing_early(
    jobs: Database, recovery: Database, own_db: ScratchDatabase
) -> None:
    await past_months(recovery, 2)
    _, tx = add_event(own_db, middle(-1))
    archive_up_to(own_db, str(int(tx) + 1))
    far = datetime.now(UTC) + timedelta(days=800)
    status = await maintain_audit_partitions(jobs, AuditPartitionMetrics.create(), now=lambda: far)
    # The database's own clock decides: last month and this one are far from 365 days old.
    assert status.dropped == ()
    assert {name(-2), name(-1), name(0)} <= partitions(own_db)


async def test_a_month_waiting_for_its_back_fill_stays(
    jobs: Database, recovery: Database, own_db: ScratchDatabase
) -> None:
    # #257: a range written to one region alone during a regional loss isn't in both regions yet.
    await past_months(recovery, 18)
    _, tx = add_event(own_db, middle(-18))
    archive_up_to(own_db, str(int(tx) + 5))
    own_db.sql(
        "INSERT INTO audit_archive_single_region (generation, from_tx, up_to_tx, region) "
        "VALUES (1, CAST(:start AS xid8), CAST(:end AS xid8), 'ap-northeast-3')",
        start=tx,
        end=str(int(tx) + 5),
    )
    later = ends(-18) + RETENTION + timedelta(hours=1)
    status = await maintain_audit_partitions(
        jobs, AuditPartitionMetrics.create(), now=lambda: later
    )
    assert (status.dropped, status.unarchived) == ((), (name(-18),))

    own_db.sql("DELETE FROM audit_archive_single_region")  # the back-fill wrote it to both
    status = await maintain_audit_partitions(
        jobs, AuditPartitionMetrics.create(), now=lambda: later
    )
    assert status.dropped == (name(-18),)


async def test_the_lifecycle_job_drops_with_its_clock_and_reports_it(
    jobs: Database, recovery: Database, own_db: ScratchDatabase
) -> None:
    await past_months(recovery, 18)
    _, tx = add_event(own_db, middle(-18))
    archive_up_to(own_db, str(int(tx) + 1))
    later = ends(-18) + RETENTION + timedelta(hours=1)
    registry = CollectorRegistry()
    job = Jobs(database=jobs, metrics=JobMetrics.create(registry), now=lambda: later)
    job.partition_metrics = AuditPartitionMetrics.create(registry)
    report = await lifecycle.maintain_partitions(job)
    assert report["partitions_dropped"] == 1
    assert report["expired_partitions"] == 0
    assert name(-18) not in partitions(own_db)


async def test_a_drop_another_run_holds_waits_for_the_next_run(
    jobs: Database, own_db: ScratchDatabase
) -> None:
    # One partition run at a time: the creation's advisory lock is the drop's too.
    holder = Database.connect(own_db.url(JOBS), pool_size=1)
    try:
        async with holder.raw_connection_for_tests() as connection, connection.begin():
            await connection.execute(text("SELECT pg_advisory_xact_lock(50000001)"))
            async with jobs.transaction(Scope.system()) as session:
                assert await audit.drop_expired_partitions(session) == {}
    finally:
        await holder.dispose()
