"""Audit partition upkeep after the #50 review: one month's failure doesn't stop the next, two
runs don't collide, a failing run still measures, and recovery can make past months."""

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from pg import ScratchDatabase
from sft.data import audit
from sft.data.database import Database
from sft.data.migrate import run
from sft.data.roles import JOBS, MIGRATE, RECOVERY
from sft.data.scope import Scope
from sft.service.audit_partitions import AuditPartitionMetrics, maintain_audit_partitions

pytestmark = pytest.mark.anyio


def month(offset: int = 0) -> date:
    now = datetime.now(UTC)
    year, index = divmod(now.year * 12 + now.month - 1 + offset, 12)
    return date(year, index + 1, 1)


def name(offset: int = 0) -> str:
    first = month(offset)
    return f"audit_events_y{first.year:04d}m{first.month:02d}"


def drop_partition(db: ScratchDatabase, partition: str) -> None:
    db.sql(f"ALTER TABLE audit_events DETACH PARTITION {partition}")
    db.sql(f"DROP TABLE {partition}")


@pytest.fixture
def own_db(empty_db: ScratchDatabase) -> ScratchDatabase:
    """A migrated database of the test's own, since these tests drop partitions."""
    run(empty_db.url(MIGRATE))
    return empty_db


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


async def test_a_failed_month_does_not_stop_the_next(
    jobs: Database, own_db: ScratchDatabase
) -> None:
    drop_partition(own_db, name(1))
    drop_partition(own_db, name(2))
    # A type with the partition's name makes its CREATE TABLE fail (duplicate_object).
    own_db.sql(f"CREATE TYPE {name(1)} AS (x int)")
    async with jobs.transaction(Scope.system()) as session:
        results = await audit.create_partitions(session)
    assert results == {name(0): "exists", name(1): "failed", name(2): "created", name(3): "exists"}


async def test_a_failed_month_is_measured_and_is_not_a_success(
    jobs: Database, own_db: ScratchDatabase
) -> None:
    drop_partition(own_db, name(1))
    own_db.sql(f"CREATE TYPE {name(1)} AS (x int)")
    metrics = AuditPartitionMetrics.create()
    status = await maintain_audit_partitions(jobs, metrics)
    assert status == audit.PartitionStatus(default_rows=0, months_covered=1, failed=(name(1),))
    assert metrics.registry.get_sample_value("sft_audit_partition_months_covered") == 1.0
    assert (
        metrics.registry.get_sample_value("sft_audit_partition_last_success_timestamp_seconds")
        == 0.0
    )


async def test_a_good_run_records_its_success(jobs: Database) -> None:
    metrics = AuditPartitionMetrics.create()
    before = datetime.now(UTC).timestamp()
    await maintain_audit_partitions(jobs, metrics)
    last = metrics.registry.get_sample_value("sft_audit_partition_last_success_timestamp_seconds")
    assert last is not None
    assert last >= before - 1


async def test_a_run_that_raises_still_measures(jobs: Database, own_db: ScratchDatabase) -> None:
    own_db.sql(
        "INSERT INTO audit_events (id, actor_type, action, outcome, occurred_at) "
        "VALUES (gen_random_uuid(), 'system', 'x.y', 'success', '2099-01-01')"
    )
    metrics = AuditPartitionMetrics.create()
    with pytest.raises(DBAPIError, match="between 0 and 12"):
        await maintain_audit_partitions(jobs, metrics, months_ahead=13)
    assert metrics.registry.get_sample_value("sft_audit_default_partition_rows") == 1.0
    assert metrics.registry.get_sample_value("sft_audit_partition_months_covered") == 4.0
    assert (
        metrics.registry.get_sample_value("sft_audit_partition_last_success_timestamp_seconds")
        == 0.0
    )


async def test_two_runs_at_once_do_not_collide(jobs: Database, own_db: ScratchDatabase) -> None:
    second = Database.connect(own_db.url(JOBS), pool_size=1)
    try:
        async with jobs.transaction(Scope.system()) as first:
            # The first run holds the lock until it commits; the second finds it taken and skips,
            # measures, and doesn't count as a success.
            assert set((await audit.create_partitions(first)).values()) == {"exists"}
            async with second.transaction(Scope.system()) as session:
                assert await audit.create_partitions(session) == {}
            metrics = AuditPartitionMetrics.create()
            status = await maintain_audit_partitions(second, metrics)
        assert status == audit.PartitionStatus(default_rows=0, months_covered=4)
        assert (
            metrics.registry.get_sample_value("sft_audit_partition_last_success_timestamp_seconds")
            == 0.0
        )
    finally:
        await second.dispose()


async def test_recovery_makes_past_months_before_it_reimports(
    recovery: Database, own_db: ScratchDatabase
) -> None:
    async with recovery.transaction(Scope.recovery()) as session:
        results = await audit.create_partitions(session, from_month=month(-3))
    assert results == {
        name(-3): "created",
        name(-2): "created",
        name(-1): "created",
        **{name(i): "exists" for i in range(4)},
    }
    # A re-imported event keeps its month and lands in that month's partition.
    event_id = uuid.uuid4()
    async with recovery.transaction(Scope.recovery()) as session:
        await session.execute(
            text(
                "INSERT INTO audit_events (id, tenant_id, tx_id, occurred_at, actor_type, action, "
                "outcome) VALUES (:id, :tenant, '7'::xid8, :at, 'system', 'transfer.revoked', "
                "'success')"
            ),
            {"id": event_id, "tenant": uuid.uuid4(), "at": month(-2)},
        )
    assert own_db.sql(
        "SELECT tableoid::regclass::text FROM audit_events WHERE id = :id", id=event_id
    ) == [(name(-2),)]


@pytest.mark.parametrize("offset", [1, -25])
async def test_from_month_is_bounded(recovery: Database, offset: int) -> None:
    with pytest.raises(DBAPIError, match="within the last 24 months"):
        async with recovery.transaction(Scope.recovery()) as session:
            await audit.create_partitions(session, from_month=month(offset))
