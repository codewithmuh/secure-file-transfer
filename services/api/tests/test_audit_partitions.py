"""Audit partitions: made ahead, a missing month caught by the default partition and the metric."""

import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import DBAPIError

from pg import ScratchDatabase
from sft.data import audit
from sft.data.database import Database
from sft.data.migrate import run
from sft.data.models import Tenant
from sft.data.roles import API, JOBS, MIGRATE, OPERATOR
from sft.data.scope import Scope
from sft.service.audit_partitions import AuditPartitionMetrics, maintain_audit_partitions

pytestmark = pytest.mark.anyio


def month_name(offset: int = 0) -> str:
    now = datetime.now(UTC)
    year, month = divmod(now.year * 12 + now.month - 1 + offset, 12)
    return f"audit_events_y{year:04d}m{month + 1:02d}"


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
async def operator(own_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(own_db.url(OPERATOR), pool_size=1)
    yield database
    await database.dispose()


def gauges(metrics: AuditPartitionMetrics) -> tuple[float | None, float | None]:
    return (
        metrics.registry.get_sample_value("sft_audit_default_partition_rows"),
        metrics.registry.get_sample_value("sft_audit_partition_months_covered"),
    )


def drop_partition(db: ScratchDatabase, name: str) -> None:
    db.sql(f"ALTER TABLE audit_events DETACH PARTITION {name}")
    db.sql(f"DROP TABLE {name}")


async def test_the_migration_makes_this_month_and_three_ahead(
    jobs: Database, own_db: ScratchDatabase
) -> None:
    metrics = AuditPartitionMetrics.create()
    status = await maintain_audit_partitions(jobs, metrics)
    assert status == audit.PartitionStatus(default_rows=0, months_covered=4)
    assert gauges(metrics) == (0.0, 4.0)
    partitions = own_db.sql(
        "SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid "
        "WHERE i.inhparent = 'audit_events'::regclass ORDER BY 1"
    )
    assert [name for (name,) in partitions] == [
        "audit_events_default",
        *(month_name(i) for i in range(4)),
    ]


async def test_the_job_creates_missing_months_ahead(
    jobs: Database, own_db: ScratchDatabase, json_logs: Callable[[], list[dict[str, object]]]
) -> None:
    drop_partition(own_db, month_name(3))
    metrics = AuditPartitionMetrics.create()
    async with jobs.transaction(Scope.system()) as session:
        assert await audit.partition_status(session) == audit.PartitionStatus(0, 3)

    status = await maintain_audit_partitions(jobs, metrics)
    assert status == audit.PartitionStatus(default_rows=0, months_covered=4)
    assert gauges(metrics) == (0.0, 4.0)
    assert [
        line["partitions"] for line in json_logs() if line["msg"] == "audit partitions created"
    ] == [[month_name(3)]]

    async with jobs.transaction(Scope.system()) as session:
        results = await audit.create_partitions(session, months_ahead=4)
    assert results == {
        **{month_name(i): "exists" for i in range(4)},
        month_name(4): "created",
    }
    # A partition the job made is like the others: indexed, owned by the owner, granted to nobody.
    assert own_db.sql(
        "SELECT pg_get_userbyid(relowner), relacl IS NULL, "
        "(SELECT count(*) FROM pg_index WHERE indrelid = c.oid) "
        "FROM pg_class c WHERE relname = :name",
        name=month_name(4),
    ) == [("sft_owner", True, 5)]


async def test_a_row_for_a_missing_month_lands_in_the_default_partition_and_raises_the_metric(
    jobs: Database, operator: Database, own_db: ScratchDatabase, json_logs: object
) -> None:
    # Acceptance criterion 2. This month's partition is missing, as if the job had stopped.
    drop_partition(own_db, month_name(0))

    # The audited action still commits: audit writes never fail for lack of a partition.
    tenant_id = uuid.uuid4()
    async with operator.transaction(Scope.tenant(tenant_id)) as session:
        session.add(Tenant(id=tenant_id, name="Example", status="active"))
        event_id = await audit.record(
            session,
            action="tenant.created",
            actor=audit.Actor(audit.ActorType.OPERATOR, uuid.uuid4()),
            target=audit.Target("tenant", tenant_id),
        )
    assert own_db.sql(
        "SELECT tableoid::regclass::text FROM audit_events WHERE id = :id", id=event_id
    ) == [("audit_events_default",)]

    metrics = AuditPartitionMetrics.create()
    status = await maintain_audit_partitions(jobs, metrics)
    assert status == audit.PartitionStatus(
        default_rows=1, months_covered=0, blocked=(month_name(0),)
    )
    assert gauges(metrics) == (1.0, 0.0)
    errors = [line for line in json_logs() if line["level"] == "error"]  # type: ignore[operator]
    assert errors == [
        {
            **errors[0],
            "msg": "audit events in the default partition",
            "default_rows": 1,
            "blocked": [month_name(0)],
        }
    ]

    # The row stays where it is: the month stays blocked, and the metric up, until an operator
    # moves it. Later months are still made.
    drop_partition(own_db, month_name(2))
    async with jobs.transaction(Scope.system()) as session:
        results = await audit.create_partitions(session)
    assert results[month_name(0)] == "blocked"
    assert results[month_name(2)] == "created"
    assert gauges(metrics) == (1.0, 0.0)


async def test_months_ahead_is_bounded(jobs: Database) -> None:
    for months in (-1, 13):
        with pytest.raises(DBAPIError, match="between 0 and 12"):
            async with jobs.transaction(Scope.system()) as session:
                await audit.create_partitions(session, months_ahead=months)


async def test_only_the_lifecycle_job_runs_partition_upkeep(own_db: ScratchDatabase) -> None:
    api = Database.connect(own_db.url(API), pool_size=1)
    try:
        for call in (audit.partition_status, audit.create_partitions):
            with pytest.raises(DBAPIError) as refused:
                # sft_api never opens system scope; in a scope it may open, the grant refuses it.
                async with api.transaction(Scope.platform()) as session:
                    await call(session)
            assert getattr(refused.value.orig, "sqlstate", None) == "42501"
    finally:
        await api.dispose()
