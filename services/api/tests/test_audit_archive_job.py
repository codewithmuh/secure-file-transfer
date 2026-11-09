"""The audit archive job (#183; architecture 5.2; data model 2.5; NFR-15; threat model T-44).

Each database test gets a freshly migrated database of its own, since the archive cursor is one row
for the whole database, and runs the job as `sft_archive` against an in-memory store of both
regions (archive_fixtures.py). Events are inserted as the superuser, one transaction each, as the
workloads' transactions would write them. The S3 adapter itself has its contract test in
test_audit_archive.py.
"""

from __future__ import annotations

import gzip
import json
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta

import pytest
from alembic.script import ScriptDirectory
from prometheus_client import CollectorRegistry
from sqlalchemy import URL, text
from sqlalchemy.exc import ProgrammingError

from archive_fixtures import FakeArchiveStore
from pg import ScratchDatabase, fresh_database
from sft.data import archive_cursor
from sft.data.access import ScopeNotAllowedError
from sft.data.archive_cursor import ArchiveRow, Claim
from sft.data.database import Database, sync_engine
from sft.data.migrate import alembic_config, run
from sft.data.rls import grant_sql, policy_sql
from sft.data.roles import API, ARCHIVE, MIGRATE, RECOVERY
from sft.data.scope import Scope
from sft.service import archive_job
from sft.service.archive_job import (
    ArchiveIncompleteError,
    ArchiveJobMetrics,
    ArchiveReport,
    batch_key,
    batches,
    run_archive,
)
from sft.service.audit_archive import Region
from sft.workers import audit_archive as archive_command

pytestmark = pytest.mark.anyio

SCRIPTS = ScriptDirectory.from_config(alembic_config())


# ---- the revision and the objects, without a database ----


def test_the_revision_keeps_the_sql_the_helpers_wrote_for_it() -> None:
    [script] = [s for s in SCRIPTS.walk_revisions() if hasattr(s.module, "CURSOR_RLS")]
    expected = (
        "ALTER TABLE audit_archive_cursor ENABLE ROW LEVEL SECURITY",
        grant_sql("audit_archive_cursor", "sft_archive", "SELECT"),
        grant_sql(
            "audit_archive_cursor",
            "sft_archive",
            "UPDATE",
            columns=["archived_up_to_tx", "claimed_up_to_tx", "archived_at"],
        ),
        grant_sql("audit_archive_cursor", "sft_recovery", "SELECT, UPDATE"),
        policy_sql(
            "archive_cursor",
            "audit_archive_cursor",
            roles=["sft_archive"],
            using="app_scope() = 'system'",
            with_check="app_scope() = 'system'",
        ),
        policy_sql(
            "recovery_cursor",
            "audit_archive_cursor",
            roles=["sft_recovery"],
            using="app_scope() = 'recovery'",
            with_check="app_scope() = 'recovery'",
        ),
    )
    rls = script.module.CURSOR_RLS
    assert rls == expected


def row(tx_id: int, occurred_at: datetime, **overrides: object) -> ArchiveRow:
    values: dict[str, object] = {
        "id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "tx_id": tx_id,
        "occurred_at": occurred_at,
        "actor_type": "system",
        "actor_id": None,
        "action": "transfer.expired",
        "target_type": "transfer",
        "target_id": str(uuid.uuid4()),
        "outcome": "success",
        "source_ip": "192.0.2.1",
        "user_agent": "test-agent",
        "request_id": "req_test",
        "trace_id": None,
        "security_critical": False,
        "details": {"system_actor": "expiry_job"},
    }
    values.update(overrides)
    return ArchiveRow(**values)  # type: ignore[arg-type]


def lines(body: bytes) -> list[dict[str, object]]:
    return [json.loads(line) for line in gzip.decompress(body).decode().splitlines()]


def test_a_range_is_one_object_per_utc_day_under_its_generation() -> None:
    claimed = Claim(generation=3, from_tx=1000, up_to_tx=1003)
    late = datetime(2026, 11, 8, 23, 59, 59, tzinfo=UTC)
    rows = [row(1000, late), row(1001, late + timedelta(seconds=2)), row(1002, late)]
    objects = batches(claimed, rows)
    assert [(key, count) for key, _, count in objects] == [
        ("g3/2026/11/08/00000000000000001000-00000000000000001003.jsonl.gz", 2),
        ("g3/2026/11/09/00000000000000001000-00000000000000001003.jsonl.gz", 1),
    ]
    first = lines(objects[0][1])
    assert [line["id"] for line in first] == [rows[0].id, rows[2].id]
    # Every column, as the security-critical records don't carry them (architecture 5.2).
    assert set(first[0]) == {
        "id",
        "tenant_id",
        "tx_id",
        "occurred_at",
        "actor_type",
        "actor_id",
        "action",
        "target_type",
        "target_id",
        "outcome",
        "source_ip",
        "user_agent",
        "request_id",
        "trace_id",
        "security_critical",
        "details",
    }


def test_the_same_range_makes_the_same_bytes() -> None:
    # A range written again after a crash must be the object S3 already holds.
    claimed = Claim(generation=1, from_tx=5, up_to_tx=9)
    at = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    rows = [row(5, at), row(7, at)]
    assert batches(claimed, rows) == batches(claimed, list(rows))
    assert batch_key(1, at.date(), claimed).startswith("g1/2026/01/02/")


# ---- against the database, as sft_archive ----


@pytest.fixture
def archive_db(admin_url: URL) -> Iterator[ScratchDatabase]:
    """A database of the test's own, migrated: the cursor starts at transaction 0."""
    with fresh_database(admin_url) as db:
        run(db.url(MIGRATE))
        yield db


@pytest.fixture
async def archive(archive_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(archive_db.url(ARCHIVE), pool_size=2)
    yield database
    await database.dispose()


def add_event(db: ScratchDatabase, *, ago: timedelta = timedelta(0)) -> str:
    """One audit event in a transaction of its own, as a workload writes it."""
    event_id = uuid.uuid4()
    db.sql(
        "INSERT INTO audit_events (id, occurred_at, actor_type, action, outcome) "
        "VALUES (:id, now() - CAST(:ago AS interval), 'system', 'transfer.expired', 'success')",
        id=event_id,
        ago=ago,
    )
    return str(event_id)


def archived(store: FakeArchiveStore, region: Region) -> list[str]:
    """Every event ID the region's batch objects hold, with repeats."""
    return [
        str(line["id"])
        for key, body in store.objects.get(region, {}).items()
        if key.startswith("g")
        for line in lines(body)
    ]


def every_event(db: ScratchDatabase) -> set[str]:
    return {str(i) for (i,) in db.sql("SELECT id FROM audit_events")}


def cursor(db: ScratchDatabase) -> tuple[object, ...]:
    [found] = db.sql(
        "SELECT generation, archived_up_to_tx::text, claimed_up_to_tx::text "
        "FROM audit_archive_cursor"
    )
    return found


async def test_every_committed_event_reaches_both_regions_once(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    events = {add_event(archive_db) for _ in range(7)}
    store = FakeArchiveStore()
    registry = CollectorRegistry()
    metrics = ArchiveJobMetrics.create(registry)
    report = await run_archive(archive, store, metrics)
    everything = every_event(archive_db)
    assert events <= everything
    for region in Region:
        held = archived(store, region)
        assert sorted(held) == sorted(everything), region
        assert registry.get_sample_value(
            "audit_archive_events_total", {"region": region.value}
        ) == len(everything)
    assert report.events == len(everything)
    assert cursor(archive_db)[2] is None
    assert registry.get_sample_value("audit_archive_lag_seconds") == 0
    # A run with nothing new writes nothing.
    writes = store.writes
    await run_archive(archive, store, metrics)
    assert store.writes == writes


async def test_small_ranges_cover_a_backlog_in_one_run(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    for _ in range(9):
        add_event(archive_db)
    store = FakeArchiveStore()
    report = await run_archive(
        archive, store, ArchiveJobMetrics.create(CollectorRegistry()), max_rows=2
    )
    assert report.ranges >= 5
    for region in Region:
        assert sorted(archived(store, region)) == sorted(every_event(archive_db))


async def test_a_failing_region_keeps_the_cursor_and_the_retry_misses_and_repeats_nothing(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    first = {add_event(archive_db) for _ in range(3)}
    store = FakeArchiveStore(fail={Region.OSAKA})
    registry = CollectorRegistry()
    metrics = ArchiveJobMetrics.create(registry)
    with pytest.raises(ArchiveIncompleteError):
        await run_archive(archive, store, metrics)
    assert cursor(archive_db)[2] is not None  # claimed, not moved
    assert registry.get_sample_value(
        "audit_archive_write_failures_total", {"region": Region.OSAKA.value}
    )
    # The lag is measured even so, and shows the events still waiting.
    assert registry.get_sample_value("audit_archive_lag_seconds") is not None
    tokyo = sorted(archived(store, Region.TOKYO))
    second = {add_event(archive_db) for _ in range(2)}  # written while Osaka is down
    store.fail.clear()
    await run_archive(archive, store, metrics)
    everything = every_event(archive_db)
    assert first | second <= everything
    for region in Region:
        held = archived(store, region)
        assert sorted(held) == sorted(everything), region  # each exactly once
    # Tokyo's objects of the claimed range were already there: written once.
    assert sorted(i for i in archived(store, Region.TOKYO) if i in set(tokyo)) == tokyo


async def test_a_run_that_died_after_its_claim_is_finished_by_the_next(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    add_event(archive_db)
    add_event(archive_db)
    # The crash: the claim committed, no object written, the cursor never moved.
    async with archive.transaction(Scope.system()) as session:
        claimed = await archive_cursor.claim(session, max_rows=100)
    assert claimed is not None
    add_event(archive_db)  # after the claim: the next range's
    store = FakeArchiveStore()
    report = await run_archive(archive, store, ArchiveJobMetrics.create(CollectorRegistry()))
    assert report.ranges == 2
    keys = sorted(store.objects[Region.TOKYO])
    assert any(f"{claimed.from_tx:020d}-{claimed.up_to_tx:020d}" in k for k in keys)
    for region in Region:
        assert sorted(archived(store, region)) == sorted(every_event(archive_db))


async def test_a_transaction_open_across_a_run_is_archived_once_it_commits(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    # Threat model T-44: a slow transaction that commits after later ones must not be skipped.
    engine = sync_engine(archive_db.admin)
    try:
        with engine.connect() as slow:
            slow.begin()
            slow_id = uuid.uuid4()
            slow.execute(
                text(
                    "INSERT INTO audit_events (id, actor_type, action, outcome) "
                    "VALUES (:id, 'system', 'transfer.expired', 'success')"
                ),
                {"id": slow_id},
            )
            later = add_event(archive_db)  # commits first, with a later transaction ID
            store = FakeArchiveStore()
            metrics = ArchiveJobMetrics.create(CollectorRegistry())
            await run_archive(archive, store, metrics)
            for region in Region:
                held = archived(store, region)
                assert str(slow_id) not in held
                assert later not in held  # past the oldest running transaction: waits
            slow.commit()
        await run_archive(archive, store, metrics)
        for region in Region:
            held = archived(store, region)
            assert held.count(str(slow_id)) == 1
            assert held.count(later) == 1
    finally:
        engine.dispose()


async def test_the_lag_is_the_age_of_the_oldest_event_not_yet_archived(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    add_event(archive_db, ago=timedelta(minutes=10))
    metrics = ArchiveJobMetrics.create(CollectorRegistry())
    lag = await archive_job.measure_lag(archive, metrics)
    assert 590 < lag < 900
    await run_archive(archive, FakeArchiveStore(), metrics)
    assert await archive_job.measure_lag(archive, metrics) == 0


async def test_dev_without_osaka_archives_to_tokyo_alone(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    add_event(archive_db)
    store = FakeArchiveStore(regions=(Region.TOKYO,))
    report = await run_archive(archive, store, ArchiveJobMetrics.create(CollectorRegistry()))
    assert Region.OSAKA not in store.objects
    assert report.objects_written == {Region.TOKYO.value: 1}


async def test_a_new_generation_archives_under_its_own_prefix(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    event = add_event(archive_db)
    store = FakeArchiveStore()
    metrics = ArchiveJobMetrics.create(CollectorRegistry())
    await run_archive(archive, store, metrics)
    # A restore took the database back (data model 2.5): the runbook starts generation 2, as
    # sft_recovery, and the cursor goes back with the database.
    recovery = Database.connect(archive_db.url(RECOVERY), pool_size=1)
    try:
        async with recovery.transaction(Scope.recovery()) as session:
            await session.execute(
                text(
                    "UPDATE audit_archive_cursor SET generation = generation + 1, "
                    "archived_up_to_tx = '0', claimed_up_to_tx = NULL"
                )
            )
    finally:
        await recovery.dispose()
    await run_archive(archive, store, metrics)
    keys = sorted(store.objects[Region.TOKYO])
    assert any(k.startswith("g1/") for k in keys)
    assert any(k.startswith("g2/") for k in keys)
    # Readers drop the repeat by ID; each generation holds the event once.
    assert archived(store, Region.TOKYO).count(event) == 2


async def test_the_archive_role_reads_events_and_moves_the_cursor_and_nothing_else(
    archive_db: ScratchDatabase, archive: Database
) -> None:
    for statement in (
        "UPDATE audit_archive_cursor SET generation = 7",
        "DELETE FROM audit_events",
        "UPDATE audit_events SET action = 'x.y'",
        "SELECT id FROM tenants",
    ):
        # A grant refuses it (42501), or the data layer first: no tenant row is written in system
        # scope (sft.data.access).
        with pytest.raises((ProgrammingError, ScopeNotAllowedError)) as refused:
            async with archive.transaction(Scope.system()) as session:
                await session.execute(text(statement))
        if isinstance(refused.value, ProgrammingError):
            assert getattr(refused.value.orig, "sqlstate", None) == "42501", statement
    # The API's role can't read the cursor at all.
    api = Database.connect(archive_db.url(API), pool_size=1)
    try:
        with pytest.raises(ProgrammingError):
            async with api.transaction(Scope.tenant(uuid.uuid4())) as session:
                await session.execute(text("SELECT generation FROM audit_archive_cursor"))
    finally:
        await api.dispose()


def test_the_job_command_refuses_bad_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("AUDIT_ARCHIVE_TOKYO_BUCKET", raising=False)
    assert archive_command.main() == 2


def test_the_report_is_one_json_line() -> None:
    report = ArchiveReport(ranges=2, events=9, objects_written={"ap-northeast-1": 2})
    report.lag_seconds = 1.23456
    assert json.loads(json.dumps(report.as_dict())) == {
        "ranges": 2,
        "events": 9,
        "objects_written": {"ap-northeast-1": 2},
        "lag_seconds": 1.235,
    }
