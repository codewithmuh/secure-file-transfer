"""The scan deadline and the scan sweep (#175; data model 3.1; abuse and rate limits 6.4, 6.5).

The deadline grows with the file's size and covers every attempt of both engines; the sweep, as
`sft_jobs`, fails what is still `scanning` past it and holds the transfer.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from prometheus_client import CollectorRegistry

from member_fixtures import ready_for_dlp, seed_user
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.outbox import Queue
from sft.data.roles import JOBS
from sft.service import scan_timing
from sft.workers.scan import ScanMetrics
from sft.workers.scan_sweep import sweep
from transfer_fixtures import actions, seed_file, seed_transfer, transfer_row

pytestmark = pytest.mark.anyio

MB = 1_000_000


@pytest.mark.parametrize("size", [1, 5 * MB, 100 * MB, 150 * MB, 2_000 * MB, 5_000 * MB])
def test_the_deadline_covers_every_attempt_of_both_engines_and_the_waits(size: int) -> None:
    now = datetime(2026, 11, 5, tzinfo=UTC)
    deadline = scan_timing.scan_deadline(size, now)
    attempt = scan_timing.attempt_timeout(size)
    assert attempt >= scan_timing.clamd_timeout(size)
    assert attempt >= scan_timing.inspector_timeout(size)
    assert attempt >= timedelta(minutes=15)  # the inspector's wall clock (abuse 6.5)
    backoff = (scan_timing.ATTEMPTS - 1) * scan_timing.VISIBILITY[Queue.SCAN_SMALL]
    assert deadline - now > scan_timing.ATTEMPTS * attempt + backoff


def test_the_deadline_grows_with_the_size() -> None:
    now = datetime(2026, 11, 5, tzinfo=UTC)
    sizes = [5 * MB, 100 * MB, 150 * MB, 2_000 * MB, 5_000 * MB]
    deadlines = [scan_timing.scan_deadline(size, now) for size in sizes]
    assert deadlines == sorted(deadlines)
    assert len(set(deadlines)) == len(deadlines)
    # A 2 GB ClamAV scan takes about 2 minutes (abuse 6.4); its timeout leaves room for more.
    assert scan_timing.clamd_timeout(2_000 * MB) > timedelta(minutes=6)


def test_files_route_to_their_pool_by_size() -> None:
    assert scan_timing.scan_topic(5 * MB) is not None
    assert scan_timing.scan_topic(5 * MB).queue is Queue.SCAN_SMALL  # type: ignore[union-attr]
    assert scan_timing.scan_topic(150 * MB).queue is Queue.SCAN_LARGE  # type: ignore[union-attr]
    assert scan_timing.scan_topic(2_000_000_001) is None
    assert scan_timing.scan_topic(150 * MB, small_pool_max=200 * MB).queue is Queue.SCAN_SMALL  # type: ignore[union-attr]


async def test_the_sweep_fails_overdue_scans_and_holds_their_transfers(
    migrated_db: ScratchDatabase,
) -> None:
    tenant_id = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id
    )
    owner = seed_user(migrated_db, tenant_id)
    ready_for_dlp(migrated_db, tenant_id, owner)  # the default policy, example.test known (#219)
    transfer_id, _ = seed_transfer(migrated_db, tenant_id, owner, state="submitted")
    overdue = seed_file(migrated_db, tenant_id, transfer_id, deadline=-timedelta(minutes=1))
    in_time = seed_file(migrated_db, tenant_id, transfer_id, deadline=timedelta(hours=1))
    registry = CollectorRegistry()
    metrics = ScanMetrics.create(registry)
    database = Database.connect(migrated_db.url(JOBS), pool_size=1)
    try:
        assert await sweep(database, metrics) == 1
        assert await sweep(database, metrics) == 0  # nothing left
    finally:
        await database.dispose()
    rows = dict(
        (file_id, (state, detail, inspection))
        for file_id, state, detail, inspection in migrated_db.sql(
            "SELECT id, state, scan_detail, inspection_state FROM files WHERE tenant_id = :t",
            t=tenant_id,
        )
    )
    assert rows[overdue] == ("scan_failed", "deadline_passed", "failed")
    assert rows[in_time][0] == "scanning"
    row = transfer_row(migrated_db, transfer_id)
    assert (row["state"], row["hold_reason"]) == ("held", "file_blocked")
    assert actions(migrated_db, overdue) == ["file.scanned"]
    samples = {
        labels["reason"]: value
        for labels, value in (
            (s.labels, s.value)
            for metric in registry.collect()
            for s in metric.samples
            if s.name == "scan_results_total" and s.value
        )
    }
    assert samples == {"deadline_passed": 1.0}
