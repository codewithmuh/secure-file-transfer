"""The metadata purge (#224; data model 6; NFR-9).

It runs as `sft_jobs`, with the jobs' injected clock moved on: a transfer or upload request is
purged 372 days after its end (7 days for its files, then 365 for its audit records), with every
child row, and nothing newer is touched; a parent whose file isn't deleted is skipped and counted;
audit events are never touched. Each test has a freshly migrated database of its own, since the
job reads across every tenant.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from prometheus_client import CollectorRegistry
from sqlalchemy import URL

from member_fixtures import Tenant, seed_tenant
from pg import ScratchDatabase, fresh_database
from sft.core.ids import uuid7
from sft.data.database import Database
from sft.data.migrate import run
from sft.data.roles import JOBS, MIGRATE
from sft.service import lifecycle
from sft.service.lifecycle import JobMetrics, Jobs, PurgeMetrics
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio

DAY = timedelta(days=1)


class Clock:
    def __init__(self) -> None:
        self.offset = timedelta(0)

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset


@dataclass
class World:
    db: ScratchDatabase
    jobs: Jobs
    clock: Clock
    registry: CollectorRegistry


@pytest.fixture
def purge_db(admin_url: URL) -> Iterator[ScratchDatabase]:
    with fresh_database(admin_url) as db:
        run(db.url(MIGRATE))
        yield db


@pytest.fixture
async def w(purge_db: ScratchDatabase) -> AsyncIterator[World]:
    database = Database.connect(purge_db.url(JOBS), pool_size=2)
    clock = Clock()
    registry = CollectorRegistry()
    jobs = Jobs(
        database=database,
        metrics=JobMetrics.create(registry),
        now=clock,
        purge_metrics=PurgeMetrics.create(registry),
    )
    yield World(purge_db, jobs, clock, registry)
    await database.dispose()


def ended_transfer(
    db: ScratchDatabase,
    tenant: Tenant,
    *,
    files_deleted: bool = True,
    ended_in: timedelta = timedelta(0),
) -> uuid.UUID:
    """A transfer that expired now, or `ended_in` from now, with a recipient, a file, the file's
    finding and download counter: the file deleted by the deletion job, unless `files_deleted` is
    false."""
    transfer_id, [recipient_id] = seed_transfer(db, tenant.id, tenant.member, state="expired")
    db.sql(
        "UPDATE transfers SET ended_at = now() + CAST(:ended_in AS interval) WHERE id = :id",
        id=transfer_id,
        ended_in=ended_in,
    )
    file_id = seed_file(db, tenant.id, transfer_id, state="clean")
    db.sql(
        "INSERT INTO dlp_findings (id, tenant_id, file_id, detector, count_low, count_medium, "
        "count_high) VALUES (:id, :tenant, :file, 'jp_my_number', 0, 0, 1)",
        id=uuid.uuid4(),
        tenant=tenant.id,
        file=file_id,
    )
    db.sql(
        "INSERT INTO download_counters (tenant_id, recipient_id, file_id) "
        "VALUES (:tenant, :recipient, :file)",
        tenant=tenant.id,
        recipient=recipient_id,
        file=file_id,
    )
    if files_deleted:
        db.sql("UPDATE files SET state = 'deleted', deleted_at = now() WHERE id = :id", id=file_id)
    return transfer_id


def ended_request(
    db: ScratchDatabase, tenant: Tenant, *, retention: timedelta | None = None
) -> uuid.UUID:
    """An upload request that expired now; with `retention`, a received file kept that long
    from now and already deleted (its owner deleted it early)."""
    request_id = uuid.uuid4()
    db.sql(
        "INSERT INTO upload_requests (id, tenant_id, created_by, state, uploader_email, "
        "email_normalized, locale, expires_at, ended_at, delivery_state) VALUES (:id, :tenant, "
        ":owner, 'expired', 'up@example.test', 'up@example.test', 'en', now(), now(), 'sent')",
        id=request_id,
        tenant=tenant.id,
        owner=tenant.target,
    )
    if retention is not None:
        file_id = uuid7()
        db.sql(
            "INSERT INTO files (id, tenant_id, upload_request_id, display_name_ct, content_type, "
            "declared_size, actual_size, storage_class, storage_key, s3_upload_id, "
            "s3_version_id, part_size, part_count, state, scan_deadline, inspection_state, "
            "scanned_at, retention_until, delete_after, deleted_at) VALUES (:id, :tenant, "
            ":request, '\\x0061', 'text/plain', 10, 10, 'standard', "
            "'tenants/' || :tenant || '/files/' || :id, 'upload-' || :id, 'v1', 5242880, 1, "
            "'deleted', now(), 'inspected', now(), now() + CAST(:retention AS interval), now(), "
            "now())",
            id=file_id,
            tenant=tenant.id,
            request=request_id,
            retention=retention,
        )
    return request_id


def exists(db: ScratchDatabase, table: str, column: str, value: uuid.UUID) -> bool:
    found = db.sql(
        f"SELECT count(*) FROM {table} WHERE {column} = :v",  # noqa: S608 - names from the test
        v=value,
    )
    return found != [(0,)]


def audit_rows(db: ScratchDatabase, tenant_id: uuid.UUID) -> list[tuple[object, ...]]:
    return db.sql(
        "SELECT id, action FROM audit_events WHERE tenant_id = :t ORDER BY id", t=tenant_id
    )


async def test_metadata_past_retention_goes_with_its_children_and_newer_stays(
    w: World,
) -> None:
    tenant = seed_tenant(w.db)
    old = ended_transfer(w.db, tenant)
    old_request = ended_request(w.db, tenant)
    # A day later, still inside the retention when the clock moves: untouched.
    w.db.sql(
        "INSERT INTO audit_events (id, tenant_id, actor_type, action, outcome) "
        "VALUES (:id, :t, 'system', 'transfer.expired', 'success')",
        id=uuid.uuid4(),
        t=tenant.id,
    )
    before = audit_rows(w.db, tenant.id)

    w.clock.offset = 371 * DAY  # one day short of 7 + 365
    report = await lifecycle.purge_metadata(w.jobs)
    assert report["transfers_purged"] == 0
    assert exists(w.db, "transfers", "id", old)
    assert exists(w.db, "upload_requests", "id", old_request)

    w.clock.offset = 373 * DAY
    newer = ended_transfer(w.db, tenant, ended_in=10 * DAY)  # inside its retention still
    report = await lifecycle.purge_metadata(w.jobs)
    assert report["transfers_purged"] == 1
    assert report["upload_requests_purged"] == 1
    assert not exists(w.db, "transfers", "id", old)
    assert not exists(w.db, "upload_requests", "id", old_request)
    for table in ("transfer_recipients", "files"):
        assert not exists(w.db, table, "transfer_id", old), table
    assert exists(w.db, "transfers", "id", newer)
    assert exists(w.db, "files", "transfer_id", newer)
    # Audit events stay, every one of them; the purge adds its own, which counts rows only.
    after = audit_rows(w.db, tenant.id)
    assert set(before) <= set(after)
    added = [action for (_, action) in sorted(set(after) - set(before))]
    assert added == ["retention.rows_deleted", "retention.rows_deleted"]
    assert w.registry.get_sample_value("metadata_purge_rows_total", {"kind": "transfer"}) == 1
    assert w.registry.get_sample_value("metadata_purge_rows_total", {"kind": "upload_request"}) == 1
    assert w.registry.get_sample_value("metadata_purge_lag_seconds") == 0


async def test_a_request_counts_from_its_last_files_retention(w: World) -> None:
    tenant = seed_tenant(w.db)
    kept = ended_request(w.db, tenant, retention=30 * DAY)
    w.clock.offset = 373 * DAY
    await lifecycle.purge_metadata(w.jobs)
    assert exists(w.db, "upload_requests", "id", kept)  # 30 + 372 days not up yet
    w.clock.offset = (30 + 373) * DAY
    await lifecycle.purge_metadata(w.jobs)
    assert not exists(w.db, "upload_requests", "id", kept)
    assert not exists(w.db, "files", "upload_request_id", kept)


async def test_a_parent_with_a_file_not_deleted_is_skipped_and_counted(w: World) -> None:
    tenant = seed_tenant(w.db)
    blocked = ended_transfer(w.db, tenant, files_deleted=False)
    w.clock.offset = 373 * DAY
    report = await lifecycle.purge_metadata(w.jobs)
    assert exists(w.db, "transfers", "id", blocked)
    assert exists(w.db, "files", "transfer_id", blocked)
    assert report["blocked_transfers"] == 1
    assert w.registry.get_sample_value("metadata_purge_blocked", {"kind": "transfer"}) == 1
    assert w.registry.get_sample_value("metadata_purge_blocked", {"kind": "upload_request"}) == 0


async def test_every_series_exists_at_zero_before_a_run() -> None:
    registry = CollectorRegistry()
    PurgeMetrics.create(registry)
    for kind in ("transfer", "upload_request"):
        assert registry.get_sample_value("metadata_purge_rows_total", {"kind": kind}) == 0
        assert registry.get_sample_value("metadata_purge_blocked", {"kind": kind}) == 0
    assert registry.get_sample_value("metadata_purge_lag_seconds") == 0


def test_only_the_jobs_role_deletes_a_parent_and_audit_events_stay_undeletable(
    purge_db: ScratchDatabase,
) -> None:
    grants = purge_db.sql(
        """
        SELECT c.relname, pg_get_userbyid(g.grantee)
          FROM pg_class c, aclexplode(c.relacl) g
         WHERE c.relnamespace = 'public'::regnamespace AND g.privilege_type = 'DELETE'
           AND c.relname IN ('transfers', 'upload_requests', 'audit_events')
           AND g.grantee <> c.relowner
        """
    )
    assert sorted((str(t), str(r)) for t, r in grants) == [
        ("transfers", "sft_jobs"),
        ("upload_requests", "sft_jobs"),
    ]
