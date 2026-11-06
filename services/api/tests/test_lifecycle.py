"""The lifecycle jobs (#181; FR-21, NFR-8; architecture 4.5; data model 3.1, 6): expiry, stale
drafts, deletion of every copy, reconciliation, the storage audit and the daily cleanup.

They run as `sft_jobs` against the real database, with the files buckets on S3Mock
(TEST_S3_ENDPOINT_URL): each test makes its own versioned bucket pair, puts real object versions
and multipart uploads there, and checks with S3's own listings that none is left. "Now" is the
jobs' clock, moved as the journey test moves it.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import pytest
from prometheus_client import CollectorRegistry
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from archive_fixtures import FakeArchiveStore, fake_archive
from member_fixtures import seed_tenant
from pg import ScratchDatabase
from sft.core.settings import JobSettings
from sft.data import downloads
from sft.data.database import Database
from sft.data.models import StorageClass
from sft.data.roles import API, JOBS
from sft.data.scope import Scope
from sft.runtime.s3 import S3Cleaner, S3Objects
from sft.service import lifecycle
from sft.service.audit_archive import Region, record_body
from sft.service.downloads import committed_record
from sft.service.lifecycle import JobMetrics, Jobs
from sft.service.objects import StoredVersion
from sft.workers import jobs as job_command
from transfer_fixtures import actions, seed_file, seed_transfer, transfer_row

pytestmark = pytest.mark.anyio

REGION = "ap-northeast-1"
FAKE_CREDENTIALS = {"AWS_ACCESS_KEY_ID": "local-fake", "AWS_SECRET_ACCESS_KEY": "local-fake"}
MIB = 1024 * 1024


@pytest.fixture(scope="session")
def endpoint() -> str:
    url = os.environ.get("TEST_S3_ENDPOINT_URL")
    if not url:
        if os.environ.get("CI"):
            pytest.fail("TEST_S3_ENDPOINT_URL must be set in CI")
        pytest.skip("set TEST_S3_ENDPOINT_URL to an S3Mock URL")
    return url


@pytest.fixture
def s3(endpoint: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    for name, value in FAKE_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    client = boto3.client("s3", endpoint_url=endpoint, region_name=REGION)
    yield client
    client.close()


@pytest.fixture
def buckets(s3: Any) -> dict[StorageClass, str]:
    suffix = secrets.token_hex(4)
    names = {
        StorageClass.STANDARD: f"sft-test-files-{suffix}",
        StorageClass.LARGE: f"sft-test-large-files-{suffix}",
    }
    for name in names.values():
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return names


class Clock:
    def __init__(self) -> None:
        self.offset = timedelta(0)

    def __call__(self) -> datetime:
        return datetime.now(UTC) + self.offset


@pytest.fixture
async def world(
    migrated_db: ScratchDatabase, endpoint: str, buckets: dict[StorageClass, str]
) -> AsyncIterator[tuple[Jobs, Clock, FakeArchiveStore]]:
    database = Database.connect(migrated_db.url(JOBS), pool_size=3)
    clock = Clock()
    store = FakeArchiveStore()
    cleaner = S3Cleaner.create({REGION: buckets}, endpoint)
    objects = S3Objects.create(
        region=REGION,
        files_bucket=buckets[StorageClass.STANDARD],
        large_files_bucket=buckets[StorageClass.LARGE],
        endpoint_url=endpoint,
        threads=2,
    )
    jobs = Jobs(
        database=database,
        metrics=JobMetrics.create(CollectorRegistry()),
        now=clock,
        cleaner=cleaner,
        objects=objects,
        archive=fake_archive(store),
    )
    yield jobs, clock, store
    await cleaner.close()
    await objects.close()
    await database.dispose()


def key_of(tenant_id: uuid.UUID, file_id: uuid.UUID) -> str:
    return f"tenants/{tenant_id}/files/{file_id}"


def put_copies(s3: Any, bucket: str, key: str, *, upload: bool = True) -> str | None:
    """Two versions and a delete marker of `key`, and an unfinished upload under it."""
    s3.put_object(Bucket=bucket, Key=key, Body=b"one")
    s3.put_object(Bucket=bucket, Key=key, Body=b"two")
    s3.delete_object(Bucket=bucket, Key=key)
    if not upload:
        return None
    upload_id: str = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=b"p" * 10)
    return upload_id


def copies(s3: Any, bucket: str, key: str) -> tuple[int, int]:
    versions = s3.list_object_versions(Bucket=bucket, Prefix=key)
    found = [
        v
        for v in [*versions.get("Versions", []), *versions.get("DeleteMarkers", [])]
        if v["Key"] == key
    ]
    uploads = [
        u for u in s3.list_multipart_uploads(Bucket=bucket).get("Uploads", []) if u["Key"] == key
    ]
    return len(found), len(uploads)


def file_row(db: ScratchDatabase, file_id: uuid.UUID) -> dict[str, Any]:
    [row] = db.sql("SELECT state, delete_after, deleted_at FROM files WHERE id = :id", id=file_id)
    return dict(zip(("state", "delete_after", "deleted_at"), row, strict=True))


def reserved(db: ScratchDatabase, tenant_id: uuid.UUID) -> int:
    [(value,)] = db.sql("SELECT bytes_reserved FROM tenant_usage WHERE tenant_id = :t", t=tenant_id)
    return int(str(value))


# ---- expiry and drafts ----


async def test_a_sent_transfer_past_expires_at_expires_on_the_next_run(
    migrated_db: ScratchDatabase, world: tuple[Jobs, Clock, FakeArchiveStore]
) -> None:
    jobs, clock, _ = world
    tenant = seed_tenant(migrated_db)
    transfer_id, _ = seed_transfer(
        migrated_db, tenant.id, tenant.target, state="sent", expires_at_offset=timedelta(hours=2)
    )
    file_id = seed_file(migrated_db, tenant.id, transfer_id, state="clean")
    await lifecycle.expire_transfers(jobs)
    assert transfer_row(migrated_db, transfer_id)["state"] == "sent", "not due yet"
    clock.offset = timedelta(hours=3)  # the journey test's move
    assert await lifecycle.expire_transfers(jobs) >= 1
    row = transfer_row(migrated_db, transfer_id)
    assert row["state"] == "expired"
    assert row["ended_at"] is not None
    assert file_row(migrated_db, file_id)["delete_after"] is not None
    assert actions(migrated_db, transfer_id)[-1] == "transfer.expired"
    assert await lifecycle.expire_transfers(jobs) == 0, "a second run finds nothing left"


async def test_a_held_transfer_expires_and_loses_its_hold(
    migrated_db: ScratchDatabase, world: tuple[Jobs, Clock, FakeArchiveStore]
) -> None:
    jobs, _, _ = world
    tenant = seed_tenant(migrated_db)
    held, _ = seed_transfer(
        migrated_db, tenant.id, tenant.target, state="held", expires_at_offset=-timedelta(hours=1)
    )
    assert await lifecycle.expire_transfers(jobs) >= 1
    assert transfer_row(migrated_db, held)["hold_reason"] is None


async def test_a_7_day_old_draft_is_cancelled_with_its_open_upload_rejected(
    migrated_db: ScratchDatabase, world: tuple[Jobs, Clock, FakeArchiveStore]
) -> None:
    jobs, _, _ = world
    tenant = seed_tenant(migrated_db)
    stale, _ = seed_transfer(migrated_db, tenant.id, tenant.target)
    fresh, _ = seed_transfer(migrated_db, tenant.id, tenant.target)
    uploading = seed_file(migrated_db, tenant.id, stale, state="uploading")
    migrated_db.sql(
        "UPDATE transfers SET last_activity_at = now() - interval '8 days' WHERE id = :id",
        id=stale,
    )
    before = reserved(migrated_db, tenant.id)
    assert await lifecycle.cancel_stale_drafts(jobs) >= 1
    assert transfer_row(migrated_db, stale)["state"] == "cancelled"
    assert transfer_row(migrated_db, fresh)["state"] == "draft"
    assert file_row(migrated_db, uploading)["state"] == "rejected"
    assert reserved(migrated_db, tenant.id) == before - 10
    assert actions(migrated_db, stale)[-1] == "transfer.cancelled"
    assert actions(migrated_db, uploading) == ["file.rejected"]


# ---- deletion ----


async def test_deletion_removes_every_version_and_upload_of_ended_transfers(
    migrated_db: ScratchDatabase,
    s3: Any,
    buckets: dict[StorageClass, str],
    world: tuple[Jobs, Clock, FakeArchiveStore],
) -> None:
    jobs, clock, _ = world
    tenant = seed_tenant(migrated_db)
    bucket = buckets[StorageClass.STANDARD]
    due: list[uuid.UUID] = []
    for state in ("expired", "revoked", "cancelled"):
        transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.target, state=state)
        for file_state in ("clean", "infected"):
            file_id = seed_file(migrated_db, tenant.id, transfer_id, state=file_state)
            upload_id = put_copies(s3, bucket, key_of(tenant.id, file_id))
            migrated_db.sql(
                "UPDATE files SET delete_after = now(), s3_upload_id = :upload WHERE id = :id",
                upload=upload_id,
                id=file_id,
            )
            due.append(file_id)
    rejected_transfer, _ = seed_transfer(migrated_db, tenant.id, tenant.target)
    rejected = seed_file(migrated_db, tenant.id, rejected_transfer, state="rejected")
    upload_id = put_copies(s3, bucket, key_of(tenant.id, rejected))
    migrated_db.sql(
        "UPDATE files SET s3_upload_id = :upload WHERE id = :id", upload=upload_id, id=rejected
    )
    # The rejection released its reservation already; deletion releases the others'.
    migrated_db.sql(
        "UPDATE tenant_usage SET bytes_reserved = bytes_reserved - 10 WHERE tenant_id = :t",
        t=tenant.id,
    )
    before = reserved(migrated_db, tenant.id)
    clock.offset = timedelta(seconds=1)
    assert await lifecycle.delete_due_files(jobs) >= len(due) + 1
    for file_id in [*due, rejected]:
        assert copies(s3, bucket, key_of(tenant.id, file_id)) == (0, 0)
        row = file_row(migrated_db, file_id)
        assert row["state"] == "deleted"
        assert row["deleted_at"] is not None
        assert actions(migrated_db, file_id)[-1] == "file.deleted"
    assert reserved(migrated_db, tenant.id) == before - 10 * len(due)
    assert await lifecycle.delete_due_files(jobs) == 0


async def test_deletion_waits_for_a_scan_or_a_completion_to_settle(
    migrated_db: ScratchDatabase,
    s3: Any,
    buckets: dict[StorageClass, str],
    world: tuple[Jobs, Clock, FakeArchiveStore],
) -> None:
    jobs, clock, _ = world
    tenant = seed_tenant(migrated_db)
    transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.target, state="revoked")
    scanning = seed_file(migrated_db, tenant.id, transfer_id, state="scanning")
    completing = seed_file(migrated_db, tenant.id, transfer_id, state="completing")
    for file_id in (scanning, completing):
        put_copies(s3, buckets[StorageClass.STANDARD], key_of(tenant.id, file_id), upload=False)
    migrated_db.sql("UPDATE files SET delete_after = now() WHERE transfer_id = :t", t=transfer_id)
    clock.offset = timedelta(seconds=1)
    await lifecycle.delete_due_files(jobs)
    assert file_row(migrated_db, scanning)["state"] == "scanning"
    assert file_row(migrated_db, completing)["state"] == "completing"
    migrated_db.sql(
        "UPDATE files SET state = 'clean', inspection_state = 'inspected', scanned_at = now() "
        "WHERE id = :id",
        id=scanning,
    )
    await lifecycle.delete_due_files(jobs)
    assert file_row(migrated_db, scanning)["state"] == "deleted"
    key = key_of(tenant.id, scanning)
    assert copies(s3, buckets[StorageClass.STANDARD], key) == (0, 0)
    assert file_row(migrated_db, completing)["state"] == "completing"


async def test_jobs_are_safe_to_run_twice_at_once(
    migrated_db: ScratchDatabase,
    s3: Any,
    buckets: dict[StorageClass, str],
    world: tuple[Jobs, Clock, FakeArchiveStore],
) -> None:
    jobs, clock, _ = world
    tenant = seed_tenant(migrated_db)
    transfer_ids = [
        seed_transfer(
            migrated_db, tenant.id, tenant.target, state="sent", expires_at_offset=-timedelta(1)
        )[0]
        for _ in range(4)
    ]
    file_ids = [seed_file(migrated_db, tenant.id, t, state="clean") for t in transfer_ids]
    for file_id in file_ids:
        put_copies(s3, buckets[StorageClass.STANDARD], key_of(tenant.id, file_id), upload=False)
    expired = await asyncio.gather(
        lifecycle.expire_transfers(jobs), lifecycle.expire_transfers(jobs)
    )
    assert sum(expired) >= len(transfer_ids)
    for transfer_id in transfer_ids:
        assert actions(migrated_db, transfer_id).count("transfer.expired") == 1
    clock.offset = timedelta(seconds=1)
    await asyncio.gather(lifecycle.delete_due_files(jobs), lifecycle.delete_due_files(jobs))
    for file_id in file_ids:
        assert actions(migrated_db, file_id).count("file.deleted") == 1
        assert file_row(migrated_db, file_id)["state"] == "deleted"


# ---- reconciliation ----


async def test_an_upload_with_no_part_for_24_hours_is_rejected_and_then_aborted(
    migrated_db: ScratchDatabase,
    s3: Any,
    buckets: dict[StorageClass, str],
    world: tuple[Jobs, Clock, FakeArchiveStore],
) -> None:
    jobs, clock, _ = world
    tenant = seed_tenant(migrated_db)
    transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.target)
    stale = seed_file(migrated_db, tenant.id, transfer_id, state="uploading")
    live = seed_file(migrated_db, tenant.id, transfer_id, state="uploading")
    bucket = buckets[StorageClass.STANDARD]
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key_of(tenant.id, stale))["UploadId"]
    migrated_db.sql(
        "UPDATE files SET s3_upload_id = :upload, last_part_at = now() - interval '25 hours' "
        "WHERE id = :id",
        upload=upload_id,
        id=stale,
    )
    await lifecycle.reconcile(jobs)
    assert file_row(migrated_db, stale)["state"] == "rejected"
    assert file_row(migrated_db, live)["state"] == "uploading"
    assert actions(migrated_db, stale) == ["file.rejected"]
    clock.offset = timedelta(seconds=1)
    await lifecycle.delete_due_files(jobs)
    assert copies(s3, bucket, key_of(tenant.id, stale)) == (0, 0)
    assert file_row(migrated_db, stale)["state"] == "deleted"


async def test_a_file_completing_for_15_minutes_is_finished_or_sent_back(
    migrated_db: ScratchDatabase,
    s3: Any,
    buckets: dict[StorageClass, str],
    world: tuple[Jobs, Clock, FakeArchiveStore],
) -> None:
    jobs, _, _ = world
    tenant = seed_tenant(migrated_db)
    transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.target)
    bucket = buckets[StorageClass.STANDARD]
    finished: list[uuid.UUID] = []
    for parts in (2, 1):  # all of a 2-part plan, then a part missing
        file_id = seed_file(migrated_db, tenant.id, transfer_id, state="completing", size=6 * MIB)
        key = key_of(tenant.id, file_id)
        upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
        sizes = (5 * MIB, MIB)
        for number in range(1, parts + 1):
            s3.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=number,
                Body=b"x" * sizes[number - 1],
            )
        migrated_db.sql(
            "UPDATE files SET s3_upload_id = :upload, part_count = 2, "
            "completion_started_at = now() - interval '16 minutes' WHERE id = :id",
            upload=upload_id,
            id=file_id,
        )
        finished.append(file_id)
    complete, incomplete = finished
    await lifecycle.reconcile(jobs)
    [(state, actual, version)] = migrated_db.sql(
        "SELECT state, actual_size, s3_version_id FROM files WHERE id = :id", id=complete
    )
    assert (state, actual) == ("scanning", 6 * MIB)
    assert version
    assert migrated_db.sql(
        "SELECT topic FROM outbox WHERE payload->>'file_id' = :id", id=str(complete)
    ) == [("file.scan",)]
    assert file_row(migrated_db, incomplete)["state"] == "uploading"
    assert actions(migrated_db, complete)[-1] == "file.uploaded"
    assert actions(migrated_db, incomplete)[-1] == "file.upload_incomplete"


async def test_an_unarchived_grant_gets_its_committed_record_written_again(
    migrated_db: ScratchDatabase, world: tuple[Jobs, Clock, FakeArchiveStore]
) -> None:
    jobs, _, store = world
    tenant = seed_tenant(migrated_db)
    transfer_id, [recipient] = seed_transfer(migrated_db, tenant.id, tenant.target, state="sent")
    file_id = seed_file(migrated_db, tenant.id, transfer_id, state="clean")
    session_id, grant_id = uuid.uuid4(), uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO link_sessions (id, tenant_id, recipient_id, session_hash, expires_at) "
        "VALUES (:id, :t, :r, sha256(convert_to(CAST(:id AS text), 'UTF8')), "
        "now() + interval '1 hour')",
        id=session_id,
        t=tenant.id,
        r=recipient,
    )
    migrated_db.sql(
        "INSERT INTO download_grants (id, tenant_id, file_id, s3_version_id, recipient_id, "
        "link_session_id, byte_budget, created_at, expires_at) VALUES (:id, :t, :f, "
        "'version-1', :r, :s, 30, now() - interval '2 minutes', now() + interval '1 hour')",
        id=grant_id,
        t=tenant.id,
        f=file_id,
        r=recipient,
        s=session_id,
    )
    await lifecycle.reconcile(jobs)
    [(archived_at,)] = migrated_db.sql(
        "SELECT archived_at FROM download_grants WHERE id = :id", id=grant_id
    )
    assert archived_at is not None
    for region in Region:
        bodies = list(store.objects[region].values())
        mine = [b for b in bodies if str(grant_id).encode() in b]
        assert len(mine) == 1
    # The record is the one the API writes: made from the row alone.
    async with jobs.database.transaction(Scope.system()) as session:
        [row] = [
            g
            for g in await downloads.unarchived(
                session, created_before=datetime.now(UTC) + timedelta(days=1), limit=1000
            )
            if g.id == grant_id
        ] or [None]
    assert row is None, "archived now, so reconciliation won't find it again"
    record = committed_record(
        downloads.Unarchived(
            grant_id,
            tenant.id,
            file_id,
            "version-1",
            recipient,
            session_id,
            30,
            datetime.now(UTC),
            datetime.now(UTC),
        )
    )
    assert record.action == "download.grant_committed"
    assert b'"download.grant_committed"' in record_body(record)


# ---- the storage audit ----


async def test_an_orphan_over_24_hours_old_is_deleted_and_a_younger_one_kept(
    migrated_db: ScratchDatabase,
    s3: Any,
    buckets: dict[StorageClass, str],
    world: tuple[Jobs, Clock, FakeArchiveStore],
) -> None:
    jobs, clock, _ = world
    tenant = seed_tenant(migrated_db)
    transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.target, state="sent")
    live = seed_file(migrated_db, tenant.id, transfer_id, state="clean")
    bucket = buckets[StorageClass.LARGE]
    orphan_key = key_of(tenant.id, uuid.uuid4())
    live_key = key_of(tenant.id, live)
    for key in (orphan_key, live_key):
        s3.put_object(Bucket=buckets[StorageClass.LARGE], Key=key, Body=b"bytes")
    stale_upload = s3.create_multipart_upload(Bucket=bucket, Key=key_of(tenant.id, uuid.uuid4()))
    # An hour later, both are younger than 24 hours: kept.
    clock.offset = timedelta(hours=1)
    report = await lifecycle.audit_storage(jobs)
    assert copies(s3, bucket, orphan_key)[0] == 1
    assert report.get("orphans_deleted", 0) == 0
    # A day later, the orphan and the stale upload go; the live file's object stays.
    jobs.report.clear()
    clock.offset = timedelta(hours=25)
    report = await lifecycle.audit_storage(jobs)
    assert copies(s3, bucket, orphan_key) == (0, 0)
    assert copies(s3, bucket, live_key)[0] == 1
    uploads = s3.list_multipart_uploads(Bucket=bucket).get("Uploads", [])
    assert stale_upload["UploadId"] not in {u["UploadId"] for u in uploads}
    assert report["orphans_deleted"] == 1
    assert report["uploads_aborted"] >= 1


# ---- the daily cleanup ----


async def test_expired_codes_sessions_and_grants_are_deleted(
    migrated_db: ScratchDatabase, world: tuple[Jobs, Clock, FakeArchiveStore]
) -> None:
    jobs, _, _ = world
    tenant = seed_tenant(migrated_db)
    transfer_id, [recipient] = seed_transfer(migrated_db, tenant.id, tenant.target, state="sent")
    file_id = seed_file(migrated_db, tenant.id, transfer_id, state="clean")
    old_session, live_session, code = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    for session_id, age in ((old_session, "2 days"), (live_session, "0 seconds")):
        migrated_db.sql(
            "INSERT INTO link_sessions (id, tenant_id, recipient_id, session_hash, created_at, "
            "last_seen_at, expires_at) VALUES (:id, :t, :r, "
            "sha256(convert_to(CAST(:id AS text), 'UTF8')), now() - CAST(:age AS interval), "
            "now() - CAST(:age AS interval), now() - CAST(:age AS interval) + interval '1 hour')",
            id=session_id,
            t=tenant.id,
            r=recipient,
            age=age,
        )
    migrated_db.sql(
        "INSERT INTO verification_codes (id, tenant_id, recipient_id, code_hmac, hmac_key_id, "
        "created_at, expires_at) VALUES (:id, :t, :r, sha256(convert_to(CAST(:id AS text), "
        "'UTF8')), 'k', now() - interval '1 hour', now() - interval '50 minutes')",
        id=code,
        t=tenant.id,
        r=recipient,
    )
    grant_id = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO download_grants (id, tenant_id, file_id, s3_version_id, recipient_id, "
        "link_session_id, byte_budget, created_at, expires_at, archived_at) VALUES (:id, :t, :f, "
        "'v', :r, :s, 30, now() - interval '3 hours', now() - interval '2 hours', now())",
        id=grant_id,
        t=tenant.id,
        f=file_id,
        r=recipient,
        s=live_session,
    )
    report = await lifecycle.clean_up(jobs)
    assert migrated_db.sql("SELECT id FROM link_sessions WHERE recipient_id = :r", r=recipient) == [
        (live_session,)
    ]
    assert migrated_db.sql("SELECT id FROM verification_codes WHERE id = :id", id=code) == []
    assert migrated_db.sql("SELECT id FROM download_grants WHERE id = :id", id=grant_id) == []
    assert report["verification_codes_deleted"] >= 1
    assert migrated_db.sql(
        "SELECT count(*) FROM audit_events WHERE action = 'retention.rows_deleted' "
        "AND tenant_id = :t",
        t=tenant.id,
    ) == [(3,)]


# ---- what the roles may do ----


def test_only_the_jobs_role_may_delete_and_the_api_role_never_files(
    migrated_db: ScratchDatabase,
) -> None:
    grants = migrated_db.sql(
        """
        SELECT c.relname, pg_get_userbyid(g.grantee)
          FROM pg_class c, aclexplode(c.relacl) g
         WHERE c.relnamespace = 'public'::regnamespace AND g.privilege_type = 'DELETE'
           AND g.grantee <> c.relowner
        """
    )
    by_table = {(str(t), str(r)) for t, r in grants}
    for table in ("verification_codes", "link_sessions", "download_grants"):
        assert (table, "sft_jobs") in by_table
    assert not any(role == "sft_api" for _, role in by_table if _ != "idempotency_keys")
    assert not any(table in ("files", "transfers") for table, _ in by_table)


async def test_the_api_roles_delete_is_refused(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    api = Database.connect(migrated_db.url(API), pool_size=1)
    try:
        for table in ("files", "download_grants", "link_sessions", "transfers"):
            with pytest.raises(ProgrammingError) as refused:
                async with api.transaction(Scope.tenant(tenant.id)) as session:
                    await session.execute(text(f"DELETE FROM {table}"))  # noqa: S608
            assert getattr(refused.value.orig, "sqlstate", None) == "42501", table
    finally:
        await api.dispose()


# ---- the command ----


async def test_the_job_command_runs_a_job_and_refuses_a_bad_name(
    migrated_db: ScratchDatabase, buckets: dict[StorageClass, str], endpoint: str
) -> None:
    assert job_command.main(["no-such-job"]) == 2
    settings = JobSettings(
        database_url=migrated_db.url(JOBS),
        s3_files_bucket=buckets[StorageClass.STANDARD],
        s3_large_files_bucket=buckets[StorageClass.LARGE],
        s3_endpoint_url=endpoint,
        audit_archive_tokyo_bucket=buckets[StorageClass.STANDARD],
        audit_archive_tokyo_endpoint_url=endpoint,
        environment="test",
        clock_offset_seconds=60,
    )
    for job in lifecycle.Job:
        report = await job_command.run_job(job, settings, CollectorRegistry())
        assert isinstance(report, dict)


# ---- review fixes (#181) ----


def seed_grant(
    db: ScratchDatabase, tenant: Any, *, archived: bool, session_age: str = "2 days"
) -> tuple[uuid.UUID, uuid.UUID]:
    """An expired link session with one expired grant, its committed record confirmed or not."""
    transfer_id, [recipient] = seed_transfer(db, tenant.id, tenant.target, state="sent")
    file_id = seed_file(db, tenant.id, transfer_id, state="clean")
    session_id, grant_id = uuid.uuid4(), uuid.uuid4()
    db.sql(
        "INSERT INTO link_sessions (id, tenant_id, recipient_id, session_hash, created_at, "
        "last_seen_at, expires_at) VALUES (:id, :t, :r, sha256(convert_to(CAST(:id AS text), "
        "'UTF8')), now() - CAST(:age AS interval), now() - CAST(:age AS interval), "
        "now() - CAST(:age AS interval) + interval '1 hour')",
        id=session_id,
        t=tenant.id,
        r=recipient,
        age=session_age,
    )
    db.sql(
        "INSERT INTO download_grants (id, tenant_id, file_id, s3_version_id, recipient_id, "
        "link_session_id, byte_budget, created_at, expires_at, archived_at) VALUES (:id, :t, :f, "
        "'v', :r, :s, 30, now() - CAST(:age AS interval), "
        "now() - CAST(:age AS interval) + interval '1 hour', CASE WHEN :archived THEN now() END)",
        id=grant_id,
        t=tenant.id,
        f=file_id,
        r=recipient,
        s=session_id,
        age=session_age,
        archived=archived,
    )
    return session_id, grant_id


async def test_the_cleanup_keeps_a_grant_waiting_for_its_record_and_its_session(
    migrated_db: ScratchDatabase, world: tuple[Jobs, Clock, FakeArchiveStore]
) -> None:
    jobs, _, _ = world
    tenant = seed_tenant(migrated_db)
    waiting_session, waiting_grant = seed_grant(migrated_db, tenant, archived=False)
    done_session, done_grant = seed_grant(migrated_db, tenant, archived=True)
    report = await lifecycle.clean_up(jobs)
    assert migrated_db.sql("SELECT id FROM download_grants WHERE id = :id", id=waiting_grant)
    assert migrated_db.sql("SELECT id FROM link_sessions WHERE id = :id", id=waiting_session)
    assert not migrated_db.sql("SELECT id FROM download_grants WHERE id = :id", id=done_grant)
    assert not migrated_db.sql("SELECT id FROM link_sessions WHERE id = :id", id=done_session)
    assert report["unarchived_grants_waiting"] >= 1
    assert jobs.metrics.unarchived._value.get() >= 1  # type: ignore[attr-defined]
    # Once reconciliation confirms its record, the next cleanup removes both.
    await lifecycle.reconcile(jobs)
    await lifecycle.clean_up(jobs)
    assert not migrated_db.sql("SELECT id FROM download_grants WHERE id = :id", id=waiting_grant)
    assert not migrated_db.sql("SELECT id FROM link_sessions WHERE id = :id", id=waiting_session)


async def test_reconciliation_routes_a_finished_completion_by_the_configured_split(
    migrated_db: ScratchDatabase,
    s3: Any,
    buckets: dict[StorageClass, str],
    world: tuple[Jobs, Clock, FakeArchiveStore],
) -> None:
    jobs, _, _ = world
    jobs.small_pool_max = 50_000_000  # SCAN_SMALL_POOL_MAX_BYTES, lowered from 100 MB
    tenant = seed_tenant(migrated_db)
    transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.target)
    size = 80 * MIB  # under the default split, over the configured one
    file_id = seed_file(migrated_db, tenant.id, transfer_id, state="completing", size=size)
    key = key_of(tenant.id, file_id)
    bucket = buckets[StorageClass.STANDARD]
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    part = b"x" * (5 * MIB)
    for number in range(1, 17):
        s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number, Body=part)
    migrated_db.sql(
        "UPDATE files SET s3_upload_id = :upload, "
        "completion_started_at = now() - interval '16 minutes' WHERE id = :id",
        upload=upload_id,
        id=file_id,
    )
    await lifecycle.reconcile(jobs)
    assert file_row(migrated_db, file_id)["state"] == "scanning"
    assert migrated_db.sql(
        "SELECT topic FROM outbox WHERE payload->>'file_id' = :id", id=str(file_id)
    ) == [("file.scan_large",)]


async def test_a_completing_file_of_a_transfer_no_longer_a_draft_is_rejected(
    migrated_db: ScratchDatabase,
    s3: Any,
    buckets: dict[StorageClass, str],
    world: tuple[Jobs, Clock, FakeArchiveStore],
) -> None:
    jobs, _, _ = world
    tenant = seed_tenant(migrated_db)
    transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.target, state="revoked")
    file_id = seed_file(migrated_db, tenant.id, transfer_id, state="completing", size=6 * MIB)
    key = key_of(tenant.id, file_id)
    bucket = buckets[StorageClass.STANDARD]
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    for number, size in ((1, 5 * MIB), (2, MIB)):
        s3.upload_part(
            Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=number, Body=b"y" * size
        )
    migrated_db.sql(
        "UPDATE files SET s3_upload_id = :upload, part_count = 2, "
        "completion_started_at = now() - interval '16 minutes' WHERE id = :id",
        upload=upload_id,
        id=file_id,
    )
    before = reserved(migrated_db, tenant.id)
    await lifecycle.reconcile(jobs)
    row = file_row(migrated_db, file_id)
    assert row["state"] == "rejected"
    assert row["delete_after"] is not None
    assert reserved(migrated_db, tenant.id) == before - 6 * MIB
    [(details,)] = migrated_db.sql(
        "SELECT details FROM audit_events WHERE target_id = :id AND action = 'file.rejected'",
        id=file_id,
    )
    assert details["reason"] == "transfer_not_open"  # type: ignore[index]
    assert details["system_actor"] == "reconciliation_job"  # type: ignore[index]


class PagedCleaner:
    """A `StorageCleaner` whose listing yields many pages, and records whether each page was
    looked up in the database before the next was read."""

    def __init__(self, tenant_id: uuid.UUID, pages: int, per_page: int) -> None:
        old = datetime.now(UTC) - timedelta(days=2)
        self.pages = [
            [
                StoredVersion(REGION, f"tenants/{tenant_id}/files/{uuid.uuid4()}", "v1", old)
                for _ in range(per_page)
            ]
            for _ in range(pages)
        ]
        self.events: list[tuple[str, int]] = []
        self.deleted: list[str] = []

    @property
    def regions(self) -> tuple[str, ...]:
        return (REGION,)

    async def version_pages(self, storage_class: StorageClass) -> AsyncIterator[list[Any]]:
        if storage_class is not StorageClass.STANDARD:
            return
        for number, page in enumerate(self.pages):
            self.events.append(("page", number))
            yield page

    async def upload_pages(self, storage_class: StorageClass) -> AsyncIterator[list[Any]]:
        if False:  # pragma: no cover - no uploads here
            yield []

    async def delete_versions(self, storage_class: StorageClass, versions: Any) -> None:
        self.events.append(("delete", len(versions)))
        self.deleted += [v.key for v in versions]


async def test_the_storage_audit_holds_one_listing_page_at_a_time(
    migrated_db: ScratchDatabase,
    world: tuple[Jobs, Clock, FakeArchiveStore],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    jobs, _, _ = world
    tenant = seed_tenant(migrated_db)
    cleaner = PagedCleaner(tenant.id, pages=5, per_page=200)
    jobs.cleaner = cleaner  # type: ignore[assignment]
    looked_up: list[int] = []
    known_keys = lifecycle.files.known_keys

    async def watched(session: Any, keys: Any) -> Any:
        looked_up.append(len(keys))
        cleaner.events.append(("lookup", len(keys)))
        return await known_keys(session, keys)

    monkeypatch.setattr(lifecycle.files, "known_keys", watched)
    report = await lifecycle.audit_storage(jobs)
    assert looked_up == [200] * 5, "one lookup per page, of that page's keys only"
    # Each page is looked up and acted on before the next page is read.
    expected = [e for n in range(5) for e in (("page", n), ("lookup", 200), ("delete", 200))]
    assert cleaner.events == expected
    assert report["orphans_deleted"] == 1000
