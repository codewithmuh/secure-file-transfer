"""Security-critical records in both regions' audit archive (#177; architecture 5.2, data model
2.5).

The writer runs against an in-memory store (archive_fixtures.py); one contract test runs the S3
adapter against S3Mock (TEST_S3_ENDPOINT_URL). The retrofit of M1 runs `deactivateUser` and a
demotion through `updateUser` over the real app, with the Osaka stand-in failing and recovering.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from datetime import UTC, datetime

import boto3
import pytest
from botocore.config import Config
from prometheus_client import CollectorRegistry

from archive_fixtures import FakeArchiveStore, fake_archive
from member_fixtures import client, seed_tenant, seed_user, session_caller
from pg import ScratchDatabase
from sft.core.errors import ServiceUnavailable
from sft.data.audit import ArchivedEvent
from sft.data.models import Role
from sft.runtime.archive import S3AuditArchive
from sft.service.audit_archive import (
    ArchiveMetrics,
    AuditArchive,
    RecordNotConfirmed,
    Region,
    intent_first,
    record_body,
    record_key,
)

pytestmark = pytest.mark.anyio

OCCURRED = datetime(2026, 11, 6, 23, 59, 59, tzinfo=UTC)


def event(**overrides: object) -> ArchivedEvent:
    values: dict[str, object] = {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "occurred_at": OCCURRED,
        "action": "user.deactivated",
        "actor_type": "admin",
        "actor_id": uuid.uuid4(),
        "target_type": "user",
        "target_id": uuid.uuid4(),
        "outcome": "success",
        "details": {},
    }
    values.update(overrides)
    return ArchivedEvent(**values)  # type: ignore[arg-type]


# ---- the writer ----


def test_a_record_is_keyed_by_its_event_and_holds_ids_enums_and_times_only() -> None:
    record = event()
    assert record_key(record) == (
        f"security-critical/v1/{record.tenant_id}/2026/11/06/{record.id}.json"
    )
    assert record_key(event(tenant_id=None, id=record.id)).startswith(
        "security-critical/v1/platform/2026/11/06/"
    )
    body = json.loads(record_body(record))
    assert body == {
        "id": str(record.id),
        "tenant_id": str(record.tenant_id),
        "occurred_at": "2026-11-06T23:59:59+00:00",
        "action": "user.deactivated",
        "actor_type": "admin",
        "actor_id": str(record.actor_id),
        "target_type": "user",
        "target_id": str(record.target_id),
        "outcome": "success",
        "security_critical": True,
        "details": {},
    }


async def test_both_regions_get_exactly_one_copy_and_a_retry_rewrites_nothing() -> None:
    store = FakeArchiveStore()
    archive = fake_archive(store)
    record = event()
    await archive.confirm([record])
    await archive.confirm([record])
    for region in Region:
        assert list(store.objects[region]) == [record_key(record)]
    # Confirmed in both regions, so this process doesn't write it again.
    assert store.writes == 2
    # Another process (a fresh archive) writes it again, and the conditional write keeps one.
    await fake_archive(store).confirm([record])
    assert store.writes == 4
    for region in Region:
        assert list(store.objects[region]) == [record_key(record)]


async def test_a_failing_region_is_a_503_and_counted_and_the_retry_completes_it() -> None:
    store = FakeArchiveStore(fail={Region.OSAKA})
    registry = CollectorRegistry()
    archive = AuditArchive(store, ArchiveMetrics.create(registry))
    record = event()
    with pytest.raises(RecordNotConfirmed) as refused:
        await archive.confirm([record])
    assert isinstance(refused.value, ServiceUnavailable)
    assert refused.value.retry_after == 5
    assert (
        registry.get_sample_value(
            "audit_archive_write_failures_total", {"region": "ap-northeast-3"}
        )
        == 1
    )
    assert list(store.objects[Region.TOKYO]) == [record_key(record)]
    store.fail.clear()
    await archive.confirm([record])
    assert list(store.objects[Region.OSAKA]) == [record_key(record)]
    assert list(store.objects[Region.TOKYO]) == [record_key(record)]


async def test_an_environment_without_osaka_writes_tokyo_alone() -> None:
    store = FakeArchiveStore(regions=(Region.TOKYO,))
    await fake_archive(store).confirm([event()])
    assert set(store.objects) == {Region.TOKYO}


async def test_intent_first_changes_nothing_when_the_intent_fails() -> None:
    store = FakeArchiveStore(fail={Region.OSAKA})
    archive = fake_archive(store)
    committed: list[str] = []

    async def commit() -> tuple[str, ArchivedEvent]:
        committed.append("grant")
        return "grant", event(action="download.grant_committed")

    with pytest.raises(RecordNotConfirmed, match="Nothing was changed"):
        await intent_first(archive, event(action="download.grant_intent"), commit)
    assert committed == []


async def test_the_committed_record_is_retried_in_the_background_until_both_confirm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sft.service.audit_archive.BACKGROUND_FIRST_WAIT", 0.01)
    store = FakeArchiveStore()
    archive = fake_archive(store)
    intent = event(action="download.grant_intent")
    committed = event(action="download.grant_committed")
    confirmed: list[str] = []

    async def commit() -> tuple[str, ArchivedEvent]:
        store.fail = {Region.OSAKA}  # Osaka goes down right after the grant commits
        return "grant", committed

    async def on_confirmed(value: str) -> None:
        confirmed.append(value)

    assert await intent_first(archive, intent, commit, on_confirmed=on_confirmed) == "grant"
    await asyncio.sleep(0.05)
    assert record_key(committed) not in store.objects[Region.OSAKA]
    assert confirmed == []
    store.fail.clear()
    await asyncio.wait_for(archive.drain(), timeout=2)
    assert confirmed == ["grant"]
    for region in Region:
        assert set(store.objects[region]) == {record_key(intent), record_key(committed)}
    await archive.close()


async def test_close_cancels_what_is_left_and_refuses_more() -> None:
    store = FakeArchiveStore(fail={Region.OSAKA})
    archive = fake_archive(store)
    archive.in_background([event()])
    await archive.close()
    with pytest.raises(RuntimeError, match="closed"):
        archive.in_background([event()])


# ---- the retrofit of M1: deactivateUser and demotions ----


async def test_a_deactivation_answers_200_only_once_both_archives_hold_it(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    store = FakeArchiveStore(fail={Region.OSAKA})
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    path = f"/v1/users/{tenant.target}/deactivate"
    async with client(migrated_db, lambda: admin, archive=fake_archive(store)) as http:
        refused = await http.post(path)
        assert (refused.status_code, refused.json()["code"]) == (503, "service_unavailable")
        assert refused.headers["retry-after"] == "5"
        # The change stands: the user is deactivated, with one security-critical event.
        [(status,)] = migrated_db.sql("SELECT status FROM users WHERE id = :id", id=tenant.target)
        assert status == "deactivated"
        assert store.actions(Region.TOKYO) == ["user.deactivated"]
        assert Region.OSAKA not in store.objects
        store.fail.clear()
        retried = await http.post(path)
        assert retried.status_code == 200
    [(event_id,)] = migrated_db.sql(
        "SELECT id FROM audit_events WHERE target_id = :id AND action = 'user.deactivated'",
        id=tenant.target,
    )
    for region in Region:
        [record] = store.records(region)
        assert record["id"] == str(event_id)
        assert record["target_id"] == str(tenant.target)


async def test_a_demotion_answers_503_with_the_change_kept_then_200(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    second = seed_user(migrated_db, tenant.id, role="admin")
    store = FakeArchiveStore(fail={Region.OSAKA})
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    path = f"/v1/users/{second}"
    async with client(migrated_db, lambda: admin, archive=fake_archive(store)) as http:
        refused = await http.patch(path, json={"role": "member"})
        assert refused.status_code == 503
        [(role,)] = migrated_db.sql("SELECT role FROM users WHERE id = :id", id=second)
        assert role == "member"
        store.fail.clear()
        assert (await http.patch(path, json={"role": "member"})).status_code == 200
        # A promotion isn't a security-critical record: nothing more is written.
        assert (await http.patch(path, json={"role": "admin"})).status_code == 200
    assert store.actions(Region.OSAKA) == ["user.role_changed"]
    assert store.actions(Region.TOKYO) == ["user.role_changed"]


async def test_a_no_op_role_with_another_change_succeeds_with_the_archive_down(
    migrated_db: ScratchDatabase,
) -> None:
    # The user was demoted long ago; this call keeps the role and changes another field. Only a
    # call that demotes answers for a demotion's record (#177 review).
    tenant = seed_tenant(migrated_db)
    second = seed_user(migrated_db, tenant.id, role="admin")
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin, archive=fake_archive()) as http:
        assert (await http.patch(f"/v1/users/{second}", json={"role": "member"})).status_code == 200
    down = FakeArchiveStore(fail=set(Region))
    async with client(migrated_db, lambda: admin, archive=fake_archive(down)) as http:
        response = await http.patch(
            f"/v1/users/{second}", json={"role": "member", "dlp_approver": True}
        )
    assert response.status_code == 200, response.text
    assert response.json()["dlp_approver"] is True


async def test_a_role_change_that_isnt_a_demotion_writes_no_record(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    store = FakeArchiveStore(fail=set(Region))
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin, archive=fake_archive(store)) as http:
        response = await http.patch(f"/v1/users/{tenant.target}", json={"dlp_approver": True})
    assert response.status_code == 200
    assert store.writes == 0


async def test_no_record_holds_a_token_code_address_file_name_or_message(
    migrated_db: ScratchDatabase,
) -> None:
    # The canary: a deactivated user whose address, and a request whose user agent, carry markers
    # that must never reach the archive.
    tenant = seed_tenant(migrated_db)
    canary = f"canary-{uuid.uuid4().hex}"
    target = seed_user(migrated_db, tenant.id, email=f"{canary}@example.test")
    store = FakeArchiveStore()
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin, archive=fake_archive(store)) as http:
        response = await http.post(
            f"/v1/users/{target}/deactivate", headers={"user-agent": f"agent-{canary}"}
        )
    assert response.status_code == 200
    stored = b"".join(b for region in store.objects.values() for b in region.values())
    assert stored
    assert canary.encode() not in stored
    assert b"@" not in stored
    assert b"127.0.0.1" not in stored
    assert b"source_ip" not in stored


# ---- the S3 adapter, against S3Mock ----


@pytest.fixture
def s3_endpoint() -> str:
    url = os.environ.get("TEST_S3_ENDPOINT_URL")
    if not url:
        if os.environ.get("CI"):
            pytest.fail("TEST_S3_ENDPOINT_URL must be set in CI")
        pytest.skip("set TEST_S3_ENDPOINT_URL to an S3Mock")
    return url


def _bucket(endpoint: str) -> str:
    name = f"sft-archive-{uuid.uuid4().hex[:12]}"
    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="ap-northeast-1",
        aws_access_key_id="test-only",
        aws_secret_access_key="test-only",  # noqa: S106 - S3Mock checks no credentials
        config=Config(s3={"addressing_style": "path"}),
    )
    client.create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": "ap-northeast-1"}
    )
    client.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    return name


async def test_the_s3_adapter_writes_each_record_once_per_region(
    s3_endpoint: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-only")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-only")
    buckets = {Region.TOKYO: _bucket(s3_endpoint), Region.OSAKA: _bucket(s3_endpoint)}
    store = S3AuditArchive.create(buckets, dict.fromkeys(Region, s3_endpoint))
    archive = AuditArchive(store, ArchiveMetrics.create(CollectorRegistry()))
    record = event()
    try:
        assert store.regions == (Region.TOKYO, Region.OSAKA)
        assert await store.put_once(Region.TOKYO, record_key(record), record_body(record))
        assert not await store.put_once(Region.TOKYO, record_key(record), b"{}")
        await archive.confirm([record])
    finally:
        await archive.close()
    reader = boto3.client(
        "s3",
        endpoint_url=s3_endpoint,
        region_name="ap-northeast-1",
        config=Config(s3={"addressing_style": "path"}),
    )
    for bucket in buckets.values():
        versions = reader.list_object_versions(Bucket=bucket).get("Versions", [])
        assert [v["Key"] for v in versions] == [record_key(record)]
        body = reader.get_object(Bucket=bucket, Key=record_key(record))["Body"].read()
        assert json.loads(body)["id"] == str(record.id)


async def test_the_s3_adapter_reports_a_region_it_cant_write(
    s3_endpoint: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-only")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-only")
    # Osaka's stand-in is a bucket that doesn't exist: every write there fails.
    buckets = {Region.TOKYO: _bucket(s3_endpoint), Region.OSAKA: "sft-no-such-archive"}
    registry = CollectorRegistry()
    archive = AuditArchive(
        S3AuditArchive.create(buckets, dict.fromkeys(Region, s3_endpoint)),
        ArchiveMetrics.create(registry),
    )
    try:
        assert await archive.write([event()]) == {Region.OSAKA}
    finally:
        await archive.close()
    assert (
        registry.get_sample_value(
            "audit_archive_write_failures_total", {"region": "ap-northeast-3"}
        )
        == 1
    )


def test_the_adapter_needs_tokyo() -> None:
    with pytest.raises(ValueError, match="Tokyo"):
        S3AuditArchive({}, {})
