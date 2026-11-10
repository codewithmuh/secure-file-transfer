"""The recovery job's entry point (#258; `sft.workers.recovery`, `sft.service.recovery`): what the
restore, failover and failback runbooks run.

The archive is read under both layouts, the API's security-critical records and the archive job's
batches in every generation, from an in-memory reader in the unit tests and from S3Mock
(TEST_S3_ENDPOINT_URL) in the run against the local services, as `sft_recovery` in recovery scope
on a migrated database of the test's own.
"""

from __future__ import annotations

import gzip
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import boto3
import pytest
from botocore.config import Config

import isolation_fixture
from isolation import seed_tenant
from pg import ScratchDatabase
from sft.core.settings import RecoverySettings
from sft.data.migrate import run
from sft.data.roles import MIGRATE, RECOVERY
from sft.service.audit_archive import PREFIX
from sft.service.recovery import (
    Step,
    highest_generation,
    parse_steps,
    read_records,
)
from sft.workers import recovery as recovery_command

pytestmark = pytest.mark.anyio

NOW = datetime.now(UTC)
SINCE = NOW - timedelta(hours=1)


def body(action: str, *, at: datetime, critical: bool, **more: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": str(uuid.uuid4()),
        "tenant_id": str(uuid.uuid4()),
        "occurred_at": at.isoformat(),
        "action": action,
        "actor_type": "system",
        "actor_id": None,
        "target_type": "transfer",
        "target_id": str(uuid.uuid4()),
        "outcome": "success",
        "security_critical": critical,
        "details": {},
    }
    return values | more


def direct_key(record: dict[str, object]) -> str:
    at = datetime.fromisoformat(str(record["occurred_at"]))
    return f"{PREFIX}/{record['tenant_id']}/{at:%Y/%m/%d}/{record['id']}.json"


def batch(*records: dict[str, object]) -> bytes:
    lines = "".join(json.dumps(r | {"tx_id": "1", "source_ip": None}) + "\n" for r in records)
    return gzip.compress(lines.encode(), mtime=0)


def batch_key(generation: int, at: datetime, name: str = "0-1") -> str:
    return f"g{generation}/{at:%Y/%m/%d}/{name}.jsonl.gz"


@dataclass
class FakeReader:
    objects: dict[str, bytes] = field(default_factory=dict)

    async def prefixes(self, prefix: str) -> list[str]:
        found = {
            prefix + key[len(prefix) :].split("/", 1)[0] + "/"
            for key in self.objects
            if key.startswith(prefix) and "/" in key[len(prefix) :]
        }
        return sorted(found)

    async def keys(self, prefix: str) -> list[str]:
        return sorted(key for key in self.objects if key.startswith(prefix))

    async def get(self, key: str) -> bytes:
        return self.objects[key]

    async def close(self) -> None:
        pass


# ---- without a database ----


def test_steps_run_in_their_order_and_unknown_ones_are_refused() -> None:
    assert parse_steps("replay, generation,partitions") == (
        Step.GENERATION,
        Step.PARTITIONS,
        Step.REPLAY,
    )
    for bad in ("", " , ", "generation,rewind"):
        with pytest.raises(ValueError, match="step"):
            parse_steps(bad)


def test_the_settings_read_the_cronjobs_empty_variables_as_unset() -> None:
    base = {
        "database_url": "postgresql://sft_recovery@db.example/sft",
        "audit_archive_bucket": "sft-prod-apne3-audit-archive-000000000000",
    }
    outbox = RecoverySettings(
        **base, recovery_steps="outbox", recovery_since=SINCE.isoformat(), recovery_rewind_to=""
    )
    assert outbox.recovery_rewind_to is None
    with pytest.raises(ValueError, match="RECOVERY_REWIND_TO"):
        RecoverySettings(**base, recovery_steps="generation", recovery_rewind_to="")
    with pytest.raises(ValueError, match="RECOVERY_SINCE"):
        RecoverySettings(**base, recovery_steps="replay", recovery_since="")
    with pytest.raises(ValueError, match="timezone"):
        RecoverySettings(**base, recovery_steps="outbox", recovery_since="2026-11-09T01:00:00")
    with pytest.raises(ValueError, match="steps"):
        RecoverySettings(**base, recovery_steps="drop")
    # As the CronJob is rendered: the settings load, and the command refuses to run (below).
    assert RecoverySettings(**base, recovery_steps="").recovery_steps == ""


async def test_both_layouts_are_read_in_every_generation_from_the_day_of_since() -> None:
    old = SINCE - timedelta(days=2)
    direct = body("transfer.revoked", at=SINCE + timedelta(minutes=5), critical=True)
    stale = body("transfer.revoked", at=old, critical=True)
    first = body("transfer.expired", at=SINCE + timedelta(minutes=1), critical=False)
    second = body("transfer.expired", at=SINCE + timedelta(minutes=2), critical=False)
    reader = FakeReader(
        {
            direct_key(direct): json.dumps(direct).encode(),
            direct_key(stale): json.dumps(stale).encode(),
            batch_key(1, SINCE): batch(first, direct),
            batch_key(2, SINCE, "1-2"): batch(second),
            batch_key(2, old): batch(stale),
        }
    )
    assert await highest_generation(reader) == 2
    found = await read_records(reader, since=SINCE, today=NOW.date())
    ids = sorted(str(r.id) for r in found)
    # The stale ones are dated before since's day, so never listed; the duplicate stays for
    # replay's merge to drop.
    assert ids == sorted([str(direct["id"]), str(direct["id"]), first["id"], second["id"]])
    assert await highest_generation(FakeReader()) == 0


async def test_an_object_that_isnt_a_record_fails_the_run_naming_its_key() -> None:
    key = f"{PREFIX}/platform/{SINCE:%Y/%m/%d}/x.json"
    with pytest.raises(ValueError, match=r"x\.json isn.t a record"):
        await read_records(FakeReader({key: b"[]"}), since=SINCE, today=NOW.date())
    with pytest.raises(ValueError, match="isn't a gzipped batch"):
        await read_records(
            FakeReader({batch_key(1, SINCE): b"plain"}), since=SINCE, today=NOW.date()
        )


# ---- against the local services: PostgreSQL and S3Mock ----


@pytest.fixture
def own_db(empty_db: ScratchDatabase) -> ScratchDatabase:
    run(empty_db.url(MIGRATE))
    empty_db.as_owner(isolation_fixture.create)
    return empty_db


@pytest.fixture
def s3_endpoint() -> str:
    url = os.environ.get("TEST_S3_ENDPOINT_URL")
    if not url:
        if os.environ.get("CI"):
            pytest.fail("TEST_S3_ENDPOINT_URL must be set in CI")
        pytest.skip("set TEST_S3_ENDPOINT_URL to an S3Mock")
    return url


@pytest.fixture
def archive_bucket(s3_endpoint: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-only")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-only")
    name = f"sft-archive-{uuid.uuid4().hex[:12]}"
    s3().create_bucket(
        Bucket=name, CreateBucketConfiguration={"LocationConstraint": "ap-northeast-3"}
    )
    return name


def s3() -> object:
    return boto3.client(
        "s3",
        endpoint_url=os.environ["TEST_S3_ENDPOINT_URL"],
        region_name="ap-northeast-3",
        aws_access_key_id="test-only",
        aws_secret_access_key="test-only",  # noqa: S106 - S3Mock checks no credentials
        config=Config(s3={"addressing_style": "path"}),
    )


def settings(db: ScratchDatabase, bucket: str, steps: str, **times: datetime) -> RecoverySettings:
    return RecoverySettings(
        database_url=db.url(RECOVERY),
        aws_region="ap-northeast-3",
        audit_archive_bucket=bucket,
        audit_archive_endpoint_url=os.environ["TEST_S3_ENDPOINT_URL"],
        recovery_steps=steps,
        recovery_since=times.get("since"),
        recovery_rewind_to=times.get("rewind_to"),
    )


async def test_the_job_runs_the_failovers_steps_against_the_local_services(
    own_db: ScratchDatabase, archive_bucket: str
) -> None:
    # Acceptance criterion: the entry point the runbooks name, against PostgreSQL and S3Mock.
    seeded = seed_tenant(own_db, "recovery-job")
    tenant, transfer = seeded.tenant_id, seeded.rows["transfer"]
    own_db.sql(
        "UPDATE transfers SET state = 'sent', expires_at = now() + interval '7 days', "
        "submitted_at = now(), sent_at = now() WHERE id = :id",
        id=transfer,
    )
    revoked = body(
        "transfer.revoked",
        at=SINCE + timedelta(minutes=10),
        critical=True,
        tenant_id=str(tenant),
        target_id=str(transfer),
        actor_type="admin",
        actor_id=str(seeded.rows["user"]),
    )
    ordinary = body(
        "transfer.expired",
        at=SINCE + timedelta(minutes=5),
        critical=False,
        tenant_id=str(tenant),
    )
    client = s3()
    for key, data in (
        (direct_key(revoked), json.dumps(revoked).encode()),
        (batch_key(1, SINCE), batch(ordinary, revoked)),
        (batch_key(2, SINCE, "5-6"), batch(ordinary)),
    ):
        client.put_object(Bucket=archive_bucket, Key=key, Body=data)  # type: ignore[attr-defined]
    sent = uuid.uuid4()
    own_db.sql(
        "INSERT INTO outbox (id, tenant_id, topic, payload, published_at) VALUES (:id, :tenant, "
        "'transfer.sent', '{}', now() - interval '30 minutes')",
        id=sent,
        tenant=tenant,
    )

    report = await recovery_command.run_once(
        settings(
            own_db, archive_bucket, "generation,partitions,replay", since=SINCE, rewind_to=SINCE
        )
    )
    assert (report.highest_in_archive, report.generation) == (2, 3)
    assert own_db.sql("SELECT generation FROM audit_archive_cursor") == [(3,)]
    assert report.records == 2  # each event once, whichever layouts held it
    assert report.newest == datetime.fromisoformat(str(revoked["occurred_at"]))
    assert report.replayed == {
        "transfer.revoked:reapplied": 1,
        "transfer.expired:reimported": 1,
    }
    assert own_db.sql("SELECT state FROM transfers WHERE id = :id", id=transfer) == [("revoked",)]

    # Again, as a runbook may: nothing changes, and the outbox step on its own.
    again = await recovery_command.run_once(
        settings(own_db, archive_bucket, "generation,replay", since=SINCE, rewind_to=SINCE)
    )
    assert again.generation == 3
    assert set(again.replayed) == {"transfer.revoked:present", "transfer.expired:present"}
    outbox = await recovery_command.run_once(
        settings(own_db, archive_bucket, "outbox", since=NOW - timedelta(hours=24))
    )
    assert outbox.republished is not None
    assert outbox.republished >= 1
    assert own_db.sql("SELECT published_at FROM outbox WHERE id = :id", id=sent) == [(None,)]


def test_the_command_refuses_bad_settings_and_fails_without_its_archive(
    monkeypatch: pytest.MonkeyPatch, own_db: ScratchDatabase
) -> None:
    monkeypatch.setenv("DATABASE_URL", own_db.url(RECOVERY))
    monkeypatch.setenv("AUDIT_ARCHIVE_BUCKET", "sft-no-such-archive")
    monkeypatch.setenv("RECOVERY_STEPS", "")
    assert recovery_command.main() == 2  # the CronJob as rendered: no step named
    monkeypatch.setenv("RECOVERY_STEPS", "replay")
    monkeypatch.setenv("RECOVERY_SINCE", "")
    assert recovery_command.main() == 2
    monkeypatch.setenv("RECOVERY_SINCE", SINCE.isoformat())
    monkeypatch.setenv("AUDIT_ARCHIVE_ENDPOINT_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-only")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-only")
    assert recovery_command.main() == 1
