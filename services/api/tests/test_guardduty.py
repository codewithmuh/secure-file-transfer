"""GuardDuty Malware Protection for files over 2 GB (#234; ADR-0019; abuse and rate limits 6.4).

The large pool's consumer of the `guardduty-results` queue runs as `sft_scan` against real
PostgreSQL, with the large-files bucket in memory (scan_fixtures.py). The local stand-in
(`sft.workers.guardduty_standin`) tags a version and sends the event that consumer reads, so the
whole local flow runs here too. The live check against GuardDuty is pending the AWS run.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from prometheus_client import CollectorRegistry
from pydantic import ValidationError

from member_fixtures import ready_for_dlp, seed_user
from pg import ScratchDatabase
from scan_fixtures import FakeScanObjects, eicar
from sft.core.settings import GuardDutyStandInSettings
from sft.data.database import Database
from sft.data.models import (
    FileState,
    InspectionReason,
    InspectionState,
    ScanDetail,
    ScanEngine,
)
from sft.data.outbox import InvalidMessageError, Queue
from sft.data.roles import JOBS, SCAN
from sft.service import guardduty, scans
from sft.service.evaluation import is_shareable
from sft.service.guardduty import TAG, Status, event_body, parse_result
from sft.workers.consumer import Delivery, Outcome
from sft.workers.guardduty_standin import GuardDutyStandIn, Version, judge
from sft.workers.queues import OutgoingMessage, SendFailure
from sft.workers.scan import (
    GuardDutyConsumer,
    GuardDutyMetrics,
    ResultTooEarlyError,
    ScanMetrics,
)
from transfer_fixtures import actions, seed_file, seed_transfer, transfer_row

pytestmark = pytest.mark.anyio

BUCKET = "sft-test-large-files"
SIZE = 3_000_000_000
NOW = "2026-11-08T01:02:03Z"


def body(
    key: str,
    status: Status = Status.NO_THREATS_FOUND,
    *,
    version: str = "v1",
    reasons: tuple[str, ...] = (),
    event_id: str | None = None,
    bucket: str = BUCKET,
) -> str:
    """An event as EventBridge delivers it, with an ID of its own unless given."""
    return event_body(
        event_id=event_id or str(uuid.uuid4()),
        bucket=bucket,
        key=key,
        version_id=version,
        status=status,
        reasons=reasons,
        time=NOW,
    )


# ---- reading an event ----


def test_a_result_names_the_tenant_file_and_version_from_the_key() -> None:
    tenant_id, file_id = uuid.uuid4(), uuid.uuid4()
    key = f"tenants/{tenant_id}/files/{file_id}"
    result = parse_result(body(key, Status.THREATS_FOUND, event_id="event-1"), bucket=BUCKET)
    assert result is not None
    assert (result.tenant_id, result.file_id, result.version_id) == (tenant_id, file_id, "v1")
    assert result.status is Status.THREATS_FOUND
    message = result.as_message()
    assert (message.tenant_id, message.topic, message.payload) == (
        tenant_id,
        "guardduty.result",
        {"file_id": file_id},
    )
    # One ID per event and version: a second delivery is a duplicate.
    again = parse_result(body(key, Status.THREATS_FOUND, event_id="event-1"), bucket=BUCKET)
    assert again is not None
    assert again.id == result.id
    other = parse_result(body(key, Status.THREATS_FOUND, event_id="event-2"), bucket=BUCKET)
    assert other is not None
    assert other.id != result.id


@pytest.mark.parametrize(
    ("key", "bucket"),
    [
        (f"tenants/{uuid.uuid4()}/files/{uuid.uuid4()}", "sft-test-files"),  # another bucket
        ("malware-protection-resource-validation-object", BUCKET),  # GuardDuty's own object
        (f"tenants/{uuid.uuid4()}/files/{uuid.uuid4()}/extra", BUCKET),
        ("tenants/not-a-uuid/files/x", BUCKET),
    ],
)
def test_an_event_for_no_file_of_ours_is_none(key: str, bucket: str) -> None:
    assert parse_result(body(key, bucket=bucket), bucket=BUCKET) is None


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[]",
        json.dumps({"source": "aws.s3", "detail-type": guardduty.DETAIL_TYPE, "id": "x"}),
        body("k").replace("NO_THREATS_FOUND", "MAYBE"),
    ],
)
def test_anything_else_is_invalid_and_left_for_the_dead_letter_queue(raw: str) -> None:
    with pytest.raises(InvalidMessageError):
        parse_result(raw, bucket=BUCKET)


@pytest.mark.parametrize(
    ("status", "reasons", "state", "detail"),
    [
        (Status.NO_THREATS_FOUND, (), FileState.CLEAN, None),
        (Status.THREATS_FOUND, (), FileState.INFECTED, None),
        (Status.UNSUPPORTED, ("PASSWORD_PROTECTED",), FileState.UNSCANNABLE, ScanDetail.ENCRYPTED),
        (
            Status.UNSUPPORTED,
            ("OBJECT_SIZE_LIMIT_EXCEEDED",),
            FileState.UNSCANNABLE,
            ScanDetail.LIMIT_EXCEEDED,
        ),
        (Status.UNSUPPORTED, (), FileState.UNSCANNABLE, ScanDetail.LIMIT_EXCEEDED),
        (Status.ACCESS_DENIED, (), FileState.SCAN_FAILED, ScanDetail.ENGINE_ERROR),
        (Status.FAILED, (), FileState.SCAN_FAILED, ScanDetail.ENGINE_ERROR),
    ],
)
def test_results_map_as_abuse_6_4_says(
    status: Status, reasons: tuple[str, ...], state: FileState, detail: ScanDetail | None
) -> None:
    key = f"tenants/{uuid.uuid4()}/files/{uuid.uuid4()}"
    result = parse_result(body(key, status, reasons=reasons), bucket=BUCKET)
    assert result is not None
    scan = result.scan_result()
    assert (scan.state, scan.detail, scan.engine) == (state, detail, ScanEngine.GUARDDUTY)


# ---- the consumer ----


@dataclass
class Rig:
    db: ScratchDatabase
    objects: FakeScanObjects
    registry: CollectorRegistry
    consumer: GuardDutyConsumer
    tenant_id: uuid.UUID
    owner: uuid.UUID

    def key(self, file_id: uuid.UUID) -> str:
        return f"tenants/{self.tenant_id}/files/{file_id}"

    def large_file(
        self, transfer_id: uuid.UUID, *, state: str = "scanning", tag: Status | None = None
    ) -> uuid.UUID:
        file_id = seed_file(
            self.db,
            self.tenant_id,
            transfer_id,
            state=state,
            size=SIZE,
            storage_class="large",
            version="v1",
        )
        self.objects.put(self.key(file_id), "v1", b"", {TAG: tag.value} if tag else {})
        return file_id

    def delivery(self, raw: str, attempt: int = 1) -> Delivery:
        message = self.consumer.parse(raw)
        assert message is not None
        return Delivery(message, attempt, raw)

    def file(self, file_id: uuid.UUID) -> dict[str, object]:
        [row] = self.db.sql(
            "SELECT state, scan_detail, scan_engine, inspection_state, inspection_reasons "
            "FROM files WHERE id = :id",
            id=file_id,
        )
        keys = ("state", "detail", "engine", "inspection", "reasons")
        return dict(zip(keys, row, strict=True))

    def outcome(self, outcome: str) -> float:
        value = self.registry.get_sample_value("guardduty_results_total", {"outcome": outcome})
        return 0.0 if value is None else value


@pytest.fixture
async def rig(migrated_db: ScratchDatabase) -> AsyncIterator[Rig]:
    tenant_id = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id
    )
    owner = seed_user(migrated_db, tenant_id)
    ready_for_dlp(migrated_db, tenant_id, owner)
    objects = FakeScanObjects()
    registry = CollectorRegistry()
    database = Database.connect(migrated_db.url(SCAN), pool_size=2)
    consumer = GuardDutyConsumer(
        database,
        objects,
        ScanMetrics.create(registry),
        GuardDutyMetrics.create(registry),
        bucket=BUCKET,
    )
    try:
        yield Rig(migrated_db, objects, registry, consumer, tenant_id, owner)
    finally:
        await database.dispose()


async def test_a_clean_result_makes_a_large_file_downloadable(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.large_file(transfer_id, tag=Status.NO_THREATS_FOUND)
    assert await rig.consumer.process(rig.delivery(body(rig.key(file_id)))) is Outcome.PROCESSED
    found = rig.file(file_id)
    # Clean, by GuardDuty; the inspector never reads a file over 2 GB, so the tenant's rules for
    # uninspected files decide (FR-47).
    assert (found["state"], found["engine"], found["inspection"]) == (
        "clean",
        "guardduty",
        "not_inspected",
    )
    assert found["reasons"] == [InspectionReason.TOO_LARGE.value]
    # The scan tag the API's read permission needs, with GuardDuty's own tag kept (ADR-0019).
    assert rig.objects.tags[(rig.key(file_id), "v1")] == {TAG: "NO_THREATS_FOUND", "scan": "clean"}
    assert rig.objects.reads == []  # nothing reads the bytes
    assert actions(rig.db, file_id) == ["file.scanned"]
    assert is_shareable(FileState.CLEAN, False, InspectionState.NOT_INSPECTED)
    # The file is shareable; the default DLP policy asks the sender to confirm a file it couldn't
    # inspect (FR-47), so the transfer waits for that, not for a scan.
    assert transfer_row(rig.db, transfer_id)["state"] == "awaiting_confirmation"
    assert rig.outcome("recorded") == 1
    [(details,)] = rig.db.sql(
        "SELECT details FROM audit_events WHERE target_id = :id AND action = 'file.scanned'",
        id=file_id,
    )
    assert (details["scan_engine"], details["state"]) == ("guardduty", "clean")


async def test_a_threat_blocks_the_file_and_holds_its_transfer(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.large_file(transfer_id, tag=Status.THREATS_FOUND)
    raw = body(rig.key(file_id), Status.THREATS_FOUND)
    assert await rig.consumer.process(rig.delivery(raw)) is Outcome.PROCESSED
    found = rig.file(file_id)
    assert (found["state"], found["engine"], found["inspection"]) == (
        "infected",
        "guardduty",
        "skipped",
    )
    assert rig.objects.tags[(rig.key(file_id), "v1")]["scan"] == "infected"
    assert transfer_row(rig.db, transfer_id)["state"] == "held"


async def test_an_encrypted_archive_follows_the_unscannable_policy(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.large_file(transfer_id, tag=Status.UNSUPPORTED)
    raw = body(rig.key(file_id), Status.UNSUPPORTED, reasons=("PASSWORD_PROTECTED",))
    await rig.consumer.process(rig.delivery(raw))
    assert (rig.file(file_id)["state"], rig.file(file_id)["detail"]) == ("unscannable", "encrypted")
    assert transfer_row(rig.db, transfer_id)["state"] == "held"  # blocked by default (FR-18)


async def test_a_result_whose_tag_names_another_is_ignored(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.large_file(transfer_id, tag=Status.THREATS_FOUND)
    # An event that says clean, for a version GuardDuty tagged as a threat: not its word.
    delivery = rig.delivery(body(rig.key(file_id), Status.NO_THREATS_FOUND))
    assert await rig.consumer.process(delivery) is Outcome.PROCESSED
    assert rig.file(file_id)["state"] == "scanning"
    assert "scan" not in rig.objects.tags[(rig.key(file_id), "v1")]
    assert rig.outcome("tag_mismatch") == 1
    assert actions(rig.db, file_id) == []
    # Recorded as handled: a second delivery is a duplicate, not a second look.
    assert await rig.consumer.process(delivery) is Outcome.DUPLICATE


async def test_a_result_before_the_tag_or_before_completion_is_tried_again(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    untagged = rig.large_file(transfer_id)
    with pytest.raises(ResultTooEarlyError):
        await rig.consumer.process(rig.delivery(body(rig.key(untagged))))
    completing = rig.large_file(transfer_id, state="completing", tag=Status.NO_THREATS_FOUND)
    with pytest.raises(ResultTooEarlyError):
        await rig.consumer.process(rig.delivery(body(rig.key(completing))))
    assert rig.outcome("too_early") == 2
    # Once GuardDuty's tag is there, the next delivery records it.
    rig.objects.tags[(rig.key(untagged), "v1")] = {TAG: "NO_THREATS_FOUND"}
    await rig.consumer.process(rig.delivery(body(rig.key(untagged)), attempt=2))
    assert rig.file(untagged)["state"] == "clean"


async def test_a_result_for_another_version_or_no_file_changes_nothing(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.large_file(transfer_id, tag=Status.NO_THREATS_FOUND)
    raw = body(rig.key(file_id), version="v0")
    assert await rig.consumer.process(rig.delivery(raw)) is Outcome.PROCESSED
    assert rig.file(file_id)["state"] == "scanning"
    assert rig.outcome("other_version") == 1
    nobody = f"tenants/{rig.tenant_id}/files/{uuid.uuid4()}"
    assert await rig.consumer.process(rig.delivery(body(nobody))) is Outcome.PROCESSED
    assert rig.outcome("not_ours") == 1
    # A file of the standard bucket is never GuardDuty's.
    small = seed_file(rig.db, rig.tenant_id, transfer_id, version="v1")
    assert await rig.consumer.process(rig.delivery(body(rig.key(small)))) is Outcome.PROCESSED
    assert rig.file(small)["state"] == "scanning"


async def test_a_late_result_changes_nothing_and_makes_the_tag_good(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.large_file(transfer_id, state="scan_failed", tag=Status.NO_THREATS_FOUND)
    assert await rig.consumer.process(rig.delivery(body(rig.key(file_id)))) is Outcome.PROCESSED
    assert rig.file(file_id)["state"] == "scan_failed"
    assert rig.objects.tags[(rig.key(file_id), "v1")]["scan"] == "scan_failed"
    assert rig.outcome("late") == 1


async def test_a_duplicate_does_the_work_once(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.large_file(transfer_id, tag=Status.NO_THREATS_FOUND)
    raw = body(rig.key(file_id))
    assert await rig.consumer.process(rig.delivery(raw)) is Outcome.PROCESSED
    assert await rig.consumer.process(rig.delivery(raw)) is Outcome.DUPLICATE
    assert actions(rig.db, file_id) == ["file.scanned"]


async def test_no_result_by_the_deadline_ends_scan_failed(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = seed_file(
        rig.db,
        rig.tenant_id,
        transfer_id,
        size=SIZE,
        storage_class="large",
        deadline=timedelta(seconds=-1),
    )
    jobs = Database.connect(rig.db.url(JOBS), pool_size=1)
    try:
        swept = await scans.fail_overdue_scans(jobs, now=datetime.now(UTC))
    finally:
        await jobs.dispose()
    assert file_id in [s.file_id for s in swept]
    assert (rig.file(file_id)["state"], rig.file(file_id)["detail"]) == (
        "scan_failed",
        "deadline_passed",
    )
    assert transfer_row(rig.db, transfer_id)["state"] == "held"


# ---- the local stand-in, end to end ----


@dataclass
class MemoryBucket:
    """`StandInBucket` over the scan worker's in-memory buckets: the same versions and tags."""

    objects: FakeScanObjects
    name: str = BUCKET
    chunk: int = 7

    async def versions(self) -> list[Version]:
        return [Version(key, version) for key, version in self.objects.versions]

    async def read(self, version: Version) -> AsyncIterator[bytes]:
        data = self.objects.versions[(version.key, version.version_id)]
        for start in range(0, len(data), self.chunk):
            yield data[start : start + self.chunk]

    async def tags(self, version: Version) -> Mapping[str, str]:
        return dict(self.objects.tags.get((version.key, version.version_id), {}))

    async def put_tags(self, version: Version, tags: Mapping[str, str]) -> None:
        self.objects.tags[(version.key, version.version_id)] = dict(tags)


@dataclass
class SentQueue:
    sent: list[tuple[str, str]] = field(default_factory=list)

    async def send_batch(
        self, queue: str, messages: Sequence[OutgoingMessage]
    ) -> list[SendFailure]:
        self.sent += [(queue, m.body) for m in messages]
        return []


async def test_the_stand_in_finds_eicar_across_chunk_edges() -> None:
    async def chunks(data: bytes, size: int) -> AsyncIterator[bytes]:
        for start in range(0, len(data), size):
            yield data[start : start + size]

    data = b"x" * 1000 + eicar() + b"y" * 1000
    for size in (1, 7, 64, 4096):
        assert await judge(chunks(data, size)) is Status.THREATS_FOUND
    assert await judge(chunks(b"quarterly report " * 100, 7)) is Status.NO_THREATS_FOUND


async def test_the_stand_in_tags_and_announces_and_the_worker_records_it(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    clean = rig.large_file(transfer_id)
    infected = rig.large_file(transfer_id)
    rig.objects.versions[(rig.key(infected), "v1")] = b"zip:" + eicar()
    rig.objects.tags[(rig.key(clean), "v1")] = {"other": "kept"}
    queue = SentQueue()
    standin = GuardDutyStandIn(MemoryBucket(rig.objects), queue)  # type: ignore[arg-type]
    assert len(await standin.scan_new()) == 2
    assert await standin.scan_new() == []  # each version once
    assert rig.objects.tags[(rig.key(clean), "v1")] == {"other": "kept", TAG: "NO_THREATS_FOUND"}
    assert [queue_name for queue_name, _ in queue.sent] == [Queue.GUARDDUTY_RESULTS.value] * 2
    for _, raw in queue.sent:
        await rig.consumer.process(rig.delivery(raw))
    assert rig.file(clean)["state"] == FileState.CLEAN.value
    assert rig.file(infected)["state"] == FileState.INFECTED.value
    assert rig.objects.tags[(rig.key(clean), "v1")] == {
        "other": "kept",
        TAG: "NO_THREATS_FOUND",
        "scan": "clean",
    }
    assert transfer_row(rig.db, transfer_id)["state"] == "held"


def test_the_stand_in_refuses_to_start_outside_local_and_test() -> None:
    base = {
        "s3_endpoint_url": "http://s3:9090",
        "s3_large_files_bucket": "sft-local-large-files",
        "sqs_endpoint_url": "http://sqs:9324",
        "sqs_queue_prefix": "sft-local-",
    }
    assert GuardDutyStandInSettings(environment="local", **base).environment == "local"  # type: ignore[arg-type]
    for environment in ("dev", "staging", "prod"):
        with pytest.raises(ValidationError, match="only with ENVIRONMENT=local or test"):
            GuardDutyStandInSettings(environment=environment, **base)  # type: ignore[arg-type]


def test_the_inspection_of_a_guardduty_file_is_not_inspected_for_too_large() -> None:
    assert guardduty.NOT_INSPECTED.state is InspectionState.NOT_INSPECTED
    assert guardduty.NOT_INSPECTED.reasons == (InspectionReason.TOO_LARGE,)
