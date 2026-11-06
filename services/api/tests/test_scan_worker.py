"""The scan worker (#175) and DLP inspection in the scan pass (#176): ADR-0019, ADR-0022; data
model 3.1, 3.5; architecture 4.1, 4.6.

The worker runs as `sft_scan` against real PostgreSQL, with clamd, the inspector and the files
buckets stood in for on real sockets (scan_fixtures.py). tests/test_scan_clamd.py runs it against
the compose clamd; tests/test_scan_inspector.py against the real inspector, in Linux.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from member_fixtures import seed_user
from pg import ScratchDatabase
from scan_fixtures import FakeClamd, FakeInspector, FakeScanObjects, eicar, finding
from sft.core.ids import uuid7
from sft.core.settings import ScanSettings
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.data.outbox import OutboxMessage, Queue
from sft.data.roles import SCAN
from sft.dlp.protocol import result
from sft.service.objects import ObjectStoreError
from sft.workers import scan as scan_worker
from sft.workers.consumer import LONG_POLL_SECONDS, Delivery, Outcome
from sft.workers.scan import (
    AttemptFailedError,
    Engines,
    Leases,
    ScanMetrics,
    SmallScanConsumer,
    scan_queues,
)
from transfer_fixtures import actions, outbox_topics, seed_file, seed_transfer, transfer_row

pytestmark = pytest.mark.anyio

DATA = b"quarterly report " * 10_000  # 170 KB: past the inspector's 64 KiB prefix


@dataclass
class Rig:
    db: ScratchDatabase
    objects: FakeScanObjects
    clamd: FakeClamd
    inspector: FakeInspector
    metrics: ScanMetrics
    registry: CollectorRegistry
    consumer: SmallScanConsumer
    tenant_id: uuid.UUID
    owner: uuid.UUID

    def scanning_file(
        self, transfer_id: uuid.UUID, data: bytes = DATA, *, version: str = "v1"
    ) -> uuid.UUID:
        file_id = seed_file(
            self.db, self.tenant_id, transfer_id, state="scanning", size=len(data), version=version
        )
        self.objects.put(self.key(file_id), version, data, {"GuardDutyMalwareScanStatus": "x"})
        return file_id

    def key(self, file_id: uuid.UUID) -> str:
        return f"tenants/{self.tenant_id}/files/{file_id}"

    def delivery(self, file_id: uuid.UUID, attempt: int = 1) -> Delivery:
        message = OutboxMessage(uuid7(), "file.scan", self.tenant_id, {"file_id": file_id})
        return Delivery(message, attempt)

    def file(self, file_id: uuid.UUID) -> dict[str, object]:
        [row] = self.db.sql(
            "SELECT state, scan_detail, scan_engine, unscannable_allowed, inspection_state, "
            "inspection_reasons, inspection_engine_version, scan_attempts "
            "FROM files WHERE id = :id",
            id=file_id,
        )
        keys = ("state", "detail", "engine", "allowed", "inspection", "reasons", "version", "tries")
        return dict(zip(keys, row, strict=True))

    def findings(self, file_id: uuid.UUID) -> list[tuple[object, ...]]:
        return self.db.sql(
            "SELECT detector, count_low, count_medium, count_high, detail_ct FROM dlp_findings "
            "WHERE file_id = :id ORDER BY detector",
            id=file_id,
        )

    def metric(self, name: str, **labels: str) -> float:
        value = self.registry.get_sample_value(name, labels)
        return 0.0 if value is None else value


@pytest.fixture
async def rig(migrated_db: ScratchDatabase) -> AsyncIterator[Rig]:
    tenant_id = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id
    )
    owner = seed_user(migrated_db, tenant_id)
    clamd, inspector = FakeClamd(), FakeInspector()
    await clamd.start()
    await inspector.start()
    objects = FakeScanObjects()
    registry = CollectorRegistry()
    metrics = ScanMetrics.create(registry)
    database = Database.connect(migrated_db.url(SCAN), pool_size=2)
    engines = Engines("127.0.0.1", clamd.port, "127.0.0.1", inspector.port, connect_timeout=2)
    leases = Leases(None, Queue.SCAN_SMALL, 4, time.time)
    consumer = SmallScanConsumer(database, objects, engines, metrics, leases)
    try:
        yield Rig(
            migrated_db, objects, clamd, inspector, metrics, registry, consumer, tenant_id, owner
        )
    finally:
        await database.dispose()
        await clamd.stop()
        await inspector.stop()


def short_timeouts(monkeypatch: pytest.MonkeyPatch, seconds: float = 0.5) -> None:
    """A forced timeout: every engine gets `seconds`, whatever the size."""
    monkeypatch.setattr(
        scan_worker.scan_timing, "clamd_timeout", lambda size: timedelta(seconds=seconds)
    )
    monkeypatch.setattr(
        scan_worker.scan_timing, "inspector_timeout", lambda size: timedelta(seconds=seconds)
    )
    monkeypatch.setattr(scan_worker, "INSPECTOR_STALL", seconds / 2)


# ---- results (ADR-0019, abuse 6.4) ----


async def test_a_clean_file_is_clean_and_tagged_after_the_commit(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.scanning_file(transfer_id)
    seen_at_tagging: list[object] = []
    rig.objects.on_put = lambda: seen_at_tagging.append(rig.file(file_id)["state"])
    assert await rig.consumer.process(rig.delivery(file_id)) is Outcome.PROCESSED
    found = rig.file(file_id)
    assert (found["state"], found["engine"], found["inspection"]) == (
        "clean",
        "clamav",
        "inspected",
    )
    assert seen_at_tagging == ["clean"]  # the tag only after the result committed
    tags = rig.objects.tags[(rig.key(file_id), "v1")]
    assert tags == {"GuardDutyMalwareScanStatus": "x", "scan": "clean"}  # other tags kept
    assert rig.clamd.received == [DATA]
    assert rig.inspector.received == [DATA]
    assert rig.objects.reads == [(rig.key(file_id), "v1")]  # one read, both engines
    # The digest of that one read, the downloads' strong ETag (#180).
    assert rig.db.sql("SELECT sha256 FROM files WHERE id = :id", id=file_id) == [
        (hashlib.sha256(DATA).digest(),)
    ]
    assert actions(rig.db, file_id) == ["file.scanned"]
    # The last file of a submitted transfer sends it.
    assert transfer_row(rig.db, transfer_id)["state"] == "sent"
    assert rig.metric("scan_results_total", state="clean", reason="none") == 1


async def test_an_infected_file_holds_its_transfer_and_keeps_no_findings(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.scanning_file(transfer_id, b"zip:" + eicar() + DATA)
    rig.inspector.answer = result(
        engine_version="fake.1",
        state="inspected",
        reasons=[],
        findings=[finding("jp_my_number")],
    )
    assert await rig.consumer.process(rig.delivery(file_id)) is Outcome.PROCESSED
    found = rig.file(file_id)
    assert (found["state"], found["inspection"]) == ("infected", "skipped")
    assert rig.findings(file_id) == []
    assert rig.objects.tags[(rig.key(file_id), "v1")]["scan"] == "infected"
    row = transfer_row(rig.db, transfer_id)
    assert (row["state"], row["hold_reason"]) == ("held", "file_blocked")
    assert outbox_topics(rig.db, "transfer_id", transfer_id) == ["transfer.held"]


@pytest.mark.parametrize(("policy", "allowed"), [("block", False), ("allow_with_warning", True)])
async def test_unscannable_follows_the_policy_at_scan_time(
    rig: Rig, policy: str, allowed: bool
) -> None:
    rig.db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale, unscannable_policy) "
        "VALUES (:t, 'en', :p)",
        t=rig.tenant_id,
        p=policy,
    )
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.scanning_file(transfer_id, b"ENCRYPTED" + DATA)
    rig.inspector.answer = result(
        engine_version="fake.1", state="not_inspected", reasons=["encrypted"]
    )
    await rig.consumer.process(rig.delivery(file_id))
    found = rig.file(file_id)
    assert (found["state"], found["detail"], found["allowed"]) == (
        "unscannable",
        "encrypted",
        allowed,
    )
    assert transfer_row(rig.db, transfer_id)["state"] == ("sent" if allowed else "held")
    # A later change of policy never changes a scanned file (data model 3.1).
    rig.db.sql(
        "UPDATE tenant_policies SET unscannable_policy = 'block' WHERE tenant_id = :t",
        t=rig.tenant_id,
    )
    assert rig.file(file_id)["allowed"] is allowed


async def test_a_forced_timeout_on_every_attempt_ends_scan_failed_on_the_last(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    short_timeouts(monkeypatch)
    rig.clamd.answer = lambda data: None  # never answers
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.scanning_file(transfer_id)
    for attempt in range(1, 5):
        with pytest.raises(AttemptFailedError):
            await rig.consumer.process(rig.delivery(file_id, attempt))
        assert rig.file(file_id)["state"] == "scanning"
    # The 5th receive records it, before the message would reach the dead-letter queue.
    assert await rig.consumer.process(rig.delivery(file_id, 5)) is Outcome.PROCESSED
    found = rig.file(file_id)
    assert (found["state"], found["detail"], found["inspection"], found["tries"]) == (
        "scan_failed",
        "engine_error",
        "skipped",
        5,
    )
    assert transfer_row(rig.db, transfer_id)["state"] == "held"
    assert rig.metric("scan_results_total", state="scan_failed", reason="engine_error") == 1


async def test_a_duplicate_does_the_work_once(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id)
    delivery = rig.delivery(file_id)
    assert await rig.consumer.process(delivery) is Outcome.PROCESSED
    assert await rig.consumer.process(delivery) is Outcome.DUPLICATE
    assert actions(rig.db, file_id) == ["file.scanned"]
    assert len(rig.clamd.received) == 1


async def test_a_result_after_scan_failed_changes_nothing(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id)
    rig.db.sql(
        "UPDATE files SET state = 'scan_failed', scan_detail = 'deadline_passed' WHERE id = :id",
        id=file_id,
    )
    assert await rig.consumer.process(rig.delivery(file_id)) is Outcome.PROCESSED
    assert rig.file(file_id)["state"] == "scan_failed"
    assert rig.clamd.received == []  # never scanned again
    assert actions(rig.db, file_id) == []


async def test_the_recorded_version_is_scanned_never_the_latest(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id, version="recorded")
    rig.objects.put(rig.key(file_id), "latest", eicar())  # written after completion
    await rig.consumer.process(rig.delivery(file_id))
    assert rig.objects.reads == [(rig.key(file_id), "recorded")]
    assert rig.file(file_id)["state"] == "clean"


async def test_a_failed_tag_is_made_good_by_the_next_delivery(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.scanning_file(transfer_id)

    def fail() -> None:
        raise RuntimeError("S3 is down")

    rig.objects.on_put = fail
    delivery = rig.delivery(file_id)
    with pytest.raises(RuntimeError):
        await rig.consumer.process(delivery)
    assert rig.file(file_id)["state"] == "clean"
    assert transfer_row(rig.db, transfer_id)["state"] == "submitted"  # not before the tag
    rig.objects.on_put = None
    assert await rig.consumer.process(delivery) is Outcome.DUPLICATE
    assert rig.objects.tags[(rig.key(file_id), "v1")]["scan"] == "clean"
    assert transfer_row(rig.db, transfer_id)["state"] == "sent"


# ---- fairness (ADR-0019, abuse 6.4) ----


async def test_the_fifth_parallel_scan_of_a_tenant_is_deferred(
    rig: Rig, counter_store: CounterStore
) -> None:
    rig.consumer.leases = Leases(counter_store, Queue.SCAN_SMALL, 4, time.time)
    for n in range(4):  # four scans of this tenant already running
        assert await rig.consumer.leases.acquire(
            rig.tenant_id, f"running-{n}", timedelta(minutes=5)
        )
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id)
    delivery = rig.delivery(file_id)
    assert await rig.consumer.process(delivery) is Outcome.PROCESSED  # deleted, never put back
    assert rig.file(file_id)["state"] == "scanning"
    [(topic, delay)] = rig.db.sql(
        "SELECT topic, delay_seconds FROM outbox WHERE payload->>'file_id' = :id", id=str(file_id)
    )
    assert (topic, delay) == ("file.scan", 30)
    assert rig.metric("scan_deferrals_total") == 1
    # A redelivered copy doesn't defer it twice.
    assert await rig.consumer.process(delivery) is Outcome.DUPLICATE
    # Another tenant isn't held back by this one's cap.
    assert await rig.consumer.leases.acquire(uuid.uuid4(), "other", timedelta(minutes=5))
    # Once a running scan ends, the deferred one runs.
    await rig.consumer.leases.release(rig.tenant_id, "running-0")
    retry = rig.delivery(file_id)
    assert await rig.consumer.process(retry) is Outcome.PROCESSED
    assert rig.file(file_id)["state"] == "clean"


async def test_without_the_counter_store_the_cap_is_skipped(rig: Rig) -> None:
    store = CounterStore.connect(
        "redis://u:p@127.0.0.1:1/0", CounterMetrics.create(CollectorRegistry())
    )
    try:
        rig.consumer.leases = Leases(store, Queue.SCAN_SMALL, 1, time.time)
        transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
        file_id = rig.scanning_file(transfer_id)
        assert await rig.consumer.process(rig.delivery(file_id)) is Outcome.PROCESSED
        assert rig.file(file_id)["state"] == "clean"
    finally:
        await store.close()


# ---- the inspection in the same pass (#176) ----


async def test_findings_are_recorded_with_the_scan_and_dont_gate_sending(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.scanning_file(transfer_id)
    rig.inspector.answer = result(
        engine_version="2.banks-x",
        state="inspected",
        reasons=[],
        findings=[finding("jp_my_number", 2), finding("email_address", 1)],
    )
    await rig.consumer.process(rig.delivery(file_id))
    assert rig.findings(file_id) == [
        ("email_address", 0, 0, 1, None),
        ("jp_my_number", 0, 0, 2, None),
    ]
    assert rig.file(file_id)["version"] == "2.banks-x"
    assert transfer_row(rig.db, transfer_id)["state"] == "sent"  # no DLP gate before DLP-4
    [(details,)] = rig.db.sql("SELECT details FROM audit_events WHERE target_id = :id", id=file_id)
    assert details["jp_my_number_high"] == 2
    assert details["findings"] == 2
    assert rig.metric("dlp_inspection_results_total", state="inspected", reason="none") == 1


async def test_a_type_the_inspector_stops_early_still_reaches_clamd_in_full(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    data = b"\x89PNG\r\n\x1a\n" + bytes(300 * 1024)
    file_id = rig.scanning_file(transfer_id, data)
    rig.inspector.mode = "stop"
    await rig.consumer.process(rig.delivery(file_id))
    assert rig.clamd.received == [data]
    assert rig.inspector.received == [data[: 64 * 1024]]
    found = rig.file(file_id)
    assert (found["state"], found["inspection"], found["reasons"]) == (
        "clean",
        "not_inspected",
        ["unsupported_type"],
    )


@pytest.mark.parametrize(
    ("mode", "kind"), [("error", "engine_error"), ("malformed", "malformed"), ("close", "protocol")]
)
async def test_an_inspector_failing_every_attempt_blocks_the_file(
    rig: Rig, mode: str, kind: str
) -> None:
    rig.inspector.mode = mode  # type: ignore[assignment]
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.scanning_file(transfer_id)
    for attempt in range(1, 5):
        with pytest.raises(AttemptFailedError):
            await rig.consumer.process(rig.delivery(file_id, attempt))
    await rig.consumer.process(rig.delivery(file_id, 5))
    found = rig.file(file_id)
    assert (found["state"], found["inspection"]) == ("clean", "failed")
    assert rig.objects.tags[(rig.key(file_id), "v1")]["scan"] == "inspection_failed"
    assert transfer_row(rig.db, transfer_id)["state"] == "held"
    assert rig.metric("dlp_inspector_failures_total", kind=kind) == 5
    assert rig.metric("dlp_inspection_results_total", state="failed", reason="none") == 1


async def test_an_inspector_that_never_answers_ends_failed_not_scanning(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        scan_worker.scan_timing, "inspector_timeout", lambda size: timedelta(seconds=0.5)
    )
    rig.inspector.mode = "hang"
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id)
    await rig.consumer.process(rig.delivery(file_id, 5))
    assert rig.file(file_id)["inspection"] == "failed"
    assert rig.metric("dlp_inspector_failures_total", kind="timeout") == 1


async def test_too_many_previews_is_an_engine_error(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id)
    answer = result(engine_version="fake.1", state="inspected", reasons=[]).model_dump()
    answer["findings"] = [
        {
            "detector": "jp_my_number",
            "counts": {"low": 0, "medium": 0, "high": 1},
            "locations": [],
            "previews": ["x"] * 4,  # at most 3 (FR-53)
        }
    ]
    rig.inspector.mode = "malformed"
    rig.inspector.raw = answer
    with pytest.raises(AttemptFailedError):
        await rig.consumer.process(rig.delivery(file_id, 1))
    assert rig.metric("dlp_inspector_failures_total", kind="malformed") == 1


async def test_a_partial_file_is_shareable_and_keeps_its_findings(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner, state="submitted")
    file_id = rig.scanning_file(transfer_id)
    rig.inspector.answer = result(
        engine_version="fake.1",
        state="partial",
        reasons=["limit_exceeded"],
        findings=[finding("payment_card", 4)],
    )
    await rig.consumer.process(rig.delivery(file_id))
    found = rig.file(file_id)
    assert (found["inspection"], found["reasons"]) == ("partial", ["limit_exceeded"])
    assert rig.findings(file_id) == [("payment_card", 0, 0, 4, None)]
    assert transfer_row(rig.db, transfer_id)["state"] == "sent"
    assert rig.metric("dlp_inspection_results_total", state="partial", reason="limit_exceeded") == 1


async def test_a_failed_read_is_a_failed_attempt_for_both_engines(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id)
    rig.objects.failing = True
    with pytest.raises(AttemptFailedError):
        await rig.consumer.process(rig.delivery(file_id, 1))
    assert rig.metric("dlp_inspector_failures_total", kind="read") == 1


async def test_metric_labels_carry_no_detector_or_value(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id)
    rig.inspector.answer = result(
        engine_version="fake.1", state="inspected", reasons=[], findings=[finding("jp_my_number")]
    )
    await rig.consumer.process(rig.delivery(file_id))
    text = generate_latest(rig.registry).decode()
    assert "jp_my_number" not in text


async def test_a_file_over_2_gb_is_left_to_guardduty_and_the_sweep(rig: Rig) -> None:
    # A file.scan_large message from before #175 named files over 2 GB; ClamAV never reads them.
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = seed_file(
        rig.db, rig.tenant_id, transfer_id, size=3_000_000_000, storage_class="large"
    )
    assert await rig.consumer.process(rig.delivery(file_id)) is Outcome.PROCESSED
    assert rig.file(file_id)["state"] == "scanning"
    assert rig.objects.reads == []


async def test_a_late_copy_for_a_deleted_object_finishes_quietly(rig: Rig) -> None:
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = seed_file(rig.db, rig.tenant_id, transfer_id, state="clean")  # no object any more

    async def gone(*args: object) -> dict[str, str]:
        raise ObjectStoreError("NoSuchVersion")

    rig.objects.object_tags = gone  # type: ignore[method-assign]
    assert await rig.consumer.process(rig.delivery(file_id)) is Outcome.PROCESSED


# ---- review fixes (#175, #176) ----


async def test_a_slow_inspector_doesnt_make_clamd_time_out(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    # clamd's timeout assumes it reads alone: the read must not follow the inspector's pace.
    monkeypatch.setattr(scan_worker.scan_timing, "clamd_timeout", lambda size: timedelta(seconds=1))
    monkeypatch.setattr(scan_worker, "INSPECTOR_STALL", 0.5)
    monkeypatch.setattr(scan_worker, "INSPECTOR_BUFFER", 1000)
    rig.inspector.mode = "slow"
    rig.inspector.pace = 0.1  # 2 MB in 64 KiB reads: about 3 s, well past clamd's timeout
    data = bytes(2 * 1024 * 1024)
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id, data)
    assert await rig.consumer.process(rig.delivery(file_id)) is Outcome.PROCESSED
    found = rig.file(file_id)
    assert (found["state"], found["inspection"]) == ("clean", "inspected")
    assert rig.clamd.received == [data]
    assert rig.inspector.received == [data]


async def test_a_stalled_inspector_is_dropped_and_clamd_reads_on(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_worker.scan_timing, "clamd_timeout", lambda size: timedelta(seconds=1))
    monkeypatch.setattr(scan_worker, "INSPECTOR_STALL", 0.3)
    monkeypatch.setattr(scan_worker, "INSPECTOR_BUFFER", 4)
    rig.inspector.mode = "stall"  # asks for the rest, then never reads it
    data = bytes(16 * 1024 * 1024)  # past the socket buffers, so the inspector's lane fills
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id, data)
    with pytest.raises(AttemptFailedError):  # the inspection failed this attempt...
        await rig.consumer.process(rig.delivery(file_id, 1))
    assert rig.clamd.received == [data]  # ...but clamd had every byte, in time
    assert rig.metric("dlp_inspector_failures_total", kind="timeout") == 1
    await rig.consumer.process(rig.delivery(file_id, 5))
    found = rig.file(file_id)
    assert (found["state"], found["inspection"]) == ("clean", "failed")  # never scan_failed


async def test_two_copies_of_a_scan_hold_two_leases(rig: Rig, counter_store: CounterStore) -> None:
    rig.consumer.leases = Leases(counter_store, Queue.SCAN_SMALL, 4, time.time)
    rig.clamd.delay = 0.5
    transfer_id, _ = seed_transfer(rig.db, rig.tenant_id, rig.owner)
    file_id = rig.scanning_file(transfer_id)
    key = f"scan:scan-small:{rig.tenant_id}"
    held: list[int] = []

    async def watch() -> None:
        await asyncio.sleep(0.3)  # both copies are scanning now
        held.append(await counter_store._client.zcard(key))

    await asyncio.gather(
        rig.consumer.process(rig.delivery(file_id)),
        rig.consumer.process(rig.delivery(file_id)),
        watch(),
    )
    assert held == [2]  # one lease each: the first to finish can't end the other's
    assert await counter_store._client.zcard(key) == 0


def test_the_worker_waits_out_a_long_poll() -> None:
    # Found by `make up`: a 3 s read timeout cut every 20 s long poll short.
    settings = ScanSettings(
        scan_pool="small",
        database_url="postgresql://sft_scan@127.0.0.1/sft",
        sqs_queue_prefix="sft-local-",
        s3_files_bucket="sft-local-files",
        s3_large_files_bucket="sft-local-large-files",
    )
    queues = scan_queues(settings)
    assert queues._client.meta.config.read_timeout > LONG_POLL_SECONDS
