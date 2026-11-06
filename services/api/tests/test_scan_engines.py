"""The scan worker against the real engines (#175, #176; ADR-0019, ADR-0022; abuse and rate limits
6.4, 6.5, 9.2).

- **clamd**, as the local stack runs it (`TEST_CLAMD_URL`, such as `tcp://127.0.0.1:3310`, with
  local/clamav/clamd.conf): a clean file is clean; the EICAR test file inside a nested archive is
  infected; an encrypted archive and zip bombs (too deep, too many files) are unscannable, never
  clean. Skipped without it; CI's scan job sets it.
- **The DLP inspector**, the real one with the real detectors in its sandbox, which needs Linux
  (seccomp): a synthetic My Number is found and counted at its confidence, and no matched value
  reaches the database, the logs, the metrics, the outbox or the audit trail (NFR-26).

The EICAR file is built in code (scan_fixtures.eicar), never kept as a file.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from prometheus_client import CollectorRegistry, generate_latest

import dlp_fixtures as fx
from member_fixtures import seed_user
from pg import ScratchDatabase
from scan_fixtures import FakeClamd, FakeInspector, FakeScanObjects, eicar
from sft.core.ids import uuid7
from sft.data.database import Database
from sft.data.outbox import OutboxMessage, Queue
from sft.data.roles import SCAN
from sft.dlp.detect.checks import my_number_check_digit
from sft.dlp.engine import load_engine
from sft.dlp.inspector import Inspector
from sft.workers.clamd import Verdict, instream
from sft.workers.consumer import Delivery
from sft.workers.scan import Engines, Leases, ScanMetrics, SmallScanConsumer
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio

CLAMD_URL = "TEST_CLAMD_URL"


def clamd_address() -> tuple[str, int]:
    raw = os.environ.get(CLAMD_URL)
    if not raw:
        if os.environ.get("CI_SCAN_ENGINES"):
            pytest.fail(f"{CLAMD_URL} must be set in CI's scan job")
        pytest.skip(f"set {CLAMD_URL} to the local stack's clamd, e.g. tcp://127.0.0.1:3310")
    parts = urlsplit(raw)
    return parts.hostname or "127.0.0.1", parts.port or 3310


async def chunks(data: bytes) -> AsyncIterator[bytes]:
    for start in range(0, len(data), 64 * 1024):
        yield data[start : start + 64 * 1024]


def encrypted_zip() -> bytes:
    return fx.encrypt_flag(fx.zip_bytes({"secret.txt": "nothing to see " * 100}), "secret.txt")


CORPUS: dict[str, tuple[Callable[[], bytes], Verdict]] = {
    "clean": (lambda: b"a perfectly ordinary report\n" * 1000, Verdict.CLEAN),
    "eicar_nested": (lambda: fx.nested_zip(3, eicar()), Verdict.INFECTED),
    "encrypted_archive": (encrypted_zip, Verdict.ENCRYPTED),
    "bomb_too_deep": (lambda: fx.nested_zip(12, b"deep"), Verdict.LIMIT_EXCEEDED),
    "bomb_too_many_files": (lambda: fx.many_members(10_050), Verdict.LIMIT_EXCEEDED),
}


@pytest.mark.parametrize("name", list(CORPUS))
async def test_clamd_answers_as_adr_0019_maps_them(name: str) -> None:
    host, port = clamd_address()
    make, expected = CORPUS[name]
    result = await instream(host, port, chunks(make()), connect_timeout=5)
    assert result.verdict is expected, result.signature


# ---- the worker, end to end against real engines ----


def seeded(
    db: ScratchDatabase, data: bytes, objects: FakeScanObjects
) -> tuple[uuid.UUID, uuid.UUID]:
    tenant_id = uuid.uuid4()
    db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id)
    transfer_id, _ = seed_transfer(db, tenant_id, seed_user(db, tenant_id), state="submitted")
    file_id = seed_file(db, tenant_id, transfer_id, size=len(data))
    objects.put(f"tenants/{tenant_id}/files/{file_id}", "version-1", data)
    return tenant_id, file_id


def delivery(tenant_id: uuid.UUID, file_id: uuid.UUID) -> Delivery:
    return Delivery(OutboxMessage(uuid7(), "file.scan", tenant_id, {"file_id": file_id}))


@pytest.mark.parametrize(
    ("name", "state", "detail"),
    [
        ("clean", "clean", None),
        ("eicar_nested", "infected", None),
        ("encrypted_archive", "unscannable", "encrypted"),
        ("bomb_too_deep", "unscannable", "limit_exceeded"),
        ("bomb_too_many_files", "unscannable", "limit_exceeded"),
    ],
)
async def test_the_worker_records_clamds_results(
    migrated_db: ScratchDatabase, name: str, state: str, detail: str | None
) -> None:
    host, port = clamd_address()
    objects = FakeScanObjects()
    tenant_id, file_id = seeded(migrated_db, CORPUS[name][0](), objects)
    inspector = FakeInspector()
    await inspector.start()
    database = Database.connect(migrated_db.url(SCAN), pool_size=2)
    try:
        consumer = SmallScanConsumer(
            database,
            objects,
            Engines(host, port, "127.0.0.1", inspector.port),
            ScanMetrics.create(CollectorRegistry()),
            Leases(None, Queue.SCAN_SMALL, 4, time.time),
        )
        await consumer.process(delivery(tenant_id, file_id))
    finally:
        await database.dispose()
        await inspector.stop()
    [row] = migrated_db.sql("SELECT state, scan_detail FROM files WHERE id = :id", id=file_id)
    assert row == (state, detail)


# ---- the real inspector, in its sandbox (Linux) ----

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="the sandbox is Linux only")


def my_number(seed: int) -> str:
    """A synthetic My Number with a valid check digit (detectors 4.1), never a real one."""
    first = f"{seed:011d}"
    return first + str(my_number_check_digit(first))


@pytest.fixture
def real_inspector(tmp_path: Path) -> Iterator[int]:
    """The inspector process's loop, in a thread, on a port of its own: one file per connection."""
    inspector = Inspector(scratch_root=tmp_path, engine=load_engine(), io_timeout=60)
    listener = socket.create_server(("127.0.0.1", 0))
    stop = threading.Event()

    def serve() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            with conn:
                inspector.handle(conn)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield listener.getsockname()[1]
    stop.set()
    thread.join(timeout=10)
    listener.close()


@linux_only
async def test_a_synthetic_my_number_is_found_counted_and_never_stored(
    migrated_db: ScratchDatabase,
    real_inspector: int,
    json_logs: Callable[[], list[dict[str, object]]],
) -> None:
    canary = my_number(31415926535)
    text = f"社員名簿\nマイナンバー: {canary}\n個人番号カードの写しは別途\n"
    data = fx.docx([text])
    objects = FakeScanObjects()
    tenant_id, file_id = seeded(migrated_db, data, objects)
    clamd = FakeClamd()
    await clamd.start()
    registry = CollectorRegistry()
    database = Database.connect(migrated_db.url(SCAN), pool_size=2)
    try:
        consumer = SmallScanConsumer(
            database,
            objects,
            Engines("127.0.0.1", clamd.port, "127.0.0.1", real_inspector, connect_timeout=5),
            ScanMetrics.create(registry),
            Leases(None, Queue.SCAN_SMALL, 4, time.time),
        )
        await consumer.process(delivery(tenant_id, file_id))
    finally:
        await database.dispose()
        await clamd.stop()
    [row] = migrated_db.sql("SELECT state, inspection_state FROM files WHERE id = :id", id=file_id)
    assert row == ("clean", "inspected")
    found = migrated_db.sql(
        "SELECT detector, count_low, count_medium, count_high FROM dlp_findings "
        "WHERE file_id = :id",
        id=file_id,
    )
    assert ("jp_my_number", 0, 0, 1) in found  # one value, at high confidence with context
    # The canary: the matched value is nowhere (NFR-26).
    dump = migrated_db.sql(
        "SELECT string_agg(to_jsonb(x)::text, '') FROM (SELECT * FROM files) x "
        "UNION ALL SELECT string_agg(to_jsonb(x)::text, '') FROM (SELECT * FROM dlp_findings) x "
        "UNION ALL SELECT string_agg(to_jsonb(x)::text, '') FROM (SELECT * FROM outbox) x "
        "UNION ALL SELECT string_agg(to_jsonb(x)::text, '') FROM (SELECT * FROM audit_events) x"
    )
    assert all(canary not in str(part) for (part,) in dump)
    assert canary not in str(json_logs())
    assert canary not in generate_latest(registry).decode()


@linux_only
async def test_the_inspector_and_clamd_read_the_bytes_once_together(
    migrated_db: ScratchDatabase, real_inspector: int
) -> None:
    host, port = clamd_address()
    data = b"\x89PNG\r\n\x1a\n" + bytes(512 * 1024)  # a type the inspector stops early on
    objects = FakeScanObjects()
    tenant_id, file_id = seeded(migrated_db, data, objects)
    database = Database.connect(migrated_db.url(SCAN), pool_size=2)
    try:
        consumer = SmallScanConsumer(
            database,
            objects,
            Engines(host, port, "127.0.0.1", real_inspector),
            ScanMetrics.create(CollectorRegistry()),
            Leases(None, Queue.SCAN_SMALL, 4, time.time),
        )
        await consumer.process(delivery(tenant_id, file_id))
    finally:
        await database.dispose()
    assert len(objects.reads) == 1
    [row] = migrated_db.sql(
        "SELECT state, inspection_state, inspection_reasons FROM files WHERE id = :id", id=file_id
    )
    assert row == ("clean", "not_inspected", ["unsupported_type"])
