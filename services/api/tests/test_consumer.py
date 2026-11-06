"""The idempotent consumer base, against real PostgreSQL as the scan worker's role.

The acceptance test of #51: a duplicate message is processed once. The handler here does what a
deferring scan worker does (ADR-0013): it writes a new, delayed outbox row in the transaction.
"""

import asyncio
import contextlib
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from prometheus_client import CollectorRegistry
from sqlalchemy import insert, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from messaging import FakeQueues, Sent, clear_messaging, pool
from pg import ScratchDatabase
from sft.data.access import ScopeNotAllowedError
from sft.data.database import Database
from sft.data.models import ProcessedMessage
from sft.data.outbox import OutboxMessage, Queue, Topic, enqueue, topic_registry
from sft.data.processed import record_processed
from sft.data.roles import API, RELAY, SCAN
from sft.data.scope import Scope
from sft.workers.consumer import (
    Consumer,
    ConsumerLoop,
    ConsumerMetrics,
    Delivery,
    Outcome,
)
from sft.workers.queues import OutgoingMessage, QueueError
from sft.workers.relay import Relay, RelayMetrics

pytestmark = pytest.mark.anyio

SCAN_TOPIC = Topic("file.scan", Queue.SCAN_SMALL)
DEFERRED = Topic("file.scan_deferred", Queue.SCAN_SMALL)
INSUFFICIENT_PRIVILEGE = "42501"


class DeferringConsumer(Consumer):
    """Defers each scan by writing a new delayed message, as the scan worker does over its cap."""

    name = "test-scan"
    queue = Queue.SCAN_SMALL

    def __init__(self, database: Database, *, pause: float = 0, fail: int = 0) -> None:
        super().__init__(database)
        self.pause = pause
        self.fail = fail
        self.calls: list[Delivery] = []

    async def handle(self, session: AsyncSession, delivery: Delivery) -> None:
        self.calls.append(delivery)
        await enqueue(
            session, DEFERRED, dict(delivery.message.payload), delay=timedelta(seconds=30)
        )
        await asyncio.sleep(self.pause)
        if self.fail:
            self.fail -= 1
            raise RuntimeError("the scan engine is down")


@pytest.fixture
def outbox_db(migrated_db: ScratchDatabase) -> ScratchDatabase:
    clear_messaging(migrated_db)
    return migrated_db


@pytest.fixture
async def scan_db(outbox_db: ScratchDatabase) -> AsyncIterator[Database]:
    async with pool(outbox_db, SCAN, size=2) as database:
        yield database


def a_message(tenant_id: uuid.UUID | None = None) -> OutboxMessage:
    return OutboxMessage(
        id=uuid.uuid4(),
        topic=SCAN_TOPIC.name,
        tenant_id=tenant_id or uuid.uuid4(),
        payload={"file_id": uuid.uuid4()},
    )


def effects(db: ScratchDatabase) -> list[tuple[object, ...]]:
    return db.sql("SELECT tenant_id, topic, delay_seconds FROM outbox ORDER BY created_at")


def records(db: ScratchDatabase) -> list[tuple[object, ...]]:
    return db.sql("SELECT consumer, message_id, tenant_id FROM processed_messages")


# ---- acceptance: a duplicate message is processed once ----


async def test_a_duplicate_message_is_processed_once(
    outbox_db: ScratchDatabase, scan_db: Database
) -> None:
    consumer = DeferringConsumer(scan_db)
    message = a_message()
    assert await consumer.process(Delivery(message)) == Outcome.PROCESSED
    assert await consumer.process(Delivery(message, receive_count=2)) == Outcome.DUPLICATE
    assert len(consumer.calls) == 1
    assert effects(outbox_db) == [(message.tenant_id, DEFERRED.name, 30)]
    assert records(outbox_db) == [("test-scan", str(message.id), message.tenant_id)]


async def test_two_copies_handled_at_the_same_time_are_processed_once(
    outbox_db: ScratchDatabase, scan_db: Database
) -> None:
    # Two worker replicas receive the same message at once. The second waits on the first's
    # record and, once the first commits, skips.
    consumer = DeferringConsumer(scan_db, pause=0.3)
    message = a_message()
    outcomes = await asyncio.gather(
        consumer.process(Delivery(message)), consumer.process(Delivery(message))
    )
    assert sorted(outcomes) == [Outcome.DUPLICATE, Outcome.PROCESSED]
    assert len(effects(outbox_db)) == 1


async def test_a_failed_attempt_leaves_no_record_and_no_effect(
    outbox_db: ScratchDatabase, scan_db: Database
) -> None:
    consumer = DeferringConsumer(scan_db, fail=1)
    message = a_message()
    with pytest.raises(RuntimeError, match="scan engine"):
        await consumer.process(Delivery(message))
    assert effects(outbox_db) == []
    assert records(outbox_db) == []
    # SQS delivers it again, and this time it is processed.
    assert await consumer.process(Delivery(message, receive_count=2)) == Outcome.PROCESSED
    assert len(effects(outbox_db)) == 1


async def test_each_consumer_keeps_its_own_records(
    outbox_db: ScratchDatabase, scan_db: Database
) -> None:
    class OtherConsumer(DeferringConsumer):
        name = "test-other"

    message = a_message()
    assert await DeferringConsumer(scan_db).process(Delivery(message)) == Outcome.PROCESSED
    assert await OtherConsumer(scan_db).process(Delivery(message)) == Outcome.PROCESSED
    assert len(records(outbox_db)) == 2


async def test_a_record_needs_the_messages_tenant_scope(
    outbox_db: ScratchDatabase, scan_db: Database
) -> None:
    # A consumer's role opens nothing but tenant scope (sft.data.access)…
    with pytest.raises(ScopeNotAllowedError, match="never opens a system scope"):
        async with scan_db.transaction(Scope.system()) as session:
            await record_processed(session, consumer="test-scan", message_id="m")
    # …and in a scope with no tenant there is nothing to record a message for.
    async with pool(outbox_db, API) as api:
        with pytest.raises(ScopeNotAllowedError, match="writes no tenant rows"):
            async with api.transaction(Scope.platform()) as session:
                await record_processed(session, consumer="test-scan", message_id="m")


async def test_a_consumer_cannot_record_or_read_another_tenants_messages(
    scan_db: Database,
) -> None:
    with pytest.raises(DBAPIError, match="row-level security"):
        async with scan_db.transaction(Scope.tenant(uuid.uuid4())) as session:
            await session.execute(
                insert(ProcessedMessage).values(
                    consumer="test-scan", message_id="m", tenant_id=uuid.uuid4()
                )
            )
    with pytest.raises(DBAPIError) as caught:
        async with scan_db.transaction(Scope.tenant(uuid.uuid4())) as session:
            await session.execute(select(ProcessedMessage.message_id))
    assert caught.value.orig.sqlstate == INSUFFICIENT_PRIVILEGE  # type: ignore[union-attr]


# ---- the loop ----


@pytest.fixture
def metrics() -> ConsumerMetrics:
    return ConsumerMetrics.create(CollectorRegistry())


def deliver(queues: FakeQueues, *bodies: str) -> None:
    for body in bodies:
        queues.sent.append(Sent("scan-small", OutgoingMessage("x", body)))


async def test_the_loop_deletes_what_it_processed_or_skipped(
    outbox_db: ScratchDatabase, scan_db: Database, metrics: ConsumerMetrics
) -> None:
    queues = FakeQueues()
    message = a_message()
    deliver(queues, message.body(), message.body())
    loop = ConsumerLoop(DeferringConsumer(scan_db), queues, metrics)
    assert await loop.poll_once() == [Outcome.PROCESSED, Outcome.DUPLICATE]
    assert queues.deleted == ["0", "1"]
    assert len(effects(outbox_db)) == 1
    counted = metrics.messages.labels("test-scan", "duplicate")._value.get()
    assert counted == 1


async def test_the_loop_leaves_a_failed_message_for_sqs_to_deliver_again(
    outbox_db: ScratchDatabase, scan_db: Database, metrics: ConsumerMetrics, json_logs: object
) -> None:
    queues = FakeQueues()
    deliver(queues, a_message().body())
    consumer = DeferringConsumer(scan_db, fail=1)
    loop = ConsumerLoop(consumer, queues, metrics)
    assert await loop.poll_once() == [Outcome.FAILED]
    assert queues.deleted == []
    # Visibility timeout over: the second delivery, with its receive count, succeeds.
    assert await loop.poll_once() == [Outcome.PROCESSED]
    assert [d.receive_count for d in consumer.calls] == [1, 2]
    assert queues.deleted == ["0"]
    failed = [line for line in json_logs() if line["msg"].startswith("message failed")]  # type: ignore[operator]
    assert failed
    assert failed[0]["receive_count"] == 1


async def test_the_loop_never_deletes_an_invalid_message(
    scan_db: Database, metrics: ConsumerMetrics
) -> None:
    queues = FakeQueues()
    deliver(queues, '{"id": "not a message"}')
    loop = ConsumerLoop(DeferringConsumer(scan_db), queues, metrics)
    assert await loop.poll_once() == [Outcome.INVALID]
    assert queues.deleted == []


async def test_the_loop_runs_until_stopped_and_survives_receive_errors(
    scan_db: Database, metrics: ConsumerMetrics, json_logs: object
) -> None:
    queues = FakeQueues(outage="ServiceUnavailable")
    loop = ConsumerLoop(DeferringConsumer(scan_db), queues, metrics, wait_seconds=0)
    stopping = asyncio.Event()
    task = asyncio.create_task(loop.run(stopping))
    await asyncio.sleep(0.1)
    stopping.set()
    await asyncio.wait_for(task, timeout=5)
    assert any(line["msg"] == "receive failed; trying again" for line in json_logs())  # type: ignore[operator]


async def test_the_trace_id_from_the_message_is_on_the_handlers_log_lines(
    scan_db: Database, metrics: ConsumerMetrics, json_logs: object
) -> None:
    queues = FakeQueues()
    message = a_message()
    traceparent = f"00-{'ef' * 16}-{'01' * 8}-01"
    deliver(
        queues,
        OutboxMessage(
            message.id,
            message.topic,
            message.tenant_id,
            message.payload,
            {"traceparent": traceparent},
        ).body(),
    )
    await ConsumerLoop(DeferringConsumer(scan_db), queues, metrics).poll_once()
    [line] = [line for line in json_logs() if line["msg"] == "message processed"]  # type: ignore[operator]
    assert line["trace_id"] == "ef" * 16
    assert line["outbox_id"] == str(message.id)


# ---- end to end: relay crash, duplicate send, one effect ----


async def test_a_relay_crash_and_its_duplicate_send_still_give_one_effect(
    outbox_db: ScratchDatabase, scan_db: Database, metrics: ConsumerMetrics
) -> None:
    async with pool(outbox_db, API) as api, api.transaction(Scope.tenant(uuid.uuid4())) as session:
        original = await enqueue(session, SCAN_TOPIC, {"file_id": uuid.uuid4()})
    queues = FakeQueues()
    topics = topic_registry(SCAN_TOPIC, DEFERRED)

    def crash() -> None:
        queues.after_send = None
        outbox_db.sql(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE usename = :role AND datname = current_database()",
            role=RELAY,
        )

    queues.after_send = crash
    for _ in range(2):  # the first relay dies after its send; the second sends again
        async with pool(outbox_db, RELAY) as relay_db:
            relay = Relay(relay_db, queues, RelayMetrics.create(CollectorRegistry()), topics=topics)
            with contextlib.suppress(Exception):  # the first one's crash
                await relay.publish_batch()
    assert [OutboxMessage.from_body(b).id for b in queues.bodies()] == [original, original]

    consumer = DeferringConsumer(scan_db)
    outcomes = await ConsumerLoop(consumer, queues, metrics).poll_once()
    assert outcomes == [Outcome.PROCESSED, Outcome.DUPLICATE]
    assert len(consumer.calls) == 1
    assert [row[1] for row in effects(outbox_db)] == [SCAN_TOPIC.name, DEFERRED.name]


# ---- the code review of #51 ----


async def test_a_failed_delete_does_not_stop_the_other_messages(
    outbox_db: ScratchDatabase, scan_db: Database, metrics: ConsumerMetrics
) -> None:
    queues = FakeQueues()
    deliver(queues, a_message().body(), a_message().body())
    queues.fail_delete.add("0")
    consumer = DeferringConsumer(scan_db)
    outcomes = await ConsumerLoop(consumer, queues, metrics).poll_once()
    assert outcomes == [Outcome.PROCESSED, Outcome.PROCESSED]
    assert queues.deleted == ["1"]


async def test_a_body_nested_too_deep_is_invalid_not_a_crash(
    scan_db: Database, metrics: ConsumerMetrics
) -> None:
    queues = FakeQueues()
    deliver(queues, "[" * 100_000, a_message().body())
    outcomes = await ConsumerLoop(DeferringConsumer(scan_db), queues, metrics).poll_once()
    assert outcomes == [Outcome.INVALID, Outcome.PROCESSED]


async def test_an_unexpected_error_fails_one_message_not_the_loop(
    outbox_db: ScratchDatabase, scan_db: Database, metrics: ConsumerMetrics
) -> None:
    class Exploding(DeferringConsumer):
        async def process(self, delivery: Delivery) -> Outcome:
            raise RecursionError("too deep")

    queues = FakeQueues()
    deliver(queues, a_message().body())
    assert await ConsumerLoop(Exploding(scan_db), queues, metrics).poll_once() == [Outcome.FAILED]
    assert queues.deleted == []


async def test_shutdown_abandons_a_long_poll_at_once(
    scan_db: Database, metrics: ConsumerMetrics
) -> None:
    class SlowQueues(FakeQueues):
        async def receive(self, queue, *, max_messages, wait_seconds):  # type: ignore[no-untyped-def]
            await asyncio.sleep(3600)  # a 20 s long poll, or a hung one
            return []

    loop = ConsumerLoop(DeferringConsumer(scan_db), SlowQueues(), metrics)
    stopping = asyncio.Event()
    task = asyncio.create_task(loop.run(stopping))
    await asyncio.sleep(0.1)
    stopping.set()
    await asyncio.wait_for(task, timeout=1)


async def test_a_long_message_is_kept_hidden_while_it_is_worked_on(
    outbox_db: ScratchDatabase, scan_db: Database, metrics: ConsumerMetrics
) -> None:
    # The scan worker's heartbeat: a scan may outlast the queue's visibility timeout (#175).
    queues = FakeQueues()
    deliver(queues, a_message().body())
    loop = ConsumerLoop(DeferringConsumer(scan_db, pause=0.25), queues, metrics)
    loop.heartbeat_seconds = 0.1  # type: ignore[assignment]
    assert await loop.poll_once() == [Outcome.PROCESSED]
    assert queues.extended
    assert {handle for handle, _ in queues.extended} == {"0"}
    count = len(queues.extended)
    await asyncio.sleep(0.25)
    assert len(queues.extended) == count  # the heartbeat stops with the message


async def test_a_failed_extension_is_only_logged(
    outbox_db: ScratchDatabase, scan_db: Database, metrics: ConsumerMetrics, json_logs: object
) -> None:
    queues = FakeQueues()
    deliver(queues, a_message().body())

    class Flaky(FakeQueues):
        async def extend_visibility(self, queue: str, receipt_handle: str, seconds: int) -> None:
            raise QueueError("ReceiptHandleIsInvalid")

    flaky = Flaky(sent=queues.sent)
    loop = ConsumerLoop(DeferringConsumer(scan_db, pause=0.25), flaky, metrics)
    loop.heartbeat_seconds = 0.1  # type: ignore[assignment]
    assert await loop.poll_once() == [Outcome.PROCESSED]
    logged = [line["msg"] for line in json_logs()]  # type: ignore[operator]
    assert any("visibility not extended" in str(msg) for msg in logged)
