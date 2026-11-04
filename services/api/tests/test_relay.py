"""The outbox relay, against real PostgreSQL and an in-memory SQS (`messaging.FakeQueues`).

The acceptance test of #51: a crash between the database write and the publish loses nothing.
"""

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from prometheus_client import CollectorRegistry

from messaging import FakeQueues, clear_messaging, pool
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.outbox import OutboxMessage, Queue, Topic, enqueue, topic_registry
from sft.data.roles import API, RELAY
from sft.data.scope import Scope
from sft.workers.relay import (
    ERROR_PAUSE_SECONDS,
    RETRY_MAX_SECONDS,
    Relay,
    RelayMetrics,
    retry_delay,
)

pytestmark = pytest.mark.anyio

SCAN = Topic("file.scan", Queue.SCAN_SMALL)
NOTIFY = Topic("transfer.notify", Queue.NOTIFY)
TOPICS = topic_registry(SCAN, NOTIFY)


@pytest.fixture
def outbox_db(migrated_db: ScratchDatabase) -> ScratchDatabase:
    clear_messaging(migrated_db)
    return migrated_db


@pytest.fixture
async def relay_db(outbox_db: ScratchDatabase) -> AsyncIterator[Database]:
    async with pool(outbox_db, RELAY) as database:
        yield database


@pytest.fixture
def queues() -> FakeQueues:
    return FakeQueues()


@pytest.fixture
def registry() -> CollectorRegistry:
    return CollectorRegistry()


def make_relay(
    database: Database, queues: FakeQueues, registry: CollectorRegistry, **options: object
) -> Relay:
    return Relay(database, queues, RelayMetrics.create(registry), topics=TOPICS, **options)  # type: ignore[arg-type]


async def write(
    db: ScratchDatabase,
    topic: Topic = SCAN,
    *,
    tenant_id: uuid.UUID | None = None,
    delay: timedelta = timedelta(0),
) -> uuid.UUID:
    """As a service function does: a message in the tenant's transaction."""
    async with (
        pool(db, API) as api,
        api.transaction(Scope.tenant(tenant_id or uuid.uuid4())) as session,
    ):
        return await enqueue(session, topic, {"file_id": uuid.uuid4()}, delay=delay)


def unpublished(db: ScratchDatabase) -> set[object]:
    return {row[0] for row in db.sql("SELECT id FROM outbox WHERE published_at IS NULL")}


def sent_ids(queues: FakeQueues) -> list[uuid.UUID]:
    return [OutboxMessage.from_body(body).id for body in queues.bodies()]


async def test_a_batch_sends_every_due_row_and_marks_it_published(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    tenant_id = uuid.uuid4()
    scan_id = await write(outbox_db, SCAN, tenant_id=tenant_id)
    notify_id = await write(outbox_db, NOTIFY, tenant_id=tenant_id)
    relay = make_relay(relay_db, queues, registry)

    assert await relay.publish_batch() == 2
    assert unpublished(outbox_db) == set()
    by_queue = {s.queue: s.message for s in queues.sent}
    assert set(by_queue) == {"scan-small", "notify"}
    scan = by_queue["scan-small"]
    assert scan.id == str(scan_id)
    assert scan.group_id == str(tenant_id)  # a fair queue: the tenant is the message group
    assert by_queue["notify"].group_id is None
    message = OutboxMessage.from_body(scan.body)
    assert (message.id, message.topic, message.tenant_id) == (scan_id, "file.scan", tenant_id)
    assert OutboxMessage.from_body(by_queue["notify"].body).id == notify_id
    assert (
        registry.get_sample_value("outbox_messages_published_total", {"queue": "scan-small"}) == 1
    )
    assert registry.get_sample_value("outbox_oldest_unpublished_age_seconds") == 0
    # Nothing left: the next batch claims nothing and sends nothing.
    assert await relay.publish_batch() == 0
    assert len(queues.sent) == 2


async def test_rows_go_out_oldest_first_in_batches_of_at_most_ten(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    written = [await write(outbox_db) for _ in range(23)]
    relay = make_relay(relay_db, queues, registry, batch_size=20)
    assert await relay.publish_batch() == 20
    assert await relay.publish_batch() == 3
    assert sent_ids(queues) == written


async def test_a_delayed_row_is_sent_at_once_with_the_delay_that_is_left(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    await write(outbox_db, delay=timedelta(seconds=30))
    await write(outbox_db, delay=timedelta(seconds=30))
    # The second row has waited 20 s in the outbox already (the relay was down, say).
    outbox_db.sql(
        "UPDATE outbox SET created_at = created_at - interval '20 seconds' "
        "WHERE id = (SELECT id FROM outbox ORDER BY id DESC LIMIT 1)"
    )
    await make_relay(relay_db, queues, registry).publish_batch()
    delays = sorted(s.message.delay_seconds for s in queues.sent)
    assert delays[0] in (10, 11)
    assert delays[1] in (29, 30)


async def test_a_row_past_its_delay_is_sent_without_one(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    await write(outbox_db, delay=timedelta(seconds=30))
    outbox_db.sql("UPDATE outbox SET created_at = created_at - interval '5 minutes'")
    await make_relay(relay_db, queues, registry).publish_batch()
    assert queues.sent[0].message.delay_seconds == 0


async def test_a_refused_row_backs_off_and_does_not_hold_up_the_others(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    refused = await write(outbox_db)
    accepted = await write(outbox_db)
    queues.refuse[str(refused)] = "InvalidParameterValue"
    relay = make_relay(relay_db, queues, registry)

    assert await relay.publish_batch() == 2
    assert sent_ids(queues) == [accepted]
    [(attempts, error, wait)] = outbox_db.sql(
        "SELECT attempts, last_error, extract(epoch FROM next_attempt_at - now()) FROM outbox "
        "WHERE id = :id",
        id=refused,
    )
    assert (attempts, error) == (1, "InvalidParameterValue")
    assert 0.5 < float(wait) <= 2  # type: ignore[arg-type]
    assert registry.get_sample_value("outbox_publish_failures_total", {"queue": "scan-small"}) == 1
    # Not due yet: the next batch leaves it alone.
    assert await relay.publish_batch() == 0
    # Once due, it is tried again and goes out.
    outbox_db.sql("UPDATE outbox SET next_attempt_at = now()")
    del queues.refuse[str(refused)]
    assert await relay.publish_batch() == 1
    assert unpublished(outbox_db) == set()


async def test_a_batch_refused_for_one_bad_row_is_sent_row_by_row(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    good = [await write(outbox_db) for _ in range(3)]
    bad = await write(outbox_db)
    queues.poison.add(str(bad))
    assert await make_relay(relay_db, queues, registry).publish_batch() == 4
    assert sorted(sent_ids(queues)) == sorted(good)
    assert unpublished(outbox_db) == {bad}
    assert queues.calls == 5  # the batch, then each of its rows
    [(error,)] = outbox_db.sql("SELECT last_error FROM outbox WHERE id = :id", id=bad)
    assert error == "BatchRequestTooLong"


async def test_an_sqs_outage_leaves_every_row_waiting(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    written = {await write(outbox_db), await write(outbox_db, NOTIFY)}
    queues.outage = "ServiceUnavailable"
    assert await make_relay(relay_db, queues, registry).publish_batch() == 2
    assert queues.calls == 2  # one per queue: an outage isn't retried row by row
    assert unpublished(outbox_db) == written
    assert {row[0] for row in outbox_db.sql("SELECT last_error FROM outbox")} == {
        "ServiceUnavailable"
    }


async def test_a_topic_the_relay_does_not_know_stays_unpublished(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    unknown = await write(outbox_db, Topic("future.topic", Queue.NOTIFY))
    assert await make_relay(relay_db, queues, registry).publish_batch() == 1
    assert queues.sent == []
    assert unpublished(outbox_db) == {unknown}
    assert registry.get_sample_value("outbox_publish_failures_total", {"queue": "unknown"}) == 1


async def test_a_row_that_breaks_the_contract_fails_alone(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    # Only hand-written SQL can do this; enqueue() refuses such a payload.
    outbox_db.sql(
        "INSERT INTO outbox (id, tenant_id, topic, payload, created_at) VALUES (gen_random_uuid(), "
        "gen_random_uuid(), 'file.scan', '{\"email\": \"someone@example.com\"}', "
        "now() - interval '1 minute')"
    )
    good = await write(outbox_db)
    assert await make_relay(relay_db, queues, registry).publish_batch() == 2
    assert sent_ids(queues) == [good]
    assert {row[0] for row in outbox_db.sql("SELECT last_error FROM outbox")} == {
        None,
        "invalid_payload",
    }
    assert all("example.com" not in body for body in queues.bodies())


def test_the_retry_delay_doubles_up_to_five_minutes_with_jitter() -> None:
    assert [retry_delay(n, jitter=0) for n in range(4)] == [2, 4, 8, 16]
    assert retry_delay(30, jitter=0) == RETRY_MAX_SECONDS
    assert retry_delay(0, jitter=1) == 1
    assert 1 <= retry_delay(0) <= 2


# ---- acceptance: a crash between the database write and the publish loses nothing ----


async def test_a_message_written_while_the_relay_is_down_is_sent_when_it_returns(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    # The change and its message committed; no relay was running (crashed, or not yet started).
    written = await write(outbox_db)
    outbox_db.sql("UPDATE outbox SET created_at = now() - interval '3 minutes'")
    assert unpublished(outbox_db) == {written}
    relay = make_relay(relay_db, queues, registry)
    assert await relay.publish_batch() == 1
    assert sent_ids(queues) == [written]


async def test_a_relay_that_dies_after_the_send_loses_nothing_and_its_rows_go_out_again(
    outbox_db: ScratchDatabase, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    written = {await write(outbox_db) for _ in range(3)}

    def crash() -> None:
        # The relay process dies after SQS accepted the batch, before it marked the rows: its
        # database session ends, its transaction rolls back and its row locks go with it.
        queues.after_send = None
        outbox_db.sql(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE usename = :role AND datname = current_database()",
            role=RELAY,
        )

    queues.after_send = crash
    async with pool(outbox_db, RELAY) as first:
        with pytest.raises(Exception, match=r"terminat|closed|connection"):
            await make_relay(first, queues, registry).publish_batch()
    assert unpublished(outbox_db) == written  # nothing marked, nothing lost

    # A relay replica (or the restarted pod) picks the rows up and sends them again.
    async with pool(outbox_db, RELAY) as second:
        assert await make_relay(second, queues, CollectorRegistry()).publish_batch() == 3
    assert unpublished(outbox_db) == set()
    # Each row went out twice; consumers skip the second copy (test_consumer).
    assert sorted(sent_ids(queues)) == sorted([*written, *written])


async def test_a_relay_cancelled_mid_send_leaves_its_rows_for_the_next_one(
    outbox_db: ScratchDatabase, relay_db: Database, registry: CollectorRegistry
) -> None:
    written = await write(outbox_db)
    entered = asyncio.Event()

    class HangingQueues(FakeQueues):
        async def send_batch(self, queue, messages):  # type: ignore[no-untyped-def]
            entered.set()
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

    task = asyncio.create_task(make_relay(relay_db, HangingQueues(), registry).publish_batch())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert unpublished(outbox_db) == {written}
    queues = FakeQueues()
    assert await make_relay(relay_db, queues, CollectorRegistry()).publish_batch() == 1
    assert sent_ids(queues) == [written]


async def test_two_relays_side_by_side_send_each_row_once(
    outbox_db: ScratchDatabase, queues: FakeQueues
) -> None:
    written = {await write(outbox_db) for _ in range(30)}
    async with pool(outbox_db, RELAY, size=2) as database:
        relays = [make_relay(database, queues, CollectorRegistry(), batch_size=5) for _ in range(2)]

        async def drain(relay: Relay) -> None:
            while await relay.publish_batch():
                pass

        await asyncio.gather(*(drain(r) for r in relays))
    assert sorted(sent_ids(queues)) == sorted(written)


# ---- the loop ----


async def test_the_loop_publishes_until_stopped(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    relay = make_relay(relay_db, queues, registry, poll_interval=0.05)
    stopping = asyncio.Event()
    task = asyncio.create_task(relay.run(stopping))
    written = await write(outbox_db)
    for _ in range(100):
        if queues.sent:
            break
        await asyncio.sleep(0.05)
    stopping.set()
    await asyncio.wait_for(task, timeout=5)
    assert sent_ids(queues) == [written]


async def test_the_loop_survives_a_database_outage(
    queues: FakeQueues, registry: CollectorRegistry, json_logs: object
) -> None:
    # Nothing listens on port 1: every batch fails, and the loop pauses and tries again.
    database = Database.connect("postgresql://sft_relay@127.0.0.1:1/sft")
    relay = make_relay(database, queues, registry)
    stopping = asyncio.Event()
    task = asyncio.create_task(relay.run(stopping))
    await asyncio.sleep(ERROR_PAUSE_SECONDS[0] * 1.5)
    stopping.set()
    await asyncio.wait_for(task, timeout=5)
    await database.dispose()
    messages = [line["msg"] for line in json_logs()]  # type: ignore[operator]
    assert messages.count("outbox batch failed; trying again") >= 2


async def test_published_rows_are_marked_in_the_relays_transaction(
    outbox_db: ScratchDatabase, relay_db: Database, queues: FakeQueues, registry: CollectorRegistry
) -> None:
    # The mark and the send share one transaction: the row's published_at is set only once the
    # batch commits, and only for what SQS accepted.
    written = await write(outbox_db)
    await make_relay(relay_db, queues, registry).publish_batch()
    [(published_at,)] = outbox_db.sql("SELECT published_at FROM outbox WHERE id = :id", id=written)
    assert published_at is not None
    assert json.loads(queues.bodies()[0])["id"] == str(written)
