"""The SQS adapter and the whole path against ElasticMQ, the local SQS (ADR-0013, #52).

`TEST_SQS_ENDPOINT_URL` names an ElasticMQ server, e.g. http://127.0.0.1:9324. Each test makes its
own queues there under a fresh prefix and deletes them afterwards. Without the variable the tests
are skipped locally; in CI they fail instead.

The last tests run the relay's entry point, `python -m sft.workers.relay`, as a real process.
"""

import asyncio
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import uuid
from collections.abc import AsyncIterator, Iterator

import boto3
import pytest
from prometheus_client import CollectorRegistry
from sqlalchemy.ext.asyncio import AsyncSession

from messaging import clear_messaging, pool
from pg import ScratchDatabase
from sft.data.outbox import Queue, Topic, enqueue, topic_registry
from sft.data.roles import API, RELAY, SCAN
from sft.data.scope import Scope
from sft.workers.consumer import Consumer, ConsumerLoop, ConsumerMetrics, Delivery, Outcome
from sft.workers.queues import OutgoingMessage, QueueError, SqsQueues
from sft.workers.relay import Relay, RelayMetrics

ENDPOINT_VARIABLE = "TEST_SQS_ENDPOINT_URL"
REGION = "ap-northeast-1"
# ElasticMQ checks no credentials, but the SDK wants some. Obviously fake.
FAKE_CREDENTIALS = {"AWS_ACCESS_KEY_ID": "local-fake", "AWS_SECRET_ACCESS_KEY": "local-fake"}

SCAN_TOPIC = Topic("file.scan", Queue.SCAN_SMALL)
NOTIFY_TOPIC = Topic("transfer.notify", Queue.NOTIFY)
TOPICS = topic_registry(SCAN_TOPIC, NOTIFY_TOPIC)


@pytest.fixture(scope="session")
def endpoint() -> str:
    url = os.environ.get(ENDPOINT_VARIABLE)
    if not url:
        if os.environ.get("CI"):
            pytest.fail(f"{ENDPOINT_VARIABLE} must be set in CI")
        pytest.skip(f"set {ENDPOINT_VARIABLE} to an ElasticMQ URL")
    return url


@pytest.fixture
def prefix(endpoint: str, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Fresh queues for this test, as the environment's would be: `{prefix}scan-small` and so on."""
    for name, value in FAKE_CREDENTIALS.items():
        monkeypatch.setenv(name, value)
    prefix = f"sft-test-{secrets.token_hex(4)}-"
    client = boto3.session.Session().client("sqs", endpoint_url=endpoint, region_name=REGION)
    urls = [
        client.create_queue(
            QueueName=prefix + queue.value,
            Attributes={"VisibilityTimeout": "1", "ReceiveMessageWaitTimeSeconds": "1"},
        )["QueueUrl"]
        for queue in Queue
    ]
    yield prefix
    for url in urls:
        client.delete_queue(QueueUrl=url)
    client.close()


@pytest.fixture
async def queues(endpoint: str, prefix: str) -> AsyncIterator[SqsQueues]:
    adapter = SqsQueues.create(region=REGION, prefix=prefix, endpoint_url=endpoint, read_timeout=10)
    yield adapter
    await adapter.close()


async def receive_all(queues: SqsQueues, queue: Queue, count: int) -> list[str]:
    bodies: list[str] = []
    for _ in range(20):
        for item in await queues.receive(queue, max_messages=10, wait_seconds=1):
            bodies.append(item.body)
            await queues.delete(queue, item.receipt_handle)
        if len(bodies) >= count:
            break
    return bodies


# ---- the adapter ----


@pytest.mark.anyio
async def test_messages_go_out_and_come_back(queues: SqsQueues) -> None:
    group = str(uuid.uuid4())
    failures = await queues.send_batch(
        Queue.SCAN_SMALL,
        [
            OutgoingMessage("a", "first", group_id=group),
            OutgoingMessage("b", "second", group_id=group),
        ],
    )
    assert failures == []
    assert sorted(await receive_all(queues, Queue.SCAN_SMALL, 2)) == ["first", "second"]


@pytest.mark.anyio
async def test_a_delayed_message_is_not_received_before_its_delay(queues: SqsQueues) -> None:
    await queues.send_batch(Queue.NOTIFY, [OutgoingMessage("a", "later", delay_seconds=2)])
    assert await queues.receive(Queue.NOTIFY, max_messages=10, wait_seconds=0) == []
    await asyncio.sleep(2.5)
    [item] = await queues.receive(Queue.NOTIFY, max_messages=10, wait_seconds=1)
    assert (item.body, item.receive_count) == ("later", 1)


@pytest.mark.anyio
async def test_a_message_not_deleted_comes_back_with_a_higher_receive_count(
    queues: SqsQueues,
) -> None:
    await queues.send_batch(Queue.NOTIFY, [OutgoingMessage("a", "again")])
    [first] = await queues.receive(Queue.NOTIFY, max_messages=1, wait_seconds=1)
    await asyncio.sleep(1.5)  # the test queues' visibility timeout is 1 s
    [second] = await queues.receive(Queue.NOTIFY, max_messages=1, wait_seconds=1)
    assert (first.receive_count, second.receive_count) == (1, 2)


@pytest.mark.anyio
async def test_a_batch_refused_for_one_message_is_a_sender_fault(queues: SqsQueues) -> None:
    # ElasticMQ refuses the whole call for one message too long (AWS: BatchRequestTooLong); the
    # relay then sends each row on its own (test_relay).
    with pytest.raises(QueueError) as caught:
        await queues.send_batch(
            Queue.NOTIFY,
            [OutgoingMessage("ok", "fine"), OutgoingMessage("bad", "x" * (1024 * 1024 + 1))],
        )
    assert caught.value.sender_fault


@pytest.mark.anyio
async def test_a_missing_queue_is_a_queue_error(endpoint: str, prefix: str) -> None:
    adapter = SqsQueues.create(region=REGION, prefix=prefix + "missing-", endpoint_url=endpoint)
    try:
        with pytest.raises(QueueError) as caught:
            await adapter.send_batch(Queue.NOTIFY, [OutgoingMessage("a", "x")])
        assert "NonExistentQueue" in caught.value.code or "QueueDoesNotExist" in caught.value.code
        # A missing queue fails every message alike: not worth re-sending row by row.
        assert not caught.value.sender_fault
    finally:
        await adapter.close()


@pytest.mark.anyio
async def test_a_batch_has_one_to_ten_messages(queues: SqsQueues) -> None:
    with pytest.raises(ValueError, match="1 to 10"):
        await queues.send_batch(Queue.NOTIFY, [])


# ---- the whole path: service transaction, relay, ElasticMQ, consumer ----


class RecordingConsumer(Consumer):
    name = "test-elasticmq"
    queue = Queue.SCAN_SMALL

    def __init__(self, *args: object) -> None:
        super().__init__(*args)  # type: ignore[arg-type]
        self.handled: list[uuid.UUID] = []

    async def handle(self, session: AsyncSession, delivery: Delivery) -> None:
        self.handled.append(delivery.message.id)


@pytest.mark.anyio
async def test_a_message_resent_by_the_relay_is_processed_once(
    migrated_db: ScratchDatabase, queues: SqsQueues
) -> None:
    clear_messaging(migrated_db)
    async with (
        pool(migrated_db, API) as api,
        api.transaction(Scope.tenant(uuid.uuid4())) as session,
    ):
        written = await enqueue(session, SCAN_TOPIC, {"file_id": uuid.uuid4()})
    async with pool(migrated_db, RELAY) as relay_db:
        relay = Relay(relay_db, queues, RelayMetrics.create(CollectorRegistry()), topics=TOPICS)
        assert await relay.publish_batch() == 1
        # As if the relay had died before its commit: the row is unpublished again, and sent twice.
        migrated_db.sql("UPDATE outbox SET published_at = NULL")
        assert await relay.publish_batch() == 1

    async with pool(migrated_db, SCAN) as scan_db:
        consumer = RecordingConsumer(scan_db)
        loop = ConsumerLoop(consumer, queues, ConsumerMetrics.create(CollectorRegistry()))
        outcomes: list[Outcome] = []
        for _ in range(10):
            outcomes += await loop.poll_once()
            if len(outcomes) == 2:
                break
    assert sorted(outcomes) == [Outcome.DUPLICATE, Outcome.PROCESSED]
    assert consumer.handled == [written]
    # Both copies were deleted: nothing comes back after the visibility timeout.
    await asyncio.sleep(1.5)
    assert await queues.receive(Queue.SCAN_SMALL, max_messages=10, wait_seconds=0) == []


# ---- the entry point, as a process ----


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def relay_env(db: ScratchDatabase, endpoint: str, prefix: str, port: int) -> dict[str, str]:
    return {
        **{k: v for k, v in os.environ.items() if not k.startswith(("RELAY_", "SQS_"))},
        **FAKE_CREDENTIALS,
        "DATABASE_URL": db.url(RELAY),
        "INTERNAL_PORT": str(port),
        "SQS_ENDPOINT_URL": endpoint,
        "SQS_QUEUE_PREFIX": prefix,
        "RELAY_POLL_INTERVAL_SECONDS": "0.1",
    }


def get(port: int, path: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def wait_for(check: object, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if check():  # type: ignore[operator]
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError("timed out")


def test_the_relay_process_runs_and_stops_cleanly_on_sigterm(
    migrated_db: ScratchDatabase, endpoint: str, prefix: str
) -> None:
    clear_messaging(migrated_db)
    # The production relay knows no topics yet (TOPICS is empty in M0), so this row stays
    # unpublished and is counted as a failure: the process still runs and drains cleanly.
    migrated_db.sql(
        "INSERT INTO outbox (id, tenant_id, topic, payload) "
        "VALUES (gen_random_uuid(), gen_random_uuid(), 'file.scan', '{}')"
    )
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "sft.workers.relay"],
        env=relay_env(migrated_db, endpoint, prefix, port),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        wait_for(lambda: get(port, "/readyz")[0] == 200)
        wait_for(
            lambda: b'outbox_publish_failures_total{queue="unknown"}' in get(port, "/metrics")[1]
        )
        _, metrics = get(port, "/metrics")
        assert b"outbox_oldest_unpublished_age_seconds" in metrics
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=20) == 0
    finally:
        process.kill()
        output = process.communicate()[0].decode()
    lines = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    messages = [line["msg"] for line in lines]
    assert "ready" in messages
    assert messages[-1] == "stopped"
    assert all("local-fake" not in line for line in output.splitlines())


def test_the_relay_process_exits_2_on_bad_settings() -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("DATABASE_URL", "SQS_QUEUE_PREFIX")}
    result = subprocess.run(
        [sys.executable, "-m", "sft.workers.relay"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 2
    [line] = [json.loads(x) for x in result.stdout.splitlines()]
    assert {e["setting"] for e in line["errors"]} == {"DATABASE_URL", "SQS_QUEUE_PREFIX"}


def test_the_relay_process_exits_3_when_its_port_is_taken(
    migrated_db: ScratchDatabase, endpoint: str, prefix: str
) -> None:
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        result = subprocess.run(
            [sys.executable, "-m", "sft.workers.relay"],
            env=relay_env(migrated_db, endpoint, prefix, taken.getsockname()[1]),
            capture_output=True,
            timeout=30,
            check=False,
        )
    assert result.returncode == 3
