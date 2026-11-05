"""One trace from an API request through the outbox, the relay and SQS to the consumer (#108).

The first test is the acceptance test of #108: a request's trace follows it through the outbox to
the consumer. The spans are what conftest's in-memory exporter got through the allowlist, as the
collector would get them. PostgreSQL is real, and each step logs in as its own role; SQS is the
in-memory fake here, and ElasticMQ in test_sqs_elasticmq.
"""

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator, Callable

import httpx2 as httpx
import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode
from prometheus_client import CollectorRegistry
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from messaging import FakeQueues, Sent, clear_messaging, pool
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.api.observability import HttpMetrics, RequestContextMiddleware
from sft.data.database import Database
from sft.data.outbox import OutboxMessage, Queue, Topic, enqueue, topic_registry
from sft.data.roles import API, RELAY, SCAN
from sft.data.scope import Scope
from sft.workers.consumer import Consumer, ConsumerLoop, ConsumerMetrics, Delivery, Outcome
from sft.workers.queues import OutgoingMessage
from sft.workers.relay import Relay, RelayMetrics

pytestmark = pytest.mark.anyio

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"  # the web app's trace
PARENT = "00f067aa0ba902b7"
SCAN_TOPIC = Topic("file.scan", Queue.SCAN_SMALL)
TOPICS = topic_registry(SCAN_TOPIC)

Logs = Callable[[], list[dict[str, object]]]
Pools = tuple[Database, Database, Database]


class ScanConsumer(Consumer):
    """Reads in the message's tenant scope and logs a line, as the scan worker will."""

    name = "test-traces"
    queue = Queue.SCAN_SMALL

    def __init__(self, database: Database, *, fail: bool = False) -> None:
        super().__init__(database)
        self.fail = fail

    async def handle(self, session: AsyncSession, delivery: Delivery) -> None:
        await session.execute(text("SELECT 1"))
        logging.getLogger("sft.workers.test").info("scanned")
        if self.fail:
            raise RuntimeError("the scan engine refused report.pdf")


@pytest.fixture
async def pools(migrated_db: ScratchDatabase) -> AsyncIterator[Pools]:
    """The API's, the relay's and the scan worker's pools, over an empty outbox."""
    clear_messaging(migrated_db)
    async with (
        pool(migrated_db, API) as api,
        pool(migrated_db, RELAY) as relay,
        pool(migrated_db, SCAN) as scan,
    ):
        yield api, relay, scan


def ids(span: ReadableSpan) -> tuple[str, str]:
    """The span's trace ID and span ID, as a `traceparent` writes them."""
    assert span.context is not None
    return f"{span.context.trace_id:032x}", f"{span.context.span_id:016x}"


def traceparent_of(span: ReadableSpan) -> str:
    assert span.context is not None
    trace_id, span_id = ids(span)
    return f"00-{trace_id}-{span_id}-{int(span.context.trace_flags):02x}"


def parent_of(span: ReadableSpan) -> str | None:
    return None if span.parent is None else f"{span.parent.span_id:016x}"


def named(spans: InMemorySpanExporter, name: str) -> list[ReadableSpan]:
    return [span for span in spans.get_finished_spans() if span.name == name]


def statements(spans: InMemorySpanExporter, sql: str) -> list[ReadableSpan]:
    """The SQL spans whose statement starts with `sql`."""
    return [
        span
        for span in spans.get_finished_spans()
        if str((span.attributes or {}).get("db.query.text", "")).startswith(sql)
    ]


async def relay_once(relay_db: Database, queues: FakeQueues) -> int:
    relay = Relay(relay_db, queues, RelayMetrics.create(CollectorRegistry()), topics=TOPICS)
    return await relay.publish_batch()


async def consume(scan_db: Database, queues: FakeQueues, *, fail: bool = False) -> list[Outcome]:
    metrics = ConsumerMetrics.create(CollectorRegistry())
    return await ConsumerLoop(ScanConsumer(scan_db, fail=fail), queues, metrics).poll_once()


async def write(api_db: Database, tenant_id: uuid.UUID | None = None) -> uuid.UUID:
    async with api_db.transaction(Scope.tenant(tenant_id or uuid.uuid4())) as session:
        return await enqueue(session, SCAN_TOPIC, {"file_id": uuid.uuid4()})


# ---- acceptance ----


async def test_a_requests_trace_follows_it_through_the_outbox_to_the_consumer(
    pools: Pools, spans: InMemorySpanExporter, json_logs: Logs
) -> None:
    api_db, relay_db, scan_db = pools
    tenant_id, file_id = uuid.uuid4(), uuid.uuid4()
    app = create_app()

    @app.post("/v1/things")
    async def create_thing() -> dict[str, str]:
        async with api_db.transaction(Scope.tenant(tenant_id)) as session:
            await enqueue(session, SCAN_TOPIC, {"file_id": file_id})
        return {}

    transport = httpx.ASGITransport(app=RequestContextMiddleware(app, HttpMetrics.create()))
    async with httpx.AsyncClient(transport=transport, base_url="http://api") as client:
        # A task of its own, so the request's log context ends with it, as in the server.
        response = await asyncio.create_task(
            client.post("/v1/things", headers={"traceparent": f"00-{TRACE}-{PARENT}-01"})
        )
    assert response.status_code == 200
    queues = FakeQueues()
    assert await relay_once(relay_db, queues) == 1
    assert await consume(scan_db, queues) == [Outcome.PROCESSED]

    [server] = named(spans, "POST /v1/things")
    [create] = named(spans, "create scan-small")
    [process] = named(spans, "process scan-small")
    # The request, the message and the consumer are one trace, the web app's, parent to child.
    assert ids(server)[0] == ids(create)[0] == ids(process)[0] == TRACE
    assert parent_of(server) == PARENT
    assert parent_of(create) == ids(server)[1]
    assert parent_of(process) == ids(create)[1]
    assert (create.kind, process.kind) == (SpanKind.PRODUCER, SpanKind.CONSUMER)
    # The outbox INSERT is under the message's span, the consumer's own SQL under its span.
    [insert] = statements(spans, "INSERT INTO outbox")
    assert parent_of(insert) == ids(create)[1]
    [select_one] = statements(spans, "SELECT 1")
    assert parent_of(select_one) == ids(process)[1]
    # The relay sent the body with the trace context the row was written with.
    [body] = queues.bodies()
    assert OutboxMessage.from_body(body).trace_context == {"traceparent": traceparent_of(create)}
    # Every log line of the request and of the consumer carries the trace ID.
    lines = json_logs()
    for msg in ("request", "scanned", "message processed"):
        [line] = [line for line in lines if line["msg"] == msg]
        assert line["trace_id"] == TRACE, msg
    # Spans carry the message's ID, never its tenant or its payload.
    assert process.attributes == {
        "messaging.system": "aws_sqs",
        "messaging.operation.type": "process",
        "messaging.destination.name": "scan-small",
        "messaging.consumer.group.name": "test-traces",
        "messaging.message.id": str(OutboxMessage.from_body(body).id),
    }
    exported = str([(s.name, s.attributes, s.events, s.links) for s in spans.get_finished_spans()])
    assert str(tenant_id) not in exported
    assert str(file_id) not in exported


# ---- the relay ----


async def test_a_relay_batch_is_a_trace_of_its_own_linked_to_each_message(
    pools: Pools, spans: InMemorySpanExporter
) -> None:
    api_db, relay_db, _ = pools
    tracer = trace.get_tracer(__name__)
    for request in ("first", "second"):  # two requests, two traces
        with tracer.start_as_current_span(request):
            await write(api_db)
    creates = named(spans, "create scan-small")
    spans.clear()
    assert await relay_once(relay_db, FakeQueues()) == 2

    [batch] = named(spans, "relay batch")
    [send] = named(spans, "send scan-small")
    assert batch.parent is None
    assert ids(batch)[0] not in {ids(create)[0] for create in creates}
    assert batch.attributes == {"messaging.batch.message_count": 2}
    assert (send.kind, parent_of(send)) == (SpanKind.PRODUCER, ids(batch)[1])
    assert {f"{link.context.span_id:016x}" for link in send.links} == {
        ids(create)[1] for create in creates
    }
    assert send.attributes == {
        "messaging.system": "aws_sqs",
        "messaging.operation.type": "send",
        "messaging.destination.name": "scan-small",
        "messaging.batch.message_count": 2,
    }
    assert send.status.status_code == StatusCode.UNSET
    # The claim and the marks are the batch's own SQL.
    statements = [s for s in spans.get_finished_spans() if s.kind == SpanKind.CLIENT]
    assert statements
    assert {parent_of(s) for s in statements} == {ids(batch)[1]}


async def test_an_idle_batch_is_one_small_trace(pools: Pools, spans: InMemorySpanExporter) -> None:
    _, relay_db, _ = pools
    assert await relay_once(relay_db, FakeQueues()) == 0
    [batch] = named(spans, "relay batch")
    assert batch.attributes == {"messaging.batch.message_count": 0}
    assert named(spans, "send scan-small") == []
    assert {ids(s)[0] for s in spans.get_finished_spans()} == {ids(batch)[0]}


@pytest.mark.parametrize(
    ("failure", "error"),
    [("outage", "ServiceUnavailable"), ("refused-batch", "BatchRequestTooLong")],
)
async def test_a_failed_send_is_an_error_span_with_the_sqs_code(
    pools: Pools, spans: InMemorySpanExporter, failure: str, error: str
) -> None:
    api_db, relay_db, _ = pools
    message_id = await write(api_db)
    if failure == "outage":
        queues = FakeQueues(outage="ServiceUnavailable")
    else:  # SQS refuses the whole call for this one message, as for one too long
        queues = FakeQueues(poison={str(message_id)})
    await relay_once(relay_db, queues)
    [send] = named(spans, "send scan-small")
    assert send.status.status_code == StatusCode.ERROR
    assert send.status.description is None
    assert send.attributes is not None
    assert send.attributes["error.type"] == error


async def test_a_row_sqs_refuses_marks_its_send_as_an_error(
    pools: Pools, spans: InMemorySpanExporter
) -> None:
    api_db, relay_db, _ = pools
    refused, sent = await write(api_db), await write(api_db)
    queues = FakeQueues(refuse={str(refused): "InvalidMessageContents"})
    assert await relay_once(relay_db, queues) == 2
    assert [OutboxMessage.from_body(b).id for b in queues.bodies()] == [sent]
    [send] = named(spans, "send scan-small")
    assert send.attributes is not None
    assert send.attributes["error.type"] == "InvalidMessageContents"
    assert send.status.status_code == StatusCode.ERROR


# ---- the consumer ----


async def test_a_message_written_outside_any_span_starts_its_trace_at_the_write(
    pools: Pools, spans: InMemorySpanExporter
) -> None:
    api_db, relay_db, scan_db = pools
    await write(api_db)  # a job, say, with no request around it
    queues = FakeQueues()
    await relay_once(relay_db, queues)
    assert await consume(scan_db, queues) == [Outcome.PROCESSED]
    [create] = named(spans, "create scan-small")
    [process] = named(spans, "process scan-small")
    assert create.parent is None
    assert ids(process)[0] == ids(create)[0]
    assert parent_of(process) == ids(create)[1]


async def test_a_failed_message_is_an_error_span_without_the_message(
    pools: Pools, spans: InMemorySpanExporter, json_logs: Logs
) -> None:
    api_db, relay_db, scan_db = pools
    with trace.get_tracer(__name__).start_as_current_span("request"):
        await write(api_db)
    queues = FakeQueues()
    await relay_once(relay_db, queues)
    assert await consume(scan_db, queues, fail=True) == [Outcome.FAILED]
    assert queues.deleted == []
    [create] = named(spans, "create scan-small")
    [process] = named(spans, "process scan-small")
    assert parent_of(process) == ids(create)[1]
    assert process.status.status_code == StatusCode.ERROR
    assert process.status.description is None
    assert process.attributes is not None
    assert process.attributes["error.type"] == "RuntimeError"
    assert "report.pdf" not in str(spans.get_finished_spans())
    [line] = [line for line in json_logs() if str(line["msg"]).startswith("message failed")]
    assert line["trace_id"] == ids(create)[0]


@pytest.mark.parametrize(
    "trace_context",
    [{}, {"trace_id": TRACE}, {"traceparent": "garbage"}],
    ids=["none", "older-format", "invalid"],
)
async def test_a_message_without_a_valid_traceparent_is_still_processed_in_a_new_trace(
    pools: Pools, spans: InMemorySpanExporter, trace_context: dict[str, str]
) -> None:
    _, _, scan_db = pools
    message = OutboxMessage(
        id=uuid.uuid4(),
        topic=SCAN_TOPIC.name,
        tenant_id=uuid.uuid4(),
        payload={"file_id": uuid.uuid4()},
        trace_context=trace_context,
    )
    queues = FakeQueues(sent=[Sent(Queue.SCAN_SMALL, OutgoingMessage("x", message.body()))])
    assert await consume(scan_db, queues) == [Outcome.PROCESSED]
    [process] = named(spans, "process scan-small")
    assert process.parent is None
    assert ids(process)[0] != TRACE


async def test_the_delete_runs_in_the_messages_span_and_the_log_context_ends_with_it(
    pools: Pools, spans: InMemorySpanExporter, json_logs: Logs
) -> None:
    api_db, relay_db, scan_db = pools
    await write(api_db)
    queues = FakeQueues()
    await relay_once(relay_db, queues)

    class DeleteLogging(FakeQueues):
        async def delete(self, queue: str, receipt_handle: str) -> None:
            logging.getLogger("sft.workers.test").info("deleting")
            await super().delete(queue, receipt_handle)

    watched = DeleteLogging(sent=queues.sent)
    assert await consume(scan_db, watched) == [Outcome.PROCESSED]
    [process] = named(spans, "process scan-small")
    [line] = [line for line in json_logs() if line["msg"] == "deleting"]
    assert line["trace_id"] == ids(process)[0]
    logging.getLogger("sft.workers.test").info("after")
    [after] = [line for line in json_logs() if line["msg"] == "after"]
    assert "trace_id" not in after
