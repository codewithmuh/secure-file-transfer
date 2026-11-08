"""The outbox: the message contract, enqueue in a service transaction, and who touches the rows."""

import asyncio
import json
import uuid
from datetime import timedelta

import pytest
from opentelemetry import trace
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind
from sqlalchemy import insert, select, text
from sqlalchemy.exc import DBAPIError

from messaging import clear_messaging, pool
from pg import ScratchDatabase
from sft.data.access import ScopeNotAllowedError
from sft.data.audit import Actor, Target, record
from sft.data.database import Database
from sft.data.models import ActorType, Outbox, Tenant
from sft.data.outbox import (
    FILE_SCAN,
    FILE_SCAN_LARGE,
    MEMBER_INVITED,
    MEMBER_SIGN_IN_RESET,
    RECIPIENT_CODE_REQUESTED,
    RECIPIENT_LINK_DUE,
    RECIPIENT_LOCKED,
    TOPICS,
    TRANSFER_HELD,
    TRANSFER_RETURNED_TO_DRAFT,
    TRANSFER_SENT,
    InvalidMessageError,
    OutboxMessage,
    Queue,
    Topic,
    claim_due,
    enqueue,
    oldest_unpublished_age,
    topic_registry,
)
from sft.data.roles import API, JOBS, NOTIFY, OPERATOR, RELAY, SCAN
from sft.data.scope import Scope

TOPIC = Topic("file.scan", Queue.SCAN_SMALL)
INSUFFICIENT_PRIVILEGE = "42501"


# ---- the message contract (ADR-0013) ----


def test_a_topic_is_named_subject_dot_event() -> None:
    for bad in ("scan", "File.Scan", "file.", "file scan", ".scan"):
        with pytest.raises(ValueError, match="named like"):
            Topic(bad, Queue.NOTIFY)


def test_a_registry_refuses_a_topic_twice() -> None:
    assert topic_registry(TOPIC) == {"file.scan": TOPIC}
    with pytest.raises(ValueError, match="twice"):
        topic_registry(TOPIC, Topic("file.scan", Queue.SCAN_LARGE))


def test_the_service_names_each_topic_it_sends() -> None:
    # Each feature adds its topics, with the queue that carries them: invitations (#112), scans
    # (#114, #175), each to the pool of its size (ADR-0019), and the evaluation's notices (#174).
    # The notification worker's own messages (#178, #179): per-recipient links, codes, lockouts.
    assert TOPICS == {
        "member.invited": MEMBER_INVITED,
        "member.sign_in_reset": MEMBER_SIGN_IN_RESET,
        "file.scan": FILE_SCAN,
        "file.scan_large": FILE_SCAN_LARGE,
        "transfer.sent": TRANSFER_SENT,
        "transfer.held": TRANSFER_HELD,
        "transfer.returned_to_draft": TRANSFER_RETURNED_TO_DRAFT,
        "recipient.link_due": RECIPIENT_LINK_DUE,
        "recipient.code_requested": RECIPIENT_CODE_REQUESTED,
        "recipient.locked": RECIPIENT_LOCKED,
    }
    assert MEMBER_INVITED.queue is Queue.NOTIFY
    assert MEMBER_SIGN_IN_RESET.queue is Queue.NOTIFY  # a sign-in reset's new invitation (#197)
    assert FILE_SCAN.queue is Queue.SCAN_SMALL
    assert FILE_SCAN_LARGE.queue is Queue.SCAN_LARGE
    notices = (TRANSFER_SENT, TRANSFER_HELD, TRANSFER_RETURNED_TO_DRAFT)
    for topic in (*notices, RECIPIENT_LINK_DUE, RECIPIENT_CODE_REQUESTED, RECIPIENT_LOCKED):
        assert topic.queue is Queue.NOTIFY


def test_only_the_scan_queues_are_fair() -> None:
    assert {q for q in Queue if q.fair} == {Queue.SCAN_SMALL, Queue.SCAN_LARGE}


def test_a_message_body_round_trips() -> None:
    message = OutboxMessage(
        id=uuid.uuid4(),
        topic="file.scan",
        tenant_id=uuid.uuid4(),
        payload={"file_id": uuid.uuid4(), "recipient_ids": (uuid.uuid4(), uuid.uuid4())},
        trace_context={"traceparent": f"00-{'ab' * 16}-{'cd' * 8}-01"},
    )
    body = message.body()
    assert set(json.loads(body)) == {"id", "topic", "tenant_id", "payload", "trace_context"}
    assert OutboxMessage.from_body(body) == message


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "someone@example.com"},  # text: could be an address, a token or a name
        {"token": "a" * 32},
        {"count": 3},
        {"file_id": [uuid.uuid4(), "x"]},
        {"File-Id": uuid.uuid4()},
        {"file_ids": [uuid.uuid4()] * 101},
        {"nested": {"file_id": uuid.uuid4()}},
    ],
)
def test_a_payload_carries_ids_only(payload: dict[str, object]) -> None:
    message = OutboxMessage(uuid.uuid4(), "file.scan", uuid.uuid4(), payload)  # type: ignore[arg-type]
    with pytest.raises(InvalidMessageError):
        message.body()


def test_a_payload_is_a_mapping() -> None:
    message = OutboxMessage(uuid.uuid4(), "file.scan", uuid.uuid4(), [])  # type: ignore[arg-type]
    with pytest.raises(InvalidMessageError, match="maps names"):
        message.body()


def _body(**changes: object) -> str:
    raw: dict[str, object] = {
        "id": str(uuid.uuid4()),
        "topic": "file.scan",
        "tenant_id": str(uuid.uuid4()),
        "payload": {"file_id": str(uuid.uuid4())},
        "trace_context": {},
    }
    raw.update(changes)
    return json.dumps({k: v for k, v in raw.items() if v is not ...})


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        "[]",
        _body(extra="field"),
        _body(trace_context=...),
        _body(id="not-a-uuid"),
        _body(tenant_id=7),
        _body(topic="Bad Topic"),
        _body(topic=3),
        _body(trace_context={"trace_id": 1}),
        _body(trace_context=[]),
        _body(payload=[]),
        _body(payload={"file_id": "not-a-uuid"}),
        _body(payload={"file_id": 5}),
        _body(payload={"file_ids": ["not-a-uuid"]}),
        _body(payload={"file_ids": [5]}),
        _body(payload={"Bad Key": str(uuid.uuid4())}),
    ],
)
def test_a_received_body_that_breaks_the_contract_is_refused(body: str) -> None:
    with pytest.raises(InvalidMessageError):
        OutboxMessage.from_body(body)


# ---- enqueue, against PostgreSQL ----


@pytest.fixture
def outbox_db(migrated_db: ScratchDatabase) -> ScratchDatabase:
    clear_messaging(migrated_db)
    return migrated_db


def rows(db: ScratchDatabase) -> list[tuple[object, ...]]:
    return db.sql(
        "SELECT id, tenant_id, topic, payload, trace_context, delay_seconds, published_at "
        "FROM outbox ORDER BY created_at, id"
    )


@pytest.mark.anyio
async def test_the_message_commits_with_the_change_that_causes_it(
    outbox_db: ScratchDatabase,
) -> None:
    tenant_id = uuid.uuid4()
    file_id = uuid.uuid4()
    async with (
        pool(outbox_db, OPERATOR) as operator,
        operator.transaction(Scope.tenant(tenant_id)) as session,
    ):
        # As the operator API's createTenant will: the change, its audit event, its message.
        session.add(Tenant(id=tenant_id, name="Example", status="active"))
        await session.flush()
        await record(
            session,
            action="tenant.created",
            actor=Actor(ActorType.OPERATOR, uuid.uuid4()),
            target=Target("tenant", tenant_id),
        )
        message_id = await enqueue(session, TOPIC, {"file_id": file_id})
    [(*row, trace_context, delay, published)] = rows(outbox_db)
    assert row == [message_id, tenant_id, "file.scan", {"file_id": str(file_id)}]
    assert (delay, published) == (0, None)
    assert set(trace_context) == {"traceparent"}  # its create span's (the trace test below)
    assert message_id.version == 7


@pytest.mark.anyio
async def test_a_change_that_rolls_back_leaves_no_message(outbox_db: ScratchDatabase) -> None:
    tenant_id = uuid.uuid4()

    async def a_change_that_fails(operator: Database) -> None:
        async with operator.transaction(Scope.tenant(tenant_id)) as session:
            session.add(Tenant(id=tenant_id, name="Example", status="active"))
            await enqueue(session, TOPIC, {"file_id": uuid.uuid4()})
            raise RuntimeError("the change failed")

    async with pool(outbox_db, OPERATOR) as operator:
        with pytest.raises(RuntimeError, match="the change failed"):
            await a_change_that_fails(operator)
    assert rows(outbox_db) == []
    assert outbox_db.sql("SELECT count(*) FROM tenants WHERE id = :id", id=tenant_id) == [(0,)]


@pytest.mark.anyio
async def test_the_message_carries_the_trace_context_of_its_create_span(
    outbox_db: ScratchDatabase, spans: InMemorySpanExporter
) -> None:
    with trace.get_tracer(__name__).start_as_current_span("request") as request:
        async with pool(outbox_db, API) as api, api.transaction(Scope.tenant(uuid.uuid4())) as s:
            message_id = await enqueue(s, TOPIC, {"file_id": uuid.uuid4()})
    [create] = [span for span in spans.get_finished_spans() if span.kind == SpanKind.PRODUCER]
    assert create.name == "create scan-small"
    assert create.parent is not None
    assert create.parent.span_id == request.get_span_context().span_id
    assert create.context is not None
    ids = create.context
    traceparent = f"00-{ids.trace_id:032x}-{ids.span_id:016x}-{int(ids.trace_flags):02x}"
    assert rows(outbox_db)[0][4] == {"traceparent": traceparent}
    assert create.attributes == {
        "messaging.system": "aws_sqs",
        "messaging.operation.type": "create",
        "messaging.destination.name": "scan-small",
        "messaging.message.id": str(message_id),
    }


@pytest.mark.anyio
async def test_a_delay_is_stored_in_whole_seconds_up_to_15_minutes(
    outbox_db: ScratchDatabase,
) -> None:
    async with pool(outbox_db, SCAN) as scan:
        async with scan.transaction(Scope.tenant(uuid.uuid4())) as session:
            await enqueue(session, TOPIC, {"file_id": uuid.uuid4()}, delay=timedelta(seconds=29.2))
            await enqueue(session, TOPIC, {"file_id": uuid.uuid4()}, delay=timedelta(minutes=15))
        for delay in (timedelta(minutes=15, seconds=1), timedelta(seconds=-1)):
            with pytest.raises(ValueError, match="15 minutes"):
                async with scan.transaction(Scope.tenant(uuid.uuid4())) as session:
                    await enqueue(session, TOPIC, {"file_id": uuid.uuid4()}, delay=delay)
    assert sorted(row[5] for row in rows(outbox_db)) == [30, 900]


@pytest.mark.anyio
@pytest.mark.parametrize(("role", "scope"), [(API, Scope.platform()), (JOBS, Scope.system())])
async def test_a_message_needs_a_tenant_scope(
    outbox_db: ScratchDatabase, role: str, scope: Scope
) -> None:
    async with pool(outbox_db, role) as database:
        with pytest.raises(ScopeNotAllowedError, match="writes no tenant rows"):
            async with database.transaction(scope) as session:
                await enqueue(session, TOPIC, {"file_id": uuid.uuid4()})


@pytest.mark.anyio
@pytest.mark.parametrize("role", [API, OPERATOR, SCAN, JOBS])
async def test_the_writers_cannot_write_for_another_tenant_or_read_the_outbox(
    outbox_db: ScratchDatabase, role: str
) -> None:
    async with pool(outbox_db, role) as database:
        with pytest.raises(DBAPIError, match="row-level security"):
            async with database.transaction(Scope.tenant(uuid.uuid4())) as session:
                await session.execute(
                    insert(Outbox).values(
                        id=uuid.uuid4(), tenant_id=uuid.uuid4(), topic="file.scan", payload={}
                    )
                )
        with pytest.raises(DBAPIError) as caught:
            async with database.transaction(Scope.tenant(uuid.uuid4())) as session:
                await session.execute(select(Outbox.id))
        assert caught.value.orig.sqlstate == INSUFFICIENT_PRIVILEGE  # type: ignore[union-attr]


@pytest.mark.anyio
async def test_the_notification_worker_writes_messages_but_reads_none(
    outbox_db: ScratchDatabase,
) -> None:
    # It writes each recipient's link message and the cap's deferrals (#178), in the message's
    # tenant, and reads nothing back, as every writer but the relay.
    tenant_id = uuid.uuid4()
    async with pool(outbox_db, NOTIFY) as notify:
        async with notify.transaction(Scope.tenant(tenant_id)) as session:
            await enqueue(session, RECIPIENT_LINK_DUE, {"recipient_id": uuid.uuid4()})
        with pytest.raises(DBAPIError) as caught:
            async with notify.transaction(Scope.tenant(tenant_id)) as session:
                await session.execute(select(Outbox.id))
        assert caught.value.orig.sqlstate == INSUFFICIENT_PRIVILEGE  # type: ignore[union-attr]
    assert outbox_db.sql("SELECT tenant_id, topic FROM outbox") == [
        (tenant_id, "recipient.link_due")
    ]


async def _enqueue_some(db: ScratchDatabase, count: int) -> None:
    async with pool(db, API) as api:
        for _ in range(count):
            async with api.transaction(Scope.tenant(uuid.uuid4())) as session:
                await enqueue(session, TOPIC, {"file_id": uuid.uuid4()})


@pytest.mark.anyio
async def test_the_relay_reads_every_tenants_rows_in_system_scope_only(
    outbox_db: ScratchDatabase,
) -> None:
    await _enqueue_some(outbox_db, 3)
    async with pool(outbox_db, RELAY) as relay:
        async with relay.transaction(Scope.system()) as session:
            assert len(await claim_due(session, 10)) == 3
        # The relay opens no other scope (sft.data.access); its policies match only system scope
        # too, which the isolation suite checks with the data layer's filter removed.
        with pytest.raises(ScopeNotAllowedError, match="never opens a tenant scope"):
            async with relay.transaction(Scope.tenant(uuid.uuid4())) as session:
                await claim_due(session, 10)
        with pytest.raises(DBAPIError) as caught:
            async with relay.transaction(Scope.system()) as session:
                await session.execute(
                    insert(Outbox).values(
                        id=uuid.uuid4(), tenant_id=uuid.uuid4(), topic="file.scan", payload={}
                    )
                )
        assert caught.value.orig.sqlstate == INSUFFICIENT_PRIVILEGE  # type: ignore[union-attr]


@pytest.mark.anyio
@pytest.mark.parametrize("scope", ["tenant", "platform", ""])
async def test_the_relays_policies_bind_outside_system_scope(
    outbox_db: ScratchDatabase, scope: str
) -> None:
    # Past the data layer, straight on a connection: the relay's policies alone refuse to show or
    # mark any row unless the transaction is in system scope.
    await _enqueue_some(outbox_db, 2)
    async with pool(outbox_db, RELAY) as relay, relay.raw_connection_for_tests() as connection:
        await connection.execute(
            text(
                "SELECT set_config('app.scope', :scope, true), "
                "set_config('app.tenant_id', '', true)"
            ),
            {"scope": scope},
        )
        assert (await connection.execute(text("SELECT count(*) FROM outbox"))).scalar() == 0
        marked = await connection.execute(text("UPDATE outbox SET published_at = now()"))
        assert marked.rowcount == 0
        await connection.rollback()
    assert outbox_db.sql("SELECT count(*) FROM outbox WHERE published_at IS NULL") == [(2,)]


@pytest.mark.anyio
async def test_two_relays_claim_different_rows(outbox_db: ScratchDatabase) -> None:
    await _enqueue_some(outbox_db, 4)
    async with pool(outbox_db, RELAY, size=2) as relay:
        first_claimed = asyncio.Event()
        release = asyncio.Event()
        claims: dict[str, set[uuid.UUID]] = {}

        async def first() -> None:
            async with relay.transaction(Scope.system()) as session:
                claims["first"] = {r.message.id for r in await claim_due(session, 3)}
                first_claimed.set()
                await release.wait()

        task = asyncio.create_task(first())
        await first_claimed.wait()
        async with relay.transaction(Scope.system()) as session:
            claims["second"] = {r.message.id for r in await claim_due(session, 3)}
        release.set()
        await task
    assert len(claims["first"]) == 3
    assert len(claims["second"]) == 1
    assert not claims["first"] & claims["second"]


@pytest.mark.anyio
async def test_the_outbox_age_counts_unpublished_rows_only(outbox_db: ScratchDatabase) -> None:
    async with pool(outbox_db, RELAY) as relay:
        async with relay.transaction(Scope.system()) as session:
            assert await oldest_unpublished_age(session) == 0.0
        await _enqueue_some(outbox_db, 1)
        outbox_db.sql("UPDATE outbox SET created_at = now() - interval '90 seconds'")
        async with relay.transaction(Scope.system()) as session:
            assert 89 < await oldest_unpublished_age(session) < 120
        outbox_db.sql("UPDATE outbox SET published_at = now()")
        async with relay.transaction(Scope.system()) as session:
            assert await oldest_unpublished_age(session) == 0.0


def test_the_unpublished_index_is_partial(migrated_db: ScratchDatabase) -> None:
    [(definition,)] = migrated_db.sql("SELECT pg_get_indexdef('outbox_unpublished_idx'::regclass)")
    assert "WHERE (published_at IS NULL)" in str(definition)


def test_delays_over_15_minutes_are_refused_by_the_table_too(outbox_db: ScratchDatabase) -> None:
    with pytest.raises(Exception, match="outbox_delay_seconds_check"):
        outbox_db.sql(
            "INSERT INTO outbox (id, tenant_id, topic, payload, delay_seconds) "
            "VALUES (gen_random_uuid(), gen_random_uuid(), 'file.scan', '{}', 901)"
        )
