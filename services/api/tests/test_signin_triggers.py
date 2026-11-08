"""The Cognito sign-in triggers and their audit trail (#238; NFR-14, NFR-15; authn and authz 2.4;
abuse and rate limits 2.3).

The handlers run as the Lambda function would call them, against a real Valkey
(`TEST_VALKEY_URL`) with a clock the test moves; the notification worker's consumer runs as
`sft_notify` against real PostgreSQL. The Lambda Runtime API loop runs against a stand-in on a
real socket. Running against Cognito is pending the AWS run.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import AsyncIterator, Iterator, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from prometheus_client import CollectorRegistry
from pydantic import ValidationError

from member_fixtures import seed_user
from pg import ScratchDatabase
from sft.core.settings import SignInTriggerSettings
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.data.outbox import InvalidMessageError, OutboxMessage
from sft.data.roles import NOTIFY
from sft.service.signin_triggers import (
    DENIED,
    POST_AUTHENTICATION,
    PRE_AUTHENTICATION,
    SignInDenied,
    SignInEvents,
    SignInTriggers,
    parse_message,
    parse_trigger,
)
from sft.workers.consumer import Delivery, Outcome
from sft.workers.notify import SignInEventsConsumer
from sft.workers.signin_trigger import RuntimeApi, serve

pytestmark = pytest.mark.anyio

UNREACHABLE = "redis://u:p@127.0.0.1:1/0"
MINUTE = 60.0


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Queue:
    """`Send` into a list, as SQS would take the batch; `down` refuses everything."""

    sent: list[tuple[OutboxMessage, int]] = field(default_factory=list)
    down: bool = False

    async def __call__(self, messages: Sequence[tuple[str, int]]) -> None:
        if self.down:
            raise RuntimeError("queue unreachable")
        self.sent += [(OutboxMessage.from_body(body), delay) for body, delay in messages]

    def topics(self) -> list[str]:
        return [message.topic for message, _ in self.sent]


def event(source: str, user_id: uuid.UUID, tenant_id: uuid.UUID, **request: Any) -> dict[str, Any]:
    """A trigger event as Cognito sends it (the fields the triggers read)."""
    return {
        "version": "1",
        "triggerSource": source,
        "region": "ap-northeast-1",
        "userPoolId": "ap-northeast-1_testonly",
        "userName": str(user_id),
        "callerContext": {"awsSdkVersion": "test", "clientId": "test-only"},
        "request": {
            "userAttributes": {"sub": str(uuid.uuid4()), "custom:tenant_id": str(tenant_id)},
            "validationData": {},
            **request,
        },
        "response": {},
    }


@dataclass
class Rig:
    triggers: SignInTriggers
    queue: Queue
    clock: Clock
    store: CounterStore
    registry: CollectorRegistry
    user_id: uuid.UUID = field(default_factory=uuid.uuid4)
    tenant_id: uuid.UUID = field(default_factory=uuid.uuid4)

    async def attempt(self) -> dict[str, Any]:
        return await self.triggers.handle(event(PRE_AUTHENTICATION, self.user_id, self.tenant_id))

    async def success(self) -> None:
        await self.attempt()
        await self.triggers.handle(event(POST_AUTHENTICATION, self.user_id, self.tenant_id))

    def rejections(self) -> float:
        value = self.registry.get_sample_value(
            "rate_limit_rejections_total", {"group": "B", "key_type": "account"}
        )
        return 0.0 if value is None else value


@pytest.fixture
def rig(counter_store: CounterStore) -> Rig:
    clock, queue, registry = Clock(), Queue(), CollectorRegistry()
    triggers = SignInTriggers(counter_store, CounterMetrics.create(registry), queue, clock=clock)
    return Rig(triggers, queue, clock, counter_store, registry)


# ---- NFR-14: 10 failed sign-ins per account in 15 minutes ----


async def test_the_11th_failed_sign_in_in_15_minutes_is_refused(rig: Rig) -> None:
    for _ in range(10):
        rig.clock.now += 30
        await rig.attempt()  # each fails at Cognito: no post-authentication
    rig.clock.now += 30
    with pytest.raises(SignInDenied) as refused:
        await rig.attempt()
    assert str(refused.value) == DENIED  # names no reason
    assert rig.rejections() == 1
    assert rig.queue.topics()[-1] == "sign_in.refused"
    # The first failure leaves the window 15 minutes after it: one more attempt is allowed then.
    rig.clock.now += 15 * MINUTE - 10 * 30
    await rig.attempt()


async def test_a_success_counts_no_failure_and_resets_none(rig: Rig) -> None:
    for _ in range(9):
        await rig.attempt()
    await rig.success()  # its own attempt is taken out again
    await rig.attempt()  # the 10th failure in the window
    with pytest.raises(SignInDenied):
        await rig.attempt()  # the 11th: the success didn't reset the 9 before it


async def test_accounts_are_counted_apart(rig: Rig) -> None:
    for _ in range(10):
        await rig.attempt()
    other = uuid.uuid4()
    await rig.triggers.handle(event(PRE_AUTHENTICATION, other, rig.tenant_id))


async def test_each_attempt_queues_its_record_and_a_delayed_check(rig: Rig) -> None:
    returned = await rig.attempt()
    assert returned["response"] == {}  # the event back, as Cognito expects
    [(attempted, now), (check, later)] = rig.queue.sent
    assert (attempted.topic, now) == ("sign_in.attempted", 0)
    assert (check.topic, later) == ("sign_in.check", 600)
    assert attempted.tenant_id == check.tenant_id == rig.tenant_id
    assert attempted.payload == check.payload
    assert attempted.payload["user_id"] == rig.user_id
    await rig.triggers.handle(event(POST_AUTHENTICATION, rig.user_id, rig.tenant_id))
    assert rig.queue.topics()[-1] == "sign_in.authenticated"


async def test_an_unknown_username_is_counted_nowhere_and_sends_nothing(rig: Rig) -> None:
    unknown = event(PRE_AUTHENTICATION, rig.user_id, rig.tenant_id, userNotFound=True)
    for _ in range(12):
        assert await rig.triggers.handle(unknown) is unknown
    assert rig.queue.sent == []
    not_ours = event(PRE_AUTHENTICATION, rig.user_id, rig.tenant_id)
    not_ours["userName"] = "someone@example.test"
    await rig.triggers.handle(not_ours)
    assert rig.queue.sent == []


async def test_another_trigger_source_is_refused(rig: Rig) -> None:
    with pytest.raises(SignInDenied):
        await rig.triggers.handle(event("PreSignUp_SignUp", rig.user_id, rig.tenant_id))


# ---- failing closed ----


async def test_with_the_counter_store_unreachable_sign_in_is_denied() -> None:
    store = CounterStore.connect(UNREACHABLE, CounterMetrics.create(CollectorRegistry()))
    queue = Queue()
    triggers = SignInTriggers(store, CounterMetrics.create(CollectorRegistry()), queue)
    user, tenant = uuid.uuid4(), uuid.uuid4()
    try:
        with pytest.raises(SignInDenied):
            await triggers.handle(event(PRE_AUTHENTICATION, user, tenant))
        with pytest.raises(SignInDenied):
            await triggers.handle(event(POST_AUTHENTICATION, user, tenant))
    finally:
        await store.close()
    assert queue.sent == []


async def test_with_the_queue_unreachable_sign_in_is_denied(rig: Rig) -> None:
    rig.queue.down = True
    with pytest.raises(SignInDenied):
        await rig.attempt()
    with pytest.raises(SignInDenied):
        await rig.triggers.handle(event(POST_AUTHENTICATION, rig.user_id, rig.tenant_id))


# ---- the audit trail, in the notification worker ----


@dataclass
class Worker:
    db: ScratchDatabase
    consumer: SignInEventsConsumer
    tenant_id: uuid.UUID
    user_id: uuid.UUID

    async def deliver(self, message: OutboxMessage) -> Outcome:
        parsed = self.consumer.parse(message.body())
        assert parsed is not None
        return await self.consumer.process(Delivery(parsed, 1, message.body()))

    def events(self) -> list[tuple[object, ...]]:
        return self.db.sql(
            "SELECT action, outcome, actor_type, target_type, details->>'system_actor', "
            "details->>'reason' FROM audit_events WHERE target_id = :id ORDER BY occurred_at, id",
            id=self.user_id,
        )


@pytest.fixture
async def worker(
    migrated_db: ScratchDatabase, counter_store: CounterStore
) -> AsyncIterator[Worker]:
    tenant_id = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id
    )
    user_id = seed_user(migrated_db, tenant_id)
    database = Database.connect(migrated_db.url(NOTIFY), pool_size=1)
    try:
        consumer = SignInEventsConsumer(database, SignInEvents(counter_store))
        yield Worker(migrated_db, consumer, tenant_id, user_id)
    finally:
        await database.dispose()


async def test_every_attempt_failure_and_success_reaches_the_audit_log(
    worker: Worker, counter_store: CounterStore
) -> None:
    queue, clock = Queue(), Clock()
    triggers = SignInTriggers(
        counter_store, CounterMetrics.create(CollectorRegistry()), queue, clock=clock
    )
    pre = event(PRE_AUTHENTICATION, worker.user_id, worker.tenant_id)
    post = event(POST_AUTHENTICATION, worker.user_id, worker.tenant_id)
    await triggers.handle(pre)  # fails at Cognito
    await triggers.handle(pre)
    await triggers.handle(post)  # succeeds
    for message, _ in queue.sent:  # the checks as if 10 minutes had passed
        assert await worker.deliver(message) is Outcome.PROCESSED
    rows = worker.events()
    actions = [(action, outcome) for action, outcome, *_ in rows]
    assert sorted(actions) == sorted(
        [
            ("sign_in.attempted", "success"),
            ("sign_in.failed", "failure"),  # the first attempt's check: still in the log
            ("sign_in.attempted", "success"),
            ("sign_in.authenticated", "success"),
        ]
    )
    assert {row[2:5] for row in rows} == {("system", "user", "signin_trigger")}
    # A redelivery is recorded once.
    assert await worker.deliver(queue.sent[0][0]) is Outcome.DUPLICATE


async def test_a_refusal_is_audited_with_its_reason(
    worker: Worker, counter_store: CounterStore
) -> None:
    queue = Queue()
    triggers = SignInTriggers(counter_store, CounterMetrics.create(CollectorRegistry()), queue)
    for _ in range(10):
        await triggers.handle(event(PRE_AUTHENTICATION, worker.user_id, worker.tenant_id))
    with pytest.raises(SignInDenied):
        await triggers.handle(event(PRE_AUTHENTICATION, worker.user_id, worker.tenant_id))
    [refused] = [m for m, _ in queue.sent if m.topic == "sign_in.refused"]
    await worker.deliver(refused)
    assert ("sign_in.refused", "failure") in [row[:2] for row in worker.events()]
    assert [row[5] for row in worker.events() if row[0] == "sign_in.refused"] == [
        "too_many_failures"
    ]


def test_only_sign_in_events_are_taken() -> None:
    other = OutboxMessage(uuid.uuid4(), "file.scan", uuid.uuid4(), {"file_id": uuid.uuid4()})
    with pytest.raises(InvalidMessageError):
        parse_message(other.body())
    with pytest.raises(InvalidMessageError):
        parse_message("not json")


def test_a_trigger_event_with_no_member_names_none() -> None:
    assert parse_trigger({}).user_id is None
    assert parse_trigger({"userName": "x", "request": "y"}).tenant_id is None
    missing_tenant = event(PRE_AUTHENTICATION, uuid.uuid4(), uuid.uuid4())
    missing_tenant["request"]["userAttributes"] = {}
    assert parse_trigger(missing_tenant).tenant_id is None


# ---- the Lambda Runtime API loop ----


@dataclass
class FakeRuntime:
    """The Lambda Runtime API on a real socket: hands out `events`, keeps the answers."""

    events: list[dict[str, Any] | str]
    answers: list[tuple[str, str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


def runtime_server(runtime: FakeRuntime) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            return

        def do_GET(self) -> None:
            with runtime.lock:
                index = len([a for a in runtime.answers if a[0] == "next"])
                runtime.answers.append(("next", str(index), None))
            item = runtime.events[index]
            body = (item if isinstance(item, str) else json.dumps(item)).encode()
            self.send_response(200)
            self.send_header("Lambda-Runtime-Aws-Request-Id", f"req-{index}")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            length = int(self.headers["Content-Length"])
            body = json.loads(self.rfile.read(length))
            kind = self.path.rsplit("/", 1)[-1]
            request_id = self.path.split("/")[-2]
            with runtime.lock:
                runtime.answers.append((kind, request_id, body))
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()

    return ThreadingHTTPServer(("127.0.0.1", 0), Handler)


@pytest.fixture
def runtime() -> Iterator[tuple[FakeRuntime, RuntimeApi]]:
    fake = FakeRuntime(events=[])
    server = runtime_server(fake)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield fake, RuntimeApi(f"127.0.0.1:{server.server_address[1]}")
    finally:
        server.shutdown()
        server.server_close()


async def test_the_runtime_loop_answers_each_invocation(
    runtime: tuple[FakeRuntime, RuntimeApi],
) -> None:
    fake, api = runtime
    fake.events = [{"ok": True}, {"deny": True}, "not json", {"boom": True}]

    async def handler(event: dict[str, Any]) -> dict[str, Any]:
        if event.get("deny"):
            raise SignInDenied
        if event.get("boom"):
            raise RuntimeError("unexpected")
        return event

    await serve(api, handler, invocations=4)
    answers = [(kind, rid, body) for kind, rid, body in fake.answers if kind != "next"]
    assert answers[0] == ("response", "req-0", {"ok": True})
    for kind, _, body in answers[1:]:
        # A refusal, a bad event and an unexpected error all refuse the sign-in, the same way.
        assert kind == "error"
        assert body == {"errorType": "SignInDenied", "errorMessage": DENIED}


def test_the_trigger_settings_need_tls_and_no_password_with_iam() -> None:
    base = {"sqs_queue_prefix": "sft-dev-apne1-"}
    ok = SignInTriggerSettings(
        valkey_url="rediss://sft-dev-signin-trigger@cache.example:6379",  # type: ignore[arg-type]
        valkey_iam_cache="sft-dev-apne1-valkey",
        **base,
    )
    assert ok.valkey_iam_cache == "sft-dev-apne1-valkey"
    with pytest.raises(ValidationError, match="TLS"):
        SignInTriggerSettings(
            valkey_url="redis://sft-dev-signin-trigger@cache.example:6379",  # type: ignore[arg-type]
            valkey_iam_cache="sft-dev-apne1-valkey",
            **base,
        )
