"""Idempotent consumers of the work queues (ADR-0013).

A consumer subclasses `Consumer` and writes `handle`, which does the message's work in the
session it is given:

    class ScanConsumer(Consumer):
        name = "scan-small"
        queue = Queue.SCAN_SMALL

        async def handle(self, session: AsyncSession, message: OutboxMessage) -> None:
            file = await files.get(session, message.payload["file_id"])
            ...  # re-read the state; the message is only a prompt (threat model T-50)

    await ConsumerLoop(ScanConsumer(database), queues, metrics).run(stopping)

`Consumer.process` opens one transaction in the message's tenant scope, records
`(name, message ID)` in `processed_messages` first, then runs `handle`; both commit together or
not at all. A copy of a message already recorded is skipped, so a relay retry, an SQS duplicate or
a re-publish after a failover does the work once. The message ID is the outbox row's, not SQS's.

`ConsumerLoop` long-polls the queue (abandoning the poll at once on shutdown), deletes each message
once it is processed or skipped, and leaves a message that failed for SQS to deliver again after its
visibility timeout; after 5 receives the redrive policy moves it to the dead-letter queue, which
alerts. `handle` sees `receive_count`, so its last attempt can record a terminal state such as
`scan_failed` first. With `heartbeat_seconds`, the loop keeps the message in hand hidden while it
works, extending its visibility every `heartbeat_seconds` to twice that: a scan can outlast the
queue's visibility timeout without a second worker taking the same file. A failed extension is
only logged: the message may then come back as a duplicate, which the record makes harmless.

A consumer whose work can't run inside one transaction overrides `process` (the scan worker: its
scan runs between two short transactions, data model 2.5) and records the message itself, with
`record_processed`, in the transaction that commits the work.

A handler whose effect is outside PostgreSQL, such as an email, can't share the transaction; the
notification worker records the message after the send instead (ADR-0013, data model 2.2).

Each message that parses is handled in a `process <queue>` CONSUMER span, the child of the span
that wrote the message (its `trace_context`, ADR-0009), so the API request's trace runs on through
the queue to the handler's own SQL, and the handler's log lines carry that trace ID. The span
carries the consumer, the queue and the outbox ID, never the payload or the tenant.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from prometheus_client import CollectorRegistry, Counter
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.telemetry import continued_trace, mark_error, messaging_attributes
from sft.data.database import Database
from sft.data.outbox import InvalidMessageError, OutboxMessage, Queue
from sft.data.processed import record_processed
from sft.data.scope import Scope
from sft.workers.process import sleep_unless
from sft.workers.queues import QueueError, Queues, ReceivedMessage

log = logging.getLogger(__name__)

LONG_POLL_SECONDS = 20
"""SQS's longest wait, as the queues are configured (ADR-0013)."""


class Outcome(StrEnum):
    PROCESSED = "processed"
    DUPLICATE = "duplicate"
    FAILED = "failed"
    INVALID = "invalid"
    IGNORED = "ignored"


@dataclass(frozen=True, slots=True)
class Delivery:
    """A message as a handler sees it: the outbox message and how often SQS has handed it out."""

    message: OutboxMessage
    receive_count: int = 1
    body: str = ""
    """The body as received, for a consumer whose queue carries more than the envelope (SES's
    events, `sft.service.ses_events`)."""


class Consumer(ABC):
    """The base of every work-queue consumer: one transaction, recorded first, handled once."""

    name: ClassVar[str]
    """The `consumer` in `processed_messages`, e.g. `scan-small`. Never change it: a new name
    would treat every message seen before as new."""
    queue: ClassVar[Queue]

    def __init__(self, database: Database) -> None:
        self.database = database

    def parse(self, body: str) -> OutboxMessage | None:
        """The message in a received body, or `InvalidMessageError`. A queue that isn't the
        outbox's (SES's events) overrides it; None is a message to delete unhandled."""
        return OutboxMessage.from_body(body)

    @abstractmethod
    async def handle(self, session: AsyncSession, delivery: Delivery) -> None:
        """Do the message's work in `session`, in the message's tenant scope. Raise to retry."""

    async def process(self, delivery: Delivery) -> Outcome:
        """Handle the message once: `PROCESSED`, or `DUPLICATE` if it was handled before.

        An exception from `handle` rolls the whole transaction back, the record included, and
        propagates, so the message is delivered again.
        """
        message = delivery.message
        async with self.database.transaction(Scope.tenant(message.tenant_id)) as session:
            if not await record_processed(session, consumer=self.name, message_id=str(message.id)):
                return Outcome.DUPLICATE
            await self.handle(session, delivery)
        return Outcome.PROCESSED


@dataclass(frozen=True)
class ConsumerMetrics:
    messages: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> ConsumerMetrics:
        return cls(
            Counter(
                "worker_messages_total",
                "Messages received, by consumer and outcome: processed, duplicate (skipped), "
                "failed (delivered again), invalid (left for the dead-letter queue) or ignored "
                "(nothing to do: deleted).",
                ["consumer", "outcome"],
                registry=registry,
            )
        )


class ConsumerLoop:
    """Receives a consumer's queue and processes each message, one at a time."""

    def __init__(
        self,
        consumer: Consumer,
        queues: Queues,
        metrics: ConsumerMetrics,
        *,
        max_messages: int = 10,
        wait_seconds: int = LONG_POLL_SECONDS,
        heartbeat_seconds: int | None = None,
    ) -> None:
        self.consumer = consumer
        self.queues = queues
        self.metrics = metrics
        self.max_messages = max_messages
        self.wait_seconds = wait_seconds
        self.heartbeat_seconds = heartbeat_seconds

    async def receive(self) -> list[ReceivedMessage]:
        return await self.queues.receive(
            self.consumer.queue, max_messages=self.max_messages, wait_seconds=self.wait_seconds
        )

    async def poll_once(self) -> list[Outcome]:
        """One receive, and every message it returned; the outcome of each."""
        return await self.handle_all(await self.receive())

    async def handle_all(self, received: list[ReceivedMessage]) -> list[Outcome]:
        """Each message on its own: one that fails, or whose delete fails, never stops the rest."""
        return [await self._one(item) for item in received]

    async def _one(self, item: ReceivedMessage) -> Outcome:
        heartbeat = (
            None
            if self.heartbeat_seconds is None
            else asyncio.create_task(self._heartbeat(item, self.heartbeat_seconds))
        )
        try:
            outcome = await self._process(item)
        except Exception:
            # Anything _process didn't expect. The message isn't deleted, so SQS delivers it
            # again and, after 5 receives, the redrive policy moves it to the dead-letter queue.
            log.exception("message failed; SQS delivers it again", extra=self._extra())
            outcome = Outcome.FAILED
        finally:
            if heartbeat is not None:
                heartbeat.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await heartbeat
        self.metrics.messages.labels(self.consumer.name, outcome).inc()
        return outcome

    async def _heartbeat(self, item: ReceivedMessage, seconds: int) -> None:
        while True:
            await asyncio.sleep(seconds)
            try:
                await self.queues.extend_visibility(
                    self.consumer.queue, item.receipt_handle, 2 * seconds
                )
            except QueueError as exc:
                log.warning(
                    "visibility not extended; the message may come back as a duplicate",
                    extra={**self._extra(), "code": exc.code},
                )

    def _extra(self) -> dict[str, object]:
        return {"consumer": self.consumer.name}

    async def _process(self, item: ReceivedMessage) -> Outcome:
        try:
            message = self.consumer.parse(item.body)
        except InvalidMessageError as exc:
            # Never deleted: after 5 receives it lands in the dead-letter queue, which alerts.
            log.error(
                "invalid message left for the dead-letter queue",
                extra={"consumer": self.consumer.name, "error": str(exc)},
            )
            return Outcome.INVALID
        if message is None:
            try:
                await self.queues.delete(self.consumer.queue, item.receipt_handle)
            except QueueError as exc:
                log.warning("delete failed", extra={**self._extra(), "code": exc.code})
            return Outcome.IGNORED
        extra = {
            "consumer": self.consumer.name,
            "outbox_id": str(message.id),
            "topic": message.topic,
            "tenant_id": str(message.tenant_id),
            "receive_count": item.receive_count,
        }
        queue = self.consumer.queue.value
        attributes = {
            **messaging_attributes("process", queue),
            "messaging.consumer.group.name": self.consumer.name,
            "messaging.message.id": str(message.id),
        }
        # The work, its log lines and the delete all run in the message's own trace (module
        # docstring); the trace ID stays bound to the logs only while the span is open.
        with continued_trace(
            message.trace_context, f"process {queue}", attributes=attributes
        ) as span:
            try:
                outcome = await self.consumer.process(
                    Delivery(message, item.receive_count, item.body)
                )
                log.info(f"message {outcome}", extra=extra)
            except Exception as exc:
                log.exception("message failed; SQS delivers it again", extra=extra)
                mark_error(span, type(exc).__qualname__)
                return Outcome.FAILED
            if outcome in (Outcome.PROCESSED, Outcome.DUPLICATE):
                # Deleted only after the commit. If the delete fails, or the process dies first,
                # SQS redelivers the message and the record makes the second delivery a duplicate.
                try:
                    await self.queues.delete(self.consumer.queue, item.receipt_handle)
                except QueueError as exc:
                    log.warning(
                        "delete failed; the message comes back as a duplicate",
                        extra={**extra, "code": exc.code},
                    )
        return outcome

    async def run(self, stopping: asyncio.Event) -> None:
        """Poll until `stopping` is set.

        A long poll in flight is abandoned the moment `stopping` is set, so shutdown never waits
        for it: messages that poll would have returned stay invisible until their visibility
        timeout, then come back. A message already being handled finishes first, within the drain.
        """
        while not stopping.is_set():
            receive = asyncio.create_task(self.receive())
            stop = asyncio.create_task(stopping.wait())
            await asyncio.wait({receive, stop}, return_when=asyncio.FIRST_COMPLETED)
            stop.cancel()
            if not receive.done():
                receive.cancel()
                with contextlib.suppress(asyncio.CancelledError, QueueError):
                    await receive
                return
            try:
                received = receive.result()
            except QueueError as exc:
                log.warning("receive failed; trying again", extra={"code": exc.code})
                await sleep_unless(stopping, 1.0)
                continue
            await self.handle_all(received)
