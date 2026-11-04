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

`ConsumerLoop` long-polls the queue, deletes each message once it is processed or skipped, and
leaves a message that failed for SQS to deliver again after its visibility timeout; after 5
receives the redrive policy moves it to the dead-letter queue, which alerts. `handle` sees
`receive_count`, so its last attempt can record a terminal state such as `scan_failed` first.

A handler whose effect is outside PostgreSQL, such as an email, can't share the transaction; the
notification worker records the message after the send instead (ADR-0013, data model 2.2).
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

from sft.core.logs import bind_context
from sft.data.database import Database
from sft.data.outbox import InvalidMessageError, OutboxMessage, Queue
from sft.data.processed import record_processed
from sft.data.scope import Scope
from sft.workers.queues import QueueError, Queues, ReceivedMessage

log = logging.getLogger(__name__)

LONG_POLL_SECONDS = 20
"""SQS's longest wait, as the queues are configured (ADR-0013)."""


class Outcome(StrEnum):
    PROCESSED = "processed"
    DUPLICATE = "duplicate"
    FAILED = "failed"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class Delivery:
    """A message as a handler sees it: the outbox message and how often SQS has handed it out."""

    message: OutboxMessage
    receive_count: int = 1


class Consumer(ABC):
    """The base of every work-queue consumer: one transaction, recorded first, handled once."""

    name: ClassVar[str]
    """The `consumer` in `processed_messages`, e.g. `scan-small`. Never change it: a new name
    would treat every message seen before as new."""
    queue: ClassVar[Queue]

    def __init__(self, database: Database) -> None:
        self.database = database

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
                "failed (delivered again) or invalid (left for the dead-letter queue).",
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
    ) -> None:
        self.consumer = consumer
        self.queues = queues
        self.metrics = metrics
        self.max_messages = max_messages
        self.wait_seconds = wait_seconds

    async def poll_once(self) -> list[Outcome]:
        """One receive, and every message it returned; the outcome of each."""
        received = await self.queues.receive(
            self.consumer.queue, max_messages=self.max_messages, wait_seconds=self.wait_seconds
        )
        return [await self._one(item) for item in received]

    async def _one(self, item: ReceivedMessage) -> Outcome:
        outcome = await self._process(item)
        self.metrics.messages.labels(self.consumer.name, outcome).inc()
        if outcome in (Outcome.PROCESSED, Outcome.DUPLICATE):
            # Deleted only after the commit. A crash before this line redelivers the message,
            # and the record makes the second delivery a duplicate.
            await self.queues.delete(self.consumer.queue, item.receipt_handle)
        return outcome

    async def _process(self, item: ReceivedMessage) -> Outcome:
        try:
            message = OutboxMessage.from_body(item.body)
        except InvalidMessageError as exc:
            # Never deleted: after 5 receives it lands in the dead-letter queue, which alerts.
            log.error(
                "invalid message left for the dead-letter queue",
                extra={"consumer": self.consumer.name, "error": str(exc)},
            )
            return Outcome.INVALID
        bind_context(request_id=None, trace_id=message.trace_context.get("trace_id"))
        extra = {
            "consumer": self.consumer.name,
            "outbox_id": str(message.id),
            "topic": message.topic,
            "tenant_id": str(message.tenant_id),
            "receive_count": item.receive_count,
        }
        try:
            outcome = await self.consumer.process(Delivery(message, item.receive_count))
            log.info(f"message {outcome}", extra=extra)
        except Exception:
            log.exception("message failed; SQS delivers it again", extra=extra)
            outcome = Outcome.FAILED
        finally:
            bind_context(request_id=None, trace_id=None)
        return outcome

    async def run(self, stopping: asyncio.Event) -> None:
        """Poll until `stopping` is set. A long poll in flight finishes first (at most 20 s)."""
        while not stopping.is_set():
            try:
                await self.poll_once()
            except QueueError as exc:
                log.warning("receive failed; trying again", extra={"code": exc.code})
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stopping.wait(), timeout=1.0)
