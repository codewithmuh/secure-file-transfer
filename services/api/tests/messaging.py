"""Helpers for the outbox, relay and consumer tests: an in-memory SQS and pools per role."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

from pg import ScratchDatabase
from sft.data.database import Database
from sft.workers.queues import (
    MAX_BATCH,
    OutgoingMessage,
    QueueError,
    ReceivedMessage,
    SendFailure,
)


@dataclass
class Sent:
    queue: str
    message: OutgoingMessage


@dataclass
class FakeQueues:
    """`Queues` in memory. Messages stay until deleted; every receive hands out all of them.

    `refuse` maps a message ID to the error code SQS gives for it; `poison` makes SQS refuse any
    whole batch that holds one of these IDs, as for a message too long; `outage` fails whole
    calls; `after_send` runs once a batch is "sent", so a test can crash the relay at that point.
    """

    sent: list[Sent] = field(default_factory=list)
    refuse: dict[str, str] = field(default_factory=dict)
    poison: set[str] = field(default_factory=set)
    calls: int = 0
    outage: str | None = None
    send_delay: float = 0.0
    """Seconds each send takes, as a slow SQS would."""
    fail_delete: set[str] = field(default_factory=set)
    after_send: Callable[[], None] | None = None
    deleted: list[str] = field(default_factory=list)
    receives: dict[str, int] = field(default_factory=dict)
    closed: bool = False

    async def send_batch(
        self, queue: str, messages: Sequence[OutgoingMessage]
    ) -> list[SendFailure]:
        assert 1 <= len(messages) <= MAX_BATCH
        self.calls += 1
        if self.send_delay:
            await asyncio.sleep(self.send_delay)
        if self.outage:
            raise QueueError(self.outage)
        if any(m.id in self.poison for m in messages):
            raise QueueError("BatchRequestTooLong", sender_fault=True)
        failures = [SendFailure(m.id, self.refuse[m.id]) for m in messages if m.id in self.refuse]
        refused = {f.id for f in failures}
        self.sent.extend(Sent(queue, m) for m in messages if m.id not in refused)
        if self.after_send is not None:
            self.after_send()
        return failures

    def bodies(self, queue: str | None = None) -> list[str]:
        return [s.message.body for s in self.sent if queue is None or s.queue == queue]

    async def receive(
        self, queue: str, *, max_messages: int, wait_seconds: int
    ) -> list[ReceivedMessage]:
        if self.outage:
            raise QueueError(self.outage)
        out = []
        for index, item in enumerate(self.sent):
            handle = f"{index}"
            if item.queue != queue or handle in self.deleted:
                continue
            self.receives[handle] = self.receives.get(handle, 0) + 1
            out.append(ReceivedMessage(item.message.body, handle, self.receives[handle]))
            if len(out) == max_messages:
                break
        return out

    async def delete(self, queue: str, receipt_handle: str) -> None:
        if receipt_handle in self.fail_delete:
            raise QueueError("ServiceUnavailable")
        self.deleted.append(receipt_handle)

    async def close(self) -> None:
        self.closed = True


@asynccontextmanager
async def pool(db: ScratchDatabase, role: str, size: int = 1) -> AsyncIterator[Database]:
    database = Database.connect(db.url(role), pool_size=size)
    try:
        yield database
    finally:
        await database.dispose()


def clear_messaging(db: ScratchDatabase) -> None:
    """The session's database is shared, so each test starts with an empty outbox."""
    db.sql("DELETE FROM outbox")
    db.sql("DELETE FROM processed_messages")
