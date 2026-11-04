"""The transactional outbox: work for the workers, committed with the change that causes it.

A service function writes the message in its own transaction (architecture 5.3, ADR-0013):

    async with database.transaction(Scope.tenant(tenant_id)) as session:
        ...  # the state change, and its audit event
        await enqueue(session, SCAN_SMALL_FILE, {"file_id": file.id})

Both commit or neither does. The outbox relay (`sft.workers.relay`) later claims the row, sends it
to its topic's queue and marks it published. Delivery is at least once, so every consumer is
idempotent (`sft.data.processed`).

A message is the contract of ADR-0013: its topic, its outbox ID, its tenant, the IDs of the rows to
act on and the trace context, nothing more. The payload accepts only UUIDs, so a link token, a
code, an email address or a file name can't reach a queue (threat model T-49): a worker re-reads
everything else from PostgreSQL in the message's tenant scope.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from enum import StrEnum
from typing import Any, Final, cast
from uuid import UUID

from sqlalchemy import Integer, Update, func, insert, select, update
from sqlalchemy import cast as sql_cast
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.core.logs import trace_id_var
from sft.data.access import in_scope, tenant_of
from sft.data.models import Outbox

MAX_DELAY: Final = timedelta(minutes=15)
"""SQS's longest per-message delay (ADR-0013). Work that must wait longer re-sends itself."""

MAX_IDS: Final = 100
"""IDs in one payload value. Messages stay small (capacity 3.1: under 1 KB each)."""

_KEY = re.compile(r"[a-z][a-z0-9_]{0,62}")
_TOPIC = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+")
_TRACE_ID = re.compile(r"[0-9a-f]{32}")

PayloadValue = UUID | Sequence[UUID]
Payload = Mapping[str, PayloadValue]


class Queue(StrEnum):
    """The work queues of ADR-0013. Each environment's queue is `{prefix}{value}`, e.g.
    `sft-dev-notify`; its dead-letter queue is `{prefix}{value}-dlq`."""

    SCAN_SMALL = "scan-small"
    SCAN_LARGE = "scan-large"
    NOTIFY = "notify"

    @property
    def fair(self) -> bool:
        """A fair queue: the relay sends the tenant as the message group (ADR-0013)."""
        return self in (Queue.SCAN_SMALL, Queue.SCAN_LARGE)


@dataclass(frozen=True, slots=True)
class Topic:
    """A kind of message, and the queue that carries it. Name it `<subject>.<event>`."""

    name: str
    queue: Queue

    def __post_init__(self) -> None:
        if not _TOPIC.fullmatch(self.name):
            raise ValueError(f"a topic is named like 'file.scan', not {self.name!r}")


def topic_registry(*topics: Topic) -> Mapping[str, Topic]:
    """The topics by name, for the relay to route rows by; a name may appear once."""
    registry: dict[str, Topic] = {}
    for topic in topics:
        if topic.name in registry:
            raise ValueError(f"topic {topic.name!r} is defined twice")
        registry[topic.name] = topic
    return registry


TOPICS: Final[Mapping[str, Topic]] = topic_registry()
"""Every topic the service sends. Each feature adds its topics here, with the queue that carries
them: scans (M2) on `Queue.SCAN_SMALL` and `Queue.SCAN_LARGE`, emails (M1, M2) on `Queue.NOTIFY`.
The relay leaves a row whose topic isn't here unpublished and counts it as a failure, which the
outbox age alert then shows, rather than drop it (an older relay during a rolling deploy)."""


class InvalidMessageError(ValueError):
    """A payload or a received message body that breaks the message contract."""


def _payload_json(payload: Payload) -> dict[str, str | list[str]]:
    if not isinstance(payload, Mapping):
        raise InvalidMessageError("the payload maps names to IDs")
    out: dict[str, str | list[str]] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise InvalidMessageError(f"payload names are lower-case identifiers, not {key!r}")
        if isinstance(value, UUID):
            out[key] = str(value)
        elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
            if len(value) > MAX_IDS:
                raise InvalidMessageError(f"{key}: at most {MAX_IDS} IDs")
            if not all(isinstance(item, UUID) for item in value):
                raise InvalidMessageError(f"{key}: the payload carries only IDs (UUIDs)")
            out[key] = [str(item) for item in value]
        else:
            raise InvalidMessageError(f"{key}: the payload carries only IDs (UUIDs)")
    return out


def _payload_from_json(raw: object) -> dict[str, PayloadValue]:
    if not isinstance(raw, dict):
        raise InvalidMessageError("the payload is an object")
    out: dict[str, PayloadValue] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise InvalidMessageError("payload names are lower-case identifiers")
        try:
            if isinstance(value, str):
                out[key] = UUID(value)
            elif (
                isinstance(value, list)
                and len(value) <= MAX_IDS
                and all(isinstance(item, str) for item in value)
            ):
                out[key] = tuple(UUID(item) for item in value)
            else:
                raise InvalidMessageError(f"{key}: the payload carries only IDs")
        except (ValueError, AttributeError) as exc:
            raise InvalidMessageError(f"{key}: not an ID") from exc
    return out


def _trace_context() -> dict[str, str]:
    # OpenTelemetry (ADR-0009) will put a W3C `traceparent` here. Until then the trace ID of the
    # request or message being handled is enough to join the logs of the API and the worker.
    trace_id = trace_id_var.get()
    return {"trace_id": trace_id} if trace_id and _TRACE_ID.fullmatch(trace_id) else {}


def _delay_seconds(delay: timedelta) -> int:
    if delay < timedelta(0) or delay > MAX_DELAY:
        raise ValueError("a delay is between 0 and 15 minutes (SQS's limit, ADR-0013)")
    return math.ceil(delay.total_seconds())


async def enqueue(
    session: AsyncSession,
    topic: Topic,
    payload: Payload,
    *,
    delay: timedelta = timedelta(0),
) -> UUID:
    """Write a message in the session's transaction, for the message's tenant; return its ID.

    The tenant is the transaction's own (`tenant_of`, a tenant scope), so a message can't name
    another tenant. `delay` holds the message back: no consumer receives it before the transaction
    started plus `delay`, at most 15 minutes. The ID is what a consumer records in
    `processed_messages`, so a re-sent copy is recognised.
    """
    tenant_id = tenant_of(session)  # the scope's tenant; refuses system and platform scopes
    message_id = uuid7()
    await session.execute(
        insert(Outbox).values(
            id=message_id,
            tenant_id=tenant_id,
            topic=topic.name,
            payload=_payload_json(payload),
            trace_context=_trace_context(),
            delay_seconds=_delay_seconds(delay),
        )
    )
    return message_id


@dataclass(frozen=True, slots=True)
class OutboxMessage:
    """A message as it travels through SQS: the body the relay sends and a consumer receives."""

    id: UUID
    topic: str
    tenant_id: UUID
    payload: Mapping[str, PayloadValue]
    trace_context: Mapping[str, str] = field(default_factory=dict)

    def body(self) -> str:
        return json.dumps(
            {
                "id": str(self.id),
                "topic": self.topic,
                "tenant_id": str(self.tenant_id),
                "payload": _payload_json(self.payload),
                "trace_context": dict(self.trace_context),
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def from_body(cls, body: str) -> OutboxMessage:
        """Parse a received body, or raise `InvalidMessageError`; nothing else is trusted."""
        try:
            raw = json.loads(body)
        except ValueError as exc:
            raise InvalidMessageError("the body is not JSON") from exc
        if not isinstance(raw, dict) or set(raw) != {
            "id",
            "topic",
            "tenant_id",
            "payload",
            "trace_context",
        }:
            raise InvalidMessageError("the body has exactly the fields of ADR-0013")
        topic, trace = raw["topic"], raw["trace_context"]
        if not isinstance(topic, str) or not _TOPIC.fullmatch(topic):
            raise InvalidMessageError("not a topic")
        if not isinstance(trace, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in trace.items()
        ):
            raise InvalidMessageError("the trace context maps names to strings")
        try:
            message_id, tenant_id = UUID(raw["id"]), UUID(raw["tenant_id"])
        except (ValueError, TypeError, AttributeError) as exc:
            raise InvalidMessageError("the message and tenant IDs are UUIDs") from exc
        return cls(
            id=message_id,
            topic=topic,
            tenant_id=tenant_id,
            payload=_payload_from_json(raw["payload"]),
            trace_context=cast(dict[str, str], trace),
        )


# ---- the relay's side, in system scope (authentication and authorization 7.3) ----


@dataclass(frozen=True, slots=True)
class DueRow:
    """An unpublished row the relay has claimed, locked until its transaction ends."""

    message: OutboxMessage
    attempts: int
    remaining_delay: int
    """Seconds of its delay still to run, for SQS's DelaySeconds: the delay counts from when the
    row was written, not from when the relay got to it."""
    error: str | None = None
    """Why the row can't be sent, such as a payload that breaks the contract (written by hand, not
    by `enqueue`). The relay counts it as a failed send, so it can't hold up the rows behind it."""


async def claim_due(session: AsyncSession, limit: int) -> list[DueRow]:
    """Lock up to `limit` unpublished rows that are due, oldest first, skipping locked ones.

    `FOR UPDATE SKIP LOCKED` lets several relays run side by side: each claims rows no other
    transaction holds, and a relay that dies releases its rows when its connection ends.
    """
    elapsed = func.extract("epoch", func.now() - Outbox.created_at)
    remaining = func.greatest(
        0, sql_cast(func.ceil(Outbox.delay_seconds - elapsed), Integer)
    ).label("remaining")
    rows = await session.execute(
        select(
            Outbox.id,
            Outbox.topic,
            Outbox.tenant_id,
            Outbox.payload,
            Outbox.trace_context,
            Outbox.attempts,
            remaining,
        )
        .where(
            Outbox.published_at.is_(None),
            Outbox.next_attempt_at <= func.now(),
            # In system scope the session lets only the relay write tenant rows (check_write).
            in_scope(Outbox, session),
        )
        .order_by(Outbox.created_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    due = []
    for row in rows:
        error = None
        try:
            payload = _payload_from_json(row.payload)
        except InvalidMessageError:
            payload, error = {}, "invalid_payload"
        message = OutboxMessage(
            id=row.id,
            topic=row.topic,
            tenant_id=row.tenant_id,
            payload=payload,
            trace_context=cast(dict[str, str], row.trace_context),
        )
        due.append(DueRow(message, row.attempts, int(row.remaining), error))
    return due


def _scoped_update(session: AsyncSession) -> Update:
    """Every UPDATE of the outbox starts here, inside the scope.

    `in_scope` keeps it to the session's scope, and the session itself refuses a system-scope
    write to tenant rows by any role but the relay (`sft.data.access.check_write`).
    """
    return update(Outbox).where(in_scope(Outbox, session))


async def mark_published(session: AsyncSession, ids: Sequence[UUID]) -> None:
    if ids:
        await session.execute(
            _scoped_update(session).where(Outbox.id.in_(ids)).values(published_at=func.now())
        )


async def mark_failed(session: AsyncSession, id_: UUID, *, error: str, retry_in: float) -> None:
    """Record a failed send; the relay tries the row again `retry_in` seconds from now."""
    await session.execute(
        _scoped_update(session)
        .where(Outbox.id == id_)
        .values(
            attempts=Outbox.attempts + 1,
            next_attempt_at=func.now() + timedelta(seconds=retry_in),
            last_error=error[:200],
        )
    )


async def oldest_unpublished_age(session: AsyncSession) -> float:
    """Seconds since the oldest unpublished row was written; 0 when every row is published.

    The alert of ADR-0013 fires above 2 minutes. Delayed rows count from when they were written
    too: the relay sends them at once and SQS holds them, so they don't age in the outbox.
    """
    age: Any = await session.scalar(
        select(func.extract("epoch", func.now() - func.min(Outbox.created_at))).where(
            Outbox.published_at.is_(None), in_scope(Outbox, session)
        )
    )
    return max(0.0, float(age)) if age is not None else 0.0
