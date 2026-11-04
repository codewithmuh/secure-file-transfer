"""The outbox relay: publishes outbox rows to SQS (ADR-0013, architecture 5.3).

`python -m sft.workers.relay`, with `RelaySettings` from the environment, in the same image as the
API. It runs as `sft_relay`, in system scope: the one role that reads and marks every tenant's
outbox rows, and the only sender to the work queues.

Each batch is one short transaction:

1. claim up to `RELAY_BATCH_SIZE` due rows, oldest first, `FOR UPDATE SKIP LOCKED`;
2. send them to their topics' queues, up to 10 per call, one call per queue at a time, each with
   the part of its delay that is left and, on a fair queue, its tenant as the message group;
3. mark the rows SQS accepted as published, and give each refused row a growing wait before it is
   tried again (2 s doubling to 5 minutes, with jitter). When SQS refuses a whole batch for
   something in it, each of its rows is sent on its own, so one bad row can't hold up the others;
4. commit, and update the outbox age metric.

A crash anywhere before the commit loses nothing: the rows stay unpublished and their locks end
with the connection, so this relay or another sends them again. A crash after the send and before
the commit sends them twice, which consumers expect (`sft.workers.consumer`). Several replicas run
side by side; `SKIP LOCKED` keeps them off each other's rows.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, RelaySettings, load_settings
from sft.data.database import Database
from sft.data.outbox import (
    TOPICS,
    DueRow,
    Topic,
    claim_due,
    mark_failed,
    mark_published,
    oldest_unpublished_age,
)
from sft.data.scope import Scope
from sft.workers.process import WorkerProcess
from sft.workers.queues import MAX_BATCH, OutgoingMessage, QueueError, Queues, SqsQueues

log = logging.getLogger("sft.workers.relay")  # not __main__ under python -m


RETRY_BASE_SECONDS = 2.0
RETRY_MAX_SECONDS = 300.0
"""A row SQS refuses waits 2 s, then 4, 8 … up to 5 minutes between tries. The outbox age alert
fires at 2 minutes (ADR-0013), long before a row reaches the cap."""

ERROR_PAUSE_SECONDS = (1.0, 30.0)
"""The relay's own pause after a batch fails as a whole (the database is down, say): from 1 s,
doubling, up to 30 s."""


def retry_delay(attempts: int, *, jitter: float | None = None) -> float:
    """Seconds before a row that has failed `attempts` times before this one is tried again."""
    base = min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * 2.0 ** min(attempts, 16))
    # Up to half of it at random, so rows that failed together don't come back together.
    share = random.random() if jitter is None else jitter  # noqa: S311 - not a secret
    return base * (1 - share / 2)


@dataclass(frozen=True)
class RelayMetrics:
    published: Counter
    failed: Counter
    oldest_unpublished_age: Gauge
    batch_duration: Histogram

    @classmethod
    def create(cls, registry: CollectorRegistry) -> RelayMetrics:
        return cls(
            published=Counter(
                "outbox_messages_published_total",
                "Outbox rows sent to SQS and marked published.",
                ["queue"],
                registry=registry,
            ),
            failed=Counter(
                "outbox_publish_failures_total",
                "Sends that failed; the row is tried again later. `queue` is `unknown` for a "
                "topic this relay doesn't know or a row that breaks the message contract.",
                ["queue"],
                registry=registry,
            ),
            oldest_unpublished_age=Gauge(
                "outbox_oldest_unpublished_age_seconds",
                "Age of the oldest unpublished outbox row, after the relay's last batch; the "
                "alert fires above 120 s (ADR-0013).",
                registry=registry,
            ),
            batch_duration=Histogram(
                "outbox_relay_batch_duration_seconds",
                "One batch: claim, send and mark, in one transaction.",
                buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
                registry=registry,
            ),
        )


class Relay:
    def __init__(
        self,
        database: Database,
        queues: Queues,
        metrics: RelayMetrics,
        *,
        topics: Mapping[str, Topic] = TOPICS,
        batch_size: int = 50,
        poll_interval: float = 1.0,
    ) -> None:
        self.database = database
        self.queues = queues
        self.metrics = metrics
        self.topics = topics
        self.batch_size = batch_size
        self.poll_interval = poll_interval

    async def publish_batch(self) -> int:
        """Claim, send and mark one batch in one transaction; return how many rows it claimed."""
        with self.metrics.batch_duration.time():
            async with self.database.transaction(Scope.system()) as session:
                due = await claim_due(session, self.batch_size)
                failures = await self._send(due) if due else {}
                await mark_published(
                    session, [row.message.id for row in due if row.message.id not in failures]
                )
                for row in due:
                    if row.message.id in failures:
                        await mark_failed(
                            session,
                            row.message.id,
                            error=failures[row.message.id],
                            retry_in=retry_delay(row.attempts),
                        )
                age = await oldest_unpublished_age(session)
        self.metrics.oldest_unpublished_age.set(age)
        return len(due)

    async def _send(self, due: list[DueRow]) -> dict[UUID, str]:
        """Send every claimed row; the rows that failed, with the error code."""
        failures: dict[UUID, str] = {}
        by_queue: dict[str, list[DueRow]] = {}
        for row in due:
            if row.error is not None:
                failures[row.message.id] = row.error
                self.metrics.failed.labels("unknown").inc()
                log.error(
                    "outbox row that breaks the message contract left unpublished",
                    extra={"outbox_id": str(row.message.id), "error": row.error},
                )
                continue
            topic = self.topics.get(row.message.topic)
            if topic is None:
                failures[row.message.id] = "unknown_topic"
                self.metrics.failed.labels("unknown").inc()
                log.error(
                    "outbox row with an unknown topic left unpublished",
                    extra={"outbox_id": str(row.message.id), "topic": row.message.topic},
                )
                continue
            by_queue.setdefault(topic.queue, []).append(row)

        calls = []
        for queue, rows in by_queue.items():
            fair = self.topics[rows[0].message.topic].queue.fair
            for start in range(0, len(rows), MAX_BATCH):
                calls.append((queue, fair, rows[start : start + MAX_BATCH]))
        # The calls run side by side, so the transaction lasts about as long as the slowest one.
        results = await asyncio.gather(
            *(self._send_chunk(queue, fair, rows) for queue, fair, rows in calls)
        )
        for (queue, _, rows), result in zip(calls, results, strict=True):
            sent = len(rows) - len(result)
            if sent:
                self.metrics.published.labels(queue).inc(sent)
            if result:
                self.metrics.failed.labels(queue).inc(len(result))
                log.warning(
                    "SQS refused outbox rows; they are tried again later",
                    extra={
                        "queue": queue,
                        "count": len(result),
                        "codes": sorted(set(result.values())),
                    },
                )
            failures.update(result)
        return failures

    async def _send_chunk(self, queue: str, fair: bool, rows: list[DueRow]) -> dict[UUID, str]:
        messages = [
            OutgoingMessage(
                id=str(row.message.id),
                body=row.message.body(),
                delay_seconds=row.remaining_delay,
                group_id=str(row.message.tenant_id) if fair else None,
            )
            for row in rows
        ]
        try:
            refused = await self.queues.send_batch(queue, messages)
        except QueueError as exc:
            if not exc.sender_fault or len(rows) == 1:
                return {row.message.id: exc.code for row in rows}
            # SQS refused the whole batch for something in it, such as one message too long. Each
            # row goes on its own, so only the bad one backs off.
            results = await asyncio.gather(*(self._send_chunk(queue, fair, [row]) for row in rows))
            return {key: code for result in results for key, code in result.items()}
        codes = {failure.id: failure.code for failure in refused}
        return {
            row.message.id: codes[str(row.message.id)]
            for row in rows
            if str(row.message.id) in codes
        }

    async def run(self, stopping: asyncio.Event) -> None:
        """Publish until `stopping` is set; the batch in hand always finishes first."""
        pause = ERROR_PAUSE_SECONDS[0]
        while not stopping.is_set():
            try:
                claimed = await self.publish_batch()
            except Exception:
                # The database or the network is down. Nothing is lost: the rows wait in the
                # outbox, and the age alert fires if this goes on.
                log.exception("outbox batch failed; trying again", extra={"pause_seconds": pause})
                await _sleep_unless(stopping, pause)
                pause = min(pause * 2, ERROR_PAUSE_SECONDS[1])
                continue
            pause = ERROR_PAUSE_SECONDS[0]
            if claimed < self.batch_size:
                await _sleep_unless(stopping, self.poll_interval)


async def _sleep_unless(stopping: asyncio.Event, seconds: float) -> None:
    with contextlib.suppress(TimeoutError):
        await asyncio.wait_for(stopping.wait(), timeout=seconds)


async def run_relay(settings: RelaySettings, *, handle_signals: bool = True) -> int:
    """The relay process: its pool, its SQS client, its probes, until a signal."""
    process = WorkerProcess(settings)
    database = Database.connect(
        settings.database_url.get_secret_value(), pool_size=settings.database_pool_size
    )
    queues = SqsQueues.create(
        region=settings.aws_region,
        prefix=settings.sqs_queue_prefix,
        endpoint_url=settings.sqs_endpoint_url,
    )
    relay = Relay(
        database,
        queues,
        RelayMetrics.create(process.registry),
        batch_size=settings.relay_batch_size,
        poll_interval=settings.relay_poll_interval_seconds,
    )
    try:
        return await process.run(relay.run, handle_signals=handle_signals)
    finally:
        await queues.close()
        await database.dispose()


def main() -> int:
    settings = load_settings(RelaySettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    return asyncio.run(run_relay(settings))


if __name__ == "__main__":
    sys.exit(main())
