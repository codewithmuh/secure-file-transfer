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
    Queue,
    Topic,
    claim_due,
    mark_failed,
    mark_published,
    oldest_unpublished_age,
)
from sft.data.scope import Scope
from sft.workers.process import WorkerProcess, sleep_unless
from sft.workers.queues import MAX_BATCH, OutgoingMessage, QueueError, Queues, SqsQueues

log = logging.getLogger("sft.workers.relay")  # not __main__ under python -m


RETRY_BASE_SECONDS = 2.0
RETRY_MAX_SECONDS = 300.0
"""A row SQS refuses waits 2 s, then 4, 8 … up to 5 minutes between tries. The outbox age alert
fires at 2 minutes (ADR-0013), long before a row reaches the cap."""

SEND_BUDGET_SECONDS = 6.0
"""The longest the relay spends on SQS in one batch, while it holds the claimed rows' locks. The
workload roles end a transaction idle for 10 s (data model 2.5); 6 s leaves the claim and the
marks the rest. SQS calls never extend it: the relay stops waiting when it runs out."""

SPLIT_BUDGET_ROWS = 20
"""Rows of one batch that may be re-sent one by one after SQS refused their whole batch."""

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
                "Age of the oldest unpublished outbox row, measured on every loop after the "
                "batch, whether it succeeded or not; the alert fires above 120 s (ADR-0013).",
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
        send_budget: float = SEND_BUDGET_SECONDS,
        split_budget: int = SPLIT_BUDGET_ROWS,
    ) -> None:
        self.database = database
        self.queues = queues
        self.metrics = metrics
        self.topics = topics
        self.batch_size = batch_size
        self.poll_interval = poll_interval
        self.send_budget = send_budget
        self.split_budget = split_budget

    async def publish_batch(self) -> int:
        """Claim, send and mark one batch in one transaction; return how many rows it claimed."""
        with self.metrics.batch_duration.time():
            async with self.database.transaction(Scope.system()) as session:
                due = await claim_due(session, self.batch_size)
                failures = await self._send(due) if due else {}
                await mark_published(
                    session, [row.message.id for row in due if row.message.id not in failures]
                )
                await mark_failed(
                    session,
                    {
                        row.message.id: (failures[row.message.id], retry_delay(row.attempts))
                        for row in due
                        if row.message.id in failures
                    },
                )
        return len(due)

    async def measure_age(self) -> None:
        """Set the outbox age gauge, in a short read of its own, whatever the last batch did."""
        async with self.database.transaction(Scope.system()) as session:
            age = await oldest_unpublished_age(session)
        self.metrics.oldest_unpublished_age.set(age)

    async def _send(self, due: list[DueRow]) -> dict[UUID, str]:
        """Send every claimed row within the send budget; the rows that failed, with a code.

        The claimed rows stay locked while this runs, so the whole send phase, per-row re-sends
        included, ends within `send_budget` (6 s), well inside the 10 s a transaction may sit idle
        (data model 2.5). A row with no answer by then counts as failed (`send_timeout`) and is
        tried again later; if SQS did take it, a consumer skips the second copy.
        """
        failures: dict[UUID, str] = {}
        by_queue: dict[Queue, list[DueRow]] = {}
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

        chunks = [
            (queue, rows[start : start + MAX_BATCH])
            for queue, rows in by_queue.items()
            for start in range(0, len(rows), MAX_BATCH)
        ]
        outcome: dict[UUID, str | None] = {}  # None: sent
        splits = _SplitBudget(self.split_budget)
        try:
            async with asyncio.timeout(self.send_budget):
                # The calls run side by side, so the phase lasts about as long as the slowest.
                await asyncio.gather(
                    *(self._send_chunk(queue, rows, outcome, splits) for queue, rows in chunks)
                )
        except TimeoutError:
            log.warning(
                "SQS didn't answer within the send budget; the rest are tried again later",
                extra={"budget_seconds": self.send_budget},
            )
        for queue, rows in chunks:
            result = {
                row.message.id: code
                for row in rows
                if (code := outcome.get(row.message.id, "send_timeout")) is not None
            }
            if sent := len(rows) - len(result):
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

    async def _send_chunk(
        self,
        queue: Queue,
        rows: list[DueRow],
        outcome: dict[UUID, str | None],
        splits: _SplitBudget,
    ) -> None:
        messages = [
            OutgoingMessage(
                id=str(row.message.id),
                body=row.message.body(),
                delay_seconds=row.remaining_delay,
                group_id=str(row.message.tenant_id) if queue.fair else None,
            )
            for row in rows
        ]
        try:
            refused = await self.queues.send_batch(queue, messages)
        except QueueError as exc:
            if exc.sender_fault and len(rows) > 1 and splits.take(len(rows)):
                # SQS refused the whole batch for something in it, such as one message too
                # long. Each row goes on its own, so only the bad one backs off; at most
                # `split_budget` rows a batch, so a storm of bad batches can't stretch the send.
                await asyncio.gather(
                    *(self._send_chunk(queue, [row], outcome, splits) for row in rows)
                )
                return
            outcome.update({row.message.id: exc.code for row in rows})
            return
        codes = {failure.id: failure.code for failure in refused}
        outcome.update({row.message.id: codes.get(str(row.message.id)) for row in rows})

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
                claimed = -1
            await self._measure_age_logged()
            if claimed < 0:
                await sleep_unless(stopping, pause)
                pause = min(pause * 2, ERROR_PAUSE_SECONDS[1])
                continue
            pause = ERROR_PAUSE_SECONDS[0]
            if claimed < self.batch_size:
                await sleep_unless(stopping, self.poll_interval)

    async def _measure_age_logged(self) -> None:
        try:
            await self.measure_age()
        except Exception:
            # The database is down too. The gauge keeps its last value; the relay's own batch
            # errors and, in M4, a missing scrape alert on it.
            log.warning("outbox age not measured", exc_info=True)


class _SplitBudget:
    """How many rows of one batch may still be re-sent one by one."""

    def __init__(self, rows: int) -> None:
        self.rows = rows

    def take(self, count: int) -> bool:
        if count > self.rows:
            return False
        self.rows -= count
        return True


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
    try:
        # Before any batch, so no claim waits on a cold URL lookup (it would still fit the budget).
        await queues.resolve(sorted({topic.queue for topic in TOPICS.values()}))
    except QueueError as exc:
        log.warning("queue URLs not resolved at startup; looked up later", extra={"code": exc.code})
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
