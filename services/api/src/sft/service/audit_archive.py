"""Security-critical records in the audit archive of both regions (#177; architecture 5.2, data
model 2.5, NFR-10, NFR-15).

Revocations, lockouts, unlocks, deactivations, demotions, forced sign-outs, sign-in resets and
download grants are written straight to the Object Lock archive bucket in Tokyo and in Osaka, and
the API answers `2xx` only once both hold the record. Two patterns:

- **Commit, then archive** (`AuditArchive.confirm`). The change commits with its audit event first
  and takes effect at once. Then its record goes to both regions; if either write fails, the call
  answers `503`, which means "done, not yet confirmed". A retry finds the change already made,
  reads its latest event (`sft.data.audit.latest_critical_event`) and writes the record if it is
  still missing, then answers `200` (API README 5).
- **Intent first** (`intent_first`), for download grants (data model 2.3; #180). An intent record
  goes to both regions before anything is counted, so a `503` there means nothing changed. Then the
  grant commits, and its committed record is written in the background, retried until both regions
  confirm (`AuditArchive.in_background`).

**Idempotent by event ID.** A record's key is its event's ID, which no restore or failover ever
gives out again (UUIDv7, made by the application), and the write is conditional (`If-None-Match:
*`): a retry that finds the record there rewrites nothing, and the bucket's Object Lock keeps the
first copy anyway.

**The key layout** (the open point of #177): `security-critical/v1/<tenant ID or "platform">/
<yyyy>/<mm>/<dd>/<event ID>.json`, dated by the event's `occurred_at` in UTC. Data model 2.5
prefixes the archive job's keys with the cursor's `generation`, because transaction IDs repeat
after a restore; a direct record is keyed by its event ID, which never repeats, so it needs no
generation. When the archive job arrives (M7) it writes under `g<generation>/` with the same
tenant and date parts, and readers merge both prefixes and drop duplicates by `id`, as data
model 2.5 already says they do.

**What a record holds:** the event's IDs, enums, times and `details` (`sft.data.audit.
ArchivedEvent`), never a token, code, address, file name, message, IP address or user agent.

The store is a thin adapter (`ArchiveStore`): `sft.runtime.archive.S3AuditArchive` in AWS and
against S3Mock, a fake in the unit tests. Failed writes are counted per region in
`audit_archive_write_failures_total{region}`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from typing import Final, Protocol
from uuid import UUID

from prometheus_client import CollectorRegistry, Counter

from sft.core.errors import ServiceUnavailable
from sft.data.audit import ArchivedEvent

log = logging.getLogger(__name__)

RETRY_AFTER_SECONDS: Final = 5
"""What a `503` from an unconfirmed record tells the client to wait."""
BACKGROUND_FIRST_WAIT: Final = 1.0
BACKGROUND_LONGEST_WAIT: Final = 60.0
"""A background write tries again after 1 s, doubling to a minute, until both regions confirm."""

PREFIX: Final = "security-critical/v1"
CONFIRMED_KEPT: Final = 10_000
"""Records a process remembers as confirmed in every region, so it never writes them again."""


class Region(StrEnum):
    """The two regions whose archive holds every security-critical record (ADR-0006)."""

    TOKYO = "ap-northeast-1"
    OSAKA = "ap-northeast-3"


class ArchiveWriteError(Exception):
    """A write to one region's archive failed. `code` is S3's error code or the client's error
    type, never a message, which could quote the request."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ArchiveStore(Protocol):
    """One object per record in each region's archive bucket."""

    @property
    def regions(self) -> tuple[Region, ...]:
        """The regions this environment archives to: both, or Tokyo alone in dev."""
        ...

    async def put_once(self, region: Region, key: str, body: bytes) -> bool:
        """Write `body` at `key` unless an object is there already: True if this call wrote it,
        False if it was there. Raises `ArchiveWriteError`."""
        ...

    async def close(self) -> None: ...


class RecordNotConfirmed(ServiceUnavailable):
    """The change stands, but its record isn't in both regions' archive yet: `503`."""

    def __init__(self, detail: str) -> None:
        super().__init__(RETRY_AFTER_SECONDS, detail)


DONE_NOT_CONFIRMED: Final = (
    "The change is done, but its audit record isn't confirmed in both regions yet. Retry the "
    "call to confirm it."
)
NOTHING_DONE: Final = "Nothing was changed: the audit archive can't be reached. Try again shortly."


def record_key(event: ArchivedEvent) -> str:
    """Where the record of `event` lives in each region's archive (module docstring)."""
    owner = "platform" if event.tenant_id is None else str(event.tenant_id)
    when = event.occurred_at.astimezone(UTC)
    return f"{PREFIX}/{owner}/{when:%Y/%m/%d}/{event.id}.json"


def record_body(event: ArchivedEvent) -> bytes:
    return json.dumps(event.as_json(), sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class ArchiveMetrics:
    failures: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> ArchiveMetrics:
        failures = Counter(
            "audit_archive_write_failures_total",
            "Writes of a security-critical record to one region's audit archive that failed.",
            ["region"],
            registry=registry,
        )
        for region in Region:
            failures.labels(region.value)
        return cls(failures)


class AuditArchive:
    """Writes security-critical records to every region of the store."""

    def __init__(self, store: ArchiveStore, metrics: ArchiveMetrics) -> None:
        self.store = store
        self.metrics = metrics
        self._background: set[asyncio.Task[None]] = set()
        self._closed = False
        self._confirmed: OrderedDict[UUID, None] = OrderedDict()

    async def write(self, events: Iterable[ArchivedEvent]) -> frozenset[Region]:
        """Write each record to each region at once; the regions where a write failed.

        A record this process has seen confirmed in every region is skipped: writing it again
        would change nothing, and a caller an attacker drives (a locked recipient's attempts)
        mustn't cost an S3 write each. The memory holds the last `CONFIRMED_KEPT` records.
        """
        pending = [event for event in events if event.id not in self._confirmed]
        writes = [(event, region) for event in pending for region in self.store.regions]
        results = await asyncio.gather(
            *(self._put(event, region) for event, region in writes), return_exceptions=False
        )
        failed = {region for (_, region), ok in zip(writes, results, strict=True) if not ok}
        unconfirmed = {event.id for (event, _), ok in zip(writes, results, strict=True) if not ok}
        for event in pending:
            if event.id not in unconfirmed:
                self._confirmed[event.id] = None
                while len(self._confirmed) > CONFIRMED_KEPT:
                    self._confirmed.popitem(last=False)
        return frozenset(failed)

    async def _put(self, event: ArchivedEvent, region: Region) -> bool:
        try:
            await self.store.put_once(region, record_key(event), record_body(event))
        except ArchiveWriteError as exc:
            self.metrics.failures.labels(region.value).inc()
            log.warning(
                "audit archive write failed",
                extra={
                    "region": region.value,
                    "code": exc.code,
                    "event_id": str(event.id),
                    "action": event.action,
                },
            )
            return False
        return True

    async def confirm(
        self, events: Sequence[ArchivedEvent], *, detail: str = DONE_NOT_CONFIRMED
    ) -> None:
        """Write the records to both regions, or raise `RecordNotConfirmed` (`503`)."""
        if not events:
            return
        if await self.write(events):
            raise RecordNotConfirmed(detail)

    def in_background(
        self,
        events: Sequence[ArchivedEvent],
        on_confirmed: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        """Write the records in the background, retried until every region confirms them; then
        run `on_confirmed`, such as setting a grant's `archived_at`. Shutdown cancels what is
        left, which reconciliation finds again (data model 2.3)."""
        if self._closed:
            raise RuntimeError("the archive is closed")
        task = asyncio.create_task(self._until_confirmed(tuple(events), on_confirmed))
        self._background.add(task)
        task.add_done_callback(self._background.discard)

    async def _until_confirmed(
        self,
        events: tuple[ArchivedEvent, ...],
        on_confirmed: Callable[[], Awaitable[None]] | None,
    ) -> None:
        wait = BACKGROUND_FIRST_WAIT
        while await self.write(events):
            await asyncio.sleep(wait)
            wait = min(wait * 2, BACKGROUND_LONGEST_WAIT)
        if on_confirmed is not None:
            try:
                await on_confirmed()
            except Exception:
                log.exception("the confirmed record's follow-up failed")

    async def drain(self) -> None:
        """Wait for the background writes in hand (tests, and a clean shutdown)."""
        while self._background:
            await asyncio.gather(*self._background, return_exceptions=True)

    async def close(self) -> None:
        self._closed = True
        for task in list(self._background):
            task.cancel()
        await asyncio.gather(*self._background, return_exceptions=True)
        await self.store.close()


async def intent_first[T](
    archive: AuditArchive,
    intent: ArchivedEvent,
    commit: Callable[[], Awaitable[tuple[T, ArchivedEvent]]],
    *,
    on_confirmed: Callable[[T], Awaitable[None]] | None = None,
) -> T:
    """The intent-first pattern of download grants (data model 2.3).

    1. The intent record goes to both regions; if either fails, `503` and nothing is changed.
    2. `commit` makes the change in its own transaction and returns it with its committed record.
    3. The committed record is written in the background until both regions confirm, then
       `on_confirmed` runs with the change.
    """
    await archive.confirm([intent], detail=NOTHING_DONE)
    value, committed = await commit()

    async def confirmed() -> None:
        if on_confirmed is not None:
            await on_confirmed(value)

    archive.in_background([committed], confirmed)
    return value
