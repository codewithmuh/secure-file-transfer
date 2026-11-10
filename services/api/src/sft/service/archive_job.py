"""The audit archive job: every committed audit event to both regions' archive, every minute (#183;
architecture 5.2, 6; data model 2.5; NFR-9, NFR-15; threat model T-44, T-45, T-46).

`python -m sft.workers.audit_archive` runs it once, as `sft_archive`, from a CronJob every minute
(deploy/charts/sft, `lifecycleJobs.audit-archive`). Each run:

1. **Claims** the next range of committed transactions in one short transaction in system scope
   (`sft.data.archive_cursor.claim`): from the cursor up to the oldest transaction still running,
   about `BATCH_ROWS` events at most, whole transactions only. It reads the range's events in the
   same transaction.
2. **Writes** them, with no transaction open, as one gzipped JSON-lines object per UTC day of
   `occurred_at`, to every region the store holds: Tokyo and Osaka in staging and prod, Tokyo
   alone in dev. Each write is conditional (`If-None-Match: *`), so a range written again after a
   crash writes nothing new and the bucket's Object Lock keeps the first copy anyway.
3. **Advances** the cursor to the range's end in a second short transaction, only once every
   region holds every object. A region that fails stops the run with the cursor where it was: the
   next run writes the same objects again and the region that had them keeps them.

It takes another range at once while more was ready than one range holds and its time budget
lasts, so a job that was down catches up; then it measures the lag.

**Why straight to both regions.** ADR-0012's replication of the archive has no time bound, and the
cursor travels with the database, so after a regional failover it could be past batches that never
reached Osaka (#42). Writing each batch to Osaka too, and moving the cursor only when both hold it,
makes "archived" mean "in both regions", as for the security-critical records. Replication stays as
a second copy.

**The key layout** (the open point #177 left): `g<generation>/<yyyy>/<mm>/<dd>/<first tx>-<end
tx>.jsonl.gz`, dated by `occurred_at` in UTC, with the range's transaction IDs zero-padded to 20
digits so keys sort in archive order. The generation comes first because transaction IDs repeat
after a restore or failover (data model 2.5). One object per run and day, not per tenant: at design
load that is 1,440 objects a day in each region rather than one per active tenant each minute,
which keeps capacity A14's 0.2 KB a row and the S3 request budget. A reader of one tenant filters
by `tenant_id`; the security-critical records keep their per-tenant layout. Readers merge
`security-critical/v1/` and every `g<n>/` and drop duplicates by `id`.

**What a line holds:** every column of the event (`sft.data.archive_cursor.ArchiveRow`), the
source IP, user agent and request and trace IDs included, which the security-critical records
leave out; `details` holds IDs, enums, numbers, flags and times only (data model 2.5). The bytes
are the same for the same range every time: lines in `(tx_id, id)` order, sorted keys, and gzip's
header time fixed at 0.

**One region alone, for a regional loss** (#257; architecture 7). While the failover's toggle names
a surviving region (`AUDIT_ARCHIVE_SURVIVING_REGION`, the chart's
`auditArchive.survivingRegionOnly`), the job writes each range to that region alone and moves the
cursor on, so the archive keeps up in the region that is left; the same transaction records the
range (`audit_archive_single_region`, revision 0039). The API's security-critical records go to that
region alone too (`sft.service.audit_archive.SurvivingRegion`). Once the toggle is off again, at
failback, each run first **back-fills**, with up to half its time budget so new events keep being
archived: it reads each recorded range's events again, makes the same objects (same keys, same
bytes, since a range's bytes depend on its rows alone) and writes them to every region, which keeps
what it already holds; then it deletes the row. So the lost region ends with exactly the objects the
surviving one has: no gap, no duplicate. The security-critical records of the window's events are
written to every region too, from the same rows, since the API's went to one region alone; and for
`GRACE_SECONDS` after the job first writes both regions again, every new range's records are written
to every region as well, because the API's pods leave the mode a little after the job does. A
grant's intent record (`download.grant_intent`) is never in the database, so it isn't back-filled:
it gave no access by itself, its committed record (which is back-filled) supersedes it, and every
reader ignores intents (data model 2.3). A month of audit events is never dropped while a range of
it waits for the back-fill (#255, revision 0040).

**Metrics** (docs/operations/metrics.md): `audit_archive_lag_seconds`, the age of the oldest
committed event not yet in both regions (alert `AuditArchiveLagging` above 2 minutes, data model
2.5); `audit_archive_events_total{region}`, events newly written to each region;
`audit_archive_write_failures_total{region}`, shared with the security-critical writes;
`audit_archive_single_region_ranges`, the ranges waiting for the back-fill
(`AuditArchiveSingleRegion`); and the run's
`lifecycle_job_last_success_timestamp_seconds{job="audit-archive"}` (`AuditArchiveJobNotRunning`).
"""

from __future__ import annotations

import gzip
import json
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date
from typing import Final
from uuid import UUID

from prometheus_client import CollectorRegistry, Counter, Gauge

from sft.data import archive_cursor
from sft.data.archive_cursor import ArchiveRow, Claim
from sft.data.audit import ArchivedEvent
from sft.data.database import Database
from sft.data.scope import Scope
from sft.service.audit_archive import (
    ArchiveMetrics,
    ArchiveStore,
    ArchiveWriteError,
    Region,
    record_body,
    record_key,
)

log = logging.getLogger(__name__)

BATCH_ROWS: Final = 5000
"""Events per range, about: a range is cut at a transaction's end after this many."""
RUN_BUDGET_SECONDS: Final = 240.0
"""A run starts no new range after this, inside the CronJob's 300-second deadline."""
CONTENT_TYPE: Final = "application/gzip"
_TX_DIGITS: Final = 20
GRACE_SECONDS: Final = 900.0
"""After a regional loss, how long the job keeps writing new ranges' security-critical records to
every region once it writes both again: an API rollout takes minutes, 15 covers it."""
BACKFILL_RANGES: Final = 50
"""Recorded ranges the back-fill reads at a time."""
BACKFILL_SHARE: Final = 0.5
"""The share of a run's budget the back-fill may take, so new events keep being archived while a
day's back-fill catches up over several runs."""


@dataclass(frozen=True)
class ArchiveJobMetrics:
    events: Counter
    lag: Gauge
    failures: ArchiveMetrics
    single_region: Gauge

    @classmethod
    def create(cls, registry: CollectorRegistry) -> ArchiveJobMetrics:
        events = Counter(
            "audit_archive_events_total",
            "Audit events the archive job newly wrote to one region's archive (#183).",
            ["region"],
            registry=registry,
        )
        lag = Gauge(
            "audit_archive_lag_seconds",
            "Age of the oldest committed audit event not yet in both regions' archive "
            "(NFR-15; the alert fires above 120 s).",
            registry=registry,
        )
        single_region = Gauge(
            "audit_archive_single_region_ranges",
            "Ranges the archive job wrote to one region's archive alone during a regional loss, "
            "waiting for the back-fill to the other (#257).",
            registry=registry,
        )
        for region in Region:
            events.labels(region.value)
        return cls(events, lag, ArchiveMetrics.create(registry), single_region)


@dataclass
class ArchiveReport:
    ranges: int = 0
    events: int = 0
    objects_written: dict[str, int] = field(default_factory=dict)
    lag_seconds: float = 0.0
    backfilled: int = 0
    """Ranges written to every region after a regional loss (module docstring)."""
    records_written: dict[str, int] = field(default_factory=dict)
    single_region: int = 0

    def as_dict(self) -> dict[str, object]:
        return {
            "ranges": self.ranges,
            "events": self.events,
            "objects_written": dict(self.objects_written),
            "lag_seconds": round(self.lag_seconds, 3),
            "backfilled": self.backfilled,
            "records_written": dict(self.records_written),
            "single_region": self.single_region,
        }


class ArchiveIncompleteError(Exception):
    """A region didn't take every object of a range; the cursor stays, and the next run retries."""


def batch_key(generation: int, day: date, claimed: Claim) -> str:
    """Where one day's events of a range live in each region's archive (module docstring)."""
    return (
        f"g{generation}/{day:%Y/%m/%d}/"
        f"{claimed.from_tx:0{_TX_DIGITS}d}-{claimed.up_to_tx:0{_TX_DIGITS}d}.jsonl.gz"
    )


def batch_body(rows: Sequence[ArchiveRow]) -> bytes:
    """The rows as gzipped JSON lines, the same bytes for the same rows every time."""
    lines = "".join(
        json.dumps(row.as_json(), sort_keys=True, separators=(",", ":")) + "\n" for row in rows
    )
    return gzip.compress(lines.encode(), mtime=0)


def batches(claimed: Claim, rows: Sequence[ArchiveRow]) -> list[tuple[str, bytes, int]]:
    """One object per UTC day of the range: its key, its body and how many events it holds."""
    by_day: dict[date, list[ArchiveRow]] = {}
    for row in rows:
        by_day.setdefault(row.occurred_at.astimezone(UTC).date(), []).append(row)
    return [
        (batch_key(claimed.generation, day, claimed), batch_body(day_rows), len(day_rows))
        for day, day_rows in sorted(by_day.items())
    ]


def _uuid(value: str | None) -> UUID | None:
    return None if value is None else UUID(value)


def records(rows: Sequence[ArchiveRow]) -> list[tuple[str, bytes]]:
    """The security-critical records of the rows, as the API writes them (#177): the same key, and
    a record made from the same columns."""
    found = []
    for row in rows:
        if not row.security_critical:
            continue
        event = ArchivedEvent(
            id=UUID(row.id),
            tenant_id=_uuid(row.tenant_id),
            occurred_at=row.occurred_at,
            action=row.action,
            actor_type=row.actor_type,
            actor_id=_uuid(row.actor_id),
            target_type=row.target_type,
            target_id=_uuid(row.target_id),
            outcome=row.outcome,
            details=dict(row.details),
        )
        found.append((record_key(event), record_body(event)))
    return found


async def _write_range(
    store: ArchiveStore,
    metrics: ArchiveJobMetrics,
    report: ArchiveReport,
    claimed: Claim,
    rows: Sequence[ArchiveRow],
    *,
    regions: Sequence[Region],
    with_records: bool,
) -> set[Region]:
    """Write the range's objects, and with `with_records` its security-critical records, to each
    of `regions`; the regions where a write failed."""
    failed: set[Region] = set()

    async def put(region: Region, key: str, body: bytes, content_type: str) -> bool | None:
        try:
            return await store.put_once(region, key, body, content_type=content_type)
        except ArchiveWriteError as exc:
            metrics.failures.failures.labels(region.value).inc()
            log.warning(
                "audit archive batch write failed",
                extra={"region": region.value, "code": exc.code, "key": key},
            )
            failed.add(region)
            return None

    for key, body, count in batches(claimed, rows):
        for region in regions:
            if await put(region, key, body, CONTENT_TYPE):
                metrics.events.labels(region.value).inc(count)
                report.objects_written[region.value] = (
                    report.objects_written.get(region.value, 0) + 1
                )
    if with_records:
        for key, body in records(rows):
            for region in regions:
                if await put(region, key, body, "application/json"):
                    report.records_written[region.value] = (
                        report.records_written.get(region.value, 0) + 1
                    )
    return failed


async def archive_range(
    database: Database,
    store: ArchiveStore,
    metrics: ArchiveJobMetrics,
    report: ArchiveReport,
    *,
    max_rows: int = BATCH_ROWS,
    surviving: Region | None = None,
    with_records: bool = False,
) -> Claim | None:
    """Claim, write and advance one range (module docstring); the range, or None when nothing was
    ready. With `surviving`, the range goes to that region alone and is recorded for the
    back-fill. Raises `ArchiveIncompleteError` if a region failed."""
    async with database.transaction(Scope.system()) as session:
        claimed = await archive_cursor.claim(session, max_rows=max_rows)
        rows = [] if claimed is None else await archive_cursor.events(session, claimed)
    if claimed is None:
        return None
    regions = (surviving,) if surviving is not None else store.regions
    failed = await _write_range(
        store, metrics, report, claimed, rows, regions=regions, with_records=with_records
    )
    if failed:
        raise ArchiveIncompleteError(",".join(sorted(r.value for r in failed)))
    async with database.transaction(Scope.system()) as session:
        if surviving is None:
            moved = await archive_cursor.advance(session, claimed)
        else:
            moved = await archive_cursor.advance_single_region(session, claimed, surviving.value)
    if not moved:
        log.info("another run moved the archive cursor first")
    report.ranges += 1
    report.events += len(rows)
    return claimed


async def backfill(
    database: Database,
    store: ArchiveStore,
    metrics: ArchiveJobMetrics,
    report: ArchiveReport,
    *,
    within_budget: Callable[[], bool],
) -> None:
    """Write every range recorded during a regional loss to every region, with its records, and
    forget it (module docstring), while the budget lasts. Raises `ArchiveIncompleteError` if a
    region failed: the range stays recorded, and the next run tries again."""
    while within_budget():
        async with database.transaction(Scope.system()) as session:
            ranges = await archive_cursor.single_region_ranges(session, limit=BACKFILL_RANGES)
        if not ranges:
            return
        for claimed in ranges:
            async with database.transaction(Scope.system()) as session:
                rows = await archive_cursor.events(session, claimed)
            failed = await _write_range(
                store, metrics, report, claimed, rows, regions=store.regions, with_records=True
            )
            if failed:
                raise ArchiveIncompleteError(",".join(sorted(r.value for r in failed)))
            async with database.transaction(Scope.system()) as session:
                if await archive_cursor.backfilled(session, claimed):
                    report.backfilled += 1
            if not within_budget():
                return


async def measure_lag(
    database: Database, metrics: ArchiveJobMetrics, report: ArchiveReport | None = None
) -> float:
    """`audit_archive_lag_seconds` and `audit_archive_single_region_ranges`, from the database;
    the lag."""
    async with database.transaction(Scope.system()) as session:
        age = await archive_cursor.unarchived_age(session)
        waiting = await archive_cursor.single_region_count(session)
    metrics.lag.set(age)
    metrics.single_region.set(waiting)
    if report is not None:
        report.lag_seconds, report.single_region = age, waiting
    return age


async def run_archive(
    database: Database,
    store: ArchiveStore,
    metrics: ArchiveJobMetrics,
    *,
    max_rows: int = BATCH_ROWS,
    budget_seconds: float = RUN_BUDGET_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
    surviving: Region | None = None,
    grace_seconds: float = GRACE_SECONDS,
) -> ArchiveReport:
    """One run: the back-fill after a regional loss, then ranges while more is ready and the
    budget lasts, then the lag. With `surviving`, every range goes to that region alone (module
    docstring). The lag is measured even when a region failed, so the gauge never goes stale
    behind an error; then the error is raised, and the run counts as failed."""
    report = ArchiveReport()
    started = monotonic()

    def within_budget() -> bool:
        return monotonic() - started < budget_seconds

    error: ArchiveIncompleteError | None = None
    try:
        with_records = False
        if surviving is None:
            async with database.transaction(Scope.system()) as session:
                window = await archive_cursor.both_regions_again(
                    session, grace_seconds=grace_seconds
                )
            with_records = window.single_region_since is not None
            if with_records:

                def backfill_budget() -> bool:
                    return monotonic() - started < budget_seconds * BACKFILL_SHARE

                await backfill(database, store, metrics, report, within_budget=backfill_budget)
        while within_budget():
            claimed = await archive_range(
                database,
                store,
                metrics,
                report,
                max_rows=max_rows,
                surviving=surviving,
                with_records=with_records,
            )
            if claimed is None or not claimed.more:
                break
    except ArchiveIncompleteError as exc:
        error = exc
    await measure_lag(database, metrics, report)
    if error is not None:
        raise error
    return report
