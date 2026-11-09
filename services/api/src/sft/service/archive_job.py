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

**Metrics** (docs/operations/metrics.md): `audit_archive_lag_seconds`, the age of the oldest
committed event not yet in both regions (alert `AuditArchiveLagging` above 2 minutes, data model
2.5); `audit_archive_events_total{region}`, events newly written to each region;
`audit_archive_write_failures_total{region}`, shared with the security-critical writes; and the
run's `lifecycle_job_last_success_timestamp_seconds{job="audit-archive"}`
(`AuditArchiveJobNotRunning`).
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

from prometheus_client import CollectorRegistry, Counter, Gauge

from sft.data import archive_cursor
from sft.data.archive_cursor import ArchiveRow, Claim
from sft.data.database import Database
from sft.data.scope import Scope
from sft.service.audit_archive import ArchiveMetrics, ArchiveStore, ArchiveWriteError, Region

log = logging.getLogger(__name__)

BATCH_ROWS: Final = 5000
"""Events per range, about: a range is cut at a transaction's end after this many."""
RUN_BUDGET_SECONDS: Final = 240.0
"""A run starts no new range after this, inside the CronJob's 300-second deadline."""
CONTENT_TYPE: Final = "application/gzip"
_TX_DIGITS: Final = 20


@dataclass(frozen=True)
class ArchiveJobMetrics:
    events: Counter
    lag: Gauge
    failures: ArchiveMetrics

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
        for region in Region:
            events.labels(region.value)
        return cls(events, lag, ArchiveMetrics.create(registry))


@dataclass
class ArchiveReport:
    ranges: int = 0
    events: int = 0
    objects_written: dict[str, int] = field(default_factory=dict)
    lag_seconds: float = 0.0

    def as_dict(self) -> dict[str, object]:
        return {
            "ranges": self.ranges,
            "events": self.events,
            "objects_written": dict(self.objects_written),
            "lag_seconds": round(self.lag_seconds, 3),
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


async def archive_range(
    database: Database,
    store: ArchiveStore,
    metrics: ArchiveJobMetrics,
    report: ArchiveReport,
    *,
    max_rows: int = BATCH_ROWS,
) -> Claim | None:
    """Claim, write and advance one range (module docstring); the range, or None when nothing was
    ready. Raises `ArchiveIncompleteError` if a region failed."""
    async with database.transaction(Scope.system()) as session:
        claimed = await archive_cursor.claim(session, max_rows=max_rows)
        rows = [] if claimed is None else await archive_cursor.events(session, claimed)
    if claimed is None:
        return None
    failed: set[Region] = set()
    for key, body, count in batches(claimed, rows):
        for region in store.regions:
            try:
                written = await store.put_once(region, key, body, content_type=CONTENT_TYPE)
            except ArchiveWriteError as exc:
                metrics.failures.failures.labels(region.value).inc()
                log.warning(
                    "audit archive batch write failed",
                    extra={"region": region.value, "code": exc.code, "key": key},
                )
                failed.add(region)
                continue
            if written:
                metrics.events.labels(region.value).inc(count)
                report.objects_written[region.value] = (
                    report.objects_written.get(region.value, 0) + 1
                )
    if failed:
        raise ArchiveIncompleteError(",".join(sorted(r.value for r in failed)))
    async with database.transaction(Scope.system()) as session:
        moved = await archive_cursor.advance(session, claimed)
    if not moved:
        log.info("another run moved the archive cursor first")
    report.ranges += 1
    report.events += len(rows)
    return claimed


async def measure_lag(database: Database, metrics: ArchiveJobMetrics) -> float:
    """`audit_archive_lag_seconds`, from the database's clock."""
    async with database.transaction(Scope.system()) as session:
        age = await archive_cursor.unarchived_age(session)
    metrics.lag.set(age)
    return age


async def run_archive(
    database: Database,
    store: ArchiveStore,
    metrics: ArchiveJobMetrics,
    *,
    max_rows: int = BATCH_ROWS,
    budget_seconds: float = RUN_BUDGET_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
) -> ArchiveReport:
    """One run: ranges while more is ready and the budget lasts, then the lag. The lag is
    measured even when a region failed, so the gauge never goes stale behind an error; then the
    error is raised, and the run counts as failed."""
    report = ArchiveReport()
    started = monotonic()
    error: ArchiveIncompleteError | None = None
    try:
        while monotonic() - started < budget_seconds:
            claimed = await archive_range(database, store, metrics, report, max_rows=max_rows)
            if claimed is None or not claimed.more:
                break
    except ArchiveIncompleteError as exc:
        error = exc
    report.lag_seconds = await measure_lag(database, metrics)
    if error is not None:
        raise error
    return report
