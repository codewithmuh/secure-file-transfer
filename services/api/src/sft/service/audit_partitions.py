"""The lifecycle job's audit partition step, and the metrics its alerts read (data model 6).

The `audit-partitions` lifecycle job (`sft.workers.audit_partitions`) runs
`maintain_audit_partitions` daily as `sft_jobs` and pushes `AuditPartitionMetrics.registry` to the
Pushgateway:

- `sft_audit_default_partition_rows`: rows in the default partition. Any row there means its
  month had no partition, so the alert fires above 0.
- `sft_audit_partition_months_covered`: months from this one on with a partition, without a gap;
  4 after a run. The alert fires when it is below 2, next month missing, within the last 7 days
  of a month.
- `sft_audit_partition_last_success_timestamp_seconds`: when a run last made every month it had
  to and dropped every expired month it could. The alert fires when it is more than a day and a
  bit old, so a job that keeps failing, or no longer runs, shows before the months run out.
- `sft_audit_expired_partitions` (#255, NFR-9): monthly partitions past the 365-day retention
  still there. The alert fires when it stays above 0 for a day, two runs in a row.

The step creates missing partitions first, then drops the months past the retention
(`audit_drop_expired_partitions`, revision 0040), then measures, each in a short transaction in
system scope. A month is dropped when its end is 365 days before the jobs' clock and every row in
it is archived in both regions. The clock is injected (`now`), so tests can move it; the database
never lets a clock ahead of its own drop a month early. A month kept because a row isn't archived
yet waits for the archive job, and is counted.

It measures even when creation or the drop fails, so the gauges never go stale behind an error.
A month whose rows already sit in the default partition is left blocked, so its alert stays on
until an operator moves the rows (docs/runbooks/audit-partitions.md); the run still counts as a
success, because the job did its part. A month that couldn't be created or dropped, or a run that
raised, doesn't.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import datetime

from prometheus_client import CollectorRegistry, Gauge

from sft.data import audit
from sft.data.database import Database
from sft.data.scope import Scope

log = logging.getLogger("sft.service.audit_partitions")

MONTHS_AHEAD = 3


@dataclass(frozen=True)
class AuditPartitionMetrics:
    registry: CollectorRegistry
    default_rows: Gauge
    months_covered: Gauge
    last_success: Gauge
    expired: Gauge

    @classmethod
    def create(cls, registry: CollectorRegistry | None = None) -> AuditPartitionMetrics:
        registry = registry or CollectorRegistry()
        default_rows = Gauge(
            "sft_audit_default_partition_rows",
            "Audit events in the default partition, whose month had no partition. Should be 0.",
            registry=registry,
        )
        months_covered = Gauge(
            "sft_audit_partition_months_covered",
            "Months from the current one on that have an audit partition, without a gap.",
            registry=registry,
        )
        last_success = Gauge(
            "sft_audit_partition_last_success_timestamp_seconds",
            "When the audit partition step last made every month it had to, as a Unix time.",
            registry=registry,
        )
        expired = Gauge(
            "sft_audit_expired_partitions",
            "Monthly audit partitions past the 365-day retention still there (NFR-9). Should be 0.",
            registry=registry,
        )
        return cls(registry, default_rows, months_covered, last_success, expired)

    def update(self, status: audit.PartitionStatus) -> None:
        self.default_rows.set(status.default_rows)
        self.months_covered.set(status.months_covered)
        self.expired.set(status.expired)


async def maintain_audit_partitions(
    database: Database,
    metrics: AuditPartitionMetrics,
    months_ahead: int = MONTHS_AHEAD,
    *,
    now: Callable[[], datetime] | None = None,
) -> audit.PartitionStatus:
    """Create the coming months' partitions, drop the expired ones, then measure and export what
    the alerts watch. `now` is the jobs' clock; without it, the database's.

    If creation or the drop raises, the step still measures and exports, then raises the error.
    """
    results: dict[str, str] = {}
    dropped: dict[str, str] = {}
    error: Exception | None = None
    as_of = None if now is None else now()
    try:
        async with database.transaction(Scope.system()) as session:
            results = await audit.create_partitions(session, months_ahead)
    except Exception as exc:  # measured below, then raised again
        log.exception("audit partition creation failed")
        error = exc
    try:
        async with database.transaction(Scope.system()) as session:
            dropped = await audit.drop_expired_partitions(session, as_of)
    except Exception as exc:  # measured below, then raised again
        log.exception("expired audit partitions not dropped")
        error = error or exc
    async with database.transaction(Scope.system()) as session:
        status = await audit.partition_status(session)
        expired = await audit.expired_partitions(session, as_of)
    status = replace(
        status,
        blocked=tuple(name for name, result in results.items() if result == "blocked"),
        failed=tuple(name for name, result in results.items() if result == "failed"),
        expired=expired,
        dropped=tuple(name for name, result in dropped.items() if result == "dropped"),
        unarchived=tuple(name for name, result in dropped.items() if result == "unarchived"),
        drop_failed=tuple(name for name, result in dropped.items() if result == "failed"),
    )
    metrics.update(status)
    if error is not None:
        raise error
    if not results:
        log.info("another run holds the audit partition lock; skipped")
    elif not status.failed and not status.drop_failed:
        metrics.last_success.set_to_current_time()
    created = [name for name, result in results.items() if result == "created"]
    if created:
        log.info("audit partitions created", extra={"partitions": created})
    if status.dropped:
        log.info("expired audit partitions dropped", extra={"partitions": list(status.dropped)})
    if status.failed:
        log.error("audit partitions not created", extra={"failed": list(status.failed)})
    if status.unarchived:
        log.warning(
            "expired audit partitions kept until they are archived in both regions",
            extra={"partitions": list(status.unarchived)},
        )
    if status.drop_failed:
        log.error(
            "expired audit partitions not dropped", extra={"failed": list(status.drop_failed)}
        )
    if status.default_rows or status.blocked:
        log.error(
            "audit events in the default partition",
            extra={"default_rows": status.default_rows, "blocked": list(status.blocked)},
        )
    return status
