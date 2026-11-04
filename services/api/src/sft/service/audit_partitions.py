"""The lifecycle job's audit partition step, and the metrics its alerts read (data model 6).

The jobs worker, which comes later, runs `maintain_audit_partitions` as `sft_jobs`, every
hour say, and serves `AuditPartitionMetrics.registry` on its `/metrics`:

- `sft_audit_default_partition_rows`: rows in the default partition. Any row there means its
  month had no partition, so the alert fires above 0.
- `sft_audit_partition_months_covered`: months from this one on with a partition, without a gap;
  4 after a run. The alert fires when it is below 2, next month missing, within the last 7 days
  of a month.
- `sft_audit_partition_last_success_timestamp_seconds`: when a run last made every month it had
  to. The alert fires when it is more than a day and a bit old, so a job that keeps failing, or
  no longer runs, shows before the months run out.

The step creates missing partitions first, then measures, in two short transactions in system
scope. It measures even when creation fails, so the gauges never go stale behind an error. A
month whose rows already sit in the default partition is left blocked, so its alert stays on
until an operator moves the rows (the runbook arrives with the alert); the run still counts as a
success, because the job did its part. A month that failed, or a run that raised, doesn't.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

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
        return cls(registry, default_rows, months_covered, last_success)

    def update(self, status: audit.PartitionStatus) -> None:
        self.default_rows.set(status.default_rows)
        self.months_covered.set(status.months_covered)


async def maintain_audit_partitions(
    database: Database, metrics: AuditPartitionMetrics, months_ahead: int = MONTHS_AHEAD
) -> audit.PartitionStatus:
    """Create the coming months' partitions, then measure and export what the alerts watch.

    If creation raises, the step still measures and exports, then raises the error.
    """
    results: dict[str, str] = {}
    error: Exception | None = None
    try:
        async with database.transaction(Scope.system()) as session:
            results = await audit.create_partitions(session, months_ahead)
    except Exception as exc:  # measured below, then raised again
        log.exception("audit partition creation failed")
        error = exc
    async with database.transaction(Scope.system()) as session:
        status = await audit.partition_status(session)
    status = replace(
        status,
        blocked=tuple(name for name, result in results.items() if result == "blocked"),
        failed=tuple(name for name, result in results.items() if result == "failed"),
    )
    metrics.update(status)
    if error is not None:
        raise error
    if not results:
        log.info("another run holds the audit partition lock; skipped")
    elif not status.failed:
        metrics.last_success.set_to_current_time()
    created = [name for name, result in results.items() if result == "created"]
    if created:
        log.info("audit partitions created", extra={"partitions": created})
    if status.failed:
        log.error("audit partitions not created", extra={"failed": list(status.failed)})
    if status.default_rows or status.blocked:
        log.error(
            "audit events in the default partition",
            extra={"default_rows": status.default_rows, "blocked": list(status.blocked)},
        )
    return status
