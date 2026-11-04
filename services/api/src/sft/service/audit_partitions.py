"""The lifecycle job's audit partition step, and the metrics its alerts read (data model 6).

The jobs worker, which comes later, runs `maintain_audit_partitions` as `sft_jobs`, every
hour say, and serves `AuditPartitionMetrics.registry` on its `/metrics`:

- `sft_audit_default_partition_rows`: rows in the default partition. Any row there means its
  month had no partition, so the alert fires above 0.
- `sft_audit_partition_months_covered`: months from this one on with a partition, without a gap;
  4 after a run. The alert fires when it is below 2, next month missing, within the last 7 days
  of a month.

The step creates missing partitions first, then measures, in two short transactions in system
scope. A month whose rows already sit in the default partition is left blocked, so its alert
stays on until an operator moves the rows (the runbook arrives with the alert).
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
        return cls(registry, default_rows, months_covered)

    def update(self, status: audit.PartitionStatus) -> None:
        self.default_rows.set(status.default_rows)
        self.months_covered.set(status.months_covered)


async def maintain_audit_partitions(
    database: Database, metrics: AuditPartitionMetrics, months_ahead: int = MONTHS_AHEAD
) -> audit.PartitionStatus:
    """Create the coming months' partitions, then measure and export what the alerts watch."""
    async with database.transaction(Scope.system()) as session:
        results = await audit.create_partitions(session, months_ahead)
    async with database.transaction(Scope.system()) as session:
        status = await audit.partition_status(session)
    status = replace(
        status, blocked=tuple(name for name, result in results.items() if result == "blocked")
    )
    metrics.update(status)
    created = [name for name, result in results.items() if result == "created"]
    if created:
        log.info("audit partitions created", extra={"partitions": created})
    if status.default_rows or status.blocked:
        log.error(
            "audit events in the default partition",
            extra={"default_rows": status.default_rows, "blocked": list(status.blocked)},
        )
    return status
