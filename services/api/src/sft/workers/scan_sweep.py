"""The scan sweep: files still `scanning` past their deadline end `scan_failed` (data model 3.1, 6;
architecture 4.1; FR-19; #175).

A worker that died without recording a result (out of memory on a zip bomb, say, with its message
dead-lettered) leaves its file `scanning`. The sweep, run as `sft_jobs`, finds such files across
tenants, records `scan_failed` for each in its tenant's scope and runs the evaluation, which holds
its transfer (`sft.service.scans.fail_overdue_scans`), with `deadline_passed`, which `ScanFailed`
pages on (deploy/alerts). Files over 2 GB don't wait for it: completion fails them at once.

The lifecycle jobs (#181) schedule it with reconciliation: `sweep` is the step they call, counting
each file in `scan_results_total`, the scan worker's metric, so the alert sees both.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sft.data.database import Database
from sft.service.scans import SWEEP_BATCH, fail_overdue_scans
from sft.workers.scan import ScanMetrics

log = logging.getLogger(__name__)


async def sweep(database: Database, metrics: ScanMetrics, *, batch: int = SWEEP_BATCH) -> int:
    """Fail every overdue scan, a batch at a time; how many files it failed."""
    total = 0
    while True:
        swept = await fail_overdue_scans(database, now=datetime.now(UTC), limit=batch)
        for item in swept:
            metrics.results.labels("scan_failed", item.detail.value).inc()
            log.warning(
                "scan deadline passed: scan_failed",
                extra={"file_id": str(item.file_id), "scan_detail": item.detail.value},
            )
        total += len(swept)
        if len(swept) < batch:
            return total
