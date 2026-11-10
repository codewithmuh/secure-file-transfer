"""The audit archive job, one run (#183; `sft.service.archive_job`): the module the chart's
CronJob runs every minute, as `sft_archive` with the `audit-archive` service account.

    python -m sft.workers.audit_archive

Locally it is `make audit-archive`, run in the compose stack's `audit-archive` service against the
S3 stand-in's two archive buckets (docs/local-development.md). A run reads `ArchiveJobSettings`,
logs its report as one JSON line and, with `METRICS_PUSHGATEWAY_URL`, pushes its metrics under the
grouping key `job="audit-archive"`, which is also its `lifecycle_job_last_success_timestamp_seconds`
label. With `AUDIT_ARCHIVE_SURVIVING_REGION` it writes that region alone and records each range
for the back-fill, which it runs once the variable is gone (#257, `sft.service.archive_job`). It
exits 0 when the archive is up to date as far as the run got, 1 when a region refused a write or
the run failed, and 2 on bad settings.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from typing import Final

from prometheus_client import CollectorRegistry, push_to_gateway

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, ArchiveJobSettings, load_settings
from sft.data.database import Database
from sft.runtime.archive import open_audit_archive
from sft.service.archive_job import ArchiveJobMetrics, ArchiveReport, run_archive
from sft.service.audit_archive import ArchiveStore, Region
from sft.service.lifecycle import last_success_gauge

log = logging.getLogger(__name__)

JOB: Final = "audit-archive"
EXIT_FAILED: Final = 1


def open_store(settings: ArchiveJobSettings) -> ArchiveStore:
    """Both regions' archive buckets, or Tokyo's alone where there is no Osaka (dev); the
    surviving region's alone during a regional loss (#257)."""
    return open_audit_archive(
        tokyo_bucket=settings.audit_archive_tokyo_bucket,
        osaka_bucket=settings.audit_archive_osaka_bucket,
        tokyo_endpoint=settings.audit_archive_tokyo_endpoint_url,
        osaka_endpoint=settings.audit_archive_osaka_endpoint_url,
        surviving_region=settings.audit_archive_surviving_region,
        threads=2,
    )


async def run_once(settings: ArchiveJobSettings, registry: CollectorRegistry) -> ArchiveReport:
    database = Database.connect(
        settings.database_url.get_secret_value(),
        pool_size=1,
        iam_region=settings.aws_region if settings.database_iam_auth else None,
    )
    store = open_store(settings)
    metrics = ArchiveJobMetrics.create(registry)
    last_success = last_success_gauge(registry)
    try:
        surviving = settings.audit_archive_surviving_region
        report = await run_archive(
            database, store, metrics, surviving=None if surviving is None else Region(surviving)
        )
        last_success.labels(JOB).set(time.time())
        return report
    finally:
        await store.close()
        await database.dispose()


def main() -> int:
    settings = load_settings(ArchiveJobSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    registry = CollectorRegistry()
    started = time.monotonic()
    try:
        report: dict[str, object] = asyncio.run(run_once(settings, registry)).as_dict()
    except Exception:
        log.exception("audit archive job failed", extra={"job": JOB})
        status, report = EXIT_FAILED, {}
    else:
        status = 0
    log.info(
        "audit archive job finished" if status == 0 else "audit archive job ended",
        extra={"job": JOB, "report": report, "seconds": round(time.monotonic() - started, 3)},
    )
    if settings.metrics_pushgateway_url:
        try:
            push_to_gateway(settings.metrics_pushgateway_url, job=JOB, registry=registry)
        except OSError as exc:
            log.warning("metrics push failed", extra={"error": type(exc).__name__})
    return status


if __name__ == "__main__":
    sys.exit(main())
