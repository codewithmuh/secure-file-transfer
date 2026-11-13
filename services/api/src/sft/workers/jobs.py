"""The lifecycle jobs' entry point (#181; architecture 4.5; data model 6): one job per run, then
exit.

    python -m sft.workers.jobs expiry|deletion|reconciliation|storage-audit|cleanup|purge|
                              audit-partitions

Each job has a module of its own too (`sft.workers.expiry`, `.deletion`, `.reconciliation`,
`.storage_audit`, `.cleanup`, `.purge`, `.audit_partitions`), which the chart's CronJobs run.
Locally they are one-shot commands, `make jobs JOB=<job>`, run in the compose stack's `jobs`
service (docs/local-development.md). The job, what it does and why are `sft.service.lifecycle`'s.
The audit archive job has its own role and settings (`sft.workers.audit_archive`).

A run reads `JobSettings`: the `sft_jobs` database role, the files buckets of each region that
holds a copy, both regions' audit archive (reconciliation rewrites a grant's committed record),
and the clock's test hook, which the settings refuse outside local and test. It logs its report
as one JSON line and, with `METRICS_PUSHGATEWAY_URL`, pushes its metrics, since a one-shot job has
no port to scrape. The push's grouping key is `job="<job>"`, the same value as the run's
`lifecycle_job_last_success_timestamp_seconds{job}` label, which the Pushgateway would otherwise
overwrite with the grouping key's. It exits 0 when the job finished, 1 when it failed, and 2 on
bad settings.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from collections.abc import Sequence
from typing import Final

from prometheus_client import CollectorRegistry, push_to_gateway

from sft.core.clock import Clock
from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, JobSettings, load_settings
from sft.data.database import Database
from sft.data.models import StorageClass
from sft.runtime.archive import open_audit_archive
from sft.runtime.s3 import S3Cleaner, S3Objects
from sft.service import sli
from sft.service.audit_archive import ArchiveMetrics, AuditArchive
from sft.service.audit_partitions import AuditPartitionMetrics
from sft.service.lifecycle import (
    RUNS,
    ApprovalBacklogMetrics,
    Job,
    JobMetrics,
    Jobs,
    PurgeMetrics,
)
from sft.workers.scan import ScanMetrics
from sft.workers.scan_sweep import sweep

log = logging.getLogger(__name__)

EXIT_FAILED: Final = 1
NEEDS_BUCKETS: Final = frozenset({Job.DELETION, Job.RECONCILIATION, Job.STORAGE_AUDIT})


def _archive(settings: JobSettings, registry: CollectorRegistry) -> AuditArchive:
    store = open_audit_archive(
        tokyo_bucket=settings.audit_archive_tokyo_bucket,
        osaka_bucket=settings.audit_archive_osaka_bucket,
        tokyo_endpoint=settings.audit_archive_tokyo_endpoint_url,
        osaka_endpoint=settings.audit_archive_osaka_endpoint_url,
        surviving_region=settings.audit_archive_surviving_region,
    )
    return AuditArchive(store, ArchiveMetrics.create(registry))


def _cleaner(settings: JobSettings) -> S3Cleaner:
    buckets = {
        settings.aws_region: {
            StorageClass.STANDARD: settings.s3_files_bucket,
            StorageClass.LARGE: settings.s3_large_files_bucket,
        }
    }
    replica = settings.s3_replica_region
    if (
        replica is not None
        and settings.s3_replica_files_bucket
        and settings.s3_replica_large_files_bucket
    ):
        buckets[replica] = {
            StorageClass.STANDARD: settings.s3_replica_files_bucket,
            StorageClass.LARGE: settings.s3_replica_large_files_bucket,
        }
    return S3Cleaner.create(buckets, settings.s3_endpoint_url)


async def run_job(job: Job, settings: JobSettings, registry: CollectorRegistry) -> dict[str, int]:
    """Run one job against the environment the settings name; its report."""
    database = Database.connect(
        settings.database_url.get_secret_value(),
        pool_size=2,
        iam_region=settings.aws_region if settings.database_iam_auth else None,
    )
    metrics = JobMetrics.create(registry)
    clock = Clock.offset_by(settings.clock_offset_seconds)
    jobs = Jobs(
        database=database,
        metrics=metrics,
        now=clock.now,
        small_pool_max=settings.scan_small_pool_max_bytes,
    )
    if job in NEEDS_BUCKETS:
        jobs.cleaner = _cleaner(settings)
        jobs.objects = S3Objects.create(
            region=settings.aws_region,
            files_bucket=settings.s3_files_bucket,
            large_files_bucket=settings.s3_large_files_bucket,
            endpoint_url=settings.s3_endpoint_url,
            threads=2,
        )
    if job is Job.PURGE:
        jobs.purge_metrics = PurgeMetrics.create(registry)
    if job is Job.AUDIT_PARTITIONS:
        jobs.partition_metrics = AuditPartitionMetrics.create(registry)
    if job is Job.EXPIRY:
        jobs.approval_metrics = ApprovalBacklogMetrics.create(registry)
    if job is Job.RECONCILIATION:
        jobs.archive = _archive(settings, registry)
        scan_metrics = ScanMetrics.create(registry)

        async def run_sweep() -> int:
            return await sweep(database, scan_metrics, now=clock.now)

        jobs.sweep = run_sweep
    # Reconciliation evaluates transfers, so it may send one: its time to shareable (#242).
    previous = sli.install(sli.SliMetrics.create(registry)) if job is Job.RECONCILIATION else None
    try:
        await RUNS[job](jobs)
        metrics.last_success.labels(job.value).set(time.time())
        return jobs.report
    finally:
        if job is Job.RECONCILIATION:
            sli.install(previous)
        for closing in (jobs.cleaner, jobs.objects, jobs.archive):
            if closing is not None:
                await closing.close()
        await database.dispose()


def main(argv: Sequence[str] | None = None, *, job: Job | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if job is None:
        names = [j.value for j in Job]
        if len(args) != 1 or args[0] not in names:
            print(f"usage: python -m sft.workers.jobs {{{'|'.join(names)}}}", file=sys.stderr)
            return EXIT_BAD_SETTINGS
        job = Job(args[0])
    settings = load_settings(JobSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    if settings.clock_offset_seconds:
        log.warning(
            "the clock's test hook is set", extra={"offset_seconds": settings.clock_offset_seconds}
        )
    registry = CollectorRegistry()
    started = time.monotonic()
    try:
        report = asyncio.run(run_job(job, settings, registry))
    except Exception:
        log.exception("lifecycle job failed", extra={"job": job.value})
        status = EXIT_FAILED
        report = {}
    else:
        status = 0
    log.info(
        "lifecycle job finished" if status == 0 else "lifecycle job ended",
        extra={"job": job.value, "report": report, "seconds": round(time.monotonic() - started, 3)},
    )
    if settings.metrics_pushgateway_url:
        try:
            push_to_gateway(settings.metrics_pushgateway_url, job=job.value, registry=registry)
        except OSError as exc:
            log.warning("metrics push failed", extra={"error": type(exc).__name__})
    return status


if __name__ == "__main__":
    sys.exit(main())
