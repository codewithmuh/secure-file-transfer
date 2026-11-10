"""The recovery job, one run (#258; `sft.service.recovery`): what the restore, failover and
failback runbooks run, as `sft_recovery` with the `recovery` service account.

    RECOVERY_STEPS=generation,partitions,replay RECOVERY_SINCE=… RECOVERY_REWIND_TO=… \\
        python -m sft.workers.recovery

The chart's `recovery` CronJob is always suspended: the runbooks render a Job from it with their
steps and times (`ops/lib/common.sh`'s `recovery_job`). It reads `RecoverySettings`, lists and
reads this region's audit archive (`AUDIT_ARCHIVE_BUCKET`), and logs its report as one JSON line:
counts, the generation and the newest record's time, which the drill log takes. It exits 0 when
every step it was given is done, 1 when one failed (running it again is safe: every step is
idempotent), and 2 on bad settings.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from datetime import UTC, datetime
from typing import Final

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, RecoverySettings, load_settings
from sft.data.database import Database
from sft.runtime.archive import S3ArchiveReader
from sft.service.recovery import RecoveryReport, parse_steps, run_recovery

log = logging.getLogger(__name__)

EXIT_FAILED: Final = 1


async def run_once(settings: RecoverySettings) -> RecoveryReport:
    database = Database.connect(
        settings.database_url.get_secret_value(),
        pool_size=1,
        iam_region=settings.aws_region if settings.database_iam_auth else None,
    )
    reader = S3ArchiveReader.create(
        region=settings.aws_region,
        bucket=settings.audit_archive_bucket,
        endpoint=settings.audit_archive_endpoint_url,
    )
    try:
        return await run_recovery(
            database,
            reader,
            steps=parse_steps(settings.recovery_steps),
            since=settings.recovery_since,
            rewind_to=settings.recovery_rewind_to,
            today=datetime.now(UTC).date(),
        )
    finally:
        await reader.close()
        await database.dispose()


def main() -> int:
    settings = load_settings(RecoverySettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    if not settings.recovery_steps.strip():
        # The CronJob as rendered: the runbook names the steps in the Job it makes from it.
        log.critical("RECOVERY_STEPS names no step: generation, partitions, replay, outbox")
        return EXIT_BAD_SETTINGS
    started = time.monotonic()
    try:
        report: dict[str, object] = asyncio.run(run_once(settings)).as_dict()
    except Exception:
        log.exception("recovery job failed; running it again is safe")
        status, report = EXIT_FAILED, {}
    else:
        status = 0
    log.info(
        "recovery job finished" if status == 0 else "recovery job ended",
        extra={"report": report, "seconds": round(time.monotonic() - started, 3)},
    )
    return status


if __name__ == "__main__":
    sys.exit(main())
