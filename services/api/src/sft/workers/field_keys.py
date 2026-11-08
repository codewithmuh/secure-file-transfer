"""The field key job's entry point (#236, #233; encryption and keys 3.2, 7.2): one step, then exit.

    python -m sft.workers.field_keys backfill|rotate|rewrap|purge [...]

What each step does is `sft.service.field_keys`'s. With no step named, the run takes
`FIELD_KEY_STEPS`, in order. The job runs as the API's workload: the API's
service account, so its IAM role (the only one the fields key lets unwrap a field data key), and
the API's database role `sft_api`. The chart runs it as the `field-keys` CronJob: `rotate`, then
`backfill`, then `purge`, daily in Tokyo; `backfill` once by hand after this change is deployed,
and `rewrap` after a manual change of the fields key (runbook `field-keys`). Locally it runs in
the compose stack with the KMS stand-in (`FIELDS_KMS_KEY_ID=local`).

It logs its report as one JSON line, counts only, and exits 0 when the step finished, 1 when it
failed (every step is safe to run again), and 2 on bad settings or usage.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Sequence
from datetime import timedelta
from typing import Final

from prometheus_client import CollectorRegistry

from sft.core.clock import Clock
from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, FieldKeySettings, load_settings
from sft.data.database import Database
from sft.runtime.kms import open_field_keys
from sft.service import fields
from sft.service.field_keys import FieldKeyJob, Step

log = logging.getLogger(__name__)

EXIT_FAILED: Final = 1


async def run_steps(steps: Sequence[Step], settings: FieldKeySettings) -> dict[str, int]:
    database = Database.connect(
        settings.database_url.get_secret_value(),
        pool_size=2,
        iam_region=settings.aws_region if settings.database_iam_auth else None,
    )
    keys = open_field_keys(
        key_id=settings.fields_kms_key_id,
        region=settings.aws_region,
        registry=CollectorRegistry(),
    )
    previous = fields.install(keys)
    clock = Clock.offset_by(settings.clock_offset_seconds)
    report: dict[str, int] = {}
    try:
        for step in steps:
            job = FieldKeyJob(
                database,
                keys,
                now=clock.now,
                batch_size=settings.field_key_batch_size,
                max_age=timedelta(days=settings.field_key_max_age_days),
            )
            done = (await job.run(step)).as_dict()
            report.update({f"{step.value}_{name}": n for name, n in done.items()})
        return report
    finally:
        fields.install(previous)
        await keys.close()
        await database.dispose()


def _usage() -> int:
    names = "|".join(s.value for s in Step)
    print(f"usage: python -m sft.workers.field_keys {{{names}}} [...]", file=sys.stderr)
    return EXIT_BAD_SETTINGS


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    names = {s.value for s in Step}
    if any(a not in names for a in args):
        return _usage()
    settings = load_settings(FieldKeySettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    steps = [Step(a) for a in (args or settings.field_key_steps)]
    if not steps:
        return _usage()
    configure_logging(settings.log_level)
    names_run = [s.value for s in steps]
    try:
        report = asyncio.run(run_steps(steps, settings))
    except Exception:
        log.exception("field key job failed; running it again is safe", extra={"steps": names_run})
        return EXIT_FAILED
    log.info("field key job done", extra={"steps": names_run, "report": report})
    return 0


if __name__ == "__main__":
    sys.exit(main())
