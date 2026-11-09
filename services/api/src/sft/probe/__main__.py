"""`python -m sft.probe`: one probe run, its result reported, then exit.

Exit status: 0 when the journey passed, 1 when a step failed (the log line names it), 2 on bad
settings. The CronJob's `backoffLimit` is 0: the next run, 5 minutes later, is the retry.
"""

from __future__ import annotations

import logging
import sys
import time
from typing import Final

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, load_settings
from sft.probe import report
from sft.probe.journey import STEPS, Probe
from sft.probe.mailbox import Mailbox, MailpitMailbox, S3Mailbox
from sft.probe.settings import ProbeSettings

log = logging.getLogger("sft.probe")

EXIT_FAILED: Final = 1


def open_mailbox(settings: ProbeSettings) -> Mailbox:
    if settings.probe_mailbox == "mailpit":
        assert settings.probe_mailpit_url is not None  # noqa: S101 - the settings check it
        return MailpitMailbox(settings.probe_mailpit_url)
    assert settings.probe_mailbox_bucket is not None  # noqa: S101 - the settings check it
    return S3Mailbox.create(
        region=settings.aws_region,
        bucket=settings.probe_mailbox_bucket,
        prefix=settings.probe_mailbox_prefix,
        endpoint_url=settings.s3_endpoint_url,
    )


def main() -> int:
    settings = load_settings(ProbeSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    probe = Probe(settings, open_mailbox(settings))
    try:
        result = probe.run()
    finally:
        probe.close()
    log.info(
        "probe passed" if result.passed else "probe failed",
        extra={
            "run": result.run,
            "passed": result.passed,
            "failed_step": result.failed_step,
            "reason": result.reason,
            "seconds": result.seconds,
            "step_seconds": result.step_seconds,
            "first_byte_seconds": result.first_byte_seconds,
        },
    )
    if settings.metrics_pushgateway_url:
        report.push(
            settings.metrics_pushgateway_url,
            report.registry_for(
                passed=result.passed,
                failed_step=result.failed_step,
                steps=STEPS,
                seconds=result.seconds,
                step_seconds=result.step_seconds,
                first_byte_seconds=result.first_byte_seconds,
                finished_at=time.time(),
            ),
        )
    if settings.probe_cloudwatch:
        report.publish(
            report.cloudwatch_client(settings.aws_region),
            environment=settings.environment,
            passed=result.passed,
            image_digest=settings.probe_image_digest,
        )
    return 0 if result.passed else EXIT_FAILED


if __name__ == "__main__":
    sys.exit(main())
