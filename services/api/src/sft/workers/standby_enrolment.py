"""The standby enrolment, one run (#258; `sft.service.standby_enrolment`; authn and authz 2.6):
after a regional failover, every active local member gets a user in this region's pool and a
re-enrolment invitation.

    python -m sft.workers.standby_enrolment

The chart's `standby-enrolment` CronJob is always suspended and runs as the notification worker:
its service account, its settings (`NotifySettings`), its egress proxy listener for Cognito and
its mail adapter. The failover runbook starts it by hand after the recovery job's replay
(`kubectl create job --from=cronjob/standby-enrolment`). It logs its counts as one JSON line and
exits 0 when done, 1 when it failed (running it again is safe: members already enrolled are
skipped), and 2 on bad settings or without a user pool.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Final

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, NotifySettings, load_settings
from sft.data.database import Database
from sft.data.mail import mailer_from_settings
from sft.service.email import EmailRenderer
from sft.service.standby_enrolment import enrol_standby
from sft.workers.notify import threaded_send, user_pool

log = logging.getLogger(__name__)

EXIT_FAILED: Final = 1


async def run_once(settings: NotifySettings) -> int:
    pool = user_pool(settings)
    if pool is None:
        log.error("the standby enrolment needs a user pool (USER_POOL_BACKEND)")
        return EXIT_BAD_SETTINGS
    database = Database.connect(
        settings.database_url.get_secret_value(),
        pool_size=1,
        iam_region=settings.aws_region if settings.database_iam_auth else None,
    )
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="mail")
    try:
        await enrol_standby(
            database,
            pool=pool,
            send=threaded_send(mailer_from_settings(settings), executor),
            renderer=EmailRenderer(settings.web_app_url),
        )
    except Exception:
        log.exception("the standby enrolment failed; running it again is safe")
        return EXIT_FAILED
    finally:
        await pool.aclose()
        await asyncio.to_thread(executor.shutdown, wait=True)
        await database.dispose()
    return 0


def main() -> int:
    settings = load_settings(NotifySettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    return asyncio.run(run_once(settings))


if __name__ == "__main__":
    sys.exit(main())
