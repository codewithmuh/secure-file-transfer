"""The notification worker: `python -m sft.workers.notify` (architecture 2, 4.1, 4.2; #178, #179).

It reads the notify queue and hands each message to `sft.service.notifications.Notifier`, which
emails recipients their links and codes and members their notices. It records each message after
the send, in a transaction of its own, so a failed send is delivered again and a recorded success
is never sent twice (ADR-0013; consumer.py).

- **Its own role**, `sft_notify`: it reads a recipient's address and link and a transfer's owner,
  state and expiry, never a file name or a message (revision 0012).
- **Its keyrings**: `link-hmac`, which only it reads, derives each link token; `code-hmac` makes
  each code's HMAC; `email-hmac` names addresses in the suppression list and the cross-tenant cap.
- **Email** through the mail adapter (`MAIL_BACKEND`): SES in AWS, Mailpit locally (ADR-0015).
  The adapter blocks, so each send runs in this worker's own small thread pool.
- **The counter store** holds the cross-tenant cap; while it is unreachable the cap counts in this
  pod (abuse 4.5).
- **The user pool's admin side** (`USER_POOL_BACKEND`, #197): it creates an invited member's pool
  user and records the identity before the invitation goes out. Locally Keycloak's admin API
  (`sft.runtime.keycloak`); `none` where there is no pool adapter yet (dev, until #193).

Probes and metrics on the internal port (architecture 8): `emails_sent_total{type}`,
`email_caps_hit_total{cap}`, `worker_messages_total{consumer,outcome}` and the counter store's.
"""

from __future__ import annotations

import asyncio
import functools
import sys
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import ClassVar

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.hmac_keyrings import CodeKeyring, LinkKeyring
from sft.core.logs import configure_logging
from sft.core.pseudonyms import EmailKeyring
from sft.core.settings import EXIT_BAD_SETTINGS, NotifySettings, load_settings
from sft.core.telemetry import configure_tracing
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.data.mail import Mailer, OutgoingEmail, mailer_from_settings
from sft.data.outbox import Queue
from sft.runtime.keycloak import KeycloakUserPool
from sft.service.email import EmailRenderer
from sft.service.notifications import CONSUMER, Done, Notifier, NotifyMetrics
from sft.service.rate_limits import RateLimiter
from sft.workers.consumer import (
    LONG_POLL_SECONDS,
    Consumer,
    ConsumerLoop,
    ConsumerMetrics,
    Delivery,
    Outcome,
)
from sft.workers.process import WorkerProcess
from sft.workers.queues import SqsQueues

SERVICE_NAME = "sft-notify"
MAIL_THREADS = 4


class NotifyConsumer(Consumer):
    """The notify queue's consumer: the work and its records are the notifier's."""

    name: ClassVar[str] = CONSUMER
    queue: ClassVar[Queue] = Queue.NOTIFY

    def __init__(self, database: Database, notifier: Notifier) -> None:
        super().__init__(database)
        self.notifier = notifier

    async def handle(self, session: AsyncSession, delivery: Delivery) -> None:  # pragma: no cover
        raise NotImplementedError("an email can't share a transaction: see process")

    async def process(self, delivery: Delivery) -> Outcome:
        done = await self.notifier.handle(delivery.message)
        return Outcome.DUPLICATE if done is Done.DUPLICATE else Outcome.PROCESSED


def threaded_send(
    mailer: Mailer, executor: ThreadPoolExecutor
) -> Callable[[OutgoingEmail], Awaitable[str]]:
    """The blocking mailer, run in `executor` so the event loop never waits on SMTP or SES."""

    async def send(email: OutgoingEmail) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(executor, functools.partial(mailer.send, email))

    return send


def user_pool(settings: NotifySettings) -> KeycloakUserPool | None:
    """The user pool's admin side the settings name, or None (`USER_POOL_BACKEND=none`)."""
    if settings.user_pool_backend != "keycloak":
        return None
    url, realm, client_id = (
        settings.keycloak_url,
        settings.keycloak_realm,
        settings.keycloak_client_id,
    )
    secret, provider = settings.keycloak_client_secret, settings.user_pool_provider_name
    # NotifySettings refuses a Keycloak pool without its parts; this only narrows the types.
    if url is None or realm is None or client_id is None or secret is None or provider is None:
        raise RuntimeError("USER_POOL_BACKEND=keycloak without its settings")
    return KeycloakUserPool(
        base_url=url,
        realm=realm,
        client_id=client_id,
        client_secret=secret.get_secret_value(),
        provider_name=provider,
    )


async def run_notify_worker(settings: NotifySettings, *, handle_signals: bool = True) -> int:
    """The notification worker process: its clients and probes, until a signal."""
    process = WorkerProcess(settings)
    database = Database.connect(
        settings.database_url.get_secret_value(), pool_size=settings.database_pool_size
    )
    queues = SqsQueues.create(
        region=settings.aws_region,
        prefix=settings.sqs_queue_prefix,
        endpoint_url=settings.sqs_endpoint_url,
        read_timeout=LONG_POLL_SECONDS + 10,
    )
    counter_metrics = CounterMetrics.create(process.registry)
    store = CounterStore.connect(settings.valkey_url.get_secret_value(), counter_metrics)
    executor = ThreadPoolExecutor(max_workers=MAIL_THREADS, thread_name_prefix="mail")
    pool = user_pool(settings)
    notifier = Notifier(
        database,
        renderer=EmailRenderer(settings.web_app_url),
        send=threaded_send(mailer_from_settings(settings), executor),
        link_keys=LinkKeyring.from_json(settings.link_hmac_keyring.get_secret_value()),
        code_keys=CodeKeyring.from_json(settings.code_hmac_keyring.get_secret_value()),
        emails=EmailKeyring.from_json(settings.email_hmac_keyring.get_secret_value()),
        limiter=RateLimiter(store, counter_metrics),
        metrics=NotifyMetrics.create(process.registry),
        pool=pool,
    )
    loop = ConsumerLoop(
        NotifyConsumer(database, notifier), queues, ConsumerMetrics.create(process.registry)
    )
    try:
        return await process.run(loop.run, handle_signals=handle_signals)
    finally:
        if pool is not None:
            await pool.aclose()
        await store.close()
        await queues.close()
        await asyncio.to_thread(executor.shutdown, wait=True)
        await database.dispose()


def main() -> int:
    settings = load_settings(NotifySettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    tracing = configure_tracing(
        SERVICE_NAME, settings.app_version, settings.otel_exporter_otlp_endpoint
    )
    try:
        return asyncio.run(run_notify_worker(settings))
    finally:
        tracing.shutdown()


if __name__ == "__main__":
    sys.exit(main())
