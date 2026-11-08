"""The notification worker: `python -m sft.workers.notify` (architecture 2, 4.1, 4.2; #178, #179).

It reads the notify queue and hands each message to `sft.service.notifications.Notifier`, which
emails recipients their links and codes and members their notices. It records each message after
the send, in a transaction of its own, so a failed send is delivered again and a recorded success
is never sent twice (ADR-0013; consumer.py).

- **Its own role**, `sft_notify`: it reads a recipient's address and link and a transfer's owner,
  state and expiry, never a file name or a message (revision 0012).
- **Its keyrings**: `link-hmac`, which only it reads, derives each link token; `code-hmac` makes
  each code's HMAC; `email-hmac` names addresses in the suppression list and the cross-tenant cap.
  In AWS each is read from Secrets Manager at start and every 5 minutes (`sft.runtime.secrets`).
- **Email** through the mail adapter (`MAIL_BACKEND`): SES in AWS, Mailpit locally (ADR-0015).
  The adapter blocks, so each send runs in this worker's own small thread pool.
- **The counter store** holds the cross-tenant cap; while it is unreachable the cap counts in this
  pod (abuse 4.5).
- **The user pool's admin side** (`USER_POOL_BACKEND`, #197, #193): it creates an invited member's
  pool user and records the identity before the invitation goes out. Cognito's admin API in AWS
  (`sft.runtime.cognito`), Keycloak's locally (`sft.runtime.keycloak`); `none` sends no invitation.
- **SES's events** (#185): a second consumer reads the `ses-events` queue beside the notify queue
  and records bounces and complaints in the tenant's suppression list (`sft.service.ses_events`).

`python -m sft.workers.notify invite-backlog` runs the one-off pass that invites, through the
pool, every member left `invited` before it existed (#193), then exits: 0 done, 1 failed.

Probes and metrics on the internal port (architecture 8): `emails_sent_total{type}`,
`email_caps_hit_total{cap}`, `worker_messages_total{consumer,outcome}` and the counter store's.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import logging
import sys
from collections.abc import Awaitable, Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import ClassVar, Protocol
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.hmac_keyrings import CodeKeyring, LinkKeyring
from sft.core.logs import configure_logging
from sft.core.pseudonyms import EmailKeyring
from sft.core.settings import EXIT_BAD_SETTINGS, NotifySettings, load_settings
from sft.core.telemetry import configure_tracing
from sft.data.counters import CounterMetrics, CounterStore, ValkeyIam
from sft.data.database import Database
from sft.data.mail import Mailer, OutgoingEmail, mailer_from_settings
from sft.data.outbox import OutboxMessage, Queue
from sft.runtime.cognito import CognitoUserPool
from sft.runtime.keycloak import KeycloakUserPool
from sft.runtime.secrets import Keyrings, KeyringUnavailableError
from sft.service.email import EmailRenderer
from sft.service.notifications import CONSUMER, Done, Notifier, NotifyMetrics, invite_backlog
from sft.service.rate_limits import RateLimiter
from sft.service.ses_events import CONSUMER as SES_CONSUMER
from sft.service.ses_events import SesEvents, parse_event
from sft.service.user_pool import UserPool
from sft.workers.consumer import (
    LONG_POLL_SECONDS,
    Consumer,
    ConsumerLoop,
    ConsumerMetrics,
    Delivery,
    Outcome,
)
from sft.workers.process import EXIT_FAILED, WorkerProcess
from sft.workers.queues import SqsQueues

log = logging.getLogger(__name__)

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


class SesEventsConsumer(Consumer):
    """The ses-events queue's consumer: each event in its tenant's scope, recorded once."""

    name: ClassVar[str] = SES_CONSUMER
    queue: ClassVar[Queue] = Queue.SES_EVENTS

    def __init__(self, database: Database, events: SesEvents) -> None:
        super().__init__(database)
        self.events = events

    def parse(self, body: str) -> OutboxMessage | None:
        event = parse_event(body)
        return None if event is None else event.as_message()

    async def handle(self, session: AsyncSession, delivery: Delivery) -> None:
        event = parse_event(delivery.body)
        if event is not None:  # parsed once already, the same way
            await self.events.handle(session, event)


def threaded_send(
    mailer: Mailer, executor: ThreadPoolExecutor
) -> Callable[[OutgoingEmail], Awaitable[str]]:
    """The blocking mailer, run in `executor` so the event loop never waits on SMTP or SES."""

    async def send(email: OutgoingEmail) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(executor, functools.partial(mailer.send, email))

    return send


def threaded_release(
    mailer: Mailer, executor: ThreadPoolExecutor
) -> Callable[[UUID, str], Awaitable[None]]:
    """The mailer's suppression release (#217), in `executor` like the sends."""

    async def release(tenant_id: UUID, address: str) -> None:
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(executor, functools.partial(mailer.release, tenant_id, address))

    return release


class ClosablePool(UserPool, Protocol):
    async def aclose(self) -> None: ...


def user_pool(settings: NotifySettings) -> ClosablePool | None:
    """The user pool's admin side the settings name, or None (`USER_POOL_BACKEND=none`)."""
    if settings.user_pool_backend == "cognito":
        pool_id, provider = settings.cognito_user_pool_id, settings.user_pool_provider_name
        if pool_id is None or provider is None:  # NotifySettings refuses it; narrows the types
            raise RuntimeError("USER_POOL_BACKEND=cognito without its settings")
        return CognitoUserPool.create(
            region=settings.aws_region, user_pool_id=pool_id, provider_name=provider
        )
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
    # Its three keyrings first: named secrets are read now, then every 5 minutes (#184).
    keyrings = Keyrings.create(region=settings.aws_region, registry=process.registry)
    try:
        link_keys = await keyrings.load(
            settings.link_hmac_keyring, LinkKeyring.from_json, name="link"
        )
        code_keys = await keyrings.load(
            settings.code_hmac_keyring, CodeKeyring.from_json, name="code"
        )
        emails = await keyrings.load(
            settings.email_hmac_keyring, EmailKeyring.from_json, name="email"
        )
    except KeyringUnavailableError as exc:
        log.critical("keyring unavailable", extra={"error": str(exc)})
        return EXIT_FAILED
    database = Database.connect(
        settings.database_url.get_secret_value(),
        pool_size=settings.database_pool_size,
        iam_region=settings.aws_region if settings.database_iam_auth else None,
    )
    queues = SqsQueues.create(
        region=settings.aws_region,
        prefix=settings.sqs_queue_prefix,
        endpoint_url=settings.sqs_endpoint_url,
        read_timeout=LONG_POLL_SECONDS + 10,
    )
    counter_metrics = CounterMetrics.create(process.registry)
    iam = ValkeyIam.of(settings.valkey_iam_cache, settings.aws_region)
    store = CounterStore.connect(settings.valkey_url.get_secret_value(), counter_metrics, iam=iam)
    executor = ThreadPoolExecutor(max_workers=MAIL_THREADS, thread_name_prefix="mail")
    pool = user_pool(settings)
    mailer = mailer_from_settings(settings)
    notifier = Notifier(
        database,
        renderer=EmailRenderer(settings.web_app_url),
        send=threaded_send(mailer, executor),
        release=threaded_release(mailer, executor),
        link_keys=link_keys,
        code_keys=code_keys,
        emails=emails,
        limiter=RateLimiter(store, counter_metrics),
        metrics=NotifyMetrics.create(process.registry),
        pool=pool,
    )
    consumer_metrics = ConsumerMetrics.create(process.registry)
    loop = ConsumerLoop(NotifyConsumer(database, notifier), queues, consumer_metrics)
    ses_loop = ConsumerLoop(
        SesEventsConsumer(database, SesEvents(emails)),
        queues,
        consumer_metrics,
    )

    async def both(stopping: asyncio.Event) -> None:
        await asyncio.gather(loop.run(stopping), ses_loop.run(stopping))

    refresh = asyncio.create_task(keyrings.run())
    try:
        return await process.run(both, handle_signals=handle_signals)
    finally:
        refresh.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await refresh
        if pool is not None:
            await pool.aclose()
        await store.close()
        await queues.close()
        await asyncio.to_thread(executor.shutdown, wait=True)
        await database.dispose()


async def run_invite_backlog(settings: NotifySettings) -> int:
    """The one-off invitation pass (#193): 0 when it finished, 1 when it failed."""
    provider = settings.user_pool_provider_name
    if settings.user_pool_backend == "none" or provider is None:
        log.error("the invitation backlog needs a user pool (USER_POOL_BACKEND)")
        return EXIT_FAILED
    database = Database.connect(
        settings.database_url.get_secret_value(),
        pool_size=1,
        iam_region=settings.aws_region if settings.database_iam_auth else None,
    )
    try:
        invited = await invite_backlog(database, provider_name=provider)
    except Exception:
        log.exception("the invitation backlog failed; running it again is safe")
        return EXIT_FAILED
    finally:
        await database.dispose()
    log.info("invitation backlog done", extra={"invited": invited})
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args not in ([], ["invite-backlog"]):
        print("usage: python -m sft.workers.notify [invite-backlog]", file=sys.stderr)
        return EXIT_BAD_SETTINGS
    settings = load_settings(NotifySettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    if args:
        return asyncio.run(run_invite_backlog(settings))
    tracing = configure_tracing(
        SERVICE_NAME, settings.app_version, settings.otel_exporter_otlp_endpoint
    )
    try:
        return asyncio.run(run_notify_worker(settings))
    finally:
        tracing.shutdown()


if __name__ == "__main__":
    sys.exit(main())
