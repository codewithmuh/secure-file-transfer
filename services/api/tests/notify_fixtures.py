"""The notification worker in the tests (#178, #179): a `Notifier` on the real database as
`sft_notify`, a sender that records every email (or fails on demand), and `drain`, which hands
every unhandled notify message in the outbox to the notifier, as the relay and SQS would.

`elapse` moves the tenant's delayed messages and notice windows back, as time passing would, for
the coalesced and digested notices (#230).

Emails are read back by recipient: `Sent.links(address)` and `Sent.codes(address)` pull the link
token and the code out of the text part, as a person would from their mailbox.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta

from prometheus_client import CollectorRegistry

from api_settings import CODE_HMAC_KEYRING, LINK_HMAC_KEYRING
from member_fixtures import EMAIL_KEYRING
from pg import ScratchDatabase
from sft.core.errors import RateLimited
from sft.core.hmac_keyrings import CodeKeyring, LinkKeyring
from sft.data.database import Database
from sft.data.mail import MailError, MailErrorKind, OutgoingEmail
from sft.data.outbox import TOPICS, OutboxMessage, Queue
from sft.service.email import EmailRenderer
from sft.service.notifications import Done, Notifier, NotifyMetrics
from sft.service.rate_limits import Charge

WEB_APP_URL = "https://app.sft.test"
LINK_KEYS = LinkKeyring.from_json(LINK_HMAC_KEYRING)
CODE_KEYS = CodeKeyring.from_json(CODE_HMAC_KEYRING)
_LINK = re.compile(re.escape(WEB_APP_URL) + r"/t#([A-Za-z0-9_-]+)")
_CODE = re.compile(r"\b([0-9]{6})\b")


@dataclass
class Sent:
    """Every email handed to the provider; `fail` makes the next sends fail with that kind."""

    emails: list[OutgoingEmail] = field(default_factory=list)
    fail: list[MailErrorKind] = field(default_factory=list)
    fail_on: dict[int, MailErrorKind] = field(default_factory=dict)
    """Calls (1-based, counted over the recorder's life) that fail with that kind."""
    calls: int = 0

    async def __call__(self, email: OutgoingEmail) -> str:
        self.calls += 1
        if self.calls in self.fail_on:
            raise MailError(self.fail_on.pop(self.calls), "TestFailure")
        if self.fail:
            raise MailError(self.fail.pop(0), "TestFailure")
        self.emails.append(email)
        return f"message-{len(self.emails)}"

    def to(self, address: str) -> list[OutgoingEmail]:
        return [e for e in self.emails if e.to == address]

    def of_type(self, email_type: str) -> list[OutgoingEmail]:
        return [e for e in self.emails if e.email_type == email_type]

    def links(self, address: str) -> list[str]:
        return [m.group(1) for e in self.to(address) for m in [_LINK.search(e.text)] if m]

    def codes(self, address: str) -> list[str]:
        return [
            m.group(1)
            for e in self.to(address)
            if e.email_type == "verification_code"
            for m in [_CODE.search(e.text)]
            if m
        ]


@dataclass
class AdmitAll:
    """A limiter that admits everything, or refuses with `retry_after` while `refuse` is set.
    `peeks` and `charges` count the cap's reads and what it spent."""

    peeks: int = 0
    charges: int = 0
    refuse: int | None = None

    async def peek_all(self, charges: Sequence[Charge]) -> None:
        self.peeks += 1
        if self.refuse is not None:
            raise RateLimited(retry_after=self.refuse)

    async def check_all(self, charges: Sequence[Charge]) -> None:
        self.charges += 1


def notifier(
    database: Database,
    sent: Sent,
    *,
    limiter: object | None = None,
    registry: CollectorRegistry | None = None,
) -> Notifier:
    return Notifier(
        database,
        renderer=EmailRenderer(WEB_APP_URL),
        send=sent,
        link_keys=LINK_KEYS,
        code_keys=CODE_KEYS,
        emails=EMAIL_KEYRING,
        limiter=limiter or AdmitAll(),  # type: ignore[arg-type]
        metrics=NotifyMetrics.create(registry or CollectorRegistry()),
    )


def message(tenant_id: uuid.UUID, topic: str, **payload: uuid.UUID) -> OutboxMessage:
    return OutboxMessage(id=uuid.uuid4(), topic=topic, tenant_id=tenant_id, payload=payload)


_NOTIFY_TOPICS = tuple(name for name, topic in TOPICS.items() if topic.queue is Queue.NOTIFY)


def pending(db: ScratchDatabase, tenant_id: uuid.UUID) -> list[OutboxMessage]:
    """The tenant's notify messages the relay hasn't sent and that are due, oldest first; each is
    then marked sent, as the relay does once SQS has it. A delayed message waits."""
    rows = db.sql(
        "UPDATE outbox SET published_at = now() WHERE tenant_id = :tenant AND published_at IS NULL "
        "AND topic = ANY (:topics) AND created_at + delay_seconds * interval '1 second' <= now() "
        "RETURNING id, topic, payload, created_at",
        tenant=tenant_id,
        topics=list(_NOTIFY_TOPICS),
    )
    return [
        OutboxMessage(
            id=row[0],  # type: ignore[arg-type]
            topic=str(row[1]),
            tenant_id=tenant_id,
            payload={k: uuid.UUID(v) for k, v in row[2].items()},  # type: ignore[union-attr]
        )
        for row in sorted(rows, key=lambda r: (r[3], str(r[0])))  # type: ignore[arg-type,return-value]
    ]


def elapse(db: ScratchDatabase, tenant_id: uuid.UUID, by: timedelta) -> None:
    """Time passes for the tenant's waiting messages and notice windows (#230): each delayed
    message and each window's times move back `by`, so what was due later is due now."""
    db.sql(
        "UPDATE outbox SET created_at = created_at - CAST(:by AS interval) "
        "WHERE tenant_id = :tenant AND published_at IS NULL",
        tenant=tenant_id,
        by=by,
    )
    db.sql(
        "UPDATE notice_windows SET window_started_at = window_started_at - CAST(:by AS interval), "
        "changed_at = changed_at - CAST(:by AS interval), due_at = due_at - CAST(:by AS interval) "
        "WHERE tenant_id = :tenant",
        tenant=tenant_id,
        by=by,
    )


async def drain(notifier: Notifier, db: ScratchDatabase, tenant_id: uuid.UUID) -> list[Done]:
    """Hand every pending notify message of the tenant to the notifier, until none is left."""
    done = []
    while found := pending(db, tenant_id):
        for item in found:
            done.append(await notifier.handle(item))
    return done
