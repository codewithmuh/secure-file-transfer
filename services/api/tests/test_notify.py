"""The notification worker (#178, #179): link emails, recipients' status, notices and codes.

The worker runs as `sft_notify` against the real database, through `Notifier.handle`, with every
email recorded (notify_fixtures.py). One test sends through the SMTP adapter to a real Mailpit
when TEST_MAIL_CATCHER_URL and TEST_SMTP_PORT are set; the cross-tenant cap's test counts in a
real Valkey (TEST_VALKEY_URL).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import threading
import time
import urllib.parse
import urllib.request
import uuid
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from prometheus_client import CollectorRegistry

from member_fixtures import (
    EMAIL_KEYRING,
    Tenant,
    client,
    seed_tenant,
    seed_user,
    session_caller,
)
from messaging import FakeQueues
from notify_fixtures import (
    CODE_KEYS,
    LINK_KEYS,
    WEB_APP_URL,
    AdmitAll,
    Sent,
    drain,
    elapse,
    message,
    notifier,
    pending,
)
from pg import ScratchDatabase
from sft.core.errors import RateLimited
from sft.core.settings import MailSettings
from sft.data.counters import CounterStore
from sft.data.database import Database
from sft.data.mail import MailError, MailErrorKind, OutgoingEmail, mailer_from_settings
from sft.data.models import Role
from sft.data.roles import NOTIFY
from sft.service.email import EmailRenderer
from sft.service.notifications import CONSUMER, Done, Notifier, NotifyMetrics
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import CROSS_TENANT_LINK_EMAILS, KeyType
from sft.workers.consumer import ConsumerLoop, ConsumerMetrics, Delivery, Outcome
from sft.workers.notify import MAIL_THREADS, NotifyConsumer, threaded_send
from sft.workers.queues import ReceivedMessage
from transfer_fixtures import seed_transfer

pytestmark = pytest.mark.anyio

Logs = Callable[[], list[dict[str, object]]]


@dataclass
class World:
    db: ScratchDatabase
    database: Database
    tenant: Tenant


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    database = Database.connect(migrated_db.url(NOTIFY), pool_size=2)
    yield World(migrated_db, database, seed_tenant(migrated_db))
    await database.dispose()


def sent_transfer(
    w: World, recipients: tuple[str, ...], *, tenant: Tenant | None = None
) -> tuple[uuid.UUID, list[uuid.UUID]]:
    """A transfer the evaluation has just sent: its recipients `queued` (data model 2.2)."""
    owner = tenant or w.tenant
    transfer_id, ids = seed_transfer(
        w.db, owner.id, owner.target, state="sent", recipients=recipients
    )
    w.db.sql(
        "UPDATE transfer_recipients SET delivery_state = 'queued' WHERE transfer_id = :id",
        id=transfer_id,
    )
    return transfer_id, ids


def recipient(w: World, recipient_id: uuid.UUID) -> dict[str, Any]:
    [row] = w.db.sql(
        "SELECT delivery_state, notified_at, link_token_hash, link_key_id, link_issued_at "
        "FROM transfer_recipients WHERE id = :id",
        id=recipient_id,
    )
    keys = ("delivery_state", "notified_at", "link_token_hash", "link_key_id", "link_issued_at")
    return dict(zip(keys, row, strict=True))


def actions(w: World, target: uuid.UUID) -> list[object]:
    return [
        a
        for (a,) in w.db.sql(
            "SELECT action FROM audit_events WHERE target_id = :id ORDER BY occurred_at, id",
            id=target,
        )
    ]


def unique() -> str:
    return f"r-{uuid.uuid4().hex[:12]}@partner.example"


# ---- the link email ----


async def test_a_sent_transfer_emails_each_recipient_their_link_in_their_locale(
    w: World, json_logs: Logs
) -> None:
    first, second = unique(), unique()
    transfer_id, ids = sent_transfer(w, (first, second))
    w.db.sql("UPDATE transfer_recipients SET locale = 'ja' WHERE id = :id", id=ids[1])
    sent = Sent()
    registry = CollectorRegistry()
    worker = notifier(w.database, sent, registry=registry)
    fan_out = message(w.tenant.id, "transfer.sent", transfer_id=transfer_id)
    assert await worker.handle(fan_out) is Done.PROCESSED
    assert sent.emails == [], "the fan-out sends nothing itself"
    assert [m.topic for m in pending(w.db, w.tenant.id)] == ["recipient.link_due"] * 2
    w.db.sql("UPDATE outbox SET published_at = NULL WHERE tenant_id = :t", t=w.tenant.id)
    assert await drain(worker, w.db, w.tenant.id) == [Done.PROCESSED] * 2
    assert [e.email_type for e in sent.emails] == ["transfer_link"] * 2
    [english], [japanese] = sent.to(first), sent.to(second)
    assert english.subject.isascii()
    assert not japanese.subject.isascii()
    assert english.reply_to == japanese.reply_to  # the sender
    for address, recipient_id in ((first, ids[0]), (second, ids[1])):
        [token] = sent.links(address)
        assert f"{WEB_APP_URL}/t#{token}" in sent.to(address)[0].text
        row = recipient(w, recipient_id)
        assert row["link_token_hash"] == hashlib.sha256(token.encode()).digest()
        assert row["delivery_state"] == "sent"
        assert row["notified_at"] is not None
        assert actions(w, recipient_id) == ["recipient.link_issued", "email.sent"]
        # The token travels in the email only: never the outbox, a log or an audit row.
        assert not w.db.sql("SELECT 1 FROM outbox WHERE payload::text LIKE :t", t=f"%{token}%")
        assert not w.db.sql(
            "SELECT 1 FROM audit_events WHERE details::text LIKE :t", t=f"%{token}%"
        )
        assert token not in json.dumps(json_logs())
    assert registry.get_sample_value("emails_sent_total", {"type": "transfer_link"}) == 2
    # The fan-out was recorded once; a second copy is a duplicate and writes nothing more.
    assert await worker.handle(fan_out) is Done.DUPLICATE
    assert pending(w.db, w.tenant.id) == []


async def test_a_retry_rebuilds_the_same_link_and_a_recorded_success_isnt_sent_again(
    w: World,
) -> None:
    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    sent = Sent(fail=[MailErrorKind.UNAVAILABLE])
    worker = notifier(w.database, sent)
    due = message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id)
    with pytest.raises(MailError):
        await worker.handle(due)
    issued = recipient(w, recipient_id)
    assert issued["delivery_state"] == "queued"
    assert issued["link_issued_at"] is not None
    assert await worker.handle(due) is Done.PROCESSED
    [token] = sent.links(address)
    assert recipient(w, recipient_id)["link_token_hash"] == issued["link_token_hash"]
    assert hashlib.sha256(token.encode()).digest() == issued["link_token_hash"]
    # The same message again, after the success it recorded: nothing more is sent.
    assert await worker.handle(due) is Done.DUPLICATE
    # Another copy of the work (a stale message) finds the email sent already.
    again = message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id)
    assert await worker.handle(again) is Done.PROCESSED
    assert len(sent.emails) == 1


async def test_clearing_the_link_gives_a_new_token_and_stops_the_old_one(w: World) -> None:
    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    sent = Sent()
    worker = notifier(w.database, sent)
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id))
    old = recipient(w, recipient_id)["link_token_hash"]
    # What an unlock does (data model 2.4).
    w.db.sql(
        "UPDATE transfer_recipients SET link_token_hash = NULL, link_issued_at = NULL, "
        "link_key_id = NULL, delivery_state = 'queued', notified_at = NULL WHERE id = :id",
        id=recipient_id,
    )
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id))
    first, second = sent.links(address)
    assert first != second
    new = recipient(w, recipient_id)["link_token_hash"]
    assert new == hashlib.sha256(second.encode()).digest() != old
    assert not w.db.sql("SELECT 1 FROM transfer_recipients WHERE link_token_hash = :h", h=old)


async def test_delivery_goes_pending_queued_sent(w: World) -> None:
    address = unique()
    transfer_id, [recipient_id] = seed_transfer(
        w.db, w.tenant.id, w.tenant.target, state="draft", recipients=(address,)
    )
    assert recipient(w, recipient_id)["delivery_state"] == "pending"
    worker = notifier(w.database, Sent())
    # A link message for a transfer that isn't sent sends nothing.
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id))
    assert recipient(w, recipient_id)["delivery_state"] == "pending"
    w.db.sql(
        "UPDATE transfers SET state = 'sent', submitted_at = now(), sent_at = now(), "
        "expires_at = now() + interval '1 day' WHERE id = :id",
        id=transfer_id,
    )
    w.db.sql(
        "UPDATE transfer_recipients SET delivery_state = 'queued' WHERE id = :id", id=recipient_id
    )
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id))
    assert recipient(w, recipient_id)["delivery_state"] == "sent"


async def test_a_recipient_suppressed_after_the_send_gets_suppressed_and_no_email(
    w: World,
) -> None:
    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    w.db.sql(
        "INSERT INTO email_suppressions (id, tenant_id, email_hmac, hmac_key_id, reason) "
        "VALUES (:id, :tenant, :hmac, :key, 'hard_bounce')",
        id=uuid.uuid4(),
        tenant=w.tenant.id,
        hmac=EMAIL_KEYRING.active(address.lower()),
        key=EMAIL_KEYRING.active_key_id,
    )
    sent = Sent()
    worker = notifier(w.database, sent)
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id))
    assert sent.emails == []
    row = recipient(w, recipient_id)
    assert (row["delivery_state"], row["notified_at"], row["link_issued_at"]) == (
        "suppressed",
        None,
        None,
    )
    assert actions(w, recipient_id) == ["recipient.suppressed"]


async def test_over_the_cap_the_email_waits_and_the_recipient_stays_queued(w: World) -> None:
    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    sent = Sent()
    registry = CollectorRegistry()
    worker = notifier(w.database, sent, limiter=AdmitAll(refuse=3600), registry=registry)
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id))
    assert sent.emails == []
    row = recipient(w, recipient_id)
    assert (row["delivery_state"], row["notified_at"]) == ("queued", None)
    # Held, not refused: a new message for later, SQS's longest delay at most.
    [(delay,)] = w.db.sql(
        "SELECT delay_seconds FROM outbox WHERE topic = 'recipient.link_due' "
        "AND payload->>'recipient_id' = :id",
        id=str(recipient_id),
    )
    assert delay == 900
    assert (
        registry.get_sample_value("email_caps_hit_total", {"cap": "address_link_emails_all"}) == 1
    )


async def test_the_101st_link_email_to_one_address_across_two_tenants_is_delayed(
    w: World, counter_store: CounterStore
) -> None:
    from sft.data.counters import CounterMetrics

    address = unique()
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()))
    keys = {KeyType.EMAIL: EMAIL_KEYRING.for_limits(address, datetime.now(UTC))}
    for _ in range(98):  # 98 link emails to the address already today, from other tenants
        await limiter.check(CROSS_TENANT_LINK_EMAILS, keys)
    other = seed_tenant(w.db)
    _, [mine] = sent_transfer(w, (address,))
    _, [theirs] = sent_transfer(w, (address,), tenant=other)
    _, [last] = sent_transfer(w, (address,), tenant=other)
    sent = Sent()
    worker = notifier(w.database, sent, limiter=limiter)
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=mine))
    await worker.handle(message(other.id, "recipient.link_due", recipient_id=theirs))
    assert len(sent.to(address)) == 2  # the 99th and 100th
    await worker.handle(message(other.id, "recipient.link_due", recipient_id=last))
    assert len(sent.to(address)) == 2, "the 101st waits"
    assert recipient(w, last)["delivery_state"] == "queued"
    assert w.db.sql(
        "SELECT 1 FROM outbox WHERE payload->>'recipient_id' = :id AND delay_seconds > 0",
        id=str(last),
    )


# ---- notices to the member ----


async def test_a_held_transfer_emails_its_member_once_per_hold(w: World) -> None:
    w.db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (:t, 'ja')",
        t=w.tenant.id,
    )
    transfer_id, _ = seed_transfer(w.db, w.tenant.id, w.tenant.target, state="held")
    [(owner,)] = w.db.sql("SELECT email FROM users WHERE id = :id", id=w.tenant.target)
    sent = Sent()
    worker = notifier(w.database, sent)
    held = message(w.tenant.id, "transfer.held", transfer_id=transfer_id)
    assert await worker.handle(held) is Done.PROCESSED
    assert await worker.handle(held) is Done.DUPLICATE
    [email] = sent.emails
    assert (email.email_type, email.to) == ("transfer_held", owner)
    assert not email.subject.isascii(), "in the tenant's language"
    assert f"{WEB_APP_URL}/transfers/{transfer_id}" in email.text
    assert actions(w, transfer_id) == ["email.sent"]
    # Once it has moved on, a late copy of a hold would be wrong: nothing is sent.
    w.db.sql(
        "UPDATE transfers SET state = 'submitted', hold_reason = NULL WHERE id = :id",
        id=transfer_id,
    )
    await worker.handle(message(w.tenant.id, "transfer.held", transfer_id=transfer_id))
    assert len(sent.emails) == 1


async def test_a_transfer_back_to_draft_emails_the_new_notice(w: World) -> None:
    transfer_id, _ = seed_transfer(w.db, w.tenant.id, w.tenant.target, state="draft")
    sent = Sent()
    worker = notifier(w.database, sent)
    await worker.handle(message(w.tenant.id, "transfer.returned_to_draft", transfer_id=transfer_id))
    [email] = sent.emails
    assert email.email_type == "transfer_returned_to_draft"
    assert email.subject == "Your transfer is back to draft"


async def test_a_first_download_emails_the_member_once_with_no_file_name(w: World) -> None:
    # #214: in the member's language (the tenant's default), whatever the transfer's state now.
    w.db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (:t, 'ja')",
        t=w.tenant.id,
    )
    transfer_id, _ = seed_transfer(w.db, w.tenant.id, w.tenant.target, state="revoked")
    [(owner,)] = w.db.sql("SELECT email FROM users WHERE id = :id", id=w.tenant.target)
    sent = Sent()
    worker = notifier(w.database, sent)
    notice = message(w.tenant.id, "transfer.first_download", transfer_id=transfer_id)
    assert await worker.handle(notice) is Done.PROCESSED
    assert await worker.handle(notice) is Done.DUPLICATE
    [email] = sent.emails
    assert (email.email_type, email.to) == ("first_download", owner)
    assert not email.subject.isascii(), "in the tenant's language"
    assert f"{WEB_APP_URL}/transfers/{transfer_id}" in email.text
    assert actions(w, transfer_id) == ["email.sent"]
    # A member who has left gets nothing.
    w.db.sql("UPDATE users SET status = 'deactivated' WHERE id = :id", id=w.tenant.target)
    await worker.handle(message(w.tenant.id, "transfer.first_download", transfer_id=transfer_id))
    assert len(sent.emails) == 1


async def test_an_invitation_is_recorded_and_sends_nothing_until_cognito(w: World) -> None:
    sent = Sent()
    worker = notifier(w.database, sent)
    invited = message(w.tenant.id, "member.invited", user_id=w.tenant.member)
    assert await worker.handle(invited) is Done.PROCESSED
    assert await worker.handle(invited) is Done.DUPLICATE
    assert sent.emails == []


async def test_a_message_of_another_kind_is_left_for_the_dead_letter_queue(w: World) -> None:
    worker = notifier(w.database, Sent())
    with pytest.raises(ValueError, match=r"no 'file\.scan' messages"):
        await worker.handle(message(w.tenant.id, "file.scan", file_id=uuid.uuid4()))
    with pytest.raises(ValueError, match="names one recipient_id"):
        await worker.handle(message(w.tenant.id, "recipient.link_due", file_id=uuid.uuid4()))


async def test_a_rejected_email_isnt_retried(w: World) -> None:
    address = unique()
    transfer_id, [recipient_id] = sent_transfer(w, (address,))
    sent = Sent(fail=[MailErrorKind.REJECTED])
    limiter = AdmitAll()
    worker = notifier(w.database, sent, limiter=limiter)
    due = message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id)
    assert await worker.handle(due) is Done.PROCESSED
    assert await worker.handle(due) is Done.DUPLICATE
    # The provider will never take it: `bounced`, audited, and the member sees it (FR-7).
    row = recipient(w, recipient_id)
    assert (row["delivery_state"], row["notified_at"]) == ("bounced", None)
    assert actions(w, recipient_id) == ["recipient.link_issued", "email.rejected"]
    assert limiter.charges == 0, "a rejected email spends no cap"
    owner = session_caller(w.tenant.id, w.tenant.target, Role.MEMBER)
    async with client(w.db, lambda: owner) as member:
        listed = await member.get(f"/v1/transfers/{transfer_id}/recipients")
    [status] = listed.json()["items"]
    assert status["delivery_state"] == "bounced"


async def test_a_notice_to_six_people_throttled_midway_reaches_each_once(w: World) -> None:
    _, [recipient_id] = sent_transfer(w, (unique(),))
    for _ in range(4):
        seed_user(w.db, w.tenant.id, role="admin")  # with the owner and the first admin: six
    w.db.sql(
        "UPDATE transfer_recipients SET failed_attempts = 20, locked_at = now() WHERE id = :id",
        id=recipient_id,
    )
    sent = Sent(fail_on={4: MailErrorKind.THROTTLED})
    worker = notifier(w.database, sent)
    locked = message(w.tenant.id, "recipient.locked", recipient_id=recipient_id)
    with pytest.raises(MailError):
        await worker.handle(locked)
    assert len(sent.emails) == 3
    assert await worker.handle(locked) is Done.PROCESSED
    to = [e.to for e in sent.emails]
    assert len(to) == len(set(to)) == 6, "each person gets exactly one"
    assert await worker.handle(locked) is Done.DUPLICATE
    assert len(sent.emails) == 6
    assert actions(w, recipient_id).count("email.sent") == 6


async def test_failed_sends_spend_nothing_of_the_cross_tenant_cap(
    w: World, counter_store: CounterStore
) -> None:
    from sft.data.counters import CounterMetrics

    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()))
    sent = Sent(fail=[MailErrorKind.UNAVAILABLE] * 5)
    worker = notifier(w.database, sent, limiter=limiter)
    due = message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id)
    for _ in range(5):
        with pytest.raises(MailError):
            await worker.handle(due)
    assert await worker.handle(due) is Done.PROCESSED
    assert len(sent.to(address)) == 1
    # Exactly one unit spent: 99 more fit in the day, the 100th more doesn't.
    keys = {KeyType.EMAIL: EMAIL_KEYRING.for_limits(address, datetime.now(UTC))}
    for _ in range(99):
        await limiter.check(CROSS_TENANT_LINK_EMAILS, keys)
    with pytest.raises(RateLimited):
        await limiter.check(CROSS_TENANT_LINK_EMAILS, keys)


async def test_a_link_another_attempt_stored_first_is_the_one_sent(w: World) -> None:
    from notify_fixtures import LINK_KEYS
    from sft.data import recipients as recipient_rows
    from sft.data.scope import Scope

    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    worker = notifier(w.database, Sent())
    async with w.database.transaction(Scope.tenant(w.tenant.id)) as session:
        seen = await recipient_rows.link_target(session, recipient_id, lock=True)
    assert seen is not None
    assert seen.link_issued_at is None
    # Meanwhile another attempt stores its link.
    stored_at = datetime(2026, 11, 6, 1, 2, 3, 456789, tzinfo=UTC)
    stored = LINK_KEYS.token("l1", recipient_id, stored_at)
    w.db.sql(
        "UPDATE transfer_recipients SET link_issued_at = :at, link_key_id = 'l1', "
        "link_token_hash = :hash WHERE id = :id",
        at=stored_at,
        hash=hashlib.sha256(stored.encode()).digest(),
        id=recipient_id,
    )
    async with w.database.transaction(Scope.tenant(w.tenant.id)) as session:
        token = await worker._token(session, seen)
    assert token == stored, "the stored link, never a token whose hash isn't stored"
    assert recipient(w, recipient_id)["link_token_hash"] == hashlib.sha256(token.encode()).digest()
    # A stored link this worker can't rebuild (its key is gone) sends nothing.
    w.db.sql("UPDATE transfer_recipients SET link_key_id = 'gone' WHERE id = :id", id=recipient_id)
    async with w.database.transaction(Scope.tenant(w.tenant.id)) as session:
        assert await worker._token(session, seen) is None


async def test_a_suspended_tenant_sends_nothing(w: World) -> None:
    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    w.db.sql("UPDATE tenants SET status = 'suspended' WHERE id = :id", id=w.tenant.id)
    sent = Sent()
    await notifier(w.database, sent).handle(
        message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id)
    )
    assert sent.emails == []


# ---- codes and lockouts (#179) ----


async def test_a_code_request_makes_a_code_that_supersedes_the_last_and_emails_it_only(
    w: World,
) -> None:
    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    sent = Sent()
    worker = notifier(w.database, sent)
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id))
    for _ in range(2):
        await worker.handle(
            message(w.tenant.id, "recipient.code_requested", recipient_id=recipient_id)
        )
    first, second = sent.codes(address)
    assert len(first) == len(second) == 6
    rows = w.db.sql(
        "SELECT id, code_hmac, superseded_at IS NOT NULL, expires_at - created_at "
        "FROM verification_codes WHERE recipient_id = :id ORDER BY created_at, id",
        id=recipient_id,
    )
    assert [r[2] for r in rows] == [True, False]
    assert str(rows[1][3]) == "0:10:00"
    from notify_fixtures import CODE_KEYS

    assert CODE_KEYS.matches("c1", rows[1][0], second, rows[1][1])  # type: ignore[arg-type]
    code_email = sent.of_type("verification_code")[-1]
    assert WEB_APP_URL not in code_email.text, "the code email holds no link"
    assert actions(w, recipient_id)[-2:] == ["verification.code_created", "email.sent"]


async def test_no_code_is_made_for_a_locked_recipient(w: World) -> None:
    address = unique()
    _, [recipient_id] = sent_transfer(w, (address,))
    sent = Sent()
    worker = notifier(w.database, sent)
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=recipient_id))
    w.db.sql(
        "UPDATE transfer_recipients SET failed_attempts = 20, locked_at = now() WHERE id = :id",
        id=recipient_id,
    )
    await worker.handle(message(w.tenant.id, "recipient.code_requested", recipient_id=recipient_id))
    assert sent.codes(address) == []
    assert not w.db.sql(
        "SELECT 1 FROM verification_codes WHERE recipient_id = :id", id=recipient_id
    )


async def test_a_lockout_notice_goes_to_the_owner_and_every_admin(w: World) -> None:
    _, [recipient_id] = sent_transfer(w, (unique(),))
    w.db.sql(
        "UPDATE transfer_recipients SET failed_attempts = 20, locked_at = now() WHERE id = :id",
        id=recipient_id,
    )
    sent = Sent()
    await notifier(w.database, sent).handle(
        message(w.tenant.id, "recipient.locked", recipient_id=recipient_id)
    )
    to = {
        email
        for (email,) in w.db.sql(
            "SELECT email FROM users WHERE id IN (:a, :b)", a=w.tenant.target, b=w.tenant.admin
        )
    }
    assert {e.to for e in sent.emails} == to
    assert {e.email_type for e in sent.emails} == {"recipient_locked"}


# ---- the admins' DLP policy notices (#218, FR-54) ----


async def test_a_dlp_policy_change_emails_every_active_admin_naming_the_change(w: World) -> None:
    second = seed_user(w.db, w.tenant.id, role="admin")
    seed_user(w.db, w.tenant.id, role="admin", status="deactivated")
    sent = Sent()
    worker = notifier(w.database, sent)
    done = await worker.handle(message(w.tenant.id, "dlp_policy.changed.rule_added"))
    assert done is Done.PROCESSED
    # Coalesced (#230): the notice waits for its 10 minutes.
    assert sent.emails == []
    elapse(w.db, w.tenant.id, timedelta(minutes=10))
    assert await drain(worker, w.db, w.tenant.id) == [Done.PROCESSED]
    to = {
        email
        for (email,) in w.db.sql(
            "SELECT email FROM users WHERE id IN (:a, :b)", a=w.tenant.admin, b=second
        )
    }
    assert {e.to for e in sent.emails} == to
    assert {e.email_type for e in sent.emails} == {"dlp_policy_changed"}
    assert all("A rule was added" in e.text for e in sent.emails)


async def test_an_admin_api_change_reaches_the_admins_through_the_outbox(w: World) -> None:
    admin = session_caller(w.tenant.id, w.tenant.admin, Role.ADMIN)
    async with client(w.db, lambda: admin) as http:
        response = await http.post(
            "/v1/dlp/detectors",
            json={"name": "Codenames", "kind": "keywords", "keywords": ["orion-codename"]},
        )
        assert response.status_code == 201, response.text
    sent = Sent()
    worker = notifier(w.database, sent)
    assert await drain(worker, w.db, w.tenant.id) == [Done.PROCESSED]
    elapse(w.db, w.tenant.id, timedelta(minutes=10))  # the coalesced notice is due (#230)
    assert await drain(worker, w.db, w.tenant.id) == [Done.PROCESSED]
    [email] = sent.emails
    assert email.email_type == "dlp_policy_changed"
    assert "A detector or keyword list was added" in email.text
    # The notice names the kind of change, never the detector or its terms.
    for secret in ("Codenames", "orion-codename"):
        assert secret not in email.text
        assert secret not in email.html


# ---- the worker's process ----


async def test_the_consumer_reports_a_duplicate_so_the_loop_deletes_it(w: World) -> None:
    consumer = NotifyConsumer(w.database, notifier(w.database, Sent()))
    invited = message(w.tenant.id, "member.invited", user_id=w.tenant.member)
    assert await consumer.process(Delivery(invited)) is Outcome.PROCESSED
    assert await consumer.process(Delivery(invited)) is Outcome.DUPLICATE
    assert consumer.name == CONSUMER == "notify"


@dataclass
class Overlap:
    """A blocking mailer that records how many sends were in flight at once."""

    in_flight: int = 0
    most: int = 0
    sent: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def send(self, email: OutgoingEmail) -> str:
        with self.lock:
            self.in_flight += 1
            self.most = max(self.most, self.in_flight)
        time.sleep(0.02)  # long enough for a second send to start, if anything started one
        with self.lock:
            self.in_flight -= 1
            self.sent += 1
            return f"message-{self.sent}"

    def release(self, tenant_id: uuid.UUID, address: str) -> None:
        pass


async def test_the_worker_has_one_send_in_flight_so_one_mail_thread_is_enough(w: World) -> None:
    # #192: the loop handles a received batch one message at a time and the notifier awaits each
    # send, so the mail pool is one thread. Given four, as before, it still uses only one.
    addresses = tuple(unique() for _ in range(4))
    transfer_id, _ = sent_transfer(w, addresses)
    mailer = Overlap()
    executor = ThreadPoolExecutor(max_workers=4)
    worker = Notifier(
        w.database,
        renderer=EmailRenderer(WEB_APP_URL),
        send=threaded_send(mailer, executor),
        link_keys=LINK_KEYS,
        code_keys=CODE_KEYS,
        emails=EMAIL_KEYRING,
        limiter=AdmitAll(),
        metrics=NotifyMetrics.create(CollectorRegistry()),
    )
    loop = ConsumerLoop(
        NotifyConsumer(w.database, worker),
        FakeQueues(),
        ConsumerMetrics.create(CollectorRegistry()),
    )
    try:
        assert (
            await worker.handle(message(w.tenant.id, "transfer.sent", transfer_id=transfer_id))
            is Done.PROCESSED
        )
        due = pending(w.db, w.tenant.id)
        received = [ReceivedMessage(m.body(), f"handle-{n}", 1) for n, m in enumerate(due)]
        assert await loop.handle_all(received) == [Outcome.PROCESSED] * len(addresses)
    finally:
        executor.shutdown(wait=True)
    assert mailer.sent == len(addresses)
    assert mailer.most == 1
    assert MAIL_THREADS == 1


# ---- through Mailpit ----


@pytest.fixture
def mailpit() -> tuple[str, str, int]:
    api, port = os.environ.get("TEST_MAIL_CATCHER_URL"), os.environ.get("TEST_SMTP_PORT")
    if not api or not port:
        pytest.skip("set TEST_MAIL_CATCHER_URL and TEST_SMTP_PORT to a Mailpit (make up)")
    return api.rstrip("/"), os.environ.get("TEST_SMTP_HOST", "127.0.0.1"), int(port)


def _search(api: str, address: str) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"query": f'to:"{address}"'})
    url = f"{api}/api/v1/search?{query}"
    with urllib.request.urlopen(url, timeout=5) as response:  # noqa: S310 - a local test URL
        found: list[dict[str, Any]] = json.load(response)["messages"]
    return found


async def test_one_link_email_per_recipient_reaches_mailpit(
    w: World, mailpit: tuple[str, str, int]
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    from sft.service.email import EmailRenderer
    from sft.service.notifications import Notifier, NotifyMetrics

    api, host, port = mailpit
    first, second = unique(), unique()
    transfer_id, _ = sent_transfer(w, (first, second))
    settings = MailSettings(
        mail_backend="smtp",
        mail_from_address="no-reply@mail.sft.localhost",
        web_app_url=WEB_APP_URL,
        smtp_host=host,
        smtp_port=port,
    )
    executor = ThreadPoolExecutor(max_workers=2)
    from notify_fixtures import CODE_KEYS, LINK_KEYS

    worker = Notifier(
        w.database,
        renderer=EmailRenderer(WEB_APP_URL),
        send=threaded_send(mailer_from_settings(settings), executor),
        link_keys=LINK_KEYS,
        code_keys=CODE_KEYS,
        emails=EMAIL_KEYRING,
        limiter=AdmitAll(),  # type: ignore[arg-type]
        metrics=NotifyMetrics.create(CollectorRegistry()),
    )
    try:
        await worker.handle(message(w.tenant.id, "transfer.sent", transfer_id=transfer_id))
        await drain(worker, w.db, w.tenant.id)
    finally:
        executor.shutdown(wait=True)
    for address in (first, second):
        for _ in range(50):
            found = _search(api, address)
            if found:
                break
            await asyncio.sleep(0.1)
        assert len(found) == 1, address
        assert found[0]["Subject"] == "T sent you files"


# ---- the batched notice of received files (#213) ----


def notice_request(w: World, *, arrived: int, blocked: int, address: str) -> uuid.UUID:
    """An upload request whose notice is due, with its counts, as scan results leave it."""
    request_id = uuid.uuid4()
    w.db.sql(
        "INSERT INTO upload_requests (id, tenant_id, created_by, state, uploader_email, "
        "email_normalized, locale, expires_at, delivery_state, notice_due_at, "
        "arrived_since_notice, blocked_since_notice) VALUES (:id, :tenant, :owner, 'open', "
        ":address, lower(:address), 'ja', now() + interval '7 days', 'sent', now(), :arrived, "
        ":blocked)",
        id=request_id,
        tenant=w.tenant.id,
        owner=w.tenant.target,
        address=address,
        arrived=arrived,
        blocked=blocked,
    )
    return request_id


def notice_counts(w: World, request_id: uuid.UUID) -> tuple[object, ...]:
    [row] = w.db.sql(
        "SELECT arrived_since_notice, blocked_since_notice, notice_due_at IS NOT NULL "
        "FROM upload_requests WHERE id = :id",
        id=request_id,
    )
    return row


def owner_address(w: World) -> str:
    [(address,)] = w.db.sql("SELECT email FROM users WHERE id = :id", id=w.tenant.target)
    return str(address)


async def test_a_notice_sends_counts_to_both_sides_and_the_uploader_learns_only_the_policy(
    w: World,
) -> None:
    address = unique()
    request_id = notice_request(w, arrived=3, blocked=2, address=address)
    sent = Sent()
    worker = notifier(w.database, sent)
    done = await worker.handle(
        message(w.tenant.id, "upload_request.files_settled", upload_request_id=request_id)
    )
    assert done is Done.PROCESSED
    to_owner = {e.email_type: e for e in sent.to(owner_address(w))}
    assert set(to_owner) == {"files_arrived", "files_blocked_member"}
    assert "3 files have arrived" in to_owner["files_arrived"].subject
    assert f"/upload-requests/{request_id}" in to_owner["files_arrived"].text
    assert "2 files" in to_owner["files_blocked_member"].subject
    [to_uploader] = sent.to(address)
    assert to_uploader.email_type == "files_blocked_uploader"
    assert to_uploader.reply_to == owner_address(w), "replies go to the member who asked"
    assert any(ord(c) > 0x3000 for c in to_uploader.subject), "in the request's language"
    for word in ("infected", "scan", "upload-requests", str(request_id)):
        assert word not in to_uploader.text, word
    assert notice_counts(w, request_id) == (0, 0, False)
    assert "upload_request.notice_sent" in actions(w, request_id)
    # A copy of the message, delivered again, sends nothing more.
    again = await worker.handle(
        message(w.tenant.id, "upload_request.files_settled", upload_request_id=request_id)
    )
    assert again is Done.PROCESSED
    assert len(sent.emails) == 3


async def test_files_that_settle_while_a_notice_is_sent_make_the_next_one_due(w: World) -> None:
    request_id = notice_request(w, arrived=1, blocked=0, address=unique())
    sent = Sent()
    worker = notifier(w.database, sent)
    original = sent.__call__

    async def one_more_meanwhile(email: Any) -> str:
        # A scan result commits between the read and the send: one more file arrived.
        w.db.sql(
            "UPDATE upload_requests SET arrived_since_notice = arrived_since_notice + 1 "
            "WHERE id = :id",
            id=request_id,
        )
        return await original(email)

    worker.send = one_more_meanwhile
    await worker.handle(
        message(w.tenant.id, "upload_request.files_settled", upload_request_id=request_id)
    )
    assert [e.email_type for e in sent.emails] == ["files_arrived"]
    assert notice_counts(w, request_id) == (1, 0, True), "the next notice is due"
    later = w.db.sql(
        "SELECT delay_seconds FROM outbox WHERE topic = 'upload_request.files_settled' "
        "AND payload->>'upload_request_id' = :id",
        id=str(request_id),
    )
    assert later == [(300,)]


async def test_a_deactivated_owner_gets_no_notice_and_nobody_to_tell_takes_the_counts_off(
    w: World,
) -> None:
    address = unique()
    request_id = notice_request(w, arrived=1, blocked=1, address=address)
    w.db.sql("UPDATE users SET status = 'deactivated' WHERE id = :id", id=w.tenant.target)
    sent = Sent()
    worker = notifier(w.database, sent)
    await worker.handle(
        message(w.tenant.id, "upload_request.files_settled", upload_request_id=request_id)
    )
    assert [e.email_type for e in sent.emails] == ["files_blocked_uploader"]
    assert notice_counts(w, request_id) == (0, 0, False)
    # Nobody at all: the uploader's address bounced too. The counts still come off.
    w.db.sql(
        "UPDATE upload_requests SET blocked_since_notice = 1, notice_due_at = now() WHERE id = :id",
        id=request_id,
    )
    w.db.sql(
        "INSERT INTO email_suppressions (id, tenant_id, email_hmac, hmac_key_id, reason) "
        "VALUES (:id, :tenant, :hmac, :key, 'hard_bounce')",
        id=uuid.uuid4(),
        tenant=w.tenant.id,
        hmac=EMAIL_KEYRING.active(address.lower()),
        key=EMAIL_KEYRING.active_key_id,
    )
    await worker.handle(
        message(w.tenant.id, "upload_request.files_settled", upload_request_id=request_id)
    )
    assert len(sent.emails) == 1
    assert notice_counts(w, request_id) == (0, 0, False)
