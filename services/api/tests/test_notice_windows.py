"""The admins' and approvers' DLP notices, coalesced, digested and capped (#230; FR-43, FR-54;
abuse and rate limits 7.1; data model 2.5).

The notification worker runs as `sft_notify` against PostgreSQL through `Notifier.handle`, with
every email recorded (notify_fixtures.py); `elapse` moves the tenant's delayed messages and notice
windows back, as time passing would. The deactivation goes through the real app as a tenant admin.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta

import pytest
from prometheus_client import CollectorRegistry

from member_fixtures import Tenant, client, seed_tenant, seed_user, session_caller
from notify_fixtures import Sent, drain, elapse, message, notifier, pending
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.mail import MailError, MailErrorKind, OutgoingEmail
from sft.data.models import Role
from sft.data.roles import NOTIFY
from sft.service.notice_windows import APPROVER_EMAILS, NO_APPROVER_EMAILS
from sft.service.notifications import Done
from transfer_fixtures import seed_transfer

pytestmark = pytest.mark.anyio


@dataclass
class World:
    db: ScratchDatabase
    database: Database
    tenant: Tenant

    def address(self, user_id: uuid.UUID) -> str:
        [(email,)] = self.db.sql("SELECT email FROM users WHERE id = :id", id=user_id)
        return str(email)

    def topics(self) -> list[tuple[object, ...]]:
        """The tenant's notice messages not handled yet, with their delays."""
        return self.db.sql(
            "SELECT topic, delay_seconds FROM outbox WHERE tenant_id = :t AND published_at IS NULL "
            "AND topic IN ('dlp_policy.notice_due', 'dlp_approval.digest_due') ORDER BY created_at",
            t=self.tenant.id,
        )

    def window(self, notice: str, user_id: uuid.UUID | None = None) -> tuple[object, ...]:
        [row] = self.db.sql(
            "SELECT sent, changes, due_at IS NOT NULL FROM notice_windows WHERE tenant_id = :t "
            "AND notice = :n AND user_id IS NOT DISTINCT FROM CAST(:u AS uuid)",
            t=self.tenant.id,
            n=notice,
            u=user_id,
        )
        return tuple(row)


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    database = Database.connect(migrated_db.url(NOTIFY), pool_size=2)
    yield World(migrated_db, database, seed_tenant(migrated_db))
    await database.dispose()


def admins(w: World) -> set[str]:
    return {
        str(email)
        for (email,) in w.db.sql(
            "SELECT email FROM users WHERE tenant_id = :t AND role = 'admin' AND status = 'active'",
            t=w.tenant.id,
        )
    }


# ---- policy changes: one email per admin per 10 minutes ----


async def test_several_policy_changes_inside_10_minutes_send_one_email_per_admin(w: World) -> None:
    seed_user(w.db, w.tenant.id, role="admin")
    sent = Sent()
    worker = notifier(w.database, sent)
    for kind in ("rule_added", "mode_changed", "rule_added", "detector_removed"):
        done = await worker.handle(message(w.tenant.id, f"dlp_policy.changed.{kind}"))
        assert done is Done.PROCESSED
    assert sent.emails == [], "nothing goes out before the window ends"
    assert w.topics() == [("dlp_policy.notice_due", 600)], "one notice, 10 minutes on"
    assert await drain(worker, w.db, w.tenant.id) == []  # not due yet
    elapse(w.db, w.tenant.id, timedelta(minutes=10))
    assert await drain(worker, w.db, w.tenant.id) == [Done.PROCESSED]
    assert sorted(e.to for e in sent.emails) == sorted(admins(w))
    assert {e.email_type for e in sent.emails} == {"dlp_policy_changed"}
    for email in sent.emails:
        for label in (
            "A rule was added",
            "The policy mode",
            "A detector or keyword list was removed",
        ):
            assert label in email.text, label
    # Sent: nothing waits, and the next change starts a new window.
    assert w.window("dlp_policy_changed")[1:] == ([], False)
    await worker.handle(message(w.tenant.id, "dlp_policy.changed.rule_changed"))
    assert w.topics() == [("dlp_policy.notice_due", 600)]


async def test_a_change_while_the_notice_goes_out_is_told_in_the_next_one(w: World) -> None:
    db = w.db

    class ChangingDuringTheSend(Sent):
        async def __call__(self, email: OutgoingEmail) -> str:
            if not self.emails:  # a change lands while the notice is being sent
                db.sql(
                    "UPDATE notice_windows SET changes = changes || ARRAY['rule_removed'], "
                    "changed_at = now() + interval '1 second' "
                    "WHERE tenant_id = :t AND notice = 'dlp_policy_changed'",
                    t=w.tenant.id,
                )
            return await super().__call__(email)

    sent = ChangingDuringTheSend()
    worker = notifier(w.database, sent)
    await worker.handle(message(w.tenant.id, "dlp_policy.changed.rule_added"))
    elapse(w.db, w.tenant.id, timedelta(minutes=10))
    await drain(worker, w.db, w.tenant.id)
    assert len(sent.emails) == 1
    assert w.topics() == [("dlp_policy.notice_due", 600)], "the next notice is due"
    elapse(w.db, w.tenant.id, timedelta(minutes=10))
    await drain(worker, w.db, w.tenant.id)
    assert len(sent.emails) == 2
    assert "A rule was removed" in sent.emails[1].text


async def test_a_copy_of_a_sent_notice_sends_nothing(w: World) -> None:
    sent = Sent()
    worker = notifier(w.database, sent)
    await worker.handle(message(w.tenant.id, "dlp_policy.changed.rule_added"))
    elapse(w.db, w.tenant.id, timedelta(minutes=10))
    await drain(worker, w.db, w.tenant.id)
    copy = message(w.tenant.id, "dlp_policy.notice_due")
    assert await worker.handle(copy) is Done.PROCESSED
    assert len(sent.emails) == 1


# ---- approval requests: one digest per approver per hour past 20 ----


def seed_request(w: World, owner: uuid.UUID) -> uuid.UUID:
    """A pending approval request of a draft transfer of `owner`, with its decision and
    confirmation, as the superuser."""
    transfer, _ = seed_transfer(w.db, w.tenant.id, owner)
    decision, confirmation, request = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    w.db.sql(
        "INSERT INTO dlp_decisions (id, tenant_id, transfer_id, policy_version, mode, outcome, "
        "enforced, untrusted_recipients, new_domains) VALUES (:id, :tenant, :transfer, 1, "
        "'enforce', 'require_approval', true, 1, 1)",
        id=decision,
        tenant=w.tenant.id,
        transfer=transfer,
    )
    w.db.sql(
        "INSERT INTO dlp_confirmations (id, tenant_id, transfer_id, decision_id, confirmed_by, "
        "justification_ct) VALUES (:id, :tenant, :transfer, :decision, :user, '\\x00')",
        id=confirmation,
        tenant=w.tenant.id,
        transfer=transfer,
        decision=decision,
        user=owner,
    )
    w.db.sql(
        "INSERT INTO dlp_approval_requests (id, tenant_id, transfer_id, decision_id, "
        "confirmation_id, requested_by, approvals_required, expires_at) VALUES (:id, :tenant, "
        ":transfer, :decision, :confirmation, :user, 1, now() + interval '1 day')",
        id=request,
        tenant=w.tenant.id,
        transfer=transfer,
        decision=decision,
        confirmation=confirmation,
        user=owner,
    )
    return request


def approver(w: World) -> uuid.UUID:
    user = seed_user(w.db, w.tenant.id)
    w.db.sql("UPDATE users SET dlp_approver = true WHERE id = :id", id=user)
    return user


async def test_many_approval_requests_send_one_digest_per_approver_per_hour(w: World) -> None:
    busy, quiet = approver(w), approver(w)
    registry = CollectorRegistry()
    sent = Sent()
    worker = notifier(w.database, sent, registry=registry)
    # `busy` had 20 request emails this hour already.
    w.db.sql(
        "INSERT INTO notice_windows (id, tenant_id, notice, user_id, sent) "
        "VALUES (gen_random_uuid(), :t, 'dlp_approval_digest', :u, :sent)",
        t=w.tenant.id,
        u=busy,
        sent=APPROVER_EMAILS,
    )
    requests = [seed_request(w, w.tenant.member) for _ in range(3)]
    for request in requests:
        handled = message(w.tenant.id, "dlp_approval.requested", approval_request_id=request)
        assert await worker.handle(handled) is Done.PROCESSED
    assert sent.to(w.address(busy)) == [], "held for the digest"
    assert len(sent.to(w.address(quiet))) == 3, "under 20: one email per request"
    assert w.window("dlp_approval_digest", quiet)[0] == 3
    # One digest message for the hour, sent again until the hour ends (SQS waits 15 minutes).
    assert w.topics() == [("dlp_approval.digest_due", 900)]
    held = registry.get_sample_value("email_caps_hit_total", {"cap": "approver_request_emails"})
    assert held == 3
    elapse(w.db, w.tenant.id, timedelta(minutes=15))
    assert await drain(worker, w.db, w.tenant.id) == [Done.PROCESSED]
    assert sent.to(w.address(busy)) == []
    assert w.topics() == [("dlp_approval.digest_due", 900)]
    elapse(w.db, w.tenant.id, timedelta(minutes=46))
    await drain(worker, w.db, w.tenant.id)
    [digest] = sent.to(w.address(busy))
    assert digest.email_type == "dlp_approval_requested"
    assert "3 transfers" in digest.subject
    assert w.window("dlp_approval_digest", busy)[2] is False
    # The hour is over: the next request is emailed one by one again.
    later = seed_request(w, w.tenant.member)
    await worker.handle(message(w.tenant.id, "dlp_approval.requested", approval_request_id=later))
    assert len(sent.to(w.address(busy))) == 2
    assert w.window("dlp_approval_digest", busy)[0] == 1


async def test_a_digest_counts_only_what_the_approver_can_still_decide(w: World) -> None:
    busy = approver(w)
    sent = Sent()
    worker = notifier(w.database, sent)
    w.db.sql(
        "INSERT INTO notice_windows (id, tenant_id, notice, user_id, sent) "
        "VALUES (gen_random_uuid(), :t, 'dlp_approval_digest', :u, :sent)",
        t=w.tenant.id,
        u=busy,
        sent=APPROVER_EMAILS,
    )
    [first, second] = [seed_request(w, w.tenant.member) for _ in range(2)]
    for request in (first, second):
        await worker.handle(
            message(w.tenant.id, "dlp_approval.requested", approval_request_id=request)
        )
    # One is decided meanwhile; one of the approver's own transfers waits for someone else.
    w.db.sql(
        "UPDATE dlp_approval_requests SET state = 'approved', ended_at = now() WHERE id = :id",
        id=first,
    )
    seed_request(w, busy)
    elapse(w.db, w.tenant.id, timedelta(hours=1))
    await drain(worker, w.db, w.tenant.id)
    [digest] = sent.to(w.address(busy))
    assert "A transfer waits" in digest.subject, "one request the approver can decide"
    # Every request decided before the hour ends: no digest at all.
    w.db.sql("UPDATE dlp_approval_requests SET state = 'withdrawn', ended_at = now()")
    w.db.sql(
        "UPDATE notice_windows SET due_at = now() - interval '1 minute' WHERE user_id = :u", u=busy
    )
    await worker.handle(message(w.tenant.id, "dlp_approval.digest_due", user_id=busy))
    assert len(sent.to(w.address(busy))) == 1
    assert w.window("dlp_approval_digest", busy)[2] is False


# ---- "no eligible approver": capped per tenant ----


async def test_the_no_eligible_approver_email_is_capped_per_tenant(w: World) -> None:
    registry = CollectorRegistry()
    sent = Sent()
    worker = notifier(w.database, sent, registry=registry)
    transfer, _ = seed_transfer(w.db, w.tenant.id, w.tenant.member)
    refused = "dlp_approval.no_eligible_approver"
    for _ in range(NO_APPROVER_EMAILS + 2):
        handled = message(w.tenant.id, refused, transfer_id=transfer)
        assert await worker.handle(handled) is Done.PROCESSED
    notices = sent.of_type("dlp_no_eligible_approver")
    assert len(notices) == NO_APPROVER_EMAILS * len(admins(w))
    capped = registry.get_sample_value(
        "email_caps_hit_total", {"cap": "tenant_no_eligible_approver"}
    )
    assert capped == 2
    # Another tenant has its own cap.
    other = seed_tenant(w.db)
    other_transfer, _ = seed_transfer(w.db, other.id, other.member)
    await worker.handle(message(other.id, refused, transfer_id=other_transfer))
    assert len(sent.of_type("dlp_no_eligible_approver")) == len(notices) + 1
    # A day later the window starts again.
    elapse(w.db, w.tenant.id, timedelta(days=1))
    await worker.handle(message(w.tenant.id, refused, transfer_id=transfer))
    assert len(sent.of_type("dlp_no_eligible_approver")) == len(notices) + 2


async def test_a_redelivered_notice_is_counted_once(w: World) -> None:
    sent = Sent(fail=[MailErrorKind.UNAVAILABLE])
    worker = notifier(w.database, sent)
    transfer, _ = seed_transfer(w.db, w.tenant.id, w.tenant.member)
    handled = message(w.tenant.id, "dlp_approval.no_eligible_approver", transfer_id=transfer)
    with pytest.raises(MailError):
        await worker.handle(handled)
    assert await worker.handle(handled) is Done.PROCESSED
    assert len(sent.of_type("dlp_no_eligible_approver")) == 1
    assert w.window("dlp_no_eligible_approver")[0] == 1


# ---- a deactivation that clears the approver designation ----


async def deactivate(w: World, user_id: uuid.UUID) -> None:
    admin = session_caller(w.tenant.id, w.tenant.admin, Role.ADMIN)
    async with client(w.db, lambda: admin) as http:
        response = await http.post(f"/v1/users/{user_id}/deactivate")
    assert response.status_code == 200, response.text


async def test_deactivating_the_last_approver_emails_the_admins_at_once(w: World) -> None:
    last = approver(w)
    await deactivate(w, last)
    [(flag,)] = w.db.sql("SELECT dlp_approver FROM users WHERE id = :id", id=last)
    assert flag is False
    sent = Sent()
    assert await drain(notifier(w.database, sent), w.db, w.tenant.id) == [Done.PROCESSED]
    notices = sent.of_type("dlp_approver_deactivated")
    assert sorted(e.to for e in notices) == sorted(admins(w))
    assert all("No approver is left" in e.text for e in notices)
    assert all(w.address(last) not in e.text for e in notices), "names nobody"


async def test_deactivating_one_of_two_approvers_says_one_is_left(w: World) -> None:
    first, _ = approver(w), approver(w)
    await deactivate(w, first)
    sent = Sent()
    await drain(notifier(w.database, sent), w.db, w.tenant.id)
    [notice] = sent.of_type("dlp_approver_deactivated")
    assert "One approver is left" in notice.text


async def test_with_approvers_left_the_change_joins_the_policy_notice(w: World) -> None:
    gone = approver(w)
    approver(w), approver(w)
    await deactivate(w, gone)
    sent = Sent()
    worker = notifier(w.database, sent)
    await drain(worker, w.db, w.tenant.id)
    assert sent.emails == []
    elapse(w.db, w.tenant.id, timedelta(minutes=10))
    await drain(worker, w.db, w.tenant.id)
    [notice] = sent.of_type("dlp_policy_changed")
    assert "approver" in notice.text.lower()
    assert [m.topic for m in pending(w.db, w.tenant.id)] == []


async def test_deactivating_a_member_who_isnt_an_approver_tells_nobody(w: World) -> None:
    await deactivate(w, w.tenant.target)
    [(count,)] = w.db.sql(
        "SELECT count(*) FROM outbox WHERE tenant_id = :t AND topic LIKE 'dlp_%'", t=w.tenant.id
    )
    assert count == 0
