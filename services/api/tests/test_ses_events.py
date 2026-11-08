"""SES's events from the `ses-events` queue (#185; ADR-0015; abuse 7.4; data model 2.5): which
events are acted on, the suppression each writes in its own tenant only, the second bounce that
suppresses for good, the link email's recipient left `bounced`, an uploader's request left
`bounced` and its address suppressed (#228), and a copy handled once. The consumer runs as
`sft_notify` against PostgreSQL, through the consumer loop and a fake queue."""

from __future__ import annotations

import base64
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest

from api_settings import EMAIL_HMAC_KEYRING
from member_fixtures import EMAIL_KEYRING, Tenant, seed_tenant
from pg import ScratchDatabase
from sft.core.pseudonyms import EmailKeyring, email_pseudonym
from sft.data.database import Database
from sft.data.outbox import InvalidMessageError, Queue
from sft.data.roles import NOTIFY
from sft.service.ses_events import EventKind, SesEvents, parse_event
from sft.workers.consumer import ConsumerLoop, ConsumerMetrics, Outcome
from sft.workers.notify import SesEventsConsumer
from sft.workers.queues import ReceivedMessage
from transfer_fixtures import seed_transfer

pytestmark = pytest.mark.anyio

ADDRESS = "Bounced@Example.test"


def ses_event(
    kind: str,
    tenant_id: uuid.UUID | None,
    *,
    address: str = ADDRESS,
    bounce_type: str = "Permanent",
    recipient_id: uuid.UUID | None = None,
    upload_request_id: uuid.UUID | None = None,
    email_type: str = "transfer_link",
    message_id: str = "0106018f-ses-message",
    envelope: bool = True,
) -> str:
    tags: dict[str, list[str]] = {"email_type": [email_type]}
    if tenant_id is not None:
        tags["tenant_id"] = [str(tenant_id)]
    if recipient_id is not None:
        tags["recipient_id"] = [str(recipient_id)]
    if upload_request_id is not None:
        tags["upload_request_id"] = [str(upload_request_id)]
    event: dict[str, object] = {
        "eventType": kind,
        "mail": {"messageId": message_id, "timestamp": "2026-11-08T00:00:00Z", "tags": tags},
    }
    at = "2026-11-08T00:00:01Z"
    if kind == "Bounce":
        event["bounce"] = {
            "bounceType": bounce_type,
            "bouncedRecipients": [{"emailAddress": address}],
            "timestamp": at,
        }
    if kind == "Complaint":
        event["complaint"] = {"complainedRecipients": [{"emailAddress": address}], "timestamp": at}
    body = json.dumps(event)
    if not envelope:
        return body
    return json.dumps({"Type": "Notification", "MessageId": str(uuid.uuid4()), "Message": body})


def test_a_permanent_bounce_and_a_complaint_are_acted_on() -> None:
    tenant = uuid.uuid4()
    bounce = parse_event(ses_event("Bounce", tenant))
    assert bounce is not None
    assert (bounce.kind, bounce.tenant_id, bounce.addresses) == (
        EventKind.BOUNCE,
        tenant,
        (ADDRESS,),
    )
    complaint = parse_event(ses_event("Complaint", tenant, envelope=False))
    assert complaint is not None
    assert complaint.kind is EventKind.COMPLAINT


def test_a_copy_has_the_same_id_and_another_event_another() -> None:
    tenant = uuid.uuid4()
    first, again = (
        parse_event(ses_event("Bounce", tenant)),
        parse_event(ses_event("Bounce", tenant)),
    )
    other = parse_event(ses_event("Bounce", tenant, message_id="another"))
    assert first is not None
    assert again is not None
    assert other is not None
    assert first.id == again.id != other.id


@pytest.mark.parametrize(
    "body",
    [
        ses_event("Delivery", uuid.uuid4()),
        ses_event("DeliveryDelay", uuid.uuid4()),
        ses_event("Bounce", uuid.uuid4(), bounce_type="Transient"),
        ses_event("Bounce", None),  # Cognito's own email carries no tenant tag
    ],
)
def test_other_events_change_nothing(body: str) -> None:
    assert parse_event(body) is None


@pytest.mark.parametrize("body", ["not json", "[]", json.dumps({"eventType": "Bounce"})])
def test_a_body_that_is_no_ses_event_is_invalid(body: str) -> None:
    with pytest.raises(InvalidMessageError):
        parse_event(body)


@dataclass
class FakeQueues:
    bodies: list[str]
    deleted: list[str] = field(default_factory=list)

    async def receive(
        self, queue: str, *, max_messages: int, wait_seconds: int
    ) -> list[ReceivedMessage]:
        assert queue == Queue.SES_EVENTS
        out = [ReceivedMessage(b, f"r{i}", 1) for i, b in enumerate(self.bodies)]
        self.bodies = []
        return out

    async def delete(self, queue: str, receipt_handle: str) -> None:
        self.deleted.append(receipt_handle)


@dataclass
class World:
    db: ScratchDatabase
    database: Database
    tenant: Tenant
    events: SesEvents = field(default_factory=lambda: SesEvents(EMAIL_KEYRING))

    async def deliver(self, *bodies: str) -> list[Outcome]:
        from prometheus_client import CollectorRegistry

        queues = FakeQueues(list(bodies))
        loop = ConsumerLoop(
            SesEventsConsumer(self.database, self.events),
            queues,  # type: ignore[arg-type]
            ConsumerMetrics.create(CollectorRegistry()),
        )
        return await loop.poll_once()

    def entries(self, tenant_id: uuid.UUID) -> list[tuple[object, ...]]:
        return self.db.sql(
            "SELECT email_hmac, reason, bounce_count, expires_at IS NULL FROM email_suppressions "
            "WHERE tenant_id = :t",
            t=tenant_id,
        )


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    database = Database.connect(migrated_db.url(NOTIFY), pool_size=2)
    yield World(migrated_db, database, seed_tenant(migrated_db))
    await database.dispose()


async def test_a_hard_bounce_suppresses_for_90_days_in_its_own_tenant_only(w: World) -> None:
    other = seed_tenant(w.db)
    assert await w.deliver(ses_event("Bounce", w.tenant.id)) == [Outcome.PROCESSED]
    [(pseudonym, reason, count, forever)] = w.entries(w.tenant.id)
    assert pseudonym == EMAIL_KEYRING.active(ADDRESS.lower())
    assert (reason, count, forever) == ("hard_bounce", 1, False)
    [(expires,)] = w.db.sql(
        "SELECT expires_at FROM email_suppressions WHERE tenant_id = :t", t=w.tenant.id
    )
    assert abs(expires - (datetime.now(UTC) + timedelta(days=90))) < timedelta(minutes=5)  # type: ignore[operator]
    assert w.entries(other.id) == []
    [(action,)] = w.db.sql(
        "SELECT action FROM audit_events WHERE tenant_id = :t AND action = 'email.suppressed'",
        t=w.tenant.id,
    )
    assert action == "email.suppressed"


async def test_a_copy_is_handled_once(w: World) -> None:
    body = ses_event("Bounce", w.tenant.id)
    assert await w.deliver(body, body) == [Outcome.PROCESSED, Outcome.DUPLICATE]
    [(_, _, count, _)] = w.entries(w.tenant.id)
    assert count == 1


async def test_a_bounce_after_the_entry_ended_suppresses_for_good(w: World) -> None:
    await w.deliver(ses_event("Bounce", w.tenant.id))
    w.db.sql("UPDATE email_suppressions SET expires_at = now() - interval '1 day'")
    await w.deliver(ses_event("Bounce", w.tenant.id, message_id="second"))
    [(_, reason, count, forever)] = w.entries(w.tenant.id)
    assert (reason, count, forever) == ("hard_bounce", 2, True)


async def test_a_complaint_suppresses_for_good_and_a_later_bounce_keeps_it(w: World) -> None:
    await w.deliver(ses_event("Complaint", w.tenant.id))
    await w.deliver(ses_event("Bounce", w.tenant.id, message_id="later"))
    [(_, reason, _, forever)] = w.entries(w.tenant.id)
    assert (reason, forever) == ("complaint", True)


async def test_a_link_email_that_bounced_leaves_its_recipient_bounced(w: World) -> None:
    _, [recipient] = seed_transfer(w.db, w.tenant.id, w.tenant.member, state="sent")
    assert await w.deliver(ses_event("Reject", w.tenant.id, recipient_id=recipient)) == [
        Outcome.PROCESSED
    ]
    [(state,)] = w.db.sql(
        "SELECT delivery_state FROM transfer_recipients WHERE id = :r", r=recipient
    )
    assert state == "bounced"
    assert w.entries(w.tenant.id) == []  # a reject names nobody to suppress


async def test_events_with_nothing_to_do_are_deleted(w: World) -> None:
    assert await w.deliver(ses_event("Delivery", w.tenant.id)) == [Outcome.IGNORED]
    assert w.entries(w.tenant.id) == []


async def test_an_entry_under_an_older_key_moves_to_the_active_key(w: World) -> None:
    old_key = b"o" * 32
    entries = [
        *json.loads(EMAIL_HMAC_KEYRING),
        {
            "id": "old",
            "state": "verify",
            "key": base64.b64encode(old_key).decode(),
            "created_at": "2025-11-01T00:00:00+00:00",
        },
    ]
    keyring = EmailKeyring.from_json(json.dumps(entries))
    normalized = ADDRESS.lower()
    w.db.sql(
        "INSERT INTO email_suppressions (id, tenant_id, email_hmac, hmac_key_id, reason, "
        "expires_at) VALUES (:id, :t, :p, 'old', 'hard_bounce', now() - interval '1 day')",
        id=uuid.uuid4(),
        t=w.tenant.id,
        p=email_pseudonym("old", old_key, normalized),
    )
    w.events = SesEvents(keyring)
    await w.deliver(ses_event("Bounce", w.tenant.id))
    [(pseudonym, reason, count, forever)] = w.entries(w.tenant.id)
    # Found under the old key, so this is the second bounce: for good, under the active key.
    assert pseudonym == keyring.active(normalized)
    assert (reason, count, forever) == ("hard_bounce", 2, True)


# ---- an uploader's emails (#228) ----


def seed_request(db: ScratchDatabase, tenant: Tenant, *, state: str = "open") -> uuid.UUID:
    """An upload request whose link email went out (`sent`), as the superuser."""
    request_id = uuid.uuid4()
    db.sql(
        "INSERT INTO upload_requests (id, tenant_id, created_by, state, uploader_email, "
        "email_normalized, locale, expires_at, delivery_state, notified_at, ended_at) VALUES "
        "(:id, :tenant, :owner, :state, :email, lower(:email), 'en', now() + interval '7 days', "
        "'sent', now(), CASE WHEN :state = 'open' THEN NULL ELSE now() END)",
        id=request_id,
        tenant=tenant.id,
        owner=tenant.member,
        state=state,
        email=ADDRESS,
    )
    return request_id


def delivery(w: World, request_id: uuid.UUID) -> object:
    [(state,)] = w.db.sql("SELECT delivery_state FROM upload_requests WHERE id = :r", r=request_id)
    return state


def request_events(w: World, request_id: uuid.UUID) -> list[tuple[object, ...]]:
    return w.db.sql(
        "SELECT action, outcome, details->>'email_type' FROM audit_events "
        "WHERE target_type = 'upload_request' AND target_id = :r ORDER BY occurred_at",
        r=request_id,
    )


def test_an_uploader_email_names_its_upload_request() -> None:
    tenant, request_id = uuid.uuid4(), uuid.uuid4()
    event = parse_event(ses_event("Bounce", tenant, upload_request_id=request_id))
    assert event is not None
    assert (event.upload_request_id, event.recipient_id) == (request_id, None)
    assert event.as_message().payload == {"upload_request_id": request_id}
    plain = parse_event(ses_event("Bounce", tenant))
    assert plain is not None
    assert plain.upload_request_id is None


@pytest.mark.parametrize("email_type", ["upload_request", "verification_code"])
async def test_a_hard_bounce_on_an_uploader_email_marks_the_request_bounced_and_suppresses(
    w: World, email_type: str
) -> None:
    request_id = seed_request(w.db, w.tenant)
    body = ses_event("Bounce", w.tenant.id, upload_request_id=request_id, email_type=email_type)
    assert await w.deliver(body) == [Outcome.PROCESSED]
    assert delivery(w, request_id) == "bounced"
    assert request_events(w, request_id) == [("email.bounced", "failure", email_type)]
    [(pseudonym, reason, _, forever)] = w.entries(w.tenant.id)
    assert (pseudonym, reason, forever) == (
        EMAIL_KEYRING.active(ADDRESS.lower()),
        "hard_bounce",
        False,
    )


async def test_a_bounce_after_the_request_ended_still_shows(w: World) -> None:
    # The blocked-file notice can go out after a revocation: its bounce is shown all the same.
    request_id = seed_request(w.db, w.tenant, state="revoked")
    body = ses_event(
        "Bounce", w.tenant.id, upload_request_id=request_id, email_type="files_blocked_uploader"
    )
    assert await w.deliver(body) == [Outcome.PROCESSED]
    assert delivery(w, request_id) == "bounced"


async def test_a_reject_of_an_uploader_email_marks_the_request_bounced(w: World) -> None:
    request_id = seed_request(w.db, w.tenant)
    body = ses_event(
        "Reject", w.tenant.id, upload_request_id=request_id, email_type="upload_request"
    )
    assert await w.deliver(body) == [Outcome.PROCESSED]
    assert delivery(w, request_id) == "bounced"
    assert w.entries(w.tenant.id) == []  # a reject names nobody to suppress


async def test_a_complaint_on_an_uploader_email_suppresses_for_good(w: World) -> None:
    request_id = seed_request(w.db, w.tenant)
    body = ses_event("Complaint", w.tenant.id, upload_request_id=request_id)
    assert await w.deliver(body) == [Outcome.PROCESSED]
    [(_, reason, _, forever)] = w.entries(w.tenant.id)
    assert (reason, forever) == ("complaint", True)
    # The email arrived: the request still reads `sent`, as a recipient's would.
    assert delivery(w, request_id) == "sent"
    assert request_events(w, request_id) == []


async def test_a_tag_naming_another_tenants_request_changes_nothing_of_it(w: World) -> None:
    other = seed_tenant(w.db)
    theirs = seed_request(w.db, other)
    body = ses_event("Bounce", w.tenant.id, upload_request_id=theirs)
    assert await w.deliver(body) == [Outcome.PROCESSED]
    assert delivery(w, theirs) == "sent"
    assert request_events(w, theirs) == []
    assert w.entries(other.id) == []
    assert len(w.entries(w.tenant.id)) == 1  # the sending tenant's own list only
