"""Recipient domain rules, clearing a suppressed address and its release at SES (#217; FR-24,
FR-45, FR-7; abuse 7.4; T-17)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import pytest

from member_fixtures import (
    EMAIL_KEYRING,
    Tenant,
    client,
    seed_tenant,
    session_caller,
)
from notify_fixtures import Sent, message, notifier
from pg import ScratchDatabase
from sft.core.errors import Unprocessable
from sft.data.database import Database
from sft.data.models import Role
from sft.data.roles import NOTIFY
from sft.service.caller import Caller
from sft.service.domain_rules import DomainError, DomainRules, normalize_domain, normalize_rules
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio


# ---- the rules themselves ----


@pytest.mark.parametrize(
    ("value", "rule"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("XN--BCHER-KVA.example", "xn--bcher-kva.example"),
        ("  mail.example.co.jp ", "mail.example.co.jp"),
    ],
)
def test_a_rule_is_lower_case_and_ascii(value: str, rule: str) -> None:
    assert normalize_domain(value) == rule


@pytest.mark.parametrize(
    "value", ["", "example", "*.example.com", "-a.example", "a..example", "a b.example", "a@b.c"]
)
def test_a_rule_is_a_domain(value: str) -> None:
    with pytest.raises(DomainError):
        normalize_domain(value)


def test_a_list_points_at_its_first_bad_or_repeated_domain() -> None:
    with pytest.raises(Unprocessable) as bad:
        normalize_rules(["example.com", "not a domain"], "blocked_domains")
    assert bad.value.errors[0].pointer == "#/blocked_domains/1"
    with pytest.raises(Unprocessable) as twice:
        normalize_rules(["example.com", "EXAMPLE.com."], "allowed_domains")
    assert twice.value.errors[0].pointer == "#/allowed_domains/1"
    with pytest.raises(Unprocessable):
        normalize_rules([f"d{i}.example" for i in range(501)], "allowed_domains")
    assert normalize_rules([f"d{i}.example" for i in range(500)], "allowed_domains")


def test_a_rule_covers_its_subdomains_and_blocked_wins() -> None:
    rules = DomainRules(
        allowed=("example.com", "xn--bcher-kva.example"), blocked=("x.example.com",)
    )
    assert rules.allows("a@example.com")
    assert rules.allows("a@mail.EXAMPLE.com")
    assert rules.allows("a@bücher.example")  # the address's IDNA form
    assert not rules.allows("a@badexample.com")  # not a subdomain
    assert not rules.allows("a@x.example.com")  # blocked wins over allowed
    assert not rules.allows("a@deep.x.example.com")
    assert not rules.allows("a@other.org")  # an allowed list refuses the rest
    assert DomainRules(blocked=("other.org",)).allows("a@example.com")  # empty allowed: any
    assert DomainRules().first_refused(["a@any.example"]) is None


# ---- the policy, createTransfer and sendTransfer ----


@dataclass
class World:
    db: ScratchDatabase
    tenant: Tenant

    def admin(self) -> Caller:
        return session_caller(self.tenant.id, self.tenant.admin, Role.ADMIN)

    def member(self) -> Caller:
        return session_caller(self.tenant.id, self.tenant.target, Role.MEMBER)

    async def policy(self, **change: object) -> dict[str, object]:
        async with client(self.db, self.admin) as http:
            updated = await http.patch("/v1/tenant/policy", json=change)
        assert updated.status_code == 200, updated.text
        body: dict[str, object] = updated.json()
        return body


@pytest.fixture
def w(migrated_db: ScratchDatabase) -> World:
    return World(migrated_db, seed_tenant(migrated_db))


async def test_an_admin_sets_the_domain_lists_and_the_record_holds_counts(w: World) -> None:
    body = await w.policy(
        allowed_domains=["Example.com", "bücher.example"], blocked_domains=["x.example.com"]
    )
    assert body["allowed_domains"] == ["example.com", "xn--bcher-kva.example"]
    assert body["blocked_domains"] == ["x.example.com"]
    again = await w.policy(allowed_domains=["example.com", "other.example"])
    assert again["allowed_domains"] == ["example.com", "other.example"]
    assert again["blocked_domains"] == ["x.example.com"]  # left out, left as it was
    async with client(w.db, w.member) as http:
        read = await http.get("/v1/tenant/policy")
    assert read.json()["allowed_domains"] == ["example.com", "other.example"]
    rows = w.db.sql(
        "SELECT details, a::text FROM audit_events a WHERE tenant_id = :t "
        "AND action = 'tenant_policy.updated' ORDER BY occurred_at",
        t=w.tenant.id,
    )
    assert [details for details, _ in rows] == [
        {
            "allowed_domains_added": 2,
            "allowed_domains_removed": 0,
            "allowed_domains_count": 2,
            "blocked_domains_added": 1,
            "blocked_domains_removed": 0,
            "blocked_domains_count": 1,
        },
        {
            "allowed_domains_added": 1,
            "allowed_domains_removed": 1,
            "allowed_domains_count": 2,
        },
    ]
    for _, text in rows:  # counts only: never a tenant-chosen domain
        assert "example" not in str(text)


async def test_a_bad_domain_is_422_with_a_pointer(w: World) -> None:
    async with client(w.db, w.admin) as http:
        bad = await http.patch(
            "/v1/tenant/policy", json={"blocked_domains": ["ok.example", "*.bad"]}
        )
    assert bad.status_code == 422
    assert bad.json()["errors"][0]["pointer"] == "#/blocked_domains/1"


async def create(w: World, *emails: str) -> tuple[int, dict[str, object]]:
    async with client(w.db, w.member) as http:
        made = await http.post("/v1/transfers", json={"recipients": [{"email": e} for e in emails]})
    body: dict[str, object] = made.json()
    return made.status_code, body


async def test_create_refuses_a_blocked_domain_and_any_outside_the_allowed_list(w: World) -> None:
    await w.policy(blocked_domains=["blocked.example"])
    status, body = await create(w, "a@fine.example", "b@mail.blocked.example")
    assert status == 422
    assert body["code"] == "recipient_domain_not_allowed"
    assert body["errors"][0]["pointer"] == "#/recipients/1/email"  # type: ignore[index]
    assert (await create(w, "a@fine.example"))[0] == 201
    await w.policy(allowed_domains=["partner.example", "bücher.example"])
    assert (await create(w, "a@fine.example"))[0] == 422
    assert (await create(w, "a@sub.partner.example", "b@BÜCHER.example"))[0] == 201
    assert (await create(w, "a@partner.example.evil"))[0] == 422


async def test_a_domain_blocked_after_the_draft_was_made_is_refused_at_send(w: World) -> None:
    transfer, _ = seed_transfer(w.db, w.tenant.id, w.tenant.target, recipients=("a@late.example",))
    seed_file(w.db, w.tenant.id, transfer, state="scanning")
    await w.policy(blocked_domains=["late.example"])
    async with client(w.db, w.member) as http:
        refused = await http.post(f"/v1/transfers/{transfer}/send")
        [(state,)] = w.db.sql("SELECT state FROM transfers WHERE id = :id", id=transfer)
        await w.policy(blocked_domains=[])
        sent = await http.post(f"/v1/transfers/{transfer}/send")
    assert refused.status_code == 422
    assert refused.json()["code"] == "recipient_domain_not_allowed"
    assert state == "draft"
    assert sent.status_code == 200, sent.text


# ---- clearEmailSuppression (FR-7, abuse 7.4) ----


def suppress(w: World, address: str, tenant: Tenant | None = None) -> uuid.UUID:
    entry = uuid.uuid4()
    w.db.sql(
        "INSERT INTO email_suppressions (id, tenant_id, email_hmac, hmac_key_id, reason) "
        "VALUES (:id, :tenant, :hmac, :key, 'complaint')",
        id=entry,
        tenant=(tenant or w.tenant).id,
        hmac=EMAIL_KEYRING.active(address.lower()),
        key=EMAIL_KEYRING.active_key_id,
    )
    return entry


def ended(w: World, entry: uuid.UUID) -> bool:
    [(done,)] = w.db.sql(
        "SELECT expires_at IS NOT NULL AND expires_at <= now() FROM email_suppressions "
        "WHERE id = :id",
        id=entry,
    )
    return bool(done)


async def test_clearing_answers_204_for_a_suppressed_and_an_unknown_address_alike(
    w: World,
) -> None:
    address = f"{uuid.uuid4().hex}@partner.example"
    entry = suppress(w, address)
    other = seed_tenant(w.db)
    theirs = suppress(w, address, other)
    async with client(w.db, w.admin) as http:
        cleared = await http.post("/v1/email-suppressions/clear", json={"email": address.upper()})
        unknown = await http.post(
            "/v1/email-suppressions/clear", json={"email": "never@partner.example"}
        )
    assert cleared.status_code == unknown.status_code == 204
    assert cleared.content == unknown.content == b""
    assert ended(w, entry)
    assert not ended(w, theirs)  # suppressions are per tenant
    rows = w.db.sql(
        "SELECT target_id, details, a::text FROM audit_events a WHERE tenant_id = :t "
        "AND action = 'email_suppression.cleared' ORDER BY occurred_at",
        t=w.tenant.id,
    )
    assert [(r[0], r[1]) for r in rows] == [
        (entry, {"cleared": True, "entries": 1}),
        (None, {"cleared": False, "entries": 0}),
    ]
    for _, _, text in rows:
        assert address not in str(text)
        assert "never@partner.example" not in str(text)
    # A transfer to the cleared address is no longer refused.
    assert (await create(w, address))[0] == 201


@dataclass
class Releases:
    calls: list[tuple[uuid.UUID, str]] = field(default_factory=list)

    async def __call__(self, tenant_id: uuid.UUID, address: str) -> None:
        self.calls.append((tenant_id, address))


@pytest.fixture
async def notify_db(migrated_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(migrated_db.url(NOTIFY), pool_size=2)
    yield database
    await database.dispose()


async def test_the_next_email_to_a_cleared_address_goes_out_after_the_ses_release(
    w: World, notify_db: Database
) -> None:
    address = f"{uuid.uuid4().hex}@partner.example"
    entry = suppress(w, address)
    async with client(w.db, w.admin) as http:
        await http.post("/v1/email-suppressions/clear", json={"email": address})
    _, [first, second] = seed_transfer(
        w.db, w.tenant.id, w.tenant.target, state="sent", recipients=(address, "x@other.example")
    )
    _another, [third] = seed_transfer(
        w.db, w.tenant.id, w.tenant.target, state="sent", recipients=(address,)
    )
    sent, releases = Sent(), Releases()
    worker = notifier(notify_db, sent)
    worker.release = releases
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=first))
    assert releases.calls == [(w.tenant.id, address)]
    assert [e.to for e in sent.emails] == [address]
    [(released,)] = w.db.sql(
        "SELECT ses_released_at IS NOT NULL FROM email_suppressions WHERE id = :id", id=entry
    )
    assert released
    assert w.db.sql(
        "SELECT count(*) FROM audit_events WHERE action = 'email_suppression.released' "
        "AND target_id = :id",
        id=entry,
    ) == [(1,)]
    # Released once: the next emails to it, and to anyone else, release nothing.
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=second))
    await worker.handle(message(w.tenant.id, "recipient.link_due", recipient_id=third))
    assert releases.calls == [(w.tenant.id, address)]
    assert len(sent.emails) == 3


async def test_a_failed_release_sends_nothing_and_is_retried(w: World, notify_db: Database) -> None:
    address = f"{uuid.uuid4().hex}@partner.example"
    suppress(w, address)
    async with client(w.db, w.admin) as http:
        await http.post("/v1/email-suppressions/clear", json={"email": address})
    _, [recipient] = seed_transfer(
        w.db, w.tenant.id, w.tenant.target, state="sent", recipients=(address,)
    )
    sent = Sent()
    worker = notifier(notify_db, sent)

    async def unavailable(tenant_id: uuid.UUID, to: str) -> None:
        raise RuntimeError("SES unavailable")

    worker.release = unavailable
    due = message(w.tenant.id, "recipient.link_due", recipient_id=recipient)
    with pytest.raises(RuntimeError):
        await worker.handle(due)
    assert sent.emails == []
    worker.release = Releases()
    await worker.handle(due)
    assert [e.to for e in sent.emails] == [address]


# ---- upload requests (#212 with #217): the uploader's address follows the same rules ----


async def test_an_upload_request_to_a_domain_outside_the_rules_is_refused(w: World) -> None:
    await w.policy(blocked_domains=["blocked.example"])
    async with client(w.db, w.member) as http:
        refused = await http.post(
            "/v1/upload-requests", json={"uploader_email": "up@mail.blocked.example"}
        )
        made = await http.post("/v1/upload-requests", json={"uploader_email": "up@fine.example"})
    assert refused.status_code == 422
    assert refused.json()["code"] == "recipient_domain_not_allowed"
    assert refused.json()["errors"][0]["pointer"] == "#/uploader_email"
    assert made.status_code == 201, made.text
    assert w.db.sql(
        "SELECT email_normalized FROM upload_requests WHERE tenant_id = :t", t=w.tenant.id
    ) == [("up@fine.example",)]


async def test_an_uploaders_link_to_a_cleared_address_goes_out_after_the_ses_release(
    w: World, notify_db: Database
) -> None:
    address = f"{uuid.uuid4().hex}@partner.example"
    entry = suppress(w, address)
    async with client(w.db, w.admin) as http:
        await http.post("/v1/email-suppressions/clear", json={"email": address})
    request_id = uuid.uuid4()
    w.db.sql(
        "INSERT INTO upload_requests (id, tenant_id, created_by, state, uploader_email, "
        "email_normalized, locale, expires_at, delivery_state) VALUES (:id, :tenant, :owner, "
        "'open', :email, :email, 'en', now() + interval '7 days', 'queued')",
        id=request_id,
        tenant=w.tenant.id,
        owner=w.tenant.target,
        email=address,
    )
    sent, releases = Sent(), Releases()
    worker = notifier(notify_db, sent)
    worker.release = releases
    await worker.handle(
        message(w.tenant.id, "upload_request.link_due", upload_request_id=request_id)
    )
    assert releases.calls == [(w.tenant.id, address)]
    assert [e.to for e in sent.emails] == [address]
    [(released,)] = w.db.sql(
        "SELECT ses_released_at IS NOT NULL FROM email_suppressions WHERE id = :id", id=entry
    )
    assert released
