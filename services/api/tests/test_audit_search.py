"""Audit search and export (#216; FR-28, FR-29, UC-4; T-47, T-48): filters, paging, the record of
each read, the CSV's formula neutralisation, the export limits, the first-export email and tenant
isolation."""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from prometheus_client import CollectorRegistry

from member_fixtures import RecordingLimiter, Tenant, client, seed_tenant, session_caller
from notify_fixtures import Sent, drain, notifier
from pg import ScratchDatabase
from sft.data.audit import Origin
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.data.models import ApiKeyScope, Role
from sft.data.roles import API, NOTIFY
from sft.service import api_keys, audit_search
from sft.service.audit_search import ExportLeases
from sft.service.caller import Caller, CallerKind
from sft.service.rate_limits import RateLimiter
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio

MONDAY = datetime(2026, 11, 2, 1, 30, tzinfo=UTC)


@dataclass
class Log:
    db: ScratchDatabase
    mine: Tenant
    theirs: Tenant

    def event(
        self,
        tenant: Tenant,
        action: str,
        *,
        at: datetime = MONDAY,
        actor_type: str = "member",
        actor_id: uuid.UUID | None = None,
        target: tuple[str, uuid.UUID] | None = None,
        ip: str | None = None,
        user_agent: str | None = None,
        details: dict[str, object] | None = None,
    ) -> uuid.UUID:
        event_id = uuid.uuid4()
        self.db.sql(
            "INSERT INTO audit_events (id, tenant_id, occurred_at, actor_type, actor_id, action, "
            "target_type, target_id, outcome, source_ip, user_agent, details) VALUES (:id, :t, "
            ":at, :actor_type, :actor_id, :action, :target_type, :target_id, 'success', "
            "CAST(:ip AS inet), :ua, CAST(:details AS jsonb))",
            id=event_id,
            t=tenant.id,
            at=at,
            actor_type=actor_type,
            actor_id=actor_id if actor_type != "system" else None,
            action=action,
            target_type=None if target is None else target[0],
            target_id=None if target is None else target[1],
            ip=ip,
            ua=user_agent,
            details=json.dumps(details or {}),
        )
        return event_id

    def admin(self, tenant: Tenant | None = None) -> Caller:
        tenant = tenant or self.mine
        return session_caller(tenant.id, tenant.admin, Role.ADMIN)


@pytest.fixture
def log(migrated_db: ScratchDatabase) -> Log:
    return Log(migrated_db, seed_tenant(migrated_db), seed_tenant(migrated_db))


async def search(log: Log, caller: Caller, **body: object) -> dict[str, object]:
    async with client(log.db, lambda: caller) as http:
        found = await http.post("/v1/audit/events/search", json=body)
    assert found.status_code == 200, found.text
    result: dict[str, object] = found.json()
    return result


def ids(page: dict[str, object]) -> list[str]:
    return [str(item["id"]) for item in page["items"]]  # type: ignore[attr-defined,index]


async def test_uc4_who_downloaded_the_contract_we_sent_on_monday(log: Log) -> None:
    transfer, [recipient] = seed_transfer(log.db, log.mine.id, log.mine.target, state="sent")
    file_id = seed_file(log.db, log.mine.id, transfer, state="clean")
    [(email,)] = log.db.sql("SELECT email FROM transfer_recipients WHERE id = :id", id=recipient)
    granted = log.event(
        log.mine,
        "download.granted",
        actor_type="recipient",
        actor_id=recipient,
        target=("file", file_id),
        ip="203.0.113.7",
    )
    log.event(log.mine, "transfer.sent", actor_id=log.mine.target, target=("transfer", transfer))
    log.event(log.mine, "download.granted", actor_type="recipient", actor_id=uuid.uuid4())
    page = await search(
        log,
        log.admin(),
        filter={
            "target_type": "transfer",
            "target_id": str(transfer),
            "actions": ["download.granted"],
            "occurred_after": (MONDAY - timedelta(hours=12)).isoformat(),
            "occurred_before": (MONDAY + timedelta(hours=12)).isoformat(),
        },
    )
    [item] = page["items"]  # type: ignore[misc]
    assert item["id"] == str(granted)
    assert item["actor_email"] == email
    assert item["source_ip"] == "203.0.113.7"
    assert datetime.fromisoformat(item["occurred_at"]) == MONDAY


async def test_every_filter_returns_only_matching_events_of_the_callers_tenant(log: Log) -> None:
    transfer, [recipient] = seed_transfer(
        log.db, log.mine.id, log.mine.target, recipients=[f"{uuid.uuid4().hex}@partner.test"]
    )
    [(recipient_email,)] = log.db.sql(
        "SELECT email FROM transfer_recipients WHERE id = :id", id=recipient
    )
    [(member_email,)] = log.db.sql("SELECT email FROM users WHERE id = :id", id=log.mine.member)
    e = {
        "member_old": log.event(
            log.mine, "transfer.created", actor_id=log.mine.member, at=MONDAY - timedelta(days=9)
        ),
        "member_ip": log.event(
            log.mine, "transfer.sent", actor_id=log.mine.member, ip="198.51.100.4"
        ),
        "admin_on_transfer": log.event(
            log.mine, "transfer.revoked", actor_type="admin", actor_id=log.mine.admin,
            target=("transfer", transfer),
        ),
        "about_member": log.event(
            log.mine, "user.role_changed", actor_type="admin", actor_id=log.mine.admin,
            target=("user", log.mine.member),
        ),
        "recipient": log.event(
            log.mine, "verification.succeeded", actor_type="recipient", actor_id=recipient,
            target=("recipient", recipient), ip="198.51.100.4",
        ),
        "system": log.event(log.mine, "transfer.expired", actor_type="system"),
    }  # fmt: skip
    # Another tenant's events carry the same shapes, IDs and addresses where they can.
    log.event(log.theirs, "transfer.sent", actor_id=log.mine.member, ip="198.51.100.4")
    log.event(log.theirs, "transfer.revoked", target=("transfer", transfer))

    cases: list[tuple[dict[str, object], set[str]]] = [
        ({}, set(e)),
        ({"occurred_after": (MONDAY - timedelta(days=1)).isoformat()}, set(e) - {"member_old"}),
        ({"occurred_before": (MONDAY - timedelta(days=1)).isoformat()}, {"member_old"}),
        ({"actor_type": "admin"}, {"admin_on_transfer", "about_member"}),
        ({"actor_id": str(log.mine.member)}, {"member_old", "member_ip"}),
        ({"email": member_email.upper()}, {"member_old", "member_ip", "about_member"}),
        ({"email": recipient_email}, {"recipient"}),
        ({"email": "nobody@example.test"}, set()),
        ({"actions": ["transfer.sent", "transfer.expired"]}, {"member_ip", "system"}),
        ({"target_type": "user"}, {"about_member"}),
        ({"target_id": str(transfer)}, {"admin_on_transfer"}),
        (
            {"target_type": "transfer", "target_id": str(transfer)},
            {"admin_on_transfer", "recipient"},
        ),
        ({"source_ip": "198.51.100.4"}, {"member_ip", "recipient"}),
        ({"source_ip": "198.51.100.4", "actor_type": "recipient"}, {"recipient"}),
        ({"email": member_email, "actions": ["user.role_changed"]}, {"about_member"}),
    ]
    for query, expected in cases:
        page = await search(log, log.admin(), filter=query, limit=100)
        # Each search records itself: those records are now's, not the seeded events.
        searches = {
            str(i)
            for (i,) in log.db.sql(
                "SELECT id FROM audit_events WHERE action = 'audit.searched' AND tenant_id = :t",
                t=log.mine.id,
            )
        }
        assert set(ids(page)) - searches == {str(e[name]) for name in expected}, query


async def test_searches_are_audited_with_the_filters_shape_never_their_values(log: Log) -> None:
    [(email,)] = log.db.sql("SELECT email FROM users WHERE id = :id", id=log.mine.member)
    await search(
        log,
        log.admin(),
        filter={"email": email, "source_ip": "192.0.2.55", "actions": ["user.invited"]},
    )
    [(details, row)] = log.db.sql(
        "SELECT details, a::text FROM audit_events a WHERE tenant_id = :t "
        "AND action = 'audit.searched'",
        t=log.mine.id,
    )
    assert details == {
        "filter_email": True,
        "filter_source_ip": True,
        "filter_actions": True,
        "results": 0,
        "later_page": False,
    }
    assert email not in str(row)
    assert "192.0.2.55" not in str(row)


async def test_pages_follow_the_cursor_newest_first(log: Log) -> None:
    made = [log.event(log.mine, "transfer.created", actor_id=log.mine.member) for _ in range(5)]
    made += [
        log.event(log.mine, "transfer.created", at=MONDAY - timedelta(minutes=m)) for m in (1, 2)
    ]
    seen: list[str] = []
    cursor = None
    while True:
        body: dict[str, object] = {"filter": {"actions": ["transfer.created"]}, "limit": 3}
        if cursor:
            body["cursor"] = cursor
        page = await search(log, log.admin(), **body)
        seen += ids(page)
        cursor = page["next_cursor"]
        if not cursor:
            break
    assert sorted(seen) == sorted(str(m) for m in made)
    assert len(seen) == len(set(seen))
    times = [
        log.db.sql("SELECT occurred_at FROM audit_events WHERE id = :id", id=i)[0][0] for i in seen
    ]
    assert times == sorted(times, reverse=True)
    async with client(log.db, log.admin) as http:
        bad = await http.post("/v1/audit/events/search", json={"cursor": "not-a-cursor"})
    assert bad.status_code == 400
    assert bad.json()["code"] == "invalid_cursor"


async def test_a_bad_filter_is_422(log: Log) -> None:
    async with client(log.db, log.admin) as http:
        ip = await http.post("/v1/audit/events/search", json={"filter": {"source_ip": "x.y"}})
        order = await http.post(
            "/v1/audit/events/search",
            json={
                "filter": {
                    "occurred_after": MONDAY.isoformat(),
                    "occurred_before": (MONDAY - timedelta(days=1)).isoformat(),
                }
            },
        )
        many = await http.post(
            "/v1/audit/events/search",
            json={"filter": {"actions": [f"a.b{'c' * i}" for i in range(21)]}},
        )
    assert ip.status_code == order.status_code == many.status_code == 422
    assert ip.json()["errors"][0]["pointer"] == "#/filter/source_ip"


# ---- exports ----


FORMULA = '=HYPERLINK("https://evil.example/x","click")'


async def test_csv_quotes_every_cell_and_neutralises_formulas(log: Log) -> None:
    for agent in (FORMULA, "+1", "-2", "@SUM(A1)", "\tlead", "\rlead", "plain"):
        log.event(log.mine, "member.signed_in", actor_id=log.mine.member, user_agent=agent)
    async with client(log.db, log.admin) as http:
        exported = await http.post("/v1/audit/exports", json={"format": "csv"})
        as_json = await http.post("/v1/audit/exports", json={"format": "json"})
    assert exported.status_code == 200, exported.text
    assert exported.headers["content-type"].startswith("text/csv")
    assert exported.headers["content-disposition"].startswith('attachment; filename="audit-')
    assert exported.headers["content-disposition"].endswith('.csv"')
    lines = exported.text.split("\r\n")
    assert lines[0] == ",".join(f'"{c}"' for c in audit_search.COLUMNS)
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    agents = {row["user_agent"] for row in rows if row["action"] == "member.signed_in"}
    assert agents == {"'" + FORMULA, "'+1", "'-2", "'@SUM(A1)", "'\tlead", "'\rlead", "plain"}
    for line in lines[1:]:
        if line:
            assert line.startswith('"')
    # A round trip gives the values back, minus the prefix.
    originals = {a[1:] if a.startswith("'") else a for a in agents}
    assert FORMULA in originals
    # JSON is unchanged.
    events = as_json.json()
    assert as_json.headers["content-disposition"].endswith('.json"')
    assert FORMULA in {e["user_agent"] for e in events}
    assert {json.dumps(e["details"]) for e in events}  # details are objects


async def test_exports_are_audited(log: Log) -> None:
    log.event(log.mine, "transfer.created", actor_id=log.mine.member)
    async with client(log.db, log.admin) as http:
        exported = await http.post(
            "/v1/audit/exports",
            json={"format": "json", "filter": {"actions": ["transfer.created"]}},
        )
    assert len(exported.json()) == 1
    assert log.db.sql(
        "SELECT details FROM audit_events WHERE tenant_id = :t AND action = 'audit.exported'",
        t=log.mine.id,
    ) == [({"filter_actions": True, "format": "json", "rows": 1},)]


async def make_key(log: Log, database: Database) -> Caller:
    made = await api_keys.create_api_key(
        database,
        log.admin(),
        name="export",
        scopes=[ApiKeyScope.AUDIT_READ],
        expires_at=None,
        environment="dev",
        limiter=RecordingLimiter(),  # type: ignore[arg-type]
        origin=Origin(),
        now=datetime.now(UTC),
    )
    return Caller(
        CallerKind.API_KEY,
        tenant_id=log.mine.id,
        user_id=log.mine.admin,
        role=Role.ADMIN,
        credential_id=made.key.id,
        scopes=frozenset({"audit:read"}),
    )


@pytest.fixture
async def api(migrated_db: ScratchDatabase) -> AsyncIterator[Database]:
    database = Database.connect(migrated_db.url(API), pool_size=2)
    yield database
    await database.dispose()


async def test_a_keys_export_is_capped_and_its_first_one_emails_the_admins_once(
    log: Log, api: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = await make_key(log, api)
    for _ in range(3):
        log.event(log.mine, "transfer.created", actor_id=log.mine.member)
    async with client(log.db, lambda: key) as http:
        first = await http.post("/v1/audit/exports", json={"format": "json"})
        second = await http.post("/v1/audit/exports", json={"format": "csv"})
        monkeypatch.setattr(audit_search, "KEY_CAP", 2)
        too_large = await http.post("/v1/audit/exports", json={"format": "json"})
    assert first.status_code == second.status_code == 200
    assert too_large.status_code == 422
    assert too_large.json()["code"] == "export_too_large"
    assert log.db.sql(
        "SELECT count(*) FROM outbox WHERE tenant_id = :t AND topic = 'api_key.first_export'",
        t=log.mine.id,
    ) == [(1,)]
    sent = Sent()
    notify = Database.connect(log.db.url(NOTIFY), pool_size=2)
    try:
        await drain(notifier(notify, sent), log.db, log.mine.id)
    finally:
        await notify.dispose()
    [email] = sent.of_type("api_key_first_export")
    assert email.to == f"{log.mine.admin.hex}@example.test"


async def test_export_rates_per_key_and_per_tenant(
    log: Log, api: Database, counter_store: CounterStore
) -> None:
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()))
    key = await make_key(log, api)
    async with client(log.db, lambda: key, limiter) as http:  # type: ignore[arg-type]
        assert (await http.post("/v1/audit/exports", json={"format": "json"})).status_code == 200
        again = await http.post("/v1/audit/exports", json={"format": "json"})
    assert again.status_code == 429  # one an hour per key
    async with client(log.db, log.admin, limiter) as http:  # type: ignore[arg-type]
        statuses = [
            (await http.post("/v1/audit/exports", json={"format": "json"})).status_code
            for _ in range(10)
        ]
    # The key's one export counts towards the tenant's 10 an hour.
    assert statuses == [200] * 9 + [429]


async def test_one_export_at_a_time_per_tenant(log: Log) -> None:
    leases = ExportLeases(None)
    held = uuid.uuid4()
    assert await leases.acquire(log.mine.id, held)
    async with client(log.db, log.admin) as http:
        http._transport.app.state.export_leases = leases  # type: ignore[attr-defined]
        busy = await http.post("/v1/audit/exports", json={"format": "json"})
        assert busy.status_code == 429
        # Another tenant's export isn't held back by this one's.
        assert await leases.acquire(log.theirs.id, uuid.uuid4())
        await leases.release(log.mine.id, held)
        # A finished export frees the lease for the next.
        assert (await http.post("/v1/audit/exports", json={"format": "json"})).status_code == 200
        assert (await http.post("/v1/audit/exports", json={"format": "json"})).status_code == 200


async def test_another_tenants_events_never_appear_by_any_filter(log: Log) -> None:
    transfer, [recipient] = seed_transfer(
        log.db, log.theirs.id, log.theirs.target, recipients=[f"{uuid.uuid4().hex}@partner.test"]
    )
    [(their_email,)] = log.db.sql("SELECT email FROM users WHERE id = :id", id=log.theirs.member)
    [(their_recipient,)] = log.db.sql(
        "SELECT email FROM transfer_recipients WHERE id = :id", id=recipient
    )
    theirs = {
        log.event(log.theirs, "transfer.sent", actor_id=log.theirs.member, ip="203.0.113.9"),
        log.event(log.theirs, "transfer.revoked", target=("transfer", transfer)),
        log.event(log.theirs, "download.granted", actor_type="recipient", actor_id=recipient),
    }
    mine = log.event(log.mine, "transfer.sent", actor_id=log.mine.member)
    filters: list[dict[str, object]] = [
        {},
        {"actor_id": str(log.theirs.member)},
        {"target_id": str(transfer)},
        {"target_type": "transfer", "target_id": str(transfer)},
        {"email": their_email},
        {"email": their_recipient},
        {"source_ip": "203.0.113.9"},
    ]
    async with client(log.db, log.admin) as http:
        for query in filters:
            found = await http.post("/v1/audit/events/search", json={"filter": query, "limit": 100})
            exported = await http.post("/v1/audit/exports", json={"format": "csv", "filter": query})
            for text in (found.text, exported.text):
                for event_id in theirs:
                    assert str(event_id) not in text, query
    page = await search(log, log.admin(), limit=100)
    assert str(mine) in ids(page)


async def test_an_uploaders_address_finds_what_they_did_and_what_was_done_to_their_request(
    log: Log,
) -> None:
    # Upload requests (#212) join the email filter: an uploader acts, and is targeted, as its
    # request's ID, and `actor_email` names the uploader's address.
    request_id = uuid.uuid4()
    address = f"{request_id.hex}@supplier.example"
    log.db.sql(
        "INSERT INTO upload_requests (id, tenant_id, created_by, state, uploader_email, "
        "email_normalized, locale, expires_at, delivery_state) VALUES (:id, :t, :owner, 'open', "
        ":email, :email, 'en', now() + interval '7 days', 'sent')",
        id=request_id,
        t=log.mine.id,
        owner=log.mine.target,
        email=address,
    )
    uploaded = log.event(
        log.mine, "file.uploaded", actor_type="uploader", actor_id=request_id, target=None
    )
    revoked = log.event(
        log.mine,
        "upload_request.revoked",
        actor_id=log.mine.target,
        target=("upload_request", request_id),
    )
    log.event(log.mine, "file.uploaded", actor_type="uploader", actor_id=uuid.uuid4())
    page = await search(log, log.admin(), filter={"email": address.upper()})
    assert set(ids(page)) == {str(uploaded), str(revoked)}
    [mine] = [item for item in page["items"] if item["id"] == str(uploaded)]  # type: ignore[attr-defined,index]
    assert mine["actor_email"] == address
    # Another tenant's admin finds nothing by it.
    assert ids(await search(log, log.admin(log.theirs), filter={"email": address})) == []
