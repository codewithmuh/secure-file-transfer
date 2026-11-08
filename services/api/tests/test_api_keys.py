"""Tenant API keys (#215; authn and authz 5): the format, create, list and revoke, the caller a
key resolves to, its owner's changes, every use audited, the secret never anywhere but the one
answer, the failed-authentication block, and the expiry emails.

Keys are made by the real service and used through the real app, whose caller dependency resolves
them (the authorization matrix replaces it with synthetic callers instead).
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
import uuid
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx2 as httpx
import pytest
from fastapi import FastAPI
from prometheus_client import CollectorRegistry
from pydantic import SecretStr
from starlette.testclient import TestClient

from api_settings import API_SETTINGS
from archive_fixtures import FakeArchiveStore, fake_archive
from member_fixtures import (
    EMAIL_KEYRING,
    RecordingLimiter,
    Tenant,
    client,
    seed_tenant,
    seed_user,
    session_caller,
)
from notify_fixtures import Sent, drain, notifier
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.api.rate_limits import get_rate_limiter
from sft.core.settings import Settings
from sft.data.audit import Origin
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.data.models import ApiKeyScope, Role
from sft.data.roles import API, JOBS, NOTIFY
from sft.service import api_keys
from sft.service.api_keys import new_key, parse_key
from sft.service.caller import Caller
from sft.service.rate_limits import RateLimiter
from transfer_fixtures import seed_transfer

pytestmark = pytest.mark.anyio

ROOT = Path(__file__).resolve().parents[3]
NOW = datetime.now(UTC)


# ---- the format (authn and authz 5.1) ----


def test_a_key_is_256_random_bits_with_its_environment_and_a_checksum() -> None:
    key = new_key("dev")
    assert re.fullmatch(r"sft_dev_[0-9A-Za-z]{43}_[0-9A-Za-z]{6}", key)
    assert parse_key(key, "dev") == key
    assert new_key("dev") != key
    assert api_keys.key_prefix(key) == key[:16]
    assert api_keys.key_hash(key) == hashlib.sha256(key.encode()).digest()


def test_a_typo_another_environment_or_a_random_string_is_refused_without_a_lookup() -> None:
    key = new_key("prd")
    assert parse_key(key, "prd") == key
    assert parse_key(key, "dev") is None  # another environment's key
    secret = key[8:51]
    typo = key[:8] + secret[:-1] + ("A" if secret[-1] != "A" else "B") + key[51:]
    assert parse_key(typo, "prd") is None  # the CRC-32 doesn't match
    for raw in ("", "sft_prd_", key[:-1], key + "x", key.replace("_", "-"), " " + key):
        assert parse_key(raw, "prd") is None


def test_the_secret_scanning_rule_matches_the_format_and_nothing_shorter() -> None:
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    assert config["extend"]["useDefault"] is True
    [rule] = [r for r in config["rules"] if r["id"] == "sft-api-key"]
    pattern = re.compile(rule["regex"])
    for environment in api_keys.KEY_ENVIRONMENTS:
        # Made here, at run time: no key-shaped string is ever in the repository.
        assert pattern.search(f"token = {new_key(environment)}\n")
    assert not pattern.search("sft_dev_" + "x" * 20)
    assert not pattern.search("sft_qa_" + "x" * 43 + "_" + "y" * 6)


# ---- the real app, whose caller dependency resolves keys ----


@dataclass
class Keys:
    db: ScratchDatabase
    database: Database
    archive: FakeArchiveStore
    tenant: Tenant

    def admin(self) -> Caller:
        return session_caller(self.tenant.id, self.tenant.admin, Role.ADMIN)

    async def make(
        self,
        scopes: tuple[ApiKeyScope, ...] = (ApiKeyScope.TRANSFERS_READ,),
        *,
        owner: uuid.UUID | None = None,
    ) -> api_keys.CreatedKey:
        caller = (
            self.admin() if owner is None else session_caller(self.tenant.id, owner, Role.ADMIN)
        )
        return await api_keys.create_api_key(
            self.database,
            caller,
            name="ci",
            scopes=scopes,
            expires_at=None,
            environment="dev",
            limiter=RecordingLimiter(),  # type: ignore[arg-type]
            origin=Origin(),
            now=datetime.now(UTC),
        )

    def app(self) -> FastAPI:
        app = create_app()
        app.state.database = self.database
        app.state.email_keyring = EMAIL_KEYRING
        app.state.audit_archive = fake_archive(self.archive)
        app.state.api_key_environment = "dev"
        limiter = RecordingLimiter()
        app.dependency_overrides[get_rate_limiter] = lambda: limiter
        return app

    @asynccontextmanager
    async def http(self) -> AsyncIterator[httpx.AsyncClient]:
        transport = httpx.ASGITransport(app=self.app())
        async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as http:
            yield http

    def uses(self, key_id: uuid.UUID) -> list[tuple[object, ...]]:
        return self.db.sql(
            "SELECT details->>'operation', (details->>'status')::int, actor_type, actor_id "
            "FROM audit_events WHERE action = 'api_key.used' AND target_id = :id "
            "ORDER BY occurred_at, id",
            id=key_id,
        )


@pytest.fixture
async def keys(migrated_db: ScratchDatabase) -> AsyncIterator[Keys]:
    database = Database.connect(migrated_db.url(API), pool_size=2)
    try:
        yield Keys(migrated_db, database, FakeArchiveStore(), seed_tenant(migrated_db))
    finally:
        await database.dispose()


def bearer(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


async def test_create_shows_the_secret_once_and_stores_only_its_hash(keys: Keys) -> None:
    async with client(keys.db, keys.admin) as http:
        created = await http.post(
            "/v1/api-keys",
            json={"name": "nightly export", "scopes": ["audit:read", "transfers:read"]},
        )
        listed = await http.get("/v1/api-keys")
    assert created.status_code == 201, created.text
    assert created.headers["cache-control"] == "no-store"
    body = created.json()
    secret = body["secret"]
    assert parse_key(secret, "dev") == secret
    assert created.headers["location"] == f"/v1/api-keys/{body['id']}"
    assert body["key_prefix"] == secret[:16]
    assert sorted(body["scopes"]) == ["audit:read", "transfers:read"]
    expires = datetime.fromisoformat(body["expires_at"])
    assert timedelta(days=89) < expires - datetime.now(UTC) <= timedelta(days=90)
    # Shown once: never in the list, and the row holds only its hash and prefix.
    assert secret not in listed.text
    assert [item["id"] for item in listed.json()["items"]] == [body["id"]]
    [(row, stored_hash)] = keys.db.sql(
        "SELECT k::text, key_hash FROM api_keys k WHERE id = :id", id=body["id"]
    )
    assert stored_hash == hashlib.sha256(secret.encode()).digest()
    assert secret not in str(row)
    assert keys.db.sql(
        "SELECT actor_type, security_critical FROM audit_events "
        "WHERE action = 'api_key.created' AND target_id = :id",
        id=body["id"],
    ) == [("admin", False)]


async def test_a_creation_checks_its_expiry_and_the_25_active_keys(keys: Keys) -> None:
    limiter = RecordingLimiter()
    async with client(keys.db, keys.admin, limiter) as http:
        too_far = (datetime.now(UTC) + timedelta(days=366)).isoformat()
        far = await http.post(
            "/v1/api-keys", json={"name": "x", "scopes": ["audit:read"], "expires_at": too_far}
        )
        past = await http.post(
            "/v1/api-keys",
            json={"name": "x", "scopes": ["audit:read"], "expires_at": NOW.isoformat()},
        )
        assert far.status_code == past.status_code == 422
        assert far.json()["errors"][0]["pointer"] == "#/expires_at"
        for _ in range(api_keys.MAX_ACTIVE):
            ok = await http.post("/v1/api-keys", json={"name": "x", "scopes": ["audit:read"]})
            assert ok.status_code == 201
        refused = await http.post("/v1/api-keys", json={"name": "x", "scopes": ["audit:read"]})
    assert refused.status_code == 422
    assert refused.json()["code"] == "validation_failed"
    # Group J's 20 a day is charged with each key that can be made, and only then.
    charged = [ids for ids, _ in limiter.checks if ids == ("J.api_keys",)]
    assert len(charged) == api_keys.MAX_ACTIVE


async def test_the_21st_key_of_a_day_is_429(keys: Keys, counter_store: CounterStore) -> None:
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()))
    async with client(keys.db, keys.admin, limiter) as http:  # type: ignore[arg-type]
        for _ in range(20):
            made = await http.post("/v1/api-keys", json={"name": "x", "scopes": ["audit:read"]})
            assert made.status_code == 201
        refused = await http.post("/v1/api-keys", json={"name": "x", "scopes": ["audit:read"]})
    assert refused.status_code == 429
    assert keys.db.sql("SELECT count(*) FROM api_keys WHERE tenant_id = :t", t=keys.tenant.id) == [
        (20,)
    ]


async def test_a_key_acts_as_its_owner_within_its_scopes_and_every_use_is_audited(
    keys: Keys,
) -> None:
    made = await keys.make((ApiKeyScope.TRANSFERS_READ,))
    owned, _ = seed_transfer(keys.db, keys.tenant.id, keys.tenant.admin)
    others, _ = seed_transfer(keys.db, keys.tenant.id, keys.tenant.member)
    async with keys.http() as http:
        listed = await http.get("/v1/transfers?scope=tenant", headers=bearer(made.secret))
        users = await http.get("/v1/users", headers=bearer(made.secret))
        me = await http.get("/v1/me", headers=bearer(made.secret))
        write = await http.post(
            "/v1/transfers",
            json={"recipients": [{"email": "partner@example.test"}]},
            headers=bearer(made.secret),
        )
    assert listed.status_code == 200
    assert {item["id"] for item in listed.json()["items"]} >= {str(owned), str(others)}
    # Web-only operations and scopes it lacks: 403, never 401 (T-55).
    for refused in (users, me, write):
        assert refused.status_code == 403
        assert refused.json()["code"] == "permission_denied"
    assert keys.uses(made.key.id) == [
        ("listTransfers", 200, "api_key", made.key.id),
        ("listUsers", 403, "api_key", made.key.id),
        ("getCurrentMember", 403, "api_key", made.key.id),
        ("createTransfer", 403, "api_key", made.key.id),
    ]


async def test_last_used_at_moves_at_most_once_an_hour(keys: Keys) -> None:
    made = await keys.make()

    def last_used() -> object:
        [(value,)] = keys.db.sql("SELECT last_used_at FROM api_keys WHERE id = :id", id=made.key.id)
        return value

    assert last_used() is None
    async with keys.http() as http:
        await http.get("/v1/transfers", headers=bearer(made.secret))
        first = last_used()
        await http.get("/v1/transfers", headers=bearer(made.secret))
        assert first is not None
        assert last_used() == first
        keys.db.sql(
            "UPDATE api_keys SET last_used_at = now() - interval '61 minutes' WHERE id = :id",
            id=made.key.id,
        )
        moved_back = last_used()
        await http.get("/v1/transfers", headers=bearer(made.secret))
    assert last_used() != moved_back
    # Every call was recorded, whether or not it moved last_used_at.
    assert len(keys.uses(made.key.id)) == 3


async def test_a_revoked_key_is_refused_on_its_next_request(keys: Keys) -> None:
    made = await keys.make()
    async with keys.http() as http:
        assert (await http.get("/v1/transfers", headers=bearer(made.secret))).status_code == 200
        async with client(keys.db, keys.admin, archive=fake_archive(keys.archive)) as admin:
            revoked = await admin.post(f"/v1/api-keys/{made.key.id}/revoke")
            again = await admin.post(f"/v1/api-keys/{made.key.id}/revoke")
        after = await http.get("/v1/transfers", headers=bearer(made.secret))
    assert revoked.status_code == again.status_code == 200
    assert revoked.json()["revoked_at"] is not None
    assert again.json()["revoked_at"] == revoked.json()["revoked_at"]  # unchanged on a retry
    assert after.status_code == 401
    assert after.json()["code"] == "credentials_invalid"
    assert after.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    # A security-critical record, in both regions' archive once.
    for region in keys.archive.regions:
        assert keys.archive.actions(region) == ["api_key.revoked"]


async def test_a_revocation_is_503_until_both_regions_hold_its_record(keys: Keys) -> None:
    made = await keys.make()
    keys.archive.fail.add(keys.archive.regions[1])
    async with client(keys.db, keys.admin, archive=fake_archive(keys.archive)) as admin:
        unconfirmed = await admin.post(f"/v1/api-keys/{made.key.id}/revoke")
        keys.archive.fail.clear()
        retried = await admin.post(f"/v1/api-keys/{made.key.id}/revoke")
    assert unconfirmed.status_code == 503
    assert retried.status_code == 200
    assert keys.archive.actions(keys.archive.regions[1]) == ["api_key.revoked"]
    async with keys.http() as http:
        assert (await http.get("/v1/transfers", headers=bearer(made.secret))).status_code == 401


async def test_an_expired_key_or_a_suspended_tenants_is_refused(keys: Keys) -> None:
    expired, live = await keys.make(), await keys.make()
    keys.db.sql(
        "UPDATE api_keys SET created_at = now() - interval '91 days', "
        "expires_at = now() - interval '1 day' WHERE id = :id",
        id=expired.key.id,
    )
    async with keys.http() as http:
        old = await http.get("/v1/transfers", headers=bearer(expired.secret))
        keys.db.sql("UPDATE tenants SET status = 'suspended' WHERE id = :id", id=keys.tenant.id)
        suspended = await http.get("/v1/transfers", headers=bearer(live.secret))
    assert old.status_code == suspended.status_code == 401
    assert old.json()["code"] == suspended.json()["code"] == "credentials_invalid"


@pytest.mark.parametrize("change", ["deactivate", "demote"])
async def test_an_owner_deactivated_or_demoted_loses_their_keys_in_that_transaction(
    keys: Keys, change: str
) -> None:
    owner = seed_user(keys.db, keys.tenant.id, role="admin")
    first = await keys.make(owner=owner)
    second = await keys.make((ApiKeyScope.AUDIT_READ,), owner=owner)
    kept = await keys.make()  # another admin's key stays
    async with client(keys.db, keys.admin, archive=fake_archive(keys.archive)) as admin:
        if change == "deactivate":
            done = await admin.post(f"/v1/users/{owner}/deactivate")
        else:
            done = await admin.patch(f"/v1/users/{owner}", json={"role": "member"})
    assert done.status_code == 200, done.text
    reason = "owner_deactivated" if change == "deactivate" else "owner_demoted"
    rows = keys.db.sql(
        "SELECT k.id, k.revoked_reason, e.security_critical, e.details->>'reason', "
        "e.tx_id = u.tx_id FROM api_keys k "
        "JOIN audit_events e ON e.target_id = k.id AND e.action = 'api_key.revoked' "
        "JOIN audit_events u ON u.target_id = :owner AND u.action = :action "
        "WHERE k.created_by = :owner ORDER BY k.id",
        owner=owner,
        action="user.deactivated" if change == "deactivate" else "user.role_changed",
    )
    assert sorted(r[0] for r in rows) == sorted([first.key.id, second.key.id])
    assert all(r[1:] == (reason, True, reason, True) for r in rows)  # one transaction
    # Both archives hold the change's record and each key's.
    for region in keys.archive.regions:
        archived = keys.archive.actions(region)
        assert archived.count("api_key.revoked") == 2
    async with keys.http() as http:
        for made in (first, second):
            assert (await http.get("/v1/transfers", headers=bearer(made.secret))).status_code == 401
        assert (await http.get("/v1/transfers", headers=bearer(kept.secret))).status_code == 200


async def test_a_malformed_key_is_refused_without_a_database_query(keys: Keys) -> None:
    app = keys.app()
    app.state.database = object()  # any query would fail the request with a 500
    made = new_key("dev")
    flipped = made[:-1] + ("a" if made[-1] != "a" else "b")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as http:
        for raw in ("x", flipped, new_key("prd"), made[:30]):
            refused = await http.get("/v1/transfers", headers=bearer(raw))
            assert refused.status_code == 401, raw
            assert refused.json()["code"] == "credentials_invalid"
        basic = await http.get("/v1/transfers", headers={"Authorization": f"Basic {made}"})
        assert basic.status_code == 401


async def test_a_cookie_and_a_key_together_are_refused(keys: Keys) -> None:
    made = await keys.make()
    async with keys.http() as http:
        both = await http.get(
            "/v1/transfers",
            headers={**bearer(made.secret), "cookie": "__Host-sft_session=" + "a" * 43},
        )
    assert both.status_code == 401
    assert both.json()["code"] == "credentials_invalid"
    assert keys.uses(made.key.id) == []


async def test_a_key_reaches_nothing_of_another_tenant(keys: Keys) -> None:
    made = await keys.make((ApiKeyScope.TRANSFERS_READ, ApiKeyScope.TRANSFERS_WRITE))
    other = seed_tenant(keys.db)
    theirs, _ = seed_transfer(keys.db, other.id, other.admin, state="sent")
    async with keys.http() as http:
        listed = await http.get("/v1/transfers?scope=tenant", headers=bearer(made.secret))
        read = await http.get(f"/v1/transfers/{theirs}", headers=bearer(made.secret))
        revoke = await http.post(f"/v1/transfers/{theirs}/revoke", headers=bearer(made.secret))
    assert str(theirs) not in listed.text
    assert read.status_code == revoke.status_code == 404
    [(state,)] = keys.db.sql("SELECT state FROM transfers WHERE id = :id", id=theirs)
    assert state == "sent"


async def test_the_secret_appears_nowhere_but_the_creation_answer(
    keys: Keys, json_logs: Callable[[], list[dict[str, object]]], spans: object
) -> None:
    async with client(keys.db, keys.admin, archive=fake_archive(keys.archive)) as admin:
        created = await admin.post("/v1/api-keys", json={"name": "c", "scopes": ["audit:read"]})
        secret = created.json()["secret"]
        key_id = created.json()["id"]
        answers: list[str] = []
        async with keys.http() as http:
            for path in ("/v1/transfers", "/v1/users"):
                answers.append((await http.get(path, headers=bearer(secret))).text)
            answers.append(
                (await http.post("/v1/audit/events/search", json={}, headers=bearer(secret))).text
            )
            await admin.post(f"/v1/api-keys/{key_id}/revoke")
            answers.append((await http.get("/v1/transfers", headers=bearer(secret))).text)
    secret_part = secret[16:]  # what the prefix doesn't show
    tables = keys.db.sql(
        "SELECT a::text FROM audit_events a WHERE tenant_id = :t "
        "UNION ALL SELECT o::text FROM outbox o WHERE tenant_id = :t "
        "UNION ALL SELECT k::text FROM api_keys k WHERE tenant_id = :t",
        t=keys.tenant.id,
    )
    everywhere = [
        *(str(row) for row in tables),
        *answers,
        json.dumps(json_logs()),
        *(json.dumps(dict(s.attributes or {})) for s in spans.get_finished_spans()),  # type: ignore[attr-defined]
        *(json.dumps(r) for r in keys.archive.records()),
    ]
    assert everywhere
    for text in everywhere:
        assert secret_part not in text


async def test_a_use_that_cannot_be_recorded_fails_closed(keys: Keys) -> None:
    made = await keys.make()
    app = keys.app()

    async def unrecorded(*args: object, **kwargs: object) -> None:
        raise RuntimeError("the audit log is unavailable")

    original = api_keys.record_use
    api_keys.record_use = unrecorded  # type: ignore[assignment]
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as http:
            refused = await http.get("/v1/transfers", headers=bearer(made.secret))
    finally:
        api_keys.record_use = original  # type: ignore[assignment]
    assert refused.status_code == 503
    assert refused.json()["code"] == "service_unavailable"
    assert refused.headers["retry-after"] == "5"


# ---- the failed-authentication block (abuse 2.2, H) ----


@pytest.fixture
def blocking_app(valkey_url: str) -> Iterator[TestClient]:
    import valkey

    with valkey.Valkey.from_url(valkey_url) as empty:  # type: ignore[no-untyped-call]
        empty.flushdb()
    app = create_app(
        Settings(
            database_url=SecretStr("postgresql://sft_api@127.0.0.1:1/sft"),
            **{**API_SETTINGS, "valkey_url": valkey_url},  # type: ignore[arg-type]
        )
    )
    with TestClient(app) as http:
        yield http


def test_100_failed_key_authentications_in_5_minutes_block_the_ip(
    blocking_app: TestClient,
) -> None:
    # Malformed keys never reach the database (here unreachable): each is a failed authentication.
    for _ in range(100):
        refused = blocking_app.get("/v1/transfers", headers=bearer(new_key("prd")))
        assert refused.status_code == 401
    blocked = blocking_app.get("/v1/transfers", headers=bearer(new_key("dev")))
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0


# ---- the expiry emails (authn and authz 5.2) ----


async def test_the_owner_and_admins_are_emailed_14_and_3_days_before_expiry(
    keys: Keys,
) -> None:
    keys.db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (:t, 'ja') "
        "ON CONFLICT (tenant_id) DO UPDATE SET default_locale = 'ja'",
        t=keys.tenant.id,
    )
    second_admin = seed_user(keys.db, keys.tenant.id, role="admin")
    soon, later, far, revoked = [await keys.make() for _ in range(4)]
    for made, days in ((soon, 2), (later, 13), (far, 30), (revoked, 2)):
        keys.db.sql(
            "UPDATE api_keys SET expires_at = now() + make_interval(days => :days) WHERE id = :id",
            id=made.key.id,
            days=days,
        )
    jobs = Database.connect(keys.db.url(JOBS), pool_size=1)
    try:
        assert await api_keys.queue_expiry_notices(jobs, now=datetime.now(UTC)) >= 3
        assert await api_keys.queue_expiry_notices(jobs, now=datetime.now(UTC)) == 0
    finally:
        await jobs.dispose()
    notices = dict(
        keys.db.sql("SELECT id, expiry_notice FROM api_keys WHERE tenant_id = :t", t=keys.tenant.id)
    )
    assert notices[soon.key.id] == 3
    assert notices[later.key.id] == 14
    assert notices[far.key.id] is None
    keys.db.sql(
        "UPDATE api_keys SET revoked_at = now(), revoked_reason = 'admin' WHERE id = :id",
        id=revoked.key.id,
    )
    sent = Sent()
    notify = Database.connect(keys.db.url(NOTIFY), pool_size=2)
    try:
        await drain(notifier(notify, sent), keys.db, keys.tenant.id)
    finally:
        await notify.dispose()
    expiring = sent.of_type("api_key_expiring")
    admins = {f"{keys.tenant.admin.hex}@example.test", f"{second_admin.hex}@example.test"}
    assert {e.to for e in expiring} == admins
    assert len(expiring) == 2 * len(admins)  # the 3-day and the 14-day key; not the revoked one
    for email in expiring:
        assert soon.secret[16:] not in email.text
        assert later.secret[16:] not in email.text
        assert "有効期限" in email.subject  # the tenant's language
    named = {e.text.split("…")[0].split()[-1] for e in expiring}
    assert named == {soon.key.key_prefix, later.key.key_prefix}
