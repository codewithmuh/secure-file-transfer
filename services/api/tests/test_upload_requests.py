"""Upload requests: members ask an outsider for files, and the uploader verifies (#212; UC-2,
FR-3, FR-10, FR-14, FR-15, FR-20, FR-33, NFR-6, NFR-14; data model 2.2, 2.4, 3.3; authn and authz
4, 9.2).

Every test runs in the link world of link_fixtures.py: the real app over ASGI against the real
database, a real Valkey for the link limits (TEST_VALKEY_URL), the notification worker as
`sft_notify` and an in-memory audit archive. Members call through member_fixtures' client, whose
limiter admits every request and records what it was asked. The uploader's link and codes come
out of the emails the worker sent, as a person would read them.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2 as httpx
import pytest
from prometheus_client import CollectorRegistry
from sqlalchemy import text

from api_settings import WEB_ORIGIN
from archive_fixtures import FakeArchiveStore, fake_archive
from link_fixtures import Browser, World, unique, w
from member_fixtures import EMAIL_KEYRING, RecordingLimiter, client, seed_tenant, session_caller
from notify_fixtures import WEB_APP_URL
from sft.core.errors import RateLimited
from sft.data import link_sessions, transfers, upload_requests
from sft.data.access import NotFoundError
from sft.data.database import Database
from sft.data.models import Role
from sft.data.roles import API, JOBS
from sft.data.scope import Scope, Subject
from sft.service.audit_archive import Region
from sft.service.caller import AuthMethod, Caller, CallerKind
from sft.service.lifecycle import JobMetrics, Jobs, expire_upload_requests
from sft.service.rate_limits import Charge
from sft.service.rate_limits.limits import G_ADDRESS_EMAILS, G_CALLER_EMAILS, G_TENANT_EMAILS

pytestmark = pytest.mark.anyio
__all__ = ["w"]  # the fixture, imported for this module's tests

_UPLOAD_LINK = re.compile(re.escape(WEB_APP_URL) + r"/u#([A-Za-z0-9_-]+)")


# ---- helpers ----


def owner_of(world: World) -> Caller:
    return session_caller(world.tenant.id, world.tenant.target, Role.MEMBER)


@asynccontextmanager
async def member(
    world: World,
    caller: Caller | None = None,
    *,
    limiter: RecordingLimiter | None = None,
    store: FakeArchiveStore | None = None,
) -> AsyncIterator[httpx.AsyncClient]:
    """The owner's (or `caller`'s) member client, with the world's archive unless `store`."""
    who = caller or owner_of(world)
    archive = fake_archive(store or world.store)
    async with client(world.db, lambda: who, limiter=limiter, archive=archive) as http:
        yield http


async def ask(world: World, address: str, **body: Any) -> dict[str, Any]:
    """The owner asks `address` for files; the new request."""
    async with member(world) as http:
        response = await http.post("/v1/upload-requests", json={"uploader_email": address, **body})
    assert response.status_code == 201, response.text
    created: dict[str, Any] = response.json()
    return created


def upload_links(world: World, address: str) -> list[str]:
    return [
        m.group(1)
        for e in world.sent.to(address)
        if e.email_type == "upload_request"
        for m in [_UPLOAD_LINK.search(e.text)]
        if m
    ]


async def link_for(world: World, address: str) -> str:
    await world.links()
    return upload_links(world, address)[-1]


async def verify(world: World, browser: Browser, address: str) -> tuple[str, dict[str, Any]]:
    token = await link_for(world, address)
    code = await world.code(browser, token, address)
    response = await browser.post("/v1/links/sessions", {"token": token, "code": code})
    assert response.status_code == 201, response.text
    return token, response.json()


def request_row(world: World, request_id: object) -> dict[str, Any]:
    [row] = world.db.sql(
        "SELECT state, delivery_state, notified_at, failed_attempts, locked_at, ended_at, "
        "revoked_by, link_token_hash, expires_at FROM upload_requests WHERE id = :id",
        id=request_id,
    )
    keys = (
        "state",
        "delivery_state",
        "notified_at",
        "failed_attempts",
        "locked_at",
        "ended_at",
        "revoked_by",
        "hash",
        "expires_at",
    )
    return dict(zip(keys, row, strict=True))


def actions(world: World, target: object) -> list[object]:
    return [
        a
        for (a,) in world.db.sql(
            "SELECT action FROM audit_events WHERE target_id = :id ORDER BY occurred_at, id",
            id=target,
        )
    ]


def open_sessions(world: World, request_id: object) -> int:
    [(count,)] = world.db.sql(
        "SELECT count(*) FROM link_sessions WHERE upload_request_id = :id AND revoked_at IS NULL",
        id=request_id,
    )
    return int(count)  # type: ignore[call-overload]


def user_email(world: World, user_id: uuid.UUID) -> str:
    [(email,)] = world.db.sql("SELECT email FROM users WHERE id = :id", id=user_id)
    return str(email)


def suppress(world: World, address: str) -> None:
    world.db.sql(
        "INSERT INTO email_suppressions (id, tenant_id, email_hmac, hmac_key_id, reason) "
        "VALUES (:id, :tenant, :hmac, :key, 'complaint')",
        id=uuid.uuid4(),
        tenant=world.tenant.id,
        hmac=EMAIL_KEYRING.active(address.lower()),
        key=EMAIL_KEYRING.active_key_id,
    )


def unsafe(browser: Browser, session: dict[str, Any]) -> dict[str, str]:
    return browser.headers(
        session["id"], origin=WEB_ORIGIN, **{"x-csrf-token": session["csrf_token"]}
    )


def japanese(value: str) -> bool:
    return any(ord(c) > 0x3000 for c in value)


# ---- createUploadRequest: the link email ----


async def test_a_request_emails_its_link_in_its_locale_and_records_the_delivery(
    w: World,
) -> None:
    address = unique()
    limiter = RecordingLimiter()
    async with member(w, limiter=limiter) as http:
        response = await http.post(
            "/v1/upload-requests",
            json={"uploader_email": address, "locale": "ja", "message": "Please send the deck."},
        )
        assert response.status_code == 201, response.text
        body = response.json()
        assert response.headers["location"] == f"/v1/upload-requests/{body['id']}"
    assert body["state"] == "open"
    assert body["uploader_email"] == address
    assert (body["locale"], body["message"]) == ("ja", "Please send the deck.")
    assert (body["delivery_state"], body["notified_at"]) == ("queued", None)
    assert (body["uploader_access_state"], body["failed_attempts"]) == ("invited", 0)
    assert (body["file_count"], body["total_size"]) == (0, 0)
    assert body["created_by"] == str(w.tenant.target)
    # 7 days by default (FR-3), as the API's clock reads it.
    expires = datetime.fromisoformat(body["expires_at"])
    assert abs(expires - (datetime.now(UTC) + timedelta(days=7))) < timedelta(minutes=1)
    # Group G, shared with sendTransfer: the caller's, the address's and the tenant's caps.
    charged = {limit for ids, _ in limiter.checks for limit in ids}
    assert {G_CALLER_EMAILS.id, G_TENANT_EMAILS.id, G_ADDRESS_EMAILS.id} <= charged
    # The worker emails the link, in the request's language, to the address only.
    await w.links()
    [email] = w.sent.of_type("upload_request")
    assert email.to == address
    assert japanese(email.subject)
    assert email.reply_to == user_email(w, w.tenant.target)
    assert "Please send the deck." not in email.text, "the message shows only after verifying"
    token = upload_links(w, address)[0]
    assert f"{WEB_APP_URL}/u#{token}" in email.text
    row = request_row(w, body["id"])
    assert row["delivery_state"] == "sent"
    assert row["notified_at"] is not None
    async with member(w) as http:
        shown = (await http.get(f"/v1/upload-requests/{body['id']}")).json()
    assert shown["delivery_state"] == "sent"
    assert shown["notified_at"] is not None
    assert actions(w, uuid.UUID(body["id"])) == [
        "upload_request.created",
        "uploader.link_issued",
        "email.sent",
    ]
    # A redelivery sends nothing more.
    await w.links()
    assert len(w.sent.of_type("upload_request")) == 1


async def test_an_english_request_gets_the_english_email(w: World) -> None:
    address = unique()
    created = await ask(w, address)  # the tenant's default language
    assert created["locale"] == "en"
    await w.links()
    [email] = w.sent.to(address)
    assert not japanese(email.subject)


# ---- the uploader verifies ----


async def test_the_uploader_verifies_into_a_session_bound_to_that_request(w: World) -> None:
    address = unique()
    created = await ask(w, address, message="hello")
    browser = await w.browser()
    token = await link_for(w, address)
    resolved = await browser.post("/v1/links/resolve", {"token": token})
    assert resolved.status_code == 200
    assert resolved.json() == {
        "kind": "upload_request",
        "access_state": "verification_required",
        "locale": "en",
    }
    code = await w.code(browser, token, address)
    assert len(code) == 6
    response = await browser.post("/v1/links/sessions", {"token": token, "code": code})
    assert response.status_code == 201, response.text
    session = response.json()
    assert session["kind"] == "upload_request"
    assert "transfer" not in session
    assert (session["email"], session["locale"]) == (address, "en")
    asked = session["upload_request"]
    assert asked == {
        "tenant_name": "T",
        "requester_email": user_email(w, w.tenant.target),
        "message": "hello",
        "expires_at": asked["expires_at"],
        "max_files": 50,
        "max_file_size": 5_000_000_000,
        "max_total_size": 20_000_000_000,
        "files_received": 0,
        "bytes_received": 0,
    }
    assert datetime.fromisoformat(asked["expires_at"]) == datetime.fromisoformat(
        created["expires_at"]
    )
    # The session is the request's only: getLinkSession, and no files before #213.
    got = await browser.get("/v1/session", session["id"])
    assert got.status_code == 200
    assert got.json()["upload_request"] == asked
    assert got.json()["csrf_token"] == session["csrf_token"]
    listed = await browser.get("/v1/session/files", session["id"])
    assert (listed.status_code, listed.json()) == (200, {"items": []})
    again = await browser.post("/v1/links/resolve", {"token": token})
    assert again.json() == {
        "kind": "upload_request",
        "access_state": "verified",
        "link_session_id": session["id"],
        "locale": "en",
    }
    async with member(w) as http:
        shown = (await http.get(f"/v1/upload-requests/{created['id']}")).json()
    assert shown["uploader_access_state"] == "verified"
    # Every step audited, as the uploader.
    [(actor_type,)] = w.db.sql(
        "SELECT DISTINCT actor_type FROM audit_events WHERE action IN "
        "('verification.code_requested', 'verification.attempted', 'link_session.started') "
        "AND actor_id = :id",
        id=uuid.UUID(created["id"]),
    )
    assert actor_type == "uploader"
    ended = await browser.http.delete("/v1/session", headers=unsafe(browser, session))
    assert ended.status_code == 204
    browser.keep(ended)
    assert (await browser.get("/v1/session", session["id"])).status_code == 401


async def test_a_recipients_session_cant_act_on_a_request_and_an_uploaders_cant_read_a_transfer(
    w: World,
) -> None:
    # T-20: each session's resource scope reaches its own subject's rows only.
    recipient, uploader = unique(), unique()
    transfer_id, [recipient_id] = w.transfer(recipient)
    created = await ask(w, uploader)
    request_id = uuid.UUID(created["id"])
    browser = await w.browser()
    _, recipients_session = await w.verify(browser, recipient)
    _, uploaders_session = await verify(w, browser, uploader)
    # One browser holds both; each X-Link-Session sees its own item only.
    as_recipient = (await browser.get("/v1/session", recipients_session["id"])).json()
    as_uploader = (await browser.get("/v1/session", uploaders_session["id"])).json()
    assert (as_recipient["kind"], "upload_request" in as_recipient) == ("transfer", False)
    assert (as_uploader["kind"], "transfer" in as_uploader) == ("upload_request", False)
    assert str(request_id) not in str(as_recipient)
    assert str(transfer_id) not in str(as_uploader)
    # An uploader's session can't download (session.download is a recipient's).
    refused = await browser.http.post(
        f"/v1/session/files/{uuid.uuid4()}/downloads",
        json={},
        headers=unsafe(browser, uploaders_session),
    )
    assert (refused.status_code, refused.json()["code"]) == (403, "permission_denied")
    # The data layer: neither resource scope reaches the other's rows.
    api = Database.connect(w.db.url(API), pool_size=1)
    try:
        recipient_scope = Scope.resource(w.tenant.id, Subject.recipient(recipient_id))
        async with api.transaction(recipient_scope) as session:
            with pytest.raises(NotFoundError):
                await upload_requests.get_request(session, request_id)
            with pytest.raises(NotFoundError):
                await upload_requests.link_view(session, request_id)
        uploader_scope = Scope.resource(w.tenant.id, Subject.upload_request(request_id))
        async with api.transaction(uploader_scope) as session:
            with pytest.raises(NotFoundError):
                await transfers.get_transfer(session, transfer_id)
            assert (await upload_requests.get_request(session, request_id)).id == request_id
            assert (
                await link_sessions.get_live(session, uuid.UUID(recipients_session["id"])) is None
            )
    finally:
        await api.dispose()


async def test_the_old_session_lookup_returns_recipients_sessions_only(w: World) -> None:
    # Revision 0019 keeps revision 0018's code working: its lookup never hands it an uploader.
    address = unique()
    await ask(w, address)
    browser = await w.browser()
    _, session = await verify(w, browser, address)
    assert browser.cookie is not None
    hashes = [link_sessions.token_hash(t) for t in browser.cookie.split(".")]
    api = Database.connect(w.db.url(API), pool_size=1)
    try:
        async with api.transaction(Scope.lookup()) as lookup:
            old = (
                await lookup.execute(
                    text("SELECT session_id FROM lookup_link_sessions(:h)"), {"h": hashes}
                )
            ).all()
            new = (
                await lookup.execute(
                    text("SELECT session_id FROM lookup_link_subject_sessions(:h)"), {"h": hashes}
                )
            ).all()
    finally:
        await api.dispose()
    assert old == []
    assert [str(r[0]) for r in new] == [session["id"]]


async def test_a_suppressed_uploader_gets_no_link_and_no_code(w: World) -> None:
    address = unique()
    created = await ask(w, address)
    suppress(w, address)
    await w.links()
    assert w.sent.to(address) == []
    assert request_row(w, created["id"])["delivery_state"] == "suppressed"
    assert "uploader.suppressed" in actions(w, uuid.UUID(created["id"]))


# ---- lockout and unlock ----


async def test_20_failures_lock_the_uploader_tell_the_people_and_an_unlock_issues_a_new_link(
    w: World,
) -> None:
    address = unique()
    created = await ask(w, address)
    request_id = created["id"]
    browser = await w.browser()
    token = await link_for(w, address)
    statuses = []
    for _ in range(4):
        code = await w.code(browser, token, address)
        wrong = f"{(int(code) + 1) % 10**6:06d}"
        for _ in range(5):
            response = await browser.post("/v1/links/sessions", {"token": token, "code": wrong})
            statuses.append((response.status_code, response.json()["code"]))
    assert statuses[:19] == [(422, "code_invalid")] * 19
    assert statuses[19] == (403, "recipient_locked")
    row = request_row(w, request_id)
    assert (row["failed_attempts"], row["locked_at"] is not None) == (20, True)
    for region in Region:
        assert w.store.actions(region) == ["uploader.locked"]
    assert w.registry.get_sample_value("uploader_lockouts_total") == 1
    assert w.registry.get_sample_value("recipient_lockouts_total") == 0
    # Locked: no code is checked, and no code is sent.
    next_try = await browser.post("/v1/links/sessions", {"token": token, "code": "000000"})
    assert (next_try.status_code, next_try.json()["code"]) == (403, "recipient_locked")
    w.clock.advance(31)
    refused = await browser.post("/v1/links/codes", {"token": token})
    assert (refused.status_code, refused.json()["code"]) == (403, "recipient_locked")
    resolved = await browser.post("/v1/links/resolve", {"token": token})
    assert resolved.json() == {"kind": "upload_request", "access_state": "locked", "locale": "en"}
    # The owner and the tenant's admins get `recipient_locked`, its upload-request variant.
    await w.links()
    notices = w.sent.of_type("recipient_locked")
    assert {e.to for e in notices} == {
        user_email(w, w.tenant.target),
        user_email(w, w.tenant.admin),
    }
    assert all(f"/upload-requests/{request_id}" in e.text for e in notices)
    assert all(address not in e.text for e in notices)
    async with member(w) as http:
        shown = (await http.get(f"/v1/upload-requests/{request_id}")).json()
        assert (shown["uploader_access_state"], shown["failed_attempts"]) == ("locked", 20)
        unlocked = await http.post(f"/v1/upload-requests/{request_id}/unlock")
        assert unlocked.status_code == 200, unlocked.text
        body = unlocked.json()
        assert (body["uploader_access_state"], body["failed_attempts"]) == ("invited", 0)
        assert (body["delivery_state"], body["notified_at"], body["locked_at"]) == (
            "queued",
            None,
            None,
        )
        again = await http.post(f"/v1/upload-requests/{request_id}/unlock")
        assert again.status_code == 200
    for region in Region:
        assert w.store.actions(region) == ["uploader.locked", "uploader.unlocked"]
    old = await browser.post("/v1/links/resolve", {"token": token})
    assert (old.status_code, old.json()["code"]) == (404, "link_not_found")
    new = await link_for(w, address)
    assert new != token
    assert (await browser.post("/v1/links/resolve", {"token": new})).status_code == 200
    assert len(upload_links(w, address)) == 2, "one new link email, however often it was unlocked"
    [unlocked_by] = w.db.sql(
        "SELECT unlocked_by FROM upload_requests WHERE id = :id", id=request_id
    )
    assert unlocked_by == (w.tenant.target,)


async def test_an_unlock_whose_record_cant_be_confirmed_answers_503_and_stands(w: World) -> None:
    created = await ask(w, unique())
    w.db.sql(
        "UPDATE upload_requests SET failed_attempts = 20, locked_at = now() WHERE id = :id",
        id=created["id"],
    )
    store = FakeArchiveStore(fail={Region.OSAKA})
    path = f"/v1/upload-requests/{created['id']}/unlock"
    async with member(w, store=store) as http:
        refused = await http.post(path)
        assert (refused.status_code, refused.json()["code"]) == (503, "service_unavailable")
        assert request_row(w, created["id"])["locked_at"] is None
        store.fail.clear()
        assert (await http.post(path)).status_code == 200
    assert store.actions(Region.OSAKA) == ["uploader.unlocked"]


async def test_an_ended_request_cant_be_unlocked_and_api_keys_never_unlock(w: World) -> None:
    revoked, expired = await ask(w, unique()), await ask(w, unique())
    w.db.sql(
        "UPDATE upload_requests SET state = 'revoked', ended_at = now() WHERE id = :id",
        id=revoked["id"],
    )
    w.db.sql(
        "UPDATE upload_requests SET expires_at = now() - interval '1 second' WHERE id = :id",
        id=expired["id"],
    )
    async with member(w) as http:
        gone = await http.post(f"/v1/upload-requests/{revoked['id']}/unlock")
        late = await http.post(f"/v1/upload-requests/{expired['id']}/unlock")
        missing = await http.post(f"/v1/upload-requests/{uuid.uuid4()}/unlock")
    assert (gone.status_code, gone.json()["code"]) == (409, "upload_request_revoked")
    assert (late.status_code, late.json()["code"]) == (409, "upload_request_expired")
    assert missing.status_code == 404
    key = Caller(
        CallerKind.API_KEY,
        tenant_id=w.tenant.id,
        user_id=w.tenant.admin,
        credential_id=uuid.uuid4(),
        scopes=frozenset({"upload_requests:write", "upload_requests:read"}),
    )
    async with member(w, key) as http:
        refused = await http.post(f"/v1/upload-requests/{expired['id']}/unlock")
    assert (refused.status_code, refused.json()["code"]) == (403, "permission_denied")


# ---- revokeUploadRequest ----


async def test_revoking_ends_the_sessions_at_once_and_answers_503_until_both_archives_hold_it(
    w: World,
) -> None:
    address = unique()
    created = await ask(w, address)
    request_id = created["id"]
    browser = await w.browser()
    token, session = await verify(w, browser, address)
    assert open_sessions(w, request_id) == 1
    store = FakeArchiveStore(fail={Region.OSAKA})
    path = f"/v1/upload-requests/{request_id}/revoke"
    async with member(w, store=store) as http:
        refused = await http.post(path)
        assert (refused.status_code, refused.json()["code"]) == (503, "service_unavailable")
        # The revocation stands: the request and its sessions ended in one transaction.
        row = request_row(w, request_id)
        assert (row["state"], row["revoked_by"]) == ("revoked", w.tenant.target)
        assert open_sessions(w, request_id) == 0
        # The uploader's next call is refused at once (NFR-6).
        gone = await browser.get("/v1/session", session["id"])
        assert (gone.status_code, gone.json()["code"]) == (410, "link_revoked")
        link = await browser.post("/v1/links/resolve", {"token": token})
        assert (link.status_code, link.json()["code"]) == (410, "link_revoked")
        store.fail.clear()
        retried = await http.post(path)
        assert retried.status_code == 200, retried.text
        body = retried.json()
    assert (body["state"], body["revoked_by"]) == ("revoked", str(w.tenant.target))
    assert body["revoked_at"] is not None
    assert store.actions(Region.OSAKA) == ["upload_request.revoked"]
    assert store.actions(Region.TOKYO) == ["upload_request.revoked"]
    assert actions(w, uuid.UUID(request_id)).count("upload_request.revoked") == 1


async def test_an_admin_without_a_passkey_revokes_and_an_expired_request_is_409(w: World) -> None:
    created, expired = await ask(w, unique()), await ask(w, unique())
    w.db.sql(
        "UPDATE upload_requests SET expires_at = now() - interval '1 second' WHERE id = :id",
        id=expired["id"],
    )
    totp = session_caller(w.tenant.id, w.tenant.admin, Role.ADMIN, AuthMethod.PASSWORD_TOTP)
    async with member(w, totp) as http:
        revoked = await http.post(f"/v1/upload-requests/{created['id']}/revoke")
        late = await http.post(f"/v1/upload-requests/{expired['id']}/revoke")
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_by"] == str(w.tenant.admin)
    assert (late.status_code, late.json()["code"]) == (409, "upload_request_expired")
    assert request_row(w, expired["id"])["state"] == "open", "the job records it, not a refusal"


# ---- expiry ----


async def test_a_request_is_expired_from_its_time_and_the_job_records_it(w: World) -> None:
    address = unique()
    created = await ask(w, address)
    request_id = created["id"]
    browser = await w.browser()
    token, session = await verify(w, browser, address)
    w.db.sql(
        "UPDATE upload_requests SET expires_at = now() - interval '1 second' WHERE id = :id",
        id=request_id,
    )
    # Before the job: the API reads expiry from expires_at.
    gone = await browser.get("/v1/session", session["id"])
    assert (gone.status_code, gone.json()["code"]) == (410, "link_expired")
    link = await browser.post("/v1/links/resolve", {"token": token})
    assert (link.status_code, link.json()["code"]) == (410, "link_expired")
    async with member(w) as http:
        assert (await http.get(f"/v1/upload-requests/{request_id}")).json()["state"] == "expired"
        listed = (await http.get("/v1/upload-requests", params={"state": "expired"})).json()
        assert [r["id"] for r in listed["items"]] == [request_id]
        assert (await http.get("/v1/upload-requests", params={"state": "open"})).json()[
            "items"
        ] == []
    assert request_row(w, request_id)["state"] == "open"
    # The job, as sft_jobs: expired, ended, its sessions closed, audited; a second run is a no-op.
    database = Database.connect(w.db.url(JOBS), pool_size=1)
    try:
        jobs = Jobs(
            database=database,
            metrics=JobMetrics.create(CollectorRegistry()),
            now=lambda: datetime.now(UTC),
        )
        # The database is shared with other tests, whose requests may be due too.
        assert await expire_upload_requests(jobs) >= 1
        assert await expire_upload_requests(jobs) == 0
    finally:
        await database.dispose()
    row = request_row(w, request_id)
    assert (row["state"], row["ended_at"] is not None) == ("expired", True)
    assert open_sessions(w, request_id) == 0
    assert actions(w, uuid.UUID(request_id))[-1] == "upload_request.expired"
    [(details,)] = w.db.sql(
        "SELECT details FROM audit_events WHERE action = 'upload_request.expired' "
        "AND target_id = :id",
        id=uuid.UUID(request_id),
    )
    assert details == {
        "system_actor": "expiry_job",
        "link_sessions_ended": 1,
        "uploads_rejected": 0,  # no upload was open (#213)
    }


# ---- createUploadRequest: refusals ----


async def test_the_expiry_is_1_hour_to_30_days_within_the_tenants_maximum(w: World) -> None:
    now = datetime.now(UTC)
    address = unique()
    async with member(w) as http:

        async def create(expires_at: datetime) -> httpx.Response:
            return await http.post(
                "/v1/upload-requests",
                json={"uploader_email": address, "expires_at": expires_at.isoformat()},
            )

        for wrong in (now + timedelta(minutes=50), now + timedelta(days=30, minutes=10)):
            response = await create(wrong)
            assert (response.status_code, response.json()["code"]) == (422, "expiry_out_of_range")
            assert response.json()["errors"][0]["pointer"] == "#/expires_at"
        # A client's clock may be a few minutes off: kept short of an hour, cut at the maximum.
        short = await create(now + timedelta(minutes=57))
        assert short.status_code == 201
        assert datetime.fromisoformat(short.json()["expires_at"]) == now + timedelta(minutes=57)
        long = await create(now + timedelta(days=30, minutes=3))
        assert long.status_code == 201
        kept = datetime.fromisoformat(long.json()["expires_at"])
        # Cut to the API's own now plus 30 days: a little after the test's now, before the ask.
        assert abs(kept - (now + timedelta(days=30))) < timedelta(minutes=1)
        assert kept < now + timedelta(days=30, minutes=3)
        # The tenant's max_expiry caps it, and the default.
        w.db.sql(
            "INSERT INTO tenant_policies (tenant_id, max_expiry, default_locale) "
            "VALUES (:t, interval '2 days', 'en') "
            "ON CONFLICT (tenant_id) DO UPDATE SET max_expiry = interval '2 days'",
            t=w.tenant.id,
        )
        over = await create(now + timedelta(days=3))
        assert (over.status_code, over.json()["code"]) == (422, "expiry_out_of_range")
        default = await http.post("/v1/upload-requests", json={"uploader_email": address})
        assert default.status_code == 201
        until = datetime.fromisoformat(default.json()["expires_at"])
        assert abs(until - (now + timedelta(days=2))) < timedelta(minutes=1)


async def test_a_suppressed_address_is_422_and_nothing_is_created(w: World) -> None:
    address = unique()
    suppress(w, address)
    async with member(w) as http:
        response = await http.post("/v1/upload-requests", json={"uploader_email": address.upper()})
    assert (response.status_code, response.json()["code"]) == (422, "recipient_undeliverable")
    assert response.json()["errors"][0]["pointer"] == "#/uploader_email"
    assert w.db.sql("SELECT 1 FROM upload_requests WHERE tenant_id = :t", t=w.tenant.id) == []


@dataclass
class EmailCapsFull(RecordingLimiter):
    """Admits the request's own limits; group G's caps are full."""

    async def check_all(self, charges: Sequence[Charge]) -> None:
        raise RateLimited(retry_after=60)


async def test_over_the_email_caps_is_429_and_nothing_is_created(w: World) -> None:
    async with member(w, limiter=EmailCapsFull()) as http:
        response = await http.post("/v1/upload-requests", json={"uploader_email": unique()})
    assert (response.status_code, response.json()["code"]) == (429, "rate_limited")
    assert response.headers["retry-after"] == "60"
    assert w.db.sql("SELECT 1 FROM upload_requests WHERE tenant_id = :t", t=w.tenant.id) == []
    assert (
        w.db.sql(
            "SELECT 1 FROM outbox WHERE tenant_id = :t AND topic = 'upload_request.link_due'",
            t=w.tenant.id,
        )
        == []
    )


async def test_an_idempotency_key_replays_the_first_answer_and_refuses_another_body(
    w: World,
) -> None:
    address = unique()
    headers = {"Idempotency-Key": f"k-{uuid.uuid4()}"}
    limiter = RecordingLimiter()
    async with member(w, limiter=limiter) as http:
        first = await http.post(
            "/v1/upload-requests", json={"uploader_email": address}, headers=headers
        )
        charged = len(limiter.checks)
        again = await http.post(
            "/v1/upload-requests", json={"uploader_email": address}, headers=headers
        )
        other = await http.post(
            "/v1/upload-requests", json={"uploader_email": unique()}, headers=headers
        )
    assert (first.status_code, again.status_code) == (201, 201)
    assert again.json()["id"] == first.json()["id"]
    assert again.headers["location"] == first.headers["location"]
    assert (other.status_code, other.json()["code"]) == (409, "idempotency_conflict")
    # The replay created, emailed and charged nothing again (group H's own check aside).
    assert len(w.db.sql("SELECT 1 FROM upload_requests WHERE tenant_id = :t", t=w.tenant.id)) == 1
    assert [ids for ids, _ in limiter.checks[charged:] if G_CALLER_EMAILS.id in ids] == []


# ---- listUploadRequests, getUploadRequest ----


async def test_members_see_their_own_requests_and_admins_the_tenants(w: World) -> None:
    mine = [await ask(w, unique()) for _ in range(3)]
    other_member = session_caller(w.tenant.id, w.tenant.member, Role.MEMBER)
    async with member(w, other_member) as http:
        theirs = await http.post("/v1/upload-requests", json={"uploader_email": unique()})
        assert theirs.status_code == 201
        assert (await http.get(f"/v1/upload-requests/{mine[0]['id']}")).status_code == 404
        own = (await http.get("/v1/upload-requests")).json()
        assert [r["id"] for r in own["items"]] == [theirs.json()["id"]]
        tenant_wide = await http.get("/v1/upload-requests", params={"scope": "tenant"})
        assert (tenant_wide.status_code, tenant_wide.json()["code"]) == (403, "permission_denied")
    async with member(w) as http:
        first = (await http.get("/v1/upload-requests", params={"limit": 2})).json()
        assert [r["id"] for r in first["items"]] == [mine[2]["id"], mine[1]["id"]]
        rest = (
            await http.get(
                "/v1/upload-requests", params={"limit": 2, "cursor": first["next_cursor"]}
            )
        ).json()
        assert ([r["id"] for r in rest["items"]], rest["next_cursor"]) == ([mine[0]["id"]], None)
        bad = await http.get("/v1/upload-requests", params={"cursor": "!!"})
        assert (bad.status_code, bad.json()["code"]) == (400, "invalid_cursor")
    admin = session_caller(w.tenant.id, w.tenant.admin, Role.ADMIN)
    async with member(w, admin) as http:
        every = (await http.get("/v1/upload-requests", params={"scope": "tenant"})).json()
        assert len(every["items"]) == 4
        assert (await http.get(f"/v1/upload-requests/{mine[0]['id']}")).status_code == 200
    totp = session_caller(w.tenant.id, w.tenant.admin, Role.ADMIN, AuthMethod.PASSWORD_TOTP)
    async with member(w, totp) as http:
        refused = await http.get("/v1/upload-requests", params={"scope": "tenant"})
    assert (refused.status_code, refused.json()["code"]) == (403, "passkey_required")


async def test_another_tenant_reaches_none_of_these_requests(w: World) -> None:
    address = unique()
    created = await ask(w, address)
    request_id = created["id"]
    other = seed_tenant(w.db)
    for caller in (
        session_caller(other.id, other.admin, Role.ADMIN),
        session_caller(other.id, other.member, Role.MEMBER),
    ):
        async with member(w, caller) as http:
            for method, path in (
                ("GET", f"/v1/upload-requests/{request_id}"),
                ("POST", f"/v1/upload-requests/{request_id}/revoke"),
                ("POST", f"/v1/upload-requests/{request_id}/unlock"),
            ):
                response = await http.request(method, path)
                assert response.status_code == 404, (method, path)
            listed = await http.get("/v1/upload-requests", params={"scope": "tenant"})
            assert request_id not in listed.text
    assert request_row(w, request_id)["state"] == "open"
    # Their token and session open nothing of ours, and ours nothing of theirs.
    browser = await w.browser()
    _, session = await verify(w, browser, address)
    stranger = await w.browser()
    assert (await stranger.get("/v1/session", session["id"])).status_code == 401
