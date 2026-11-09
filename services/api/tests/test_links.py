"""Recipients' links, verification codes and link sessions (#179; FR-14, FR-15, NFR-14; authn and
authz 4, 9.2; abuse and rate limits 9.2).

Every test runs in the link world of link_fixtures.py: the real app over ASGI against the real
database, a real Valkey for the limits (TEST_VALKEY_URL) with a clock the test moves, the
notification worker as `sft_notify` and an in-memory audit archive. A recipient's link and codes
come out of the emails the worker sent, as a person would read them.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import httpx2 as httpx
import pytest
from prometheus_client import CollectorRegistry

from api_settings import WEB_ORIGIN
from archive_fixtures import FakeArchiveStore, fake_archive
from link_fixtures import BASE, COOKIE, World, build_app, unique, w
from member_fixtures import EMAIL_KEYRING, client, seed_tenant, session_caller
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.models import Role
from sft.service.audit_archive import Region
from sft.service.rate_limits import RateLimiter

pytestmark = pytest.mark.anyio
__all__ = ["w"]  # the fixture, imported for this module's tests


def recipient_row(w: World, recipient_id: uuid.UUID) -> dict[str, Any]:
    [row] = w.db.sql(
        "SELECT failed_attempts, locked_at, first_verified_at, last_verified_at, "
        "link_token_hash FROM transfer_recipients WHERE id = :id",
        id=recipient_id,
    )
    keys = ("failed_attempts", "locked_at", "first_verified_at", "last_verified_at", "hash")
    return dict(zip(keys, row, strict=True))


# ---- resolveLink ----


async def test_a_token_reveals_only_the_kind_the_access_state_and_the_locale(w: World) -> None:
    address = unique()
    transfer_id, _ = w.transfer(address)
    token = await w.link_for(address)
    browser = await w.browser()
    response = await browser.post("/v1/links/resolve", {"token": token})
    assert response.status_code == 200
    assert response.json() == {
        "kind": "transfer",
        "access_state": "verification_required",
        "locale": "en",
    }
    assert response.headers["cache-control"] == "no-store"
    unknown = await browser.post("/v1/links/resolve", {"token": "x" * 43})
    assert (unknown.status_code, unknown.json()["code"]) == (404, "link_not_found")
    w.db.sql("UPDATE transfers SET expires_at = now() - interval '1 second' WHERE id = :id",
             id=transfer_id)  # fmt: skip
    expired = await browser.post("/v1/links/resolve", {"token": token})
    assert (expired.status_code, expired.json()["code"]) == (410, "link_expired")
    w.db.sql(
        "UPDATE transfers SET state = 'revoked', ended_at = now() WHERE id = :id", id=transfer_id
    )
    revoked = await browser.post("/v1/links/resolve", {"token": token})
    assert (revoked.status_code, revoked.json()["code"]) == (410, "link_revoked")


async def test_a_browser_with_a_live_session_is_told_its_id(w: World) -> None:
    address = unique()
    w.transfer(address)
    browser = await w.browser()
    token, session = await w.verify(browser, address)
    response = await browser.post("/v1/links/resolve", {"token": token})
    assert response.json() == {
        "kind": "transfer",
        "access_state": "verified",
        "link_session_id": session["id"],
        "locale": "en",
    }
    # Another browser has no session for the link.
    other = await w.browser()
    assert (await other.post("/v1/links/resolve", {"token": token})).json()[
        "access_state"
    ] == "verification_required"


# ---- codes ----


async def test_a_code_has_6_digits_reaches_only_the_stored_address_and_supersedes(
    w: World,
) -> None:
    address, other = unique(), unique()
    w.transfer(address, other)
    browser = await w.browser()
    token = await w.link_for(address)
    first = await w.code(browser, token, address)
    second = await w.code(browser, token, address)
    assert len(first) == len(second) == 6
    assert first.isdigit()
    assert w.sent.codes(other) == []
    assert all(e.to == address for e in w.sent.of_type("verification_code"))
    if first != second:
        old = await browser.post("/v1/links/sessions", {"token": token, "code": first})
        assert (old.status_code, old.json()["code"]) == (422, "code_invalid")
    ok = await browser.post("/v1/links/sessions", {"token": token, "code": second})
    assert ok.status_code == 201


async def test_a_code_is_refused_after_10_minutes_and_after_5_attempts(w: World) -> None:
    address = unique()
    _, [recipient_id] = w.transfer(address)
    browser = await w.browser()
    token = await w.link_for(address)
    code = await w.code(browser, token, address)
    wrong = f"{(int(code) + 1) % 10**6:06d}"
    for remaining in (4, 3, 2, 1, 0):
        response = await browser.post("/v1/links/sessions", {"token": token, "code": wrong})
        assert response.json()["code"] == "code_invalid"
        assert response.json()["attempts_remaining"] == remaining
    used_up = await browser.post("/v1/links/sessions", {"token": token, "code": code})
    assert (used_up.status_code, used_up.json()["code"]) == (422, "code_attempts_exhausted")
    code = await w.code(browser, token, address)
    w.db.sql(
        "UPDATE verification_codes SET created_at = created_at - interval '11 minutes', "
        "expires_at = expires_at - interval '11 minutes' WHERE recipient_id = :id",
        id=recipient_id,
    )
    late = await browser.post("/v1/links/sessions", {"token": token, "code": code})
    assert (late.status_code, late.json()["code"]) == (422, "code_expired")


async def test_a_suppressed_address_gets_422_and_no_email(w: World) -> None:
    address = unique()
    _, [recipient_id] = w.transfer(address)
    token = await w.link_for(address)
    w.db.sql(
        "INSERT INTO email_suppressions (id, tenant_id, email_hmac, hmac_key_id, reason) "
        "VALUES (:id, :tenant, :hmac, :key, 'complaint')",
        id=uuid.uuid4(),
        tenant=w.tenant.id,
        hmac=EMAIL_KEYRING.active(address.lower()),
        key=EMAIL_KEYRING.active_key_id,
    )
    browser = await w.browser()
    response = await browser.post("/v1/links/codes", {"token": token})
    assert (response.status_code, response.json()["code"]) == (422, "recipient_undeliverable")
    await w.links()
    assert w.sent.codes(address) == []
    assert not w.db.sql(
        "SELECT 1 FROM outbox WHERE topic = 'recipient.code_requested' "
        "AND payload->>'recipient_id' = :id",
        id=str(recipient_id),
    )


async def test_a_code_under_a_key_the_api_lacks_adds_no_failure(w: World) -> None:
    address = unique()
    _, [recipient_id] = w.transfer(address)
    browser = await w.browser()
    token = await w.link_for(address)
    code = await w.code(browser, token, address)
    # The code's key has left the API's keyring (a rotation): it can't be checked.
    w.db.sql(
        "UPDATE verification_codes SET hmac_key_id = 'retired' WHERE recipient_id = :id",
        id=recipient_id,
    )
    response = await browser.post("/v1/links/sessions", {"token": token, "code": code})
    assert (response.status_code, response.json()["code"]) == (422, "code_expired")
    assert recipient_row(w, recipient_id)["failed_attempts"] == 0
    assert (
        w.registry.get_sample_value("verification_attempts_total", {"result": "unknown_key"}) == 1
    )
    [(reason,)] = w.db.sql(
        "SELECT details->>'reason' FROM audit_events WHERE action = 'verification.attempted' "
        "AND target_id = :id",
        id=recipient_id,
    )
    assert reason == "unknown_key"


async def test_a_recipients_code_opens_no_other_recipients_link(w: World) -> None:
    mine, theirs = unique(), unique()
    w.transfer(mine, theirs)
    browser = await w.browser()
    my_token = await w.link_for(mine)
    their_token = w.sent.links(theirs)[-1]
    code = await w.code(browser, my_token, mine)
    response = await browser.post("/v1/links/sessions", {"token": their_token, "code": code})
    assert (response.status_code, response.json()["code"]) == (422, "code_expired")


# ---- attempts and the lockout ----


async def test_20_parallel_wrong_codes_count_exactly_5(w: World) -> None:
    address = unique()
    _, [recipient_id] = w.transfer(address)
    browser = await w.browser()
    token = await w.link_for(address)
    code = await w.code(browser, token, address)
    wrong = f"{(int(code) + 1) % 10**6:06d}"
    responses = await asyncio.gather(
        *(browser.post("/v1/links/sessions", {"token": token, "code": wrong}) for _ in range(20))
    )
    codes = sorted(r.json()["code"] for r in responses)
    assert codes.count("code_invalid") == 5
    assert codes.count("code_attempts_exhausted") == 15
    assert recipient_row(w, recipient_id)["failed_attempts"] == 5
    [(attempts,)] = w.db.sql(
        "SELECT attempts FROM verification_codes WHERE recipient_id = :id", id=recipient_id
    )
    assert attempts == 5


async def test_the_20th_failure_locks_the_recipient_archives_it_and_tells_the_people(
    w: World,
) -> None:
    address = unique()
    transfer_id, [recipient_id] = w.transfer(address)
    browser = await w.browser()
    token = await w.link_for(address)
    statuses = []
    for _ in range(4):
        code = await w.code(browser, token, address)
        wrong = f"{(int(code) + 1) % 10**6:06d}"
        for _ in range(5):
            response = await browser.post("/v1/links/sessions", {"token": token, "code": wrong})
            statuses.append((response.status_code, response.json()["code"]))
    assert statuses[:19] == [(422, "code_invalid")] * 19
    assert statuses[19] == (403, "recipient_locked")
    row = recipient_row(w, recipient_id)
    assert row["failed_attempts"] == 20
    assert row["locked_at"] is not None
    for region in Region:
        assert w.store.actions(region) == ["recipient.locked"]
    assert w.registry.get_sample_value("recipient_lockouts_total") == 1
    # The next attempt is refused before any code is checked, and a code request sends nothing.
    code_rows = w.db.sql(
        "SELECT id, attempts FROM verification_codes WHERE recipient_id = :id", id=recipient_id
    )
    next_try = await browser.post("/v1/links/sessions", {"token": token, "code": "000000"})
    assert (next_try.status_code, next_try.json()["code"]) == (403, "recipient_locked")
    assert (
        w.db.sql(
            "SELECT id, attempts FROM verification_codes WHERE recipient_id = :id", id=recipient_id
        )
        == code_rows
    )
    # The lockout's record is confirmed: more attempts on the locked recipient write nothing.
    writes = w.store.writes
    for _ in range(5):
        again = await browser.post("/v1/links/sessions", {"token": token, "code": "000000"})
        assert (again.status_code, again.json()["code"]) == (403, "recipient_locked")
    assert w.store.writes == writes
    w.clock.advance(31)
    refused = await browser.post("/v1/links/codes", {"token": token})
    assert (refused.status_code, refused.json()["code"]) == (403, "recipient_locked")
    codes_before = len(w.sent.of_type("verification_code"))
    await w.links()
    assert len(w.sent.of_type("verification_code")) == codes_before
    # The owner and the tenant's admins are emailed.
    locked = {e.to for e in w.sent.of_type("recipient_locked")}
    expected = {
        str(e)
        for (e,) in w.db.sql(
            "SELECT email FROM users WHERE id IN (:a, :b)", a=w.tenant.target, b=w.tenant.admin
        )
    }
    assert locked == expected
    resolved = await browser.post("/v1/links/resolve", {"token": token})
    assert resolved.json()["access_state"] == "locked"
    # The member sees it, and unlocks: a new link, and the old one is 404.
    owner = session_caller(w.tenant.id, w.tenant.target, Role.MEMBER)
    async with client(w.db, lambda: owner, archive=fake_archive(w.store)) as member:
        listed = await member.get(f"/v1/transfers/{transfer_id}/recipients")
        [status] = listed.json()["items"]
        assert (status["access_state"], status["failed_attempts"]) == ("locked", 20)
        unlocked = await member.post(
            f"/v1/transfers/{transfer_id}/recipients/{recipient_id}/unlock"
        )
        assert unlocked.status_code == 200, unlocked.text
        body = unlocked.json()
        assert (body["access_state"], body["failed_attempts"], body["delivery_state"]) == (
            "invited",
            0,
            "queued",
        )
        assert body["locked_at"] is None
        assert body["notified_at"] is None
        # A retry finds it unlocked: the same status, nothing new sent.
        again = await member.post(f"/v1/transfers/{transfer_id}/recipients/{recipient_id}/unlock")
        assert again.status_code == 200
    for region in Region:
        assert w.store.actions(region) == ["recipient.locked", "recipient.unlocked"]
    old = await browser.post("/v1/links/resolve", {"token": token})
    assert (old.status_code, old.json()["code"]) == (404, "link_not_found")
    new = await w.link_for(address)
    assert new != token
    assert (await browser.post("/v1/links/resolve", {"token": new})).status_code == 200
    assert len(w.sent.links(address)) == 2, "one new link email, however often it was unlocked"


async def test_an_unlock_whose_record_cant_be_confirmed_answers_503_and_stands(
    w: World,
) -> None:
    address = unique()
    transfer_id, [recipient_id] = w.transfer(address)
    w.db.sql(
        "UPDATE transfer_recipients SET failed_attempts = 20, locked_at = now() WHERE id = :id",
        id=recipient_id,
    )
    store = FakeArchiveStore(fail={Region.OSAKA})
    owner = session_caller(w.tenant.id, w.tenant.target, Role.MEMBER)
    path = f"/v1/transfers/{transfer_id}/recipients/{recipient_id}/unlock"
    async with client(w.db, lambda: owner, archive=fake_archive(store)) as member:
        refused = await member.post(path)
        assert (refused.status_code, refused.json()["code"]) == (503, "service_unavailable")
        assert recipient_row(w, recipient_id)["locked_at"] is None
        store.fail.clear()
        assert (await member.post(path)).status_code == 200
    assert store.actions(Region.OSAKA) == ["recipient.unlocked"]


async def test_an_ended_transfer_cant_be_unlocked(w: World) -> None:
    transfer_id, [recipient_id] = w.transfer(unique())
    w.db.sql(
        "UPDATE transfers SET state = 'revoked', ended_at = now() WHERE id = :id", id=transfer_id
    )
    owner = session_caller(w.tenant.id, w.tenant.target, Role.MEMBER)
    async with client(w.db, lambda: owner) as member:
        response = await member.post(
            f"/v1/transfers/{transfer_id}/recipients/{recipient_id}/unlock"
        )
        missing = await member.post(f"/v1/transfers/{transfer_id}/recipients/{uuid.uuid4()}/unlock")
    assert (response.status_code, response.json()["code"]) == (409, "transfer_revoked")
    assert missing.status_code == 404


# ---- the limits ----


async def test_the_21st_code_on_one_link_in_a_day_is_429_and_another_tenants_link_still_gets_one(
    w: World,
) -> None:
    address = unique()
    w.transfer(address)
    other = seed_tenant(w.db)
    w.transfer(address, tenant=other)
    browser = await w.browser()
    token = await w.link_for(address)
    for _ in range(20):
        w.clock.advance(13 * 60)  # under the address's 5 an hour
        assert (await browser.post("/v1/links/codes", {"token": token})).status_code == 202
    w.clock.advance(13 * 60)
    refused = await browser.post("/v1/links/codes", {"token": token})
    assert (refused.status_code, refused.json()["code"]) == (429, "rate_limited")
    assert int(refused.headers["retry-after"]) >= 1
    their_token = await w.link_for(address, other)
    w.clock.advance(13 * 60)
    assert (await browser.post("/v1/links/codes", {"token": their_token})).status_code == 202


async def test_the_6th_code_to_one_address_in_an_hour_is_429(w: World) -> None:
    address = unique()
    w.transfer(address)
    other = seed_tenant(w.db)
    w.transfer(address, tenant=other)
    browser = await w.browser()
    mine, theirs = await w.link_for(address), await w.link_for(address, other)
    for token in (mine, theirs, mine, theirs, mine):
        w.clock.advance(31)
        assert (await browser.post("/v1/links/codes", {"token": token})).status_code == 202
    w.clock.advance(31)
    sixth = await browser.post("/v1/links/codes", {"token": theirs})
    assert (sixth.status_code, sixth.json()["code"]) == (429, "rate_limited")


async def test_with_the_counter_store_down_the_link_steps_answer_503(w: World) -> None:
    address = unique()
    w.transfer(address)
    token = await w.link_for(address)
    down = CounterStore.connect(
        "redis://u:p@127.0.0.1:1/0", CounterMetrics.create(CollectorRegistry())
    )
    limiter = RateLimiter(down, CounterMetrics.create(CollectorRegistry()))
    app, _ = build_app(w.db, w.api, limiter, w.store)
    transport = httpx.ASGITransport(app=app)
    try:
        async with httpx.AsyncClient(transport=transport, base_url=BASE) as http:
            for path, body in (
                ("/v1/links/resolve", {"token": token}),
                ("/v1/links/codes", {"token": token}),
                ("/v1/links/sessions", {"token": token, "code": "123456"}),
            ):
                response = await http.post(path, json=body)
                assert (response.status_code, response.json()["code"]) == (
                    503,
                    "service_unavailable",
                ), path
                assert response.headers["retry-after"] == "5"
    finally:
        await down.close()


async def test_20_unknown_tokens_an_hour_block_the_ip(w: World) -> None:
    browser = await w.browser()
    for _ in range(20):
        response = await browser.post("/v1/links/resolve", {"token": uuid.uuid4().hex * 2})
        assert response.status_code == 404
    blocked = await browser.post("/v1/links/resolve", {"token": uuid.uuid4().hex * 2})
    assert blocked.status_code == 429


# ---- link sessions ----


async def test_a_session_shows_the_transfer_and_its_shareable_files_only(w: World) -> None:
    address = unique()
    transfer_id, [recipient_id] = w.transfer(
        address, files=("clean", "unscannable", "infected", "scanning")
    )
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    assert session["kind"] == "transfer"
    assert session["email"] == address
    assert session["transfer"]["message"] == "hello"
    assert session["transfer"]["tenant_name"] == "T"
    assert "upload_request" not in session
    headers = browser.headers(session["id"])
    got = await browser.http.get("/v1/session", headers=headers)
    assert got.status_code == 200
    assert got.headers["cache-control"] == "no-store"
    assert got.json()["csrf_token"] == session["csrf_token"]
    files = await browser.http.get("/v1/session/files", headers=headers)
    items = files.json()["items"]
    assert sorted(i["state"] for i in items) == ["clean", "unscannable"]
    for item in items:
        assert item["download_limit"] is None
        assert item["downloads_used"] == 0
        assert ("warning" in item) == (item["state"] == "unscannable")
        assert "upload" not in item
    row = recipient_row(w, recipient_id)
    assert row["first_verified_at"] is not None
    assert row["last_verified_at"] is not None
    owner = session_caller(w.tenant.id, w.tenant.target, Role.MEMBER)
    async with client(w.db, lambda: owner) as member:
        listed = await member.get(f"/v1/transfers/{transfer_id}/recipients")
    [status] = listed.json()["items"]
    assert (status["access_state"], status["delivery_state"]) == ("verified", "sent")


async def test_x_link_session_picks_the_session_and_401s_otherwise(w: World) -> None:
    address = unique()
    w.transfer(address)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    for headers in (
        browser.headers(),  # no X-Link-Session
        browser.headers(uuid.uuid4()),  # one this browser doesn't hold
        browser.headers("not-a-uuid"),
        {"x-link-session": session["id"]},  # no cookie
    ):
        browser.http.cookies.clear()
        response = await browser.http.get("/v1/session", headers=headers)
        assert (response.status_code, response.json()["code"]) == (
            401,
            "authentication_required",
        )
    bearer = await browser.http.get(
        "/v1/session", headers={**browser.headers(session["id"]), "authorization": "Bearer x"}
    )
    assert bearer.status_code == 401


async def test_verifying_a_second_link_keeps_the_first_and_an_11th_ends_the_oldest(
    w: World,
) -> None:
    addresses = [unique() for _ in range(11)]
    w.transfer(*addresses)
    browser = await w.browser()
    sessions = []
    for address in addresses[:2]:
        _, session = await w.verify(browser, address)
        sessions.append(session)
    for session in sessions:
        ok = await browser.http.get("/v1/session", headers=browser.headers(session["id"]))
        assert ok.status_code == 200
        assert ok.json()["email"] in addresses
    for address in addresses[2:]:
        _, session = await w.verify(browser, address)
        sessions.append(session)
    assert browser.cookie is not None
    assert len(browser.cookie.split(".")) == 10
    oldest = await browser.http.get("/v1/session", headers=browser.headers(sessions[0]["id"]))
    assert oldest.status_code == 401
    newest = await browser.http.get("/v1/session", headers=browser.headers(sessions[-1]["id"]))
    assert newest.status_code == 200
    [(ended,)] = w.db.sql(
        "SELECT details->>'reason' FROM audit_events WHERE action = 'link_session.ended' "
        "AND target_id = :id",
        id=uuid.UUID(sessions[0]["id"]),
    )
    assert ended == "session_limit"


async def test_verifying_again_replaces_the_browsers_session_for_that_recipient(
    w: World,
) -> None:
    address = unique()
    w.transfer(address)
    browser = await w.browser()
    _, first = await w.verify(browser, address)
    _, second = await w.verify(browser, address)
    assert first["id"] != second["id"]
    assert first["csrf_token"] != second["csrf_token"]
    assert browser.cookie is not None
    assert "." not in browser.cookie
    old = await browser.http.get("/v1/session", headers=browser.headers(first["id"]))
    assert old.status_code == 401


async def test_a_session_ends_after_an_hour_idle_and_after_24_hours(w: World) -> None:
    first, second = unique(), unique()
    w.transfer(first, second)
    browser = await w.browser()
    _, idle = await w.verify(browser, first)
    _, old = await w.verify(browser, second)
    w.db.sql(
        "UPDATE link_sessions SET last_seen_at = now() - interval '61 minutes' WHERE id = :id",
        id=uuid.UUID(idle["id"]),
    )
    w.db.sql(
        "UPDATE link_sessions SET created_at = now() - interval '25 hours', "
        "last_seen_at = now(), expires_at = now() - interval '1 hour' WHERE id = :id",
        id=uuid.UUID(old["id"]),
    )
    for session in (idle, old):
        response = await browser.http.get("/v1/session", headers=browser.headers(session["id"]))
        assert (response.status_code, response.json()["code"]) == (401, "session_expired")


async def test_ending_a_session_needs_its_csrf_token_and_keeps_the_others(w: World) -> None:
    first, second = unique(), unique()
    w.transfer(first, second)
    browser = await w.browser()
    _, one = await w.verify(browser, first)
    _, two = await w.verify(browser, second)
    no_token = await browser.http.delete(
        "/v1/session", headers=browser.headers(one["id"], origin=WEB_ORIGIN)
    )
    assert (no_token.status_code, no_token.json()["code"]) == (403, "csrf_failed")
    # Another session's token is no good either (authn and authz 9.2, CSRF).
    wrong = await browser.http.delete(
        "/v1/session",
        headers=browser.headers(
            one["id"], origin=WEB_ORIGIN, **{"x-csrf-token": two["csrf_token"]}
        ),
    )
    assert wrong.status_code == 403
    foreign = await browser.http.delete(
        "/v1/session",
        headers=browser.headers(
            one["id"], origin="https://evil.example", **{"x-csrf-token": one["csrf_token"]}
        ),
    )
    assert foreign.status_code == 403
    ended = await browser.http.delete(
        "/v1/session",
        headers=browser.headers(
            one["id"], origin=WEB_ORIGIN, **{"x-csrf-token": one["csrf_token"]}
        ),
    )
    assert ended.status_code == 204
    browser.keep(ended)
    assert (
        await browser.http.get("/v1/session", headers=browser.headers(one["id"]))
    ).status_code == 401
    assert (
        await browser.http.get("/v1/session", headers=browser.headers(two["id"]))
    ).status_code == 200
    last = await browser.http.delete(
        "/v1/session",
        headers=browser.headers(
            two["id"], origin=WEB_ORIGIN, **{"x-csrf-token": two["csrf_token"]}
        ),
    )
    assert last.status_code == 204
    assert "Max-Age=0" in last.headers["set-cookie"] or "max-age=0" in last.headers["set-cookie"]


async def test_the_link_cookie_is_host_only_secure_http_only_and_strict(w: World) -> None:
    address = unique()
    w.transfer(address)
    browser = await w.browser()
    token = await w.link_for(address)
    code = await w.code(browser, token, address)
    response = await browser.http.post("/v1/links/sessions", json={"token": token, "code": code})
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    attributes = {part.strip().split("=")[0].lower() for part in cookie.split(";")[1:]}
    assert {"httponly", "secure", "path", "samesite"} <= attributes
    assert "domain" not in attributes
    assert "max-age" not in attributes
    assert "samesite=strict" in cookie.lower()
    assert response.headers["cache-control"] == "no-store"


# ---- every attempt is audited ----


async def test_every_attempt_is_audited_with_the_source_ip_and_user_agent(w: World) -> None:
    address = unique()
    _, [recipient_id] = w.transfer(address)
    browser = await w.browser()
    token = await w.link_for(address)
    code = await w.code(browser, token, address)
    agent = {"user-agent": "test-browser/1.0"}
    for attempt in (f"{(int(code) + 1) % 10**6:06d}", code):
        await browser.http.post(
            "/v1/links/sessions",
            json={"token": token, "code": attempt},
            headers={**browser.headers(), **agent},
        )
    rows = w.db.sql(
        "SELECT outcome, actor_type, host(source_ip), user_agent FROM audit_events "
        "WHERE action = 'verification.attempted' AND target_id = :id ORDER BY occurred_at, id",
        id=recipient_id,
    )
    assert rows == [
        ("failure", "recipient", "127.0.0.1", "test-browser/1.0"),
        ("success", "recipient", "127.0.0.1", "test-browser/1.0"),
    ]
    requested = w.db.sql(
        "SELECT outcome FROM audit_events WHERE action = 'verification.code_requested' "
        "AND target_id = :id",
        id=recipient_id,
    )
    assert requested == [("success",)]


# ---- callers and isolation (authn and authz 9.2) ----


async def test_the_session_routes_refuse_every_caller_but_a_link_session(w: World) -> None:
    browser = await w.browser()
    member_cookie = {
        "cookie": "__Host-sft_session=" + "a" * 43,
        "x-link-session": str(uuid.uuid4()),
    }
    for headers in (
        {},  # no credential
        member_cookie,  # a member's session
        {"authorization": "Bearer sft_dev_x", "x-link-session": str(uuid.uuid4())},  # a key
    ):
        for method, path in (("GET", "/v1/session"), ("GET", "/v1/session/files"),
                             ("DELETE", "/v1/session")):  # fmt: skip
            response = await browser.http.request(method, path, headers=headers)
            assert response.status_code == 401, (headers, path)


async def test_another_tenants_token_and_session_reach_nothing_here(w: World) -> None:
    mine, theirs = unique(), unique()
    my_transfer, _ = w.transfer(mine)
    other = seed_tenant(w.db)
    their_transfer, _ = w.transfer(theirs, tenant=other)
    browser = await w.browser()
    _, my_session = await w.verify(browser, mine)
    _, their_session = await w.verify(browser, theirs, other)
    # One browser holds both; each session sees its own transfer's files only.
    mine_files = await browser.http.get(
        "/v1/session/files", headers=browser.headers(my_session["id"])
    )
    their_files = await browser.http.get(
        "/v1/session/files", headers=browser.headers(their_session["id"])
    )
    my_ids = {i["id"] for i in mine_files.json()["items"]}
    their_ids = {i["id"] for i in their_files.json()["items"]}
    assert my_ids
    assert their_ids
    assert not my_ids & their_ids
    assert str(their_transfer) not in mine_files.text
    # A session of another browser can't be picked with this one's cookie.
    other_browser = await w.browser()
    stolen = await other_browser.http.get(
        "/v1/session", headers=other_browser.headers(my_session["id"])
    )
    assert stolen.status_code == 401
    # A member of this tenant never sees the other tenant's recipients.
    owner = session_caller(w.tenant.id, w.tenant.target, Role.MEMBER)
    async with client(w.db, lambda: owner) as member:
        assert (await member.get(f"/v1/transfers/{their_transfer}/recipients")).status_code == 404
        assert (await member.get(f"/v1/transfers/{my_transfer}/recipients")).status_code == 200


async def test_another_recipients_session_isnt_picked_from_this_cookie(w: World) -> None:
    first, second = unique(), unique()
    w.transfer(first, second)
    alice, bob = await w.browser(), await w.browser()
    _, alices = await w.verify(alice, first)
    _, bobs = await w.verify(bob, second)
    response = await alice.http.get("/v1/session", headers=alice.headers(bobs["id"]))
    assert response.status_code == 401
    assert (
        await alice.http.get("/v1/session", headers=alice.headers(alices["id"]))
    ).status_code == 200


async def test_a_revoked_transfers_session_gets_410(w: World) -> None:
    address = unique()
    transfer_id, _ = w.transfer(address)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    w.db.sql(
        "UPDATE transfers SET state = 'revoked', ended_at = now() WHERE id = :id", id=transfer_id
    )
    response = await browser.http.get("/v1/session", headers=browser.headers(session["id"]))
    assert (response.status_code, response.json()["code"]) == (410, "link_revoked")


async def test_the_link_metrics_count_each_result(w: World) -> None:
    address = unique()
    w.transfer(address)
    browser = await w.browser()
    await w.verify(browser, address)
    await browser.post("/v1/links/resolve", {"token": "y" * 43})
    sample = w.registry.get_sample_value
    assert sample("link_lookups_total", {"result": "found"}) == 2
    assert sample("link_lookups_total", {"result": "not_found"}) == 1
    assert sample("verification_codes_total", {"result": "requested"}) == 1
    assert sample("verification_attempts_total", {"result": "match"}) == 1


async def test_link_page_requests_past_60_a_minute_from_one_ip_get_429(w: World) -> None:
    """NFR-14: at most 60 link-page requests per IP a minute (abuse 2.2 A, `A.ip_requests`). GCRA
    admits 31 at once, then one every 2 s, so no minute holds more than 60 (#235)."""
    address = unique()
    w.transfer(address)
    token = await w.link_for(address)
    browser = await w.browser()
    answers = [
        (await browser.post("/v1/links/resolve", {"token": token})).status_code for _ in range(32)
    ]
    assert answers == [200] * 31 + [429]
    refused = await browser.post("/v1/links/resolve", {"token": token})
    assert refused.json()["code"] == "rate_limited"
    assert int(refused.headers["retry-after"]) >= 1
    w.clock.advance(60)  # a minute on: the window rolled over
    assert (await browser.post("/v1/links/resolve", {"token": token})).status_code == 200
