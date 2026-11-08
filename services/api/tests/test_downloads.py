"""Download grants, streamed content and revocation (#180; FR-4, FR-6, FR-14, FR-20, NFR-6, NFR-10;
abuse and rate limits 5, 9.2; data model 2.3).

The tests run in the link world of link_fixtures.py: the real app over ASGI, the real database,
a real Valkey for the limits, an in-memory audit archive and in-memory file contents, with a
stream re-check of 0.2 s so "stops within two intervals" is quick to show. Recipients verify as a
person would, from the emails the notification worker sent. The ASGI client reads a whole
response, so the tests that watch a stream while it runs drive `sft.service.downloads` directly.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2 as httpx
import pytest

from api_settings import WEB_ORIGIN
from archive_fixtures import fake_archive
from link_fixtures import Browser, World, unique, w
from member_fixtures import RecordingLimiter, Tenant, client, seed_tenant, session_caller
from sft.core.errors import Forbidden, RateLimited, ServiceUnavailable
from sft.data.audit import Origin
from sft.data.models import Role
from sft.service import downloads
from sft.service.audit_archive import Region
from sft.service.downloads import Ended, parse_range
from sft.service.links import cookie_tokens
from sft.service.links import session_caller as link_caller
from sft.service.rate_limits import Charge
from sft.service.rate_limits.downloads import D_SUBJECT_BYTES, D_TENANT_BYTES
from sft.service.rate_limits.limits import KeyType
from sft.service.revocation import revoke_transfer
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio
__all__ = ["w"]  # the fixture, imported for this module's tests

SIZE = 300_000


def shared(
    w: World,
    *addresses: str,
    size: int = SIZE,
    limit: int | None = None,
    tenant: Tenant | None = None,
    files: int = 1,
    state: str = "clean",
) -> tuple[uuid.UUID, list[uuid.UUID], list[uuid.UUID], list[bytes]]:
    """A sent transfer to `addresses` with `files` shareable files of `size` random bytes, their
    SHA-256 recorded as the scan worker records it, and each recipient's counters."""
    owner = tenant or w.tenant
    transfer_id, recipient_ids = seed_transfer(
        w.db, owner.id, owner.target, state="sent", recipients=addresses, download_limit=limit
    )
    w.db.sql("UPDATE transfers SET sent_at = now() WHERE id = :id", id=transfer_id)
    w.db.sql(
        "UPDATE transfer_recipients SET delivery_state = 'queued' WHERE transfer_id = :id",
        id=transfer_id,
    )
    w.db.sql(
        "INSERT INTO outbox (id, tenant_id, topic, payload) VALUES (:id, :tenant, "
        "'transfer.sent', jsonb_build_object('transfer_id', CAST(:transfer AS text)))",
        id=uuid.uuid4(),
        tenant=owner.id,
        transfer=str(transfer_id),
    )
    file_ids, contents = [], []
    for _ in range(files):
        data = os.urandom(min(size, 2_000_000))
        storage_class = "large" if size > 2_000_000_000 else "standard"
        file_id = seed_file(
            w.db,
            owner.id,
            transfer_id,
            state=state,
            size=size,
            storage_class=storage_class,
            unscannable_allowed=state == "unscannable",
        )
        w.db.sql(
            "UPDATE files SET sha256 = :digest WHERE id = :id",
            digest=hashlib.sha256(data).digest(),
            id=file_id,
        )
        w.content.put(f"tenants/{owner.id}/files/{file_id}", "version-1", data)
        for recipient_id in recipient_ids:
            w.db.sql(
                "INSERT INTO download_counters (tenant_id, recipient_id, file_id, download_limit) "
                "VALUES (:t, :r, :f, :limit)",
                t=owner.id,
                r=recipient_id,
                f=file_id,
                limit=limit,
            )
        file_ids.append(file_id)
        contents.append(data)
    return transfer_id, recipient_ids, file_ids, contents


async def grant(
    browser: Browser,
    session: dict[str, Any],
    file_id: uuid.UUID,
    body: dict[str, Any] | None = None,
) -> httpx.Response:
    headers = browser.headers(
        session["id"], origin=WEB_ORIGIN, **{"x-csrf-token": session["csrf_token"]}
    )
    return await browser.http.post(
        f"/v1/session/files/{file_id}/downloads", json=body or {}, headers=headers
    )


async def content(browser: Browser, url: str, **headers: str) -> httpx.Response:
    return await browser.http.get(url, headers=browser.headers(None, **headers))


def count(w: World, recipient_id: uuid.UUID, file_id: uuid.UUID) -> int:
    [(value,)] = w.db.sql(
        "SELECT count FROM download_counters WHERE recipient_id = :r AND file_id = :f",
        r=recipient_id,
        f=file_id,
    )
    return int(str(value))


def grant_row(w: World, grant_id: object) -> dict[str, Any]:
    [row] = w.db.sql(
        "SELECT bytes_served, request_count, archived_at, active_stream_id FROM download_grants "
        "WHERE id = :id",
        id=uuid.UUID(str(grant_id)),
    )
    return dict(zip(("bytes", "requests", "archived_at", "stream"), row, strict=True))


def actions(w: World, target: uuid.UUID) -> list[object]:
    return [
        a
        for (a,) in w.db.sql(
            "SELECT action FROM audit_events WHERE target_id = :id ORDER BY occurred_at, id",
            id=target,
        )
    ]


def owner_of(w: World, tenant: Tenant | None = None) -> Any:
    owner = tenant or w.tenant
    return session_caller(owner.id, owner.target, Role.MEMBER)


async def revoke(w: World, transfer_id: uuid.UUID) -> None:
    await revoke_transfer(
        w.api,
        w.downloads.archive,
        owner_of(w),
        transfer_id,
        origin=Origin(),
        now=datetime.now(UTC),
    )


# ---- grants ----


async def test_a_grant_counts_once_and_its_content_streams_with_the_security_headers(
    w: World,
) -> None:
    address = unique()
    _, [recipient], [file_id], [data] = shared(w, address, limit=3)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    response = await grant(browser, session, file_id)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["method"] == "stream"
    assert body["url"] == f"/v1/session/downloads/{body['grant_id']}/content"
    assert body["byte_budget"] == 3 * SIZE
    assert body["request_limit"] == 20
    assert body["downloads_remaining"] == 2
    assert body["file"]["size"] == SIZE
    assert body["file"]["sha256"] == hashlib.sha256(data).hexdigest()
    assert "warning" not in body
    assert response.headers["cache-control"] == "no-store"
    assert count(w, recipient, file_id) == 1

    got = await content(browser, body["url"])
    assert got.status_code == 200
    assert got.content == data
    headers = got.headers
    assert headers["content-type"] == "application/octet-stream"
    assert headers["etag"] == f'"{hashlib.sha256(data).hexdigest()}"'
    assert headers["accept-ranges"] == "bytes"
    assert headers["content-disposition"] == "attachment; filename*=UTF-8''a"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["content-security-policy"] == "sandbox; default-src 'none'"
    assert headers["cache-control"] == "no-store"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["content-length"] == str(SIZE)
    assert count(w, recipient, file_id) == 1, "content requests count nothing"

    await w.downloads.archive.drain()
    row = grant_row(w, body["grant_id"])
    assert row["bytes"] == SIZE
    assert row["requests"] == 1
    assert row["archived_at"] is not None
    assert row["stream"] is None, "the lease ends with the stream"
    for region in Region:
        assert w.store.actions(region) == ["download.grant_committed", "download.grant_intent"]
    assert actions(w, file_id) == ["download.granted", "download.completed"]
    [(critical,)] = w.db.sql(
        "SELECT security_critical FROM audit_events WHERE action = 'download.granted' "
        "AND target_id = :f",
        f=file_id,
    )
    assert critical is True


async def test_50_parallel_grants_at_limit_1_give_exactly_one(w: World) -> None:
    address = unique()
    _, [recipient], [file_id], _ = shared(w, address, limit=1)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    responses = await asyncio.gather(*(grant(browser, session, file_id) for _ in range(50)))
    # Exactly one grant. The other 49 are refused: by the download limit (403) or, when the
    # counter store is up, by group D's grant rate first (429). Both are right for a burst of 50.
    assert [r.status_code for r in responses].count(200) == 1
    refused = {(r.status_code, r.json()["code"]) for r in responses if r.status_code != 200}
    assert refused <= {(403, "download_limit_reached"), (429, "rate_limited")}, refused
    assert count(w, recipient, file_id) == 1
    assert w.db.sql("SELECT count(*) FROM download_grants WHERE file_id = :f", f=file_id) == [(1,)]


async def test_a_failed_intent_write_gives_503_and_counts_nothing(w: World) -> None:
    address = unique()
    _, [recipient], [file_id], _ = shared(w, address, limit=1)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    w.store.fail = {Region.OSAKA}
    refused = await grant(browser, session, file_id)
    assert refused.status_code == 503, refused.text
    assert refused.headers["retry-after"] == "5"
    assert count(w, recipient, file_id) == 0
    assert w.db.sql("SELECT count(*) FROM download_grants WHERE file_id = :f", f=file_id) == [(0,)]
    w.store.fail = set()
    assert (await grant(browser, session, file_id)).status_code == 200
    assert count(w, recipient, file_id) == 1


async def test_an_interrupted_download_resumes_with_range_and_is_not_counted_again(
    w: World,
) -> None:
    address = unique()
    _, [recipient], [file_id], [data] = shared(w, address, limit=1)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    body = (await grant(browser, session, file_id)).json()
    half = SIZE // 2
    first = await content(browser, body["url"], range=f"bytes=0-{half - 1}")
    assert first.status_code == 206
    assert first.headers["content-range"] == f"bytes 0-{half - 1}/{SIZE}"
    etag = first.headers["etag"]
    rest = await content(browser, body["url"], range=f"bytes={half}-", **{"if-range": etag})
    assert rest.status_code == 206
    assert rest.headers["content-range"] == f"bytes {half}-{SIZE - 1}/{SIZE}"
    joined = first.content + rest.content
    assert hashlib.sha256(joined).hexdigest() == hashlib.sha256(data).hexdigest()
    assert count(w, recipient, file_id) == 1
    # After a reload, the same grant comes back, uncounted.
    again = await grant(browser, session, file_id, {"resume_grant_id": body["grant_id"]})
    assert again.status_code == 200, again.text
    assert again.json()["grant_id"] == body["grant_id"]
    assert count(w, recipient, file_id) == 1
    # A changed validator gets the whole file.
    whole = await content(browser, body["url"], range="bytes=10-", **{"if-range": '"other"'})
    assert (whole.status_code, whole.content) == (200, data)
    # A new grant, without resume_grant_id, is a new download: at limit 1, refused.
    refused = await grant(browser, session, file_id)
    assert (refused.status_code, refused.json()["code"]) == (403, "download_limit_reached")


async def test_a_grant_is_used_up_by_3_times_its_size_or_20_requests(w: World) -> None:
    address = unique()
    _, _, [by_bytes, by_requests], _ = shared(w, address, size=1000, files=2)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    body = (await grant(browser, session, by_bytes)).json()
    for _ in range(3):
        assert (await content(browser, body["url"])).status_code == 200
    spent = await content(browser, body["url"])
    assert (spent.status_code, spent.json()["code"]) == (403, "download_grant_exhausted")
    resumed = await grant(browser, session, by_bytes, {"resume_grant_id": body["grant_id"]})
    assert (resumed.status_code, resumed.json()["code"]) == (403, "download_grant_exhausted")

    body = (await grant(browser, session, by_requests)).json()
    for _ in range(20):
        assert (await content(browser, body["url"], range="bytes=0-0")).status_code == 206
    over = await content(browser, body["url"], range="bytes=0-0")
    assert (over.status_code, over.json()["code"]) == (403, "download_grant_exhausted")
    # Another file's grant, or another session's, can't be resumed here: 404.
    other = await grant(browser, session, by_bytes, {"resume_grant_id": body["grant_id"]})
    assert other.status_code == 404


async def test_one_range_per_request(w: World) -> None:
    address = unique()
    _, _, [file_id], [data] = shared(w, address, size=1000)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    url = (await grant(browser, session, file_id)).json()["url"]
    suffix = await content(browser, url, range="bytes=-100")
    assert (suffix.status_code, suffix.content) == (206, data[-100:])
    assert suffix.headers["content-range"] == "bytes 900-999/1000"
    clamped = await content(browser, url, range="bytes=990-5000")
    assert (clamped.status_code, clamped.content) == (206, data[990:])
    for bad in ("bytes=0-1,5-6", "bytes=1000-", "bytes=5-1", "items=0-1", "bytes=-0", "x"):
        refused = await content(browser, url, range=bad)
        assert refused.status_code == 416, bad
        assert refused.json()["code"] == "range_not_satisfiable"
        assert refused.headers["content-range"] == "bytes */1000"


def test_parse_range() -> None:
    assert parse_range(None, 10) is None
    assert parse_range("bytes=2-", 10) == downloads.ByteRange(2, 9)
    assert parse_range("bytes=2-4", 10) == downloads.ByteRange(2, 4)
    assert parse_range("bytes=-3", 10) == downloads.ByteRange(7, 9)
    assert parse_range("bytes=-30", 10) == downloads.ByteRange(0, 9)


async def test_an_unscannable_file_carries_its_warning_and_a_blocked_one_is_409(w: World) -> None:
    address = unique()
    _, _, [allowed], _ = shared(w, address, state="unscannable")
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    response = await grant(browser, session, allowed)
    assert response.json()["warning"] == "unscannable"
    w.db.sql("UPDATE files SET inspection_state = 'failed' WHERE id = :id", id=allowed)
    blocked = await grant(browser, session, allowed)
    assert (blocked.status_code, blocked.json()["code"]) == (409, "file_not_shareable")
    unknown = await grant(browser, session, uuid.uuid4())
    assert unknown.status_code == 404


# ---- who may fetch the bytes (FR-14) ----


async def test_the_content_url_needs_a_cookie_that_holds_the_grants_session(w: World) -> None:
    mine, yours, theirs = unique(), unique(), unique()
    _, _, [file_id], [data] = shared(w, mine, yours)
    other = seed_tenant(w.db)
    _, _, [their_file], _ = shared(w, theirs, tenant=other)
    browser, someone, stranger = await w.browser(), await w.browser(), await w.browser()
    _, session = await w.verify(browser, mine)
    _, _ = await w.verify(someone, yours)
    _, their_session = await w.verify(stranger, theirs, other)
    url = (await grant(browser, session, file_id)).json()["url"]
    # Without the cookie: 401. With another recipient's, or another tenant's: 404.
    anonymous = await w.browser()
    assert (await content(anonymous, url)).status_code == 401
    assert (await content(someone, url)).status_code == 404
    assert (await content(stranger, url)).status_code == 404
    # The other tenant's own grant isn't reachable with this cookie either.
    their_url = (await grant(stranger, their_session, their_file)).json()["url"]
    assert (await content(browser, their_url)).status_code == 404
    # A navigation sends no X-Link-Session, and needs none.
    assert (await content(browser, url)).content == data
    # Every other /session call still needs it.
    no_header = await browser.http.post(
        f"/v1/session/files/{file_id}/downloads",
        json={},
        headers=browser.headers(None, origin=WEB_ORIGIN),
    )
    assert no_header.status_code == 401


async def test_the_download_routes_refuse_every_caller_but_the_grants_session(w: World) -> None:
    browser = await w.browser()
    path = f"/v1/session/files/{uuid.uuid4()}/downloads"
    for headers in (
        {},
        {"cookie": "__Host-sft_session=" + "a" * 43, "x-link-session": str(uuid.uuid4())},
        {"authorization": "Bearer sft_dev_x", "x-link-session": str(uuid.uuid4())},
    ):
        assert (await browser.http.post(path, json={}, headers=headers)).status_code == 401
        got = await browser.http.get(
            f"/v1/session/downloads/{uuid.uuid4()}/content", headers=headers
        )
        assert got.status_code == 401, headers


async def test_a_grant_needs_the_session_csrf_token(w: World) -> None:
    address = unique()
    _, _, [file_id], _ = shared(w, address)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    refused = await browser.http.post(
        f"/v1/session/files/{file_id}/downloads",
        json={},
        headers=browser.headers(session["id"], origin=WEB_ORIGIN),
    )
    assert (refused.status_code, refused.json()["code"]) == (403, "csrf_failed")


# ---- revocation (NFR-6) ----


async def test_after_a_revocation_grants_content_and_the_link_get_410(w: World) -> None:
    address = unique()
    transfer_id, _, [file_id], _ = shared(w, address)
    browser = await w.browser()
    token, session = await w.verify(browser, address)
    url = (await grant(browser, session, file_id)).json()["url"]
    await revoke(w, transfer_id)
    for response in (
        await grant(browser, session, file_id),
        await content(browser, url),
        await browser.post("/v1/links/resolve", {"token": token}),
    ):
        assert (response.status_code, response.json()["code"]) == (410, "link_revoked")
    [(revoked_at,)] = w.db.sql("SELECT revoked_at FROM link_sessions WHERE id = :id",
                               id=uuid.UUID(session["id"]))  # fmt: skip
    assert revoked_at is not None


async def drain(stream: downloads.Stream, *, after: Any = None) -> tuple[int, float | None]:
    """Read the stream to its end; with `after`, run it once after the first chunk and time the
    stop from there."""
    started = None
    sent = 0
    try:
        async for chunk in stream.chunks():
            sent += len(chunk)
            if after is not None and started is None:
                await after()
                started = time.monotonic()
    finally:
        await stream.finish()
    return sent, None if started is None else time.monotonic() - started


async def test_a_revocation_stops_a_running_stream_within_two_rechecks(w: World) -> None:
    address = unique()
    transfer_id, _, [file_id], _ = shared(w, address)
    w.content.chunk, w.content.delay = 1000, 0.01  # 300 chunks: about 3 s, if never stopped
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    body = (await grant(browser, session, file_id)).json()
    download = await downloads.open_content(
        w.api,
        w.downloads,
        cookie_tokens(browser.cookie),
        uuid.UUID(body["grant_id"]),
        range_header=None,
        if_range=None,
        ip="192.0.2.1",
        now=datetime.now(UTC),
    )

    async def revoke_now() -> None:
        await revoke(w, transfer_id)

    sent, stopped_after = await drain(download.stream, after=revoke_now)
    assert download.stream.ended is Ended.REVOKED
    assert stopped_after is not None
    assert stopped_after < 2 * w.downloads.recheck_seconds + 0.1
    assert sent < SIZE
    assert grant_row(w, body["grant_id"])["bytes"] == sent, "the bytes it sent still count"
    assert "download.stopped" in actions(w, file_id)


async def test_a_new_request_takes_the_stream_over_and_the_old_one_records_its_bytes(
    w: World,
) -> None:
    address = unique()
    _, _, [file_id], _ = shared(w, address)
    w.content.chunk, w.content.delay = 1000, 0.01
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    grant_id = uuid.UUID((await grant(browser, session, file_id)).json()["grant_id"])

    async def opened() -> downloads.Download:
        return await downloads.open_content(
            w.api,
            w.downloads,
            cookie_tokens(browser.cookie),
            grant_id,
            range_header=None,
            if_range=None,
            ip="192.0.2.1",
            now=datetime.now(UTC),
        )

    old = await opened()
    newer: list[downloads.Download] = []

    async def take_over() -> None:
        newer.append(await opened())

    sent, stopped_after = await drain(old.stream, after=take_over)
    assert old.stream.ended is Ended.TAKEN_OVER
    assert stopped_after is not None
    assert stopped_after < 2 * w.downloads.recheck_seconds + 0.1
    w.content.delay = 0
    new_sent, _ = await drain(newer[0].stream)
    assert new_sent == SIZE
    assert grant_row(w, grant_id)["bytes"] == sent + SIZE


async def test_a_7th_stream_of_one_session_is_429_and_a_full_pod_503(w: World) -> None:
    address = unique()
    _, _, [file_id], _ = shared(w, address, size=100)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    grant_id = uuid.UUID((await grant(browser, session, file_id)).json()["grant_id"])

    async def opened() -> downloads.Download:
        return await downloads.open_content(
            w.api,
            w.downloads,
            cookie_tokens(browser.cookie),
            grant_id,
            range_header=None,
            if_range=None,
            ip="192.0.2.7",
            now=datetime.now(UTC),
        )

    held = [await opened() for _ in range(6)]
    with pytest.raises(RateLimited):
        await opened()
    for download in held:
        await download.stream.finish()
    assert (await opened()).status == 200
    w.downloads.limits.pod_streams = w.downloads.limits.active
    with pytest.raises(ServiceUnavailable) as full:
        await opened()
    assert full.value.retry_after == 10
    url = f"/v1/session/downloads/{grant_id}/content"
    refused = await content(browser, url)
    assert (refused.status_code, refused.headers["retry-after"]) == (503, "10")


async def test_a_recipient_past_25_gb_of_grants_in_a_day_gets_429(w: World) -> None:
    address = unique()
    _, _, file_ids, _ = shared(w, address, size=5_000_000_000, files=6)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    for file_id in file_ids[:5]:
        assert (await grant(browser, session, file_id)).status_code == 200
    over = await grant(browser, session, file_ids[5])
    assert (over.status_code, over.json()["code"]) == (429, "rate_limited")
    assert int(over.headers["retry-after"]) >= 1


# ---- revokeTransfer (NFR-10) ----


async def test_revoke_answers_200_once_both_archives_hold_it_and_a_retry_confirms(
    w: World,
) -> None:
    address = unique()
    transfer_id, _, [file_id], _ = shared(w, address)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    store = w.store
    store.fail = {Region.OSAKA}
    async with client(w.db, lambda: owner_of(w), archive=fake_archive(store)) as member:
        unconfirmed = await member.post(f"/v1/transfers/{transfer_id}/revoke")
        assert unconfirmed.status_code == 503
        [(state, ended_at, revoked_by)] = w.db.sql(
            "SELECT state, ended_at, revoked_by FROM transfers WHERE id = :id", id=transfer_id
        )
        assert (state, revoked_by) == ("revoked", w.tenant.target)
        assert ended_at is not None
        [(delete_after,)] = w.db.sql("SELECT delete_after FROM files WHERE id = :id", id=file_id)
        assert delete_after is not None
        assert (await grant(browser, session, file_id)).status_code == 410
        store.fail = set()
        confirmed = await member.post(f"/v1/transfers/{transfer_id}/revoke")
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json()["state"] == "revoked"
    for region in Region:
        assert "transfer.revoked" in store.actions(region)
    assert actions(w, transfer_id).count("transfer.revoked") == 1


async def test_revoke_refuses_a_draft_and_an_expired_transfer(w: World) -> None:
    draft, _ = seed_transfer(w.db, w.tenant.id, w.tenant.target)
    expired, _ = seed_transfer(
        w.db, w.tenant.id, w.tenant.target, state="sent", expires_at_offset=-timedelta(hours=1)
    )
    async with client(w.db, lambda: owner_of(w)) as member:
        refused = await member.post(f"/v1/transfers/{draft}/revoke")
        assert (refused.status_code, refused.json()["code"]) == (409, "invalid_state")
        late = await member.post(f"/v1/transfers/{expired}/revoke")
        assert (late.status_code, late.json()["code"]) == (409, "transfer_expired")


async def test_revoke_is_a_safety_action_outside_the_tenant_budget(w: World) -> None:
    sent, _ = seed_transfer(w.db, w.tenant.id, w.tenant.target, state="sent")
    limiter = RecordingLimiter()
    async with client(w.db, lambda: owner_of(w), limiter=limiter) as member:
        assert (await member.post(f"/v1/transfers/{sent}/revoke")).status_code == 200
    assert limiter.checks, "the caller's own limit applies"
    for ids, _ in limiter.checks:
        assert "H.tenant_requests" not in ids


async def test_the_download_metrics_count_each_result(w: World) -> None:
    address = unique()
    _, _, [file_id], _ = shared(w, address, limit=1)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    url = (await grant(browser, session, file_id)).json()["url"]
    await grant(browser, session, file_id)
    await content(browser, url)
    registry = w.registry
    assert registry.get_sample_value("download_grants_total", {"result": "granted"}) == 1
    assert registry.get_sample_value("download_grants_total", {"result": "limit_reached"}) == 1
    assert registry.get_sample_value("download_bytes_total") == SIZE
    assert registry.get_sample_value("download_streams_ended_total", {"reason": "completed"}) == 1
    assert registry.get_sample_value("download_streams_active") == 0


# ---- review fixes (#180) ----


async def used(w: World, limit: Any, value: object) -> int:
    now_ms = int(w.clock() * 1000)
    key = w.downloads.limiter._plan(Charge(limit, {limit.keys[0]: str(value)}), now_ms).key
    found = await w.downloads.limiter._store._client.get(key)
    return int(found or 0)


async def opened(w: World, browser: Browser, grant_id: uuid.UUID, **kw: Any) -> downloads.Download:
    return await downloads.open_content(
        w.api,
        w.downloads,
        cookie_tokens(browser.cookie),
        grant_id,
        range_header=kw.get("range_header"),
        if_range=None,
        ip="192.0.2.9",
        now=datetime.now(UTC),
    )


async def test_a_source_that_fails_to_close_still_records_the_bytes_and_the_event(
    w: World,
) -> None:
    address = unique()
    _, _, [file_id], _ = shared(w, address)
    w.content.chunk, w.content.fail_on_close = 1000, True
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    grant_id = uuid.UUID((await grant(browser, session, file_id)).json()["grant_id"])
    download = await opened(w, browser, grant_id)
    body = download.stream.chunks()
    assert len(await anext(body)) == 1000
    download.stream.ended = Ended.REVOKED  # as a re-check that saw the revocation sets it
    await download.stream.finish()  # closing the source raises; the end is still recorded
    await body.aclose()
    assert grant_row(w, grant_id)["bytes"] == 1000
    assert "download.stopped" in actions(w, file_id)
    assert w.registry.get_sample_value("download_streams_active") == 0


async def test_a_revocation_during_the_archive_writes_answers_410_and_counts_nothing(
    w: World,
) -> None:
    address = unique()
    transfer_id, [recipient], [file_id], _ = shared(w, address)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    original = w.store.put_once
    done: list[bool] = []

    async def revoke_first(region: Region, key: str, body: bytes) -> bool:
        if not done:
            done.append(True)
            await revoke(w, transfer_id)
        return await original(region, key, body)

    w.store.put_once = revoke_first  # type: ignore[method-assign]
    raced = await grant(browser, session, file_id)
    assert (raced.status_code, raced.json()["code"]) == (410, "link_revoked")
    assert count(w, recipient, file_id) == 0
    assert w.db.sql("SELECT count(*) FROM download_grants WHERE file_id = :f", f=file_id) == [(0,)]


@pytest.mark.parametrize(
    "ending",
    ["revoked_at = now()", "expires_at = now()"],
    ids=["signed_out", "expired"],
)
async def test_a_session_ending_during_the_archive_writes_answers_401_not_500(
    w: World, ending: str
) -> None:
    address = unique()
    _, [recipient], [file_id], _ = shared(w, address)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    original = w.store.put_once
    done: list[bool] = []

    async def end_session_first(region: Region, key: str, body: bytes) -> bool:
        if not done:
            done.append(True)
            w.db.sql(
                f"UPDATE link_sessions SET {ending} WHERE id = :id",  # noqa: S608 - fixed text
                id=uuid.UUID(session["id"]),
            )
        return await original(region, key, body)

    w.store.put_once = end_session_first  # type: ignore[method-assign]
    raced = await grant(browser, session, file_id)
    assert (raced.status_code, raced.json()["code"]) == (401, "session_expired")
    assert count(w, recipient, file_id) == 0


async def test_a_503_or_a_lost_race_leaves_the_caps_unchanged(w: World) -> None:
    address = unique()
    _, [recipient], [file_id], _ = shared(w, address, limit=1, size=5_000_000)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    w.store.fail = {Region.OSAKA}
    assert (await grant(browser, session, file_id)).status_code == 503
    assert await used(w, D_SUBJECT_BYTES, recipient) == 0
    assert await used(w, D_TENANT_BYTES, w.tenant.id) == 0
    w.store.fail = set()
    # Two at once at limit 1: the loser's 403 costs nothing, the winner's grant 5 MB once.
    responses = await asyncio.gather(
        grant(browser, session, file_id), grant(browser, session, file_id)
    )
    assert sorted(r.status_code for r in responses) == [200, 403]
    assert await used(w, D_SUBJECT_BYTES, recipient) == 5
    assert await used(w, D_TENANT_BYTES, w.tenant.id) == 5


async def test_two_grants_racing_for_the_tenants_last_bytes_charge_only_the_winner(
    w: World,
) -> None:
    first, second = unique(), unique()
    _, recipients, [file_id], _ = shared(w, first, second, size=5_000_000_000)
    # The tenant has room for one more 5 GB grant today, not two.
    now_ms = int(w.clock() * 1000)
    key = w.downloads.limiter._plan(
        Charge(D_TENANT_BYTES, {KeyType.TENANT: str(w.tenant.id)}), now_ms
    ).key
    await w.downloads.limiter._store._client.set(key, 500_000 - 5_000)
    one, two = await w.browser(), await w.browser()
    _, one_session = await w.verify(one, first)
    _, two_session = await w.verify(two, second)
    responses = await asyncio.gather(
        grant(one, one_session, file_id), grant(two, two_session, file_id)
    )
    statuses = [r.status_code for r in responses]
    assert sorted(statuses) == [200, 429]
    winner, loser = (0, 1) if statuses[0] == 200 else (1, 0)
    assert await used(w, D_SUBJECT_BYTES, recipients[winner]) == 5_000
    assert await used(w, D_SUBJECT_BYTES, recipients[loser]) == 0, "the loser's cap is unchanged"
    assert await used(w, D_TENANT_BYTES, w.tenant.id) == 500_000


async def test_a_body_that_never_starts_leaves_the_gauge_at_zero(w: World) -> None:
    address = unique()
    _, _, [file_id], _ = shared(w, address, size=100)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    grant_id = uuid.UUID((await grant(browser, session, file_id)).json()["grant_id"])
    download = await opened(w, browser, grant_id)
    await download.stream.finish()  # the client went away before the first byte
    assert w.registry.get_sample_value("download_streams_active") == 0
    assert w.downloads.limits.active == 0


async def test_a_request_the_budget_cant_cover_is_refused_and_none_declares_more_than_it_sends(
    w: World,
) -> None:
    address = unique()
    _, _, [file_id], [data] = shared(w, address, size=1000)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    url = (await grant(browser, session, file_id)).json()["url"]
    sent = [await content(browser, url) for _ in range(2)]
    sent.append(await content(browser, url, range="bytes=0-499"))  # 2,500 of 3,000 used
    whole = await content(browser, url)  # needs 1,000: more than the 500 left
    assert (whole.status_code, whole.json()["code"]) == (403, "download_grant_exhausted")
    tail = await content(browser, url, range="bytes=500-999")  # exactly what is left
    assert (tail.status_code, tail.content) == (206, data[500:])
    for response in (*sent, tail):
        assert int(response.headers["content-length"]) == len(response.content)


async def test_the_grant_flow_reads_the_injected_clock(w: World) -> None:
    address = unique()
    _, _, [file_id], _ = shared(w, address)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    later = datetime.now(UTC) + timedelta(hours=25)  # the clock's test hook, a day on
    link = await link_caller(
        w.api, cookie_tokens(browser.cookie), uuid.UUID(session["id"]), now=later
    )
    view = await downloads.create_session_download(
        w.api, w.downloads, link, file_id, resume_grant_id=None, ip="192.0.2.1",
        origin=Origin(), now=later,
    )  # fmt: skip
    [intent] = [r for r in w.store.records() if r["action"] == "download.grant_intent"]
    assert intent["occurred_at"] == later.isoformat()
    # The grant lasts a day by the database's clock, so a day on by the injected one it is spent.
    with pytest.raises(Forbidden):
        await downloads.create_session_download(
            w.api, w.downloads, link, file_id, resume_grant_id=view.grant_id, ip="192.0.2.1",
            origin=Origin(), now=later,
        )  # fmt: skip
    resumed = await downloads.create_session_download(
        w.api, w.downloads, link, file_id, resume_grant_id=view.grant_id, ip="192.0.2.1",
        origin=Origin(), now=datetime.now(UTC),
    )  # fmt: skip
    assert resumed.grant_id == view.grant_id


# ---- the first-download notice (#214, FR-8) ----


def notices(w: World, transfer_id: uuid.UUID) -> int:
    [(found,)] = w.db.sql(
        "SELECT count(*) FROM outbox WHERE topic = 'transfer.first_download' "
        "AND payload->>'transfer_id' = :id",
        id=str(transfer_id),
    )
    return int(str(found))


async def two_recipients_download_three_files(
    w: World, *, notify: bool
) -> tuple[uuid.UUID, list[uuid.UUID], list[tuple[Browser, dict[str, Any], str]]]:
    """A transfer to two recipients with three files; between them they download each file, and
    one file twice. The grants, each with its browser and session."""
    first, second = unique(), unique()
    transfer_id, _, file_ids, _ = shared(w, first, second, files=3)
    w.db.sql(
        "UPDATE transfers SET notify_on_first_download = :notify WHERE id = :id",
        notify=notify,
        id=transfer_id,
    )
    one, two = await w.browser(), await w.browser()
    _, one_session = await w.verify(one, first)
    _, two_session = await w.verify(two, second)
    grants = []
    for browser, session, file_id in (
        (one, one_session, file_ids[0]),
        (two, two_session, file_ids[1]),
        (one, one_session, file_ids[2]),
        (two, two_session, file_ids[0]),
    ):
        response = await grant(browser, session, file_id)
        assert response.status_code == 200, response.text
        grants.append((browser, session, response.json()["grant_id"]))
    return transfer_id, file_ids, grants


async def test_the_first_download_of_a_transfer_emails_its_member_once(w: World) -> None:
    w.db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (:t, 'ja')", t=w.tenant.id
    )
    transfer_id, file_ids, grants = await two_recipients_download_three_files(w, notify=True)
    assert notices(w, transfer_id) == 1
    [(notified,)] = w.db.sql(
        "SELECT first_download_notified_at IS NOT NULL FROM transfers WHERE id = :id",
        id=transfer_id,
    )
    assert notified is True
    await w.links()
    [email] = w.sent.of_type("first_download")
    [(owner,)] = w.db.sql("SELECT email FROM users WHERE id = :id", id=w.tenant.target)
    assert email.to == owner
    assert not email.subject.isascii(), "in the member's language, the tenant's default"
    assert f"/transfers/{transfer_id}" in email.text
    assert all(str(file_id) not in email.text for file_id in file_ids)
    assert actions(w, transfer_id).count("email.sent") == 1

    # A resume, and another counted download of a file already downloaded, send nothing more.
    browser, session, grant_id = grants[0]
    resumed = await grant(browser, session, file_ids[0], {"resume_grant_id": grant_id})
    assert resumed.status_code == 200, resumed.text
    assert (await grant(browser, session, file_ids[0])).status_code == 200
    await w.links()
    assert notices(w, transfer_id) == 1
    assert len(w.sent.of_type("first_download")) == 1


async def test_without_the_flag_no_first_download_email_is_sent(w: World) -> None:
    transfer_id, _, _ = await two_recipients_download_three_files(w, notify=False)
    await w.links()
    assert notices(w, transfer_id) == 0
    assert w.sent.of_type("first_download") == []
    [(notified,)] = w.db.sql(
        "SELECT first_download_notified_at FROM transfers WHERE id = :id", id=transfer_id
    )
    assert notified is None


async def test_a_refused_grant_writes_no_first_download_notice(w: World) -> None:
    address = unique()
    transfer_id, _, [file_id], _ = shared(w, address)
    w.db.sql("UPDATE transfers SET notify_on_first_download = true WHERE id = :id", id=transfer_id)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    w.store.fail = {Region.OSAKA}  # the intent record fails: nothing is counted
    response = await grant(browser, session, file_id)
    assert response.status_code == 503, response.text
    assert notices(w, transfer_id) == 0
    w.store.fail = set()
    assert (await grant(browser, session, file_id)).status_code == 200
    assert notices(w, transfer_id) == 1
