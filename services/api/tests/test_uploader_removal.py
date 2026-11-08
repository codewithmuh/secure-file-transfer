"""The uploader takes a file back, and an allowed unscannable file reads as accepted (#229; FR-11,
FR-12, FR-27; abuse and rate limits 2.2 F; authn and authz 6.3, `session.upload`).

`deleteSessionUploadFile` runs in the received-files rig of test_received_files.py: the real app
over ASGI against the real database, the uploader verified from the emails, the member's calls
with a member session that exists. Every caller of authn and authz 9.2 that can reach the route is
tried here, as the authorization matrix expects (`COVERED_BY_RECEIVED_FILE_TESTS`).
"""

from __future__ import annotations

import os
import uuid

import httpx2 as httpx
import pytest

from api_settings import WEB_ORIGIN
from link_fixtures import unique, w
from test_received_files import (
    SIZE,
    Rig,
    Uploader,
    actions,
    complete,
    declare,
    file_row,
    part_urls,
    rig,
    seed_received,
    session_files,
    upload,
    uploader,
)
from test_upload_requests import unsafe

pytestmark = pytest.mark.anyio
__all__ = ["rig", "w"]  # the fixtures, imported for this module's tests


async def remove(up: Uploader, file_id: object, *, csrf: bool = True) -> httpx.Response:
    headers = (
        unsafe(up.browser, up.session)
        if csrf
        else up.browser.headers(up.session["id"], origin=WEB_ORIGIN)
    )
    return await up.browser.http.delete(f"/v1/session/files/{file_id}", headers=headers)


def reserved(rig: Rig) -> int:
    rows = rig.w.db.sql(
        "SELECT bytes_reserved FROM tenant_usage WHERE tenant_id = :t", t=rig.tenant.id
    )
    return int(rows[0][0]) if rows else 0  # type: ignore[arg-type]


def notice_counts(rig: Rig, request_id: uuid.UUID) -> tuple[object, ...]:
    [row] = rig.w.db.sql(
        "SELECT arrived_since_notice, blocked_since_notice, notice_due_at IS NOT NULL "
        "FROM upload_requests WHERE id = :id",
        id=request_id,
    )
    return tuple(row)


def removal_details(rig: Rig, file_id: object) -> list[tuple[object, ...]]:
    return rig.w.db.sql(
        "SELECT actor_type, details->>'reason', details->>'notice_withdrawn' FROM audit_events "
        "WHERE target_id = :id AND action = 'file.removed'",
        id=file_id,
    )


async def test_an_uploading_file_is_taken_back_and_no_longer_counts(rig: Rig) -> None:
    up = await uploader(rig)
    declared = await declare(up)
    assert declared.status_code == 201, declared.text
    file_id = uuid.UUID(declared.json()["id"])
    assert reserved(rig) == SIZE
    removed = await remove(up, file_id)
    assert removed.status_code == 204, removed.text
    assert removed.headers["cache-control"] == "no-store"
    assert file_row(rig, file_id)["removed_at"] is not None
    assert file_row(rig, file_id)["delete_after"] is not None, "the deletion job aborts it"
    assert reserved(rig) == 0
    assert (await session_files(up)).json()["items"] == []
    # Its upload is over: a completion finds nothing, and no part URL is issued.
    assert (await complete(up, file_id)).status_code == 404
    assert (await part_urls(up, file_id, [1])).status_code == 404
    # A retry changes nothing and is still 204; the removal is audited once, as the uploader.
    assert (await remove(up, file_id)).status_code == 204
    assert removal_details(rig, file_id) == [("uploader", "uploader_removed", "false")]
    # The member never sees it, and the request's counts leave it out.
    owner = rig.member()
    listed = await rig.as_member(owner, "GET", f"/v1/upload-requests/{up.request_id}/files")
    assert listed.json()["items"] == []
    request = await rig.as_member(owner, "GET", f"/v1/upload-requests/{up.request_id}")
    assert (request.json()["file_count"], request.json()["total_size"]) == (0, 0)
    # Its declaration still counts toward the 100.
    [(declared_count,)] = rig.w.db.sql(
        "SELECT count(*) FROM files WHERE upload_request_id = :r", r=up.request_id
    )
    assert declared_count == 1


async def test_a_received_file_is_taken_off_its_pending_notice_and_its_grant_stops(
    rig: Rig,
) -> None:
    up = await uploader(rig)
    data = os.urandom(SIZE)
    file_id = await upload(rig, up, "a.pdf", data)
    await rig.scan(file_id, data)
    assert notice_counts(rig, up.request_id) == (1, 0, True)
    owner = rig.member()
    granted = await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})
    assert granted.status_code == 200, granted.text
    assert (await remove(up, file_id)).status_code == 204
    # Nothing left to tell: the notice is no longer due, so the member isn't told of it.
    assert notice_counts(rig, up.request_id) == (0, 0, False)
    assert removal_details(rig, file_id) == [("uploader", "uploader_removed", "true")]
    assert (await rig.as_member(owner, "GET", granted.json()["url"])).status_code == 404
    assert (await rig.as_member(owner, "GET", f"/v1/files/{file_id}")).status_code == 404
    assert reserved(rig) == 0


async def test_a_file_told_of_already_leaves_the_next_notice_as_it_is(rig: Rig) -> None:
    up = await uploader(rig)
    [told, pending] = seed_received(rig, up.request_id, count=2)
    # `told` settled before this notice's window began; `pending` within it.
    rig.w.db.sql("UPDATE files SET scanned_at = now() - interval '1 hour' WHERE id = :id", id=told)
    rig.w.db.sql(
        "UPDATE upload_requests SET arrived_since_notice = 1, "
        "notice_due_at = now() + interval '4 minutes' WHERE id = :id",
        id=up.request_id,
    )
    assert (await remove(up, told)).status_code == 204
    assert notice_counts(rig, up.request_id) == (1, 0, True), "the pending file is still told"
    assert (await remove(up, pending)).status_code == 204
    assert notice_counts(rig, up.request_id) == (0, 0, False)


async def test_a_blocked_file_stays_for_the_company(rig: Rig) -> None:
    up = await uploader(rig)
    [infected] = seed_received(rig, up.request_id, state="infected")
    [unscannable] = seed_received(rig, up.request_id, state="unscannable")
    for file_id in (infected, unscannable):
        refused = await remove(up, file_id)
        assert refused.status_code == 409, refused.text
        assert refused.json()["code"] == "invalid_state"
        assert file_row(rig, file_id)["removed_at"] is None
    # An unscannable file the policy allowed is the uploader's to take back.
    rig.w.db.sql("UPDATE files SET unscannable_allowed = true WHERE id = :id", id=unscannable)
    assert (await remove(up, unscannable)).status_code == 204


async def test_an_ended_request_takes_nothing_back(rig: Rig) -> None:
    up = await uploader(rig)
    [file_id] = seed_received(rig, up.request_id)
    owner = rig.member()
    revoked = await rig.as_member(owner, "POST", f"/v1/upload-requests/{up.request_id}/revoke")
    assert revoked.status_code == 200, revoked.text
    gone = await remove(up, file_id)
    assert gone.status_code == 410
    assert gone.json()["code"] == "link_revoked"
    assert file_row(rig, file_id)["removed_at"] is None


async def test_an_expired_request_takes_nothing_back(rig: Rig) -> None:
    up = await uploader(rig)
    declared = (await declare(up)).json()
    rig.w.db.sql(
        "UPDATE upload_requests SET expires_at = now() - interval '1 second' WHERE id = :id",
        id=up.request_id,
    )
    gone = await remove(up, declared["id"])
    assert (gone.status_code, gone.json()["code"]) == (410, "link_expired")


async def test_only_the_uploaders_own_session_removes_and_only_its_own_files(rig: Rig) -> None:
    up = await uploader(rig)
    mine = uuid.UUID((await declare(up)).json()["id"])
    # Another request's uploader: 404, as if the file didn't exist.
    other = await uploader(rig)
    assert (await remove(other, mine)).status_code == 404
    assert (await remove(other, uuid.uuid4())).status_code == 404
    # A recipient's session: 403.
    address = unique()
    rig.w.transfer(address)
    browser = await rig.w.browser()
    _, session = await rig.w.verify(browser, address)
    recipient = Uploader(up.request_id, address, browser, session)
    refused = await remove(recipient, mine)
    assert (refused.status_code, refused.json()["code"]) == (403, "permission_denied")
    # Without the CSRF token: refused.
    bare = await remove(up, mine, csrf=False)
    assert (bare.status_code, bare.json()["code"]) == (403, "csrf_failed")
    # A member's caller, an admin's or an API key's holds no link session: 401.
    for who in (rig.member(), rig.member(rig.tenant.admin)):
        answer = await rig.as_member(who, "DELETE", f"/v1/session/files/{mine}")
        assert answer.status_code == 401, answer.text
        assert answer.json()["code"] == "authentication_required"
    assert file_row(rig, mine)["removed_at"] is None
    assert [a for a, _ in actions(rig, mine)].count("file.removed") == 0


async def test_an_allowed_unscannable_file_reads_as_accepted_to_the_uploader(rig: Rig) -> None:
    up = await uploader(rig)
    [allowed, refused] = seed_received(rig, up.request_id, state="unscannable", count=2)
    rig.w.db.sql("UPDATE files SET unscannable_allowed = true WHERE id = :id", id=allowed)
    items = {item["id"]: item for item in (await session_files(up)).json()["items"]}
    assert items[str(allowed)]["state"] == "unscannable"
    assert items[str(allowed)]["warning"] == "unscannable"
    assert "warning" not in items[str(refused)]


async def test_after_a_removal_another_file_fits_under_the_total(rig: Rig) -> None:
    up = await uploader(rig)
    big = seed_received(rig, up.request_id, size=4_900_000_000, count=4)
    too_much = await declare(up, size=1_000_000_000)
    assert (too_much.status_code, too_much.json()["code"]) == (413, "total_too_large")
    assert (await remove(up, big[0])).status_code == 204
    fits = await declare(up, size=1_000_000_000)
    assert fits.status_code == 201, fits.text
