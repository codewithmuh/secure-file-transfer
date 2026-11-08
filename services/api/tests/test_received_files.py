"""Received files: the uploader uploads, files are scanned, the member downloads what arrived (#213;
UC-2, UC-3, FR-11, FR-12, FR-13, FR-16, FR-17, NFR-3, NFR-6; data model 2.3, 3.1, 6; abuse and
rate limits 2.2 D, E, F, 5.4, 6.3; authn and authz 4.3, 6.4).

The tests run in the link world of link_fixtures.py: the real app over ASGI against the real
database, a real Valkey for the limits, the notification worker as `sft_notify`, an in-memory
audit archive, the upload buckets stood in for by `FakeObjects` and the files' bytes by
`FakeContent`. The uploader verifies as a person would, from the emails; the scan worker runs as
`sft_scan` against fake clamd and inspector sockets (scan_fixtures.py). The member's calls go
through the same app with the member's caller put in place of the session cookie's, for a member
session that exists in the database, since a grant belongs to it.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2 as httpx
import pytest
from prometheus_client import CollectorRegistry

from api_settings import WEB_ORIGIN
from link_fixtures import Browser, World, unique, w
from member_fixtures import Tenant, seed_tenant
from object_fixtures import FakeObjects
from scan_fixtures import FakeClamd, FakeInspector, FakeScanObjects, eicar
from sft.api.caller import get_caller
from sft.core.ids import uuid7
from sft.data.database import Database
from sft.data.models import Role
from sft.data.outbox import OutboxMessage, Queue
from sft.data.roles import SCAN
from sft.data.scope import Subject
from sft.service.caller import AuthMethod, Caller, CallerKind
from sft.service.uploads import UploadPolicy
from sft.workers.consumer import Delivery
from sft.workers.scan import Engines, Leases, ScanMetrics, SmallScanConsumer
from test_upload_requests import ask, unsafe, verify

pytestmark = pytest.mark.anyio
__all__ = ["w"]  # the fixture, imported for this module's tests

MIB = 1024 * 1024
SIZE = 6 * MIB
"""Two parts: 5 MiB and 1 MiB."""


# ---- the rig ----


@dataclass
class Member:
    """A member session as the database holds it, and the caller it resolves to."""

    caller: Caller
    session_id: uuid.UUID


@dataclass
class Rig:
    w: World
    objects: FakeObjects
    scanned: FakeScanObjects
    consumer: SmallScanConsumer
    clamd: FakeClamd
    acting: list[Caller | None] = field(default_factory=list)

    @property
    def tenant(self) -> Tenant:
        return self.w.tenant

    def member(
        self,
        user_id: uuid.UUID | None = None,
        *,
        role: Role = Role.MEMBER,
        tenant: Tenant | None = None,
        method: AuthMethod = AuthMethod.PASSKEY,
    ) -> Member:
        """A live member session of `user_id` (the request owner's by default)."""
        owner = tenant or self.tenant
        user = user_id or owner.target
        session_id = uuid7()
        self.w.db.sql(
            "INSERT INTO member_sessions (id, tenant_id, user_id, identity_id, session_hash, "
            "auth_time, auth_method, expires_at) VALUES (:id, :tenant, :user, :identity, "
            "sha256(convert_to(:token, 'UTF8')), now(), 'passkey', now() + interval '12 hours')",
            id=session_id,
            tenant=owner.id,
            user=user,
            identity=uuid.uuid4(),
            token=secrets.token_urlsafe(32),
        )
        caller = Caller.member(
            tenant_id=owner.id,
            user_id=user,
            role=role,
            auth_method=method,
            auth_time=datetime.now(UTC) - timedelta(minutes=1),
            session_id=session_id,
        )
        return Member(caller, session_id)

    async def as_member(
        self, who: Member | None, method: str, path: str, **kwargs: Any
    ) -> httpx.Response:
        """A member call through the app, as `who` (no session cookie at all when None)."""
        app = self.w.app
        if who is None:
            app.dependency_overrides.pop(get_caller, None)
        else:
            app.dependency_overrides[get_caller] = lambda: who.caller
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://api.sft.test") as http:
            return await http.request(method, path, **kwargs)

    async def scan(self, file_id: uuid.UUID, data: bytes) -> None:
        """The scan worker's pass over the file's recorded version, as the queue delivers it."""
        key = f"tenants/{self.tenant.id}/files/{file_id}"
        self.scanned.put(key, "version-1", data)
        self.w.content.put(key, "version-1", data)
        message = OutboxMessage(uuid7(), "file.scan", self.tenant.id, {"file_id": file_id})
        await self.consumer.process(Delivery(message, 1))


@pytest.fixture
async def rig(w: World) -> AsyncIterator[Rig]:
    objects = FakeObjects()
    w.app.state.objects = objects
    w.app.state.upload_policy = UploadPolicy()
    clamd, inspector = FakeClamd(), FakeInspector()
    await clamd.start()
    await inspector.start()
    scanned = FakeScanObjects()
    database = Database.connect(w.db.url(SCAN), pool_size=2)
    consumer = SmallScanConsumer(
        database,
        scanned,
        Engines("127.0.0.1", clamd.port, "127.0.0.1", inspector.port, connect_timeout=2),
        ScanMetrics.create(CollectorRegistry()),
        Leases(None, Queue.SCAN_SMALL, 4, time.time),
    )
    try:
        yield Rig(w, objects, scanned, consumer, clamd)
    finally:
        w.app.dependency_overrides.pop(get_caller, None)
        await clamd.stop()
        await inspector.stop()
        await database.dispose()


@dataclass
class Uploader:
    request_id: uuid.UUID
    address: str
    browser: Browser
    session: dict[str, Any]


async def uploader(rig: Rig) -> Uploader:
    """A request of the owner's, and its uploader verified in a browser."""
    address = unique()
    created = await ask(rig.w, address)
    browser = await rig.w.browser()
    _, session = await verify(rig.w, browser, address)
    return Uploader(uuid.UUID(created["id"]), address, browser, session)


async def declare(
    up: Uploader, name: str = "report.pdf", size: int = SIZE, **headers: str
) -> httpx.Response:
    return await up.browser.http.post(
        "/v1/session/files",
        json={"display_name": name, "size": size, "content_type": "application/pdf"},
        headers={**unsafe(up.browser, up.session), **headers},
    )


async def part_urls(up: Uploader, file_id: object, numbers: list[int]) -> httpx.Response:
    return await up.browser.http.post(
        f"/v1/session/files/{file_id}/parts",
        json={"part_numbers": numbers},
        headers=unsafe(up.browser, up.session),
    )


async def uploaded(up: Uploader, file_id: object) -> httpx.Response:
    return await up.browser.http.get(
        f"/v1/session/files/{file_id}/parts", headers=up.browser.headers(up.session["id"])
    )


async def complete(up: Uploader, file_id: object) -> httpx.Response:
    return await up.browser.http.post(
        f"/v1/session/files/{file_id}/complete", headers=unsafe(up.browser, up.session)
    )


async def session_files(up: Uploader) -> httpx.Response:
    return await up.browser.http.get(
        "/v1/session/files", headers=up.browser.headers(up.session["id"])
    )


def upload_id(rig: Rig, file_id: object) -> str:
    [(value,)] = rig.w.db.sql("SELECT s3_upload_id FROM files WHERE id = :id", id=file_id)
    return str(value)


def put(rig: Rig, file_id: object, number: int, size: int) -> None:
    """The browser's PUT of one part to its URL."""
    rig.objects.put_part(upload_id(rig, file_id), number, size)


def put_all(rig: Rig, file_id: object, size: int = SIZE) -> None:
    put(rig, file_id, 1, 5 * MIB)
    put(rig, file_id, 2, size - 5 * MIB)


def file_row(rig: Rig, file_id: object) -> dict[str, Any]:
    [row] = rig.w.db.sql(
        "SELECT state, retention_until, delete_after, removed_at, upload_request_id, "
        "transfer_id FROM files WHERE id = :id",
        id=file_id,
    )
    keys = ("state", "retention_until", "delete_after", "removed_at", "request", "transfer")
    return dict(zip(keys, row, strict=True))


def notices_due(rig: Rig, request_id: uuid.UUID) -> list[tuple[object, ...]]:
    return rig.w.db.sql(
        "SELECT delay_seconds FROM outbox WHERE topic = 'upload_request.files_settled' "
        "AND payload->>'upload_request_id' = :id",
        id=str(request_id),
    )


async def send_notices(rig: Rig) -> None:
    """The notice window passes, and the notification worker sends what is due."""
    rig.w.db.sql(
        "UPDATE outbox SET created_at = created_at - interval '5 minutes' "
        "WHERE topic = 'upload_request.files_settled' AND published_at IS NULL"
    )
    await rig.w.links()


def owner_email(rig: Rig) -> str:
    [(address,)] = rig.w.db.sql("SELECT email FROM users WHERE id = :id", id=rig.tenant.target)
    return str(address)


def seed_received(
    rig: Rig,
    request_id: uuid.UUID,
    *,
    state: str = "clean",
    size: int = 10,
    count: int = 1,
) -> list[uuid.UUID]:
    """Files of the request in `state`, as the superuser, with their reservations."""
    ids = []
    for _ in range(count):
        file_id = uuid7()
        scanned = state not in ("uploading", "completing", "rejected")
        rig.w.db.sql(
            "INSERT INTO files (id, tenant_id, upload_request_id, display_name_ct, content_type, "
            "declared_size, actual_size, storage_class, storage_key, s3_upload_id, s3_version_id, "
            "part_size, part_count, state, scan_deadline, inspection_state, scanned_at, "
            "retention_until, delete_after) VALUES (:id, :tenant, :request, '\\x0061', "
            "'text/plain', :size, CASE WHEN :scanned THEN :size END, "
            "CASE WHEN :size > 2000000000 THEN 'large' ELSE 'standard' END, "
            "'tenants/' || :tenant || '/files/' || :id, 'upload-' || :id, "
            "CASE WHEN :scanned THEN 'version-1' END, 5242880, "
            "greatest(1, ceil(:size / 5242880.0))::int, :state, "
            "CASE WHEN :scanned THEN now() + interval '2 hours' END, "
            "CASE WHEN :scanned THEN 'inspected' ELSE 'pending' END, "
            "CASE WHEN :scanned THEN now() END, "
            "CASE WHEN :scanned THEN now() + interval '30 days' END, "
            "CASE WHEN :scanned THEN now() + interval '30 days' "
            "WHEN :state = 'rejected' THEN now() END)",
            id=file_id,
            tenant=rig.tenant.id,
            request=request_id,
            size=size,
            scanned=scanned,
            state=state,
        )
        if state != "rejected":
            rig.w.db.sql(
                "INSERT INTO tenant_usage (tenant_id, bytes_reserved) VALUES (:t, :size) "
                "ON CONFLICT (tenant_id) DO UPDATE "
                "SET bytes_reserved = tenant_usage.bytes_reserved + :size",
                t=rig.tenant.id,
                size=size,
            )
        ids.append(file_id)
    return ids


async def upload(rig: Rig, up: Uploader, name: str, data: bytes) -> uuid.UUID:
    """Declare, send every part and complete: the file is `scanning`."""
    declared = await declare(up, name, len(data))
    assert declared.status_code == 201, declared.text
    file_id = uuid.UUID(declared.json()["id"])
    urls = await part_urls(up, file_id, [1, 2])
    assert urls.status_code == 200, urls.text
    put_all(rig, file_id, len(data))
    done = await complete(up, file_id)
    assert done.status_code == 200, done.text
    assert done.json()["state"] == "scanning"
    return file_id


def actions(rig: Rig, target: object) -> list[tuple[object, ...]]:
    return rig.w.db.sql(
        "SELECT action, actor_type FROM audit_events WHERE target_id = :id "
        "ORDER BY occurred_at, id",
        id=target,
    )


# ---- the journey: upload, resume, scan, one notice, download with a resume ----


async def test_two_files_of_two_parts_resume_reach_clean_one_notice_and_download_with_a_range(
    rig: Rig,
) -> None:
    up = await uploader(rig)
    datas = [os.urandom(SIZE), os.urandom(SIZE)]

    # The first file: its second part's PUT is cut off; the browser asks what arrived and sends
    # only the missing part (NFR-3).
    key = "Idempotency-Key"
    declared = await declare(up, "a.pdf", **{key: "first-file"})
    assert declared.status_code == 201, declared.text
    first = declared.json()
    assert first["state"] == "uploading"
    assert first["upload"] == {"part_size": 5 * MIB, "part_count": 2}
    assert declared.headers["cache-control"] == "no-store"
    again = await declare(up, "a.pdf", **{key: "first-file"})
    assert again.status_code == 201
    assert again.json()["id"] == first["id"], "a retry, not a second file"
    a = uuid.UUID(first["id"])
    urls = await part_urls(up, a, [1, 2])
    assert [p["size"] for p in urls.json()["parts"]] == [5 * MIB, MIB]
    put(rig, a, 1, 5 * MIB)
    listed = await session_files(up)
    assert [f["state"] for f in listed.json()["items"]] == ["uploading"]
    assert listed.json()["items"][0]["upload"] == {"part_size": 5 * MIB, "part_count": 2}
    assert listed.json()["items"][0]["size"] == SIZE
    assert listed.json()["items"][0]["display_name"] == "a.pdf"
    have = await uploaded(up, a)
    assert have.status_code == 200
    assert have.json()["parts"] == [{"part_number": 1, "size": 5 * MIB}]
    incomplete = await complete(up, a)
    assert incomplete.status_code == 409
    assert incomplete.json()["code"] == "upload_incomplete"
    again_urls = await part_urls(up, a, [2])
    assert [p["part_number"] for p in again_urls.json()["parts"]] == [2]
    put(rig, a, 2, MIB)
    done = await complete(up, a)
    assert done.status_code == 200, done.text
    assert done.json()["state"] == "scanning"
    assert "upload" not in done.json()
    row = file_row(rig, a)
    assert row["request"] == up.request_id
    assert row["transfer"] is None
    assert row["retention_until"] is not None
    assert row["delete_after"] == row["retention_until"], "retention from the acceptance"
    assert row["retention_until"] - datetime.now(UTC) > timedelta(days=29)

    b = await upload(rig, up, "b.pdf", datas[1])
    for file_id, data in ((a, datas[0]), (b, datas[1])):
        await rig.scan(file_id, data)
        assert file_row(rig, file_id)["state"] == "clean"
    assert notices_due(rig, up.request_id) == [(300,)], "one notice for the window"
    assert [f["state"] for f in (await session_files(up)).json()["items"]] == ["clean", "clean"]
    assert ("file.added", "uploader") in actions(rig, a)
    assert ("file.uploaded", "uploader") in actions(rig, a)
    assert ("file.scanned", "system") in actions(rig, a)

    await send_notices(rig)
    arrived = [e for e in rig.w.sent.to(owner_email(rig)) if e.email_type == "files_arrived"]
    assert len(arrived) == 1
    assert "2 files have arrived" in arrived[0].subject
    assert "a.pdf" not in arrived[0].text
    assert "b.pdf" not in arrived[0].text
    [(left,)] = rig.w.db.sql(
        "SELECT arrived_since_notice + blocked_since_notice FROM upload_requests WHERE id = :id",
        id=up.request_id,
    )
    assert left == 0

    # The member sees both, with their retention, and downloads each with a resume, under one
    # grant each.
    owner = rig.member()
    listing = await rig.as_member(owner, "GET", f"/v1/upload-requests/{up.request_id}/files")
    assert listing.status_code == 200, listing.text
    items = listing.json()["items"]
    assert [i["display_name"] for i in items] == ["a.pdf", "b.pdf"]
    assert all(i["upload_request_id"] == str(up.request_id) for i in items)
    assert all(i["transfer_id"] is None and i["shareable"] for i in items)
    assert all(i["retention_until"] for i in items)
    request = await rig.as_member(owner, "GET", f"/v1/upload-requests/{up.request_id}")
    assert request.json()["file_count"] == 2
    assert request.json()["total_size"] == 2 * SIZE
    session = await up.browser.http.get("/v1/session", headers=up.browser.headers(up.session["id"]))
    assert session.json()["upload_request"]["files_received"] == 2
    for file_id, data in ((a, datas[0]), (b, datas[1])):
        granted = await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})
        assert granted.status_code == 200, granted.text
        body = granted.json()
        assert body["url"] == f"/v1/files/{file_id}/downloads/{body['grant_id']}/content"
        assert body["byte_budget"] == 3 * SIZE
        assert "downloads_remaining" not in body or body["downloads_remaining"] is None
        head = await rig.as_member(owner, "GET", body["url"], headers={"range": "bytes=0-99"})
        assert head.status_code == 206
        assert head.content == data[:100]
        assert head.headers["content-range"] == f"bytes 0-99/{SIZE}"
        etag = head.headers["etag"]
        assert etag == f'"{hashlib.sha256(data).hexdigest()}"'
        rest = await rig.as_member(
            owner, "GET", body["url"], headers={"range": "bytes=100-", "if-range": etag}
        )
        assert rest.status_code == 206
        assert rest.content == data[100:]
        resumed = await rig.as_member(
            owner,
            "POST",
            f"/v1/files/{file_id}/downloads",
            json={"resume_grant_id": body["grant_id"]},
        )
        assert resumed.json()["grant_id"] == body["grant_id"], "the same grant"
        [(grants,)] = rig.w.db.sql(
            "SELECT count(*) FROM download_grants WHERE file_id = :f", f=file_id
        )
        assert grants == 1
        kinds = [a for a, _ in actions(rig, file_id)]
        assert "download.granted" in kinds
        assert "download.resumed" in kinds
        assert "download.completed" in kinds


async def test_an_eicar_file_is_reported_to_both_sides_and_the_uploader_learns_no_detail(
    rig: Rig,
) -> None:
    up = await uploader(rig)
    data = eicar() + os.urandom(SIZE - len(eicar()))
    file_id = await upload(rig, up, "invoice.zip", data)
    await rig.scan(file_id, data)
    assert file_row(rig, file_id)["state"] == "infected"
    listed = (await session_files(up)).json()["items"]
    assert [f["state"] for f in listed] == ["infected"]
    assert set(listed[0]) <= {"id", "display_name", "content_type", "size", "state", "blocked"}
    assert listed[0]["blocked"] is True  # that much, and no reason (#221)
    await send_notices(rig)
    member_mail = rig.w.sent.to(owner_email(rig))
    assert [e.email_type for e in member_mail] == ["files_blocked_member"]
    [uploader_mail] = [e for e in rig.w.sent.to(up.address) if e.email_type.startswith("files_")]
    assert uploader_mail.email_type == "files_blocked_uploader"
    words = (uploader_mail.subject + uploader_mail.text + uploader_mail.html).lower()
    for detail in ("eicar", "infected", "invoice", "malware", "virus", "finding", "scan"):
        assert detail not in words, detail
    # The member sees why on the request page, and can't download it.
    owner = rig.member()
    [item] = (
        await rig.as_member(owner, "GET", f"/v1/upload-requests/{up.request_id}/files")
    ).json()["items"]
    assert item["state"] == "infected"
    assert not item["shareable"]
    refused = await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})
    assert refused.status_code == 409
    assert refused.json()["code"] == "file_not_shareable"


async def test_revoking_during_an_upload_never_assembles_it_and_received_files_stay(
    rig: Rig,
) -> None:
    up = await uploader(rig)
    data = os.urandom(SIZE)
    received_id = await upload(rig, up, "kept.pdf", data)
    await rig.scan(received_id, data)
    declared = await declare(up, "late.pdf")
    late = uuid.UUID(declared.json()["id"])
    await part_urls(up, late, [1, 2])
    put(rig, late, 1, 5 * MIB)
    owner = rig.member()
    revoked = await rig.as_member(owner, "POST", f"/v1/upload-requests/{up.request_id}/revoke")
    assert revoked.status_code == 200, revoked.text
    assert file_row(rig, late)["state"] == "rejected"
    put(rig, late, 2, MIB)  # a part sent afterwards
    refused = await complete(up, late)
    assert refused.status_code == 410
    assert refused.json()["code"] == "link_revoked"
    assert f"tenants/{rig.tenant.id}/files/{late}" not in rig.objects.objects, "never assembled"
    assert (await session_files(up)).status_code == 410
    assert ("file.rejected", "member") in actions(rig, late)
    # What arrived before stays the member's to download.
    granted = await rig.as_member(owner, "POST", f"/v1/files/{received_id}/downloads", json={})
    assert granted.status_code == 200, granted.text
    got = await rig.as_member(owner, "GET", granted.json()["url"])
    assert got.status_code == 200
    assert got.content == data


async def test_the_request_limits_hold_and_two_parallel_completes_cant_pass_them(
    rig: Rig,
) -> None:
    up = await uploader(rig)
    # 50 counted files: the 51st is 422 too_many_files.
    seed_received(rig, up.request_id, count=50)
    over = await declare(up, "51.pdf")
    assert over.status_code == 422
    assert over.json()["code"] == "too_many_files"

    up = await uploader(rig)
    # 100 declarations, rejected ones included: the 101st is refused.
    seed_received(rig, up.request_id, state="rejected", count=100)
    over = await declare(up, "101.pdf")
    assert over.status_code == 422
    assert over.json()["code"] == "too_many_files"
    assert "100" in over.json()["detail"]

    up = await uploader(rig)
    # 20 GB in all: 4 files of 5 GB, then one byte more is 413 total_too_large.
    seed_received(rig, up.request_id, size=5_000_000_000, count=3)
    seed_received(rig, up.request_id, size=4_999_999_999)
    over = await declare(up, "byte.pdf", 2)
    assert over.status_code == 413
    assert over.json()["code"] == "total_too_large"
    fits = await declare(up, "byte.pdf", 1)
    assert fits.status_code == 201, fits.text

    # Two uploads slipped in beside 49 files (51 counted): two completes at once queue on the
    # request's row lock, each counting again, so exactly one passes and 50 files count.
    up = await uploader(rig)
    seed_received(rig, up.request_id, count=49)
    racing = seed_received(rig, up.request_id, state="uploading", size=SIZE, count=2)
    for file_id in racing:
        put_all(rig, file_id)
    answers = await asyncio.gather(*(complete(up, file_id) for file_id in racing))
    assert sorted(a.status_code for a in answers) == [200, 422], [a.text for a in answers]
    assert [a.json()["code"] for a in answers if a.status_code == 422] == ["too_many_files"]
    [(counted,)] = rig.w.db.sql(
        "SELECT count(*) FROM files WHERE upload_request_id = :r AND state <> 'rejected'",
        r=up.request_id,
    )
    assert counted == 50


async def test_admins_see_metadata_but_never_download_and_others_get_404(rig: Rig) -> None:
    up = await uploader(rig)
    data = os.urandom(SIZE)
    file_id = await upload(rig, up, "a.pdf", data)
    await rig.scan(file_id, data)
    admin = rig.member(rig.tenant.admin, role=Role.ADMIN)
    other = rig.member(rig.tenant.member)
    owner = rig.member()
    stranger_tenant = seed_tenant(rig.w.db)
    stranger = rig.member(stranger_tenant.admin, role=Role.ADMIN, tenant=stranger_tenant)

    listed = await rig.as_member(admin, "GET", f"/v1/upload-requests/{up.request_id}/files")
    assert listed.status_code == 200
    assert len(listed.json()["items"]) == 1
    assert (await rig.as_member(admin, "GET", f"/v1/files/{file_id}")).status_code == 200
    inspection = await rig.as_member(admin, "GET", f"/v1/files/{file_id}/inspection")
    assert inspection.status_code == 200
    assert inspection.json()["dlp_blocked"] is False
    refused = await rig.as_member(admin, "POST", f"/v1/files/{file_id}/downloads", json={})
    assert refused.status_code == 403
    assert refused.json()["code"] == "permission_denied"
    for who in (other, stranger):
        for method, path in (
            ("GET", f"/v1/upload-requests/{up.request_id}/files"),
            ("GET", f"/v1/files/{file_id}"),
            ("GET", f"/v1/files/{file_id}/inspection"),
            ("POST", f"/v1/files/{file_id}/downloads"),
            ("DELETE", f"/v1/files/{file_id}"),
        ):
            answer = await rig.as_member(who, method, path, json={} if method == "POST" else None)
            assert answer.status_code == 404, (method, path, answer.text)

    # The content URL works only with the member session that made the grant.
    granted = (await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})).json()
    second_device = rig.member()
    assert (await rig.as_member(second_device, "GET", granted["url"])).status_code == 404
    anonymous = await rig.as_member(None, "GET", granted["url"])
    assert anonymous.status_code == 401
    assert anonymous.json()["code"] == "authentication_required"
    wrong_file = granted["url"].replace(str(file_id), str(uuid.uuid4()))
    assert (await rig.as_member(owner, "GET", wrong_file)).status_code == 404
    assert (await rig.as_member(owner, "GET", granted["url"])).status_code == 200


async def test_recipients_cant_upload_uploaders_cant_download_and_only_their_own_files(
    rig: Rig,
) -> None:
    up = await uploader(rig)
    mine = uuid.UUID((await declare(up)).json()["id"])
    # A recipient's session: 403 on every upload operation.
    address = unique()
    rig.w.transfer(address)
    browser = await rig.w.browser()
    _, session = await rig.w.verify(browser, address)
    recipient = Uploader(up.request_id, address, browser, session)
    for answer in (
        await declare(recipient),
        await part_urls(recipient, mine, [1]),
        await uploaded(recipient, mine),
        await complete(recipient, mine),
    ):
        assert answer.status_code == 403, answer.text
        assert answer.json()["code"] == "permission_denied"
    # An uploader's session: 403 on a download; another request's uploader can't see mine.
    downloading = await up.browser.http.post(
        f"/v1/session/files/{mine}/downloads", json={}, headers=unsafe(up.browser, up.session)
    )
    assert downloading.status_code == 403
    other = await uploader(rig)
    for answer in (
        await part_urls(other, mine, [1]),
        await uploaded(other, mine),
        await complete(other, mine),
    ):
        assert answer.status_code == 404, answer.text
    assert (await session_files(other)).json()["items"] == []
    # Without the CSRF token, an upload call is refused.
    bare = await up.browser.http.post(
        "/v1/session/files",
        json={"display_name": "x", "size": 1},
        headers=up.browser.headers(up.session["id"], origin=WEB_ORIGIN),
    )
    assert bare.status_code == 403
    assert bare.json()["code"] == "csrf_failed"


async def test_the_member_deletes_a_received_file_early_and_its_download_stops(rig: Rig) -> None:
    up = await uploader(rig)
    data = os.urandom(SIZE)
    file_id = await upload(rig, up, "a.pdf", data)
    await rig.scan(file_id, data)
    owner = rig.member()
    granted = (await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})).json()
    before = file_row(rig, file_id)
    deleted = await rig.as_member(owner, "DELETE", f"/v1/files/{file_id}")
    assert deleted.status_code == 204, deleted.text
    after = file_row(rig, file_id)
    assert after["removed_at"] is not None
    assert after["delete_after"] < before["delete_after"], "moved forward"
    assert after["retention_until"] == before["retention_until"]
    assert (await rig.as_member(owner, "GET", granted["url"])).status_code == 404
    assert (await rig.as_member(owner, "GET", f"/v1/files/{file_id}")).status_code == 404
    again = await rig.as_member(owner, "DELETE", f"/v1/files/{file_id}")
    assert again.status_code == 204
    assert [a for a, _ in actions(rig, file_id)].count("file.removed") == 1
    assert (await session_files(up)).json()["items"] == []


async def test_a_file_past_its_retention_is_gone_before_the_job_deletes_it(rig: Rig) -> None:
    up = await uploader(rig)
    [file_id] = seed_received(rig, up.request_id, size=SIZE)
    rig.w.content.put(f"tenants/{rig.tenant.id}/files/{file_id}", "version-1", os.urandom(SIZE))
    owner = rig.member()
    granted = await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})
    assert granted.status_code == 200, granted.text
    rig.w.db.sql(
        "UPDATE files SET retention_until = now() - interval '1 second', "
        "delete_after = now() - interval '1 second' WHERE id = :id",
        id=file_id,
    )
    url = granted.json()["url"]
    assert (await rig.as_member(owner, "GET", url)).status_code == 404
    again = await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})
    assert again.status_code == 404


async def test_an_ended_member_session_stops_its_grant(rig: Rig) -> None:
    up = await uploader(rig)
    [file_id] = seed_received(rig, up.request_id, size=SIZE)
    rig.w.content.put(f"tenants/{rig.tenant.id}/files/{file_id}", "version-1", os.urandom(SIZE))
    owner = rig.member()
    granted = (await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})).json()
    rig.w.db.sql(
        "UPDATE member_sessions SET revoked_at = now(), revoked_reason = 'signed_out' "
        "WHERE id = :id",
        id=owner.session_id,
    )
    ended = await rig.as_member(owner, "GET", granted["url"])
    assert ended.status_code == 401
    assert ended.json()["code"] == "session_expired"


# ---- the member's download with every caller of authn and authz 9.2 ----


def callers(rig: Rig, other_tenant: Tenant) -> dict[str, Caller | None]:
    tenant = rig.tenant

    def member(user: uuid.UUID, role: Role, **kwargs: Any) -> Caller:
        return Caller.member(
            tenant_id=kwargs.pop("tenant_id", tenant.id),
            user_id=user,
            role=role,
            auth_method=kwargs.pop("method", AuthMethod.PASSKEY),
            auth_time=datetime.now(UTC) - kwargs.pop("ago", timedelta(minutes=1)),
            session_id=uuid.uuid4(),
        )

    return {
        "no_credential": None,
        "member": member(tenant.member, Role.MEMBER),
        "admin_passkey": member(tenant.admin, Role.ADMIN),
        "admin_totp": member(tenant.admin, Role.ADMIN, method=AuthMethod.PASSWORD_TOTP),
        "admin_stale": member(tenant.admin, Role.ADMIN, ago=timedelta(minutes=16)),
        "admin_other_tenant": member(other_tenant.admin, Role.ADMIN, tenant_id=other_tenant.id),
        "api_key": Caller(
            CallerKind.API_KEY,
            tenant_id=tenant.id,
            user_id=tenant.target,
            credential_id=uuid.uuid4(),
            scopes=frozenset({"upload_requests:read", "upload_requests:write"}),
        ),
        "recipient": Caller(
            CallerKind.RECIPIENT,
            tenant_id=tenant.id,
            subject=Subject.recipient(uuid.uuid4()),
            credential_id=uuid.uuid4(),
        ),
        "uploader": Caller(
            CallerKind.UPLOADER,
            tenant_id=tenant.id,
            subject=Subject.upload_request(uuid.uuid4()),
            credential_id=uuid.uuid4(),
        ),
        "operator": Caller(CallerKind.OPERATOR, credential_id=uuid.uuid4()),
    }


GRANT_ROW = {
    "no_credential": 401,
    "member": 404,
    "admin_passkey": 403,
    "admin_totp": 404,
    "admin_stale": 403,
    "admin_other_tenant": 404,
    "api_key": 403,
    "recipient": 401,
    "uploader": 401,
    "operator": 401,
}
"""`createReceivedFileDownload`: Own for a member and an admin alike, a member session only. An
admin acting as one sees the file, so 403; one acting as a member (TOTP), another member and
another tenant can't, so 404. A live API key is a credential the member routes read, so it is
refused with 403 (#215, `_web_only`); link sessions and operators hold no credential it takes."""


CONTENT_ROW = {"api_key": 403}
"""`getReceivedFileDownloadContent` refuses a key as `createReceivedFileDownload` does."""


async def test_the_member_download_answers_every_caller_as_table_6_3_says(rig: Rig) -> None:
    up = await uploader(rig)
    [file_id] = seed_received(rig, up.request_id, size=SIZE)
    rig.w.content.put(f"tenants/{rig.tenant.id}/files/{file_id}", "version-1", os.urandom(SIZE))
    owner = rig.member()
    granted = await rig.as_member(owner, "POST", f"/v1/files/{file_id}/downloads", json={})
    assert granted.status_code == 200, granted.text
    url = granted.json()["url"]
    for name, caller in callers(rig, seed_tenant(rig.w.db)).items():
        who = None if caller is None else Member(caller, caller.credential_id or uuid.uuid4())
        answer = await rig.as_member(who, "POST", f"/v1/files/{file_id}/downloads", json={})
        assert answer.status_code == GRANT_ROW[name], (name, answer.text)
        content = await rig.as_member(who, "GET", url)
        assert content.status_code == CONTENT_ROW.get(
            name, 401 if GRANT_ROW[name] == 401 else 404
        ), name
        if answer.status_code == 403:
            assert answer.json()["code"] == "permission_denied"
    [(grants,)] = rig.w.db.sql("SELECT count(*) FROM download_grants WHERE file_id = :f", f=file_id)
    assert grants == 1, "no refused caller got a grant"


async def test_the_uploaders_operations_need_the_uploaders_link_session(rig: Rig) -> None:
    up = await uploader(rig)
    mine = uuid.UUID((await declare(up)).json()["id"])
    # A member's caller holds no link session: every /session call is 401 without one.
    member = rig.member()
    for method, path in (
        ("POST", "/v1/session/files"),
        ("POST", f"/v1/session/files/{mine}/parts"),
        ("GET", f"/v1/session/files/{mine}/parts"),
        ("POST", f"/v1/session/files/{mine}/complete"),
    ):
        answer = await rig.as_member(member, method, path, json={} if method == "POST" else None)
        assert answer.status_code == 401, (method, path)
        assert answer.json()["code"] == "authentication_required"


async def test_a_received_file_over_2_gb_is_scan_failed_at_once_and_told_as_blocked(
    rig: Rig,
) -> None:
    up = await uploader(rig)
    size = 2_500_000_000
    declared = await declare(up, "huge.iso", size)
    assert declared.status_code == 201, declared.text
    file_id = declared.json()["id"]
    plan = declared.json()["upload"]
    uploading = upload_id(rig, file_id)
    for number in range(1, plan["part_count"] + 1):
        last = size - (plan["part_count"] - 1) * plan["part_size"]
        rig.objects.put_part(
            uploading, number, plan["part_size"] if number < plan["part_count"] else last
        )
    done = await complete(up, file_id)
    assert done.status_code == 200, done.text
    assert done.json()["state"] == "scan_failed"
    [(detail, storage)] = rig.w.db.sql(
        "SELECT scan_detail, storage_class FROM files WHERE id = :id", id=uuid.UUID(file_id)
    )
    assert (detail, storage) == ("large_file_scanning_unavailable", "large")
    [(blocked,)] = rig.w.db.sql(
        "SELECT blocked_since_notice FROM upload_requests WHERE id = :id", id=up.request_id
    )
    assert blocked == 1
    assert notices_due(rig, up.request_id) == [(300,)]
