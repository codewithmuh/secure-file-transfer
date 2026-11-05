"""Draft transfers and file uploads through the routes (#114; architecture 4.1, data model 3.1).

Real PostgreSQL as `sft_api`, and an in-memory object store (object_fixtures.py), so a test can
change the transfer while completion is between its phases. tests/test_s3_s3mock.py runs the same
path against S3Mock, and tests/test_authorization_matrix.py every operation with every caller.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import httpx2 as httpx
import pytest
from fastapi import FastAPI

from member_fixtures import RecordingLimiter, app_for, seed_user, session_caller
from object_fixtures import FakeObjects
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.models import Role
from sft.service import uploads
from sft.service.caller import Caller, CallerKind
from sft.service.uploads import UploadPolicy, upload_plan

pytestmark = pytest.mark.anyio

MIB = 1024 * 1024


@dataclass
class World:
    db: ScratchDatabase
    objects: FakeObjects
    client: httpx.AsyncClient
    app: FastAPI
    limiter: RecordingLimiter
    tenant_id: uuid.UUID
    users: dict[str, Caller]
    current: list[Caller | None] = field(default_factory=lambda: [None])

    def act_as(self, name: str | None) -> None:
        self.current[0] = None if name is None else self.users[name]

    def act_with(self, caller: Caller) -> None:
        self.current[0] = caller

    def file_row(self, file_id: str) -> tuple[object, ...]:
        [row] = self.db.sql(
            "SELECT state, s3_upload_id, actual_size, s3_version_id FROM files WHERE id = :id",
            id=uuid.UUID(file_id),
        )
        return row

    def actions(self, target: str) -> list[object]:
        return [
            r[0]
            for r in self.db.sql(
                "SELECT action FROM audit_events WHERE target_id = :id ORDER BY occurred_at, id",
                id=uuid.UUID(target),
            )
        ]

    def reserved(self) -> object:
        rows = self.db.sql(
            "SELECT bytes_reserved FROM tenant_usage WHERE tenant_id = :t", t=self.tenant_id
        )
        return rows[0][0] if rows else 0


def add_tenant(
    db: ScratchDatabase, *names: tuple[str, Role]
) -> tuple[uuid.UUID, dict[str, Caller]]:
    tenant_id = uuid.uuid4()
    db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, :name, 'active')",
        id=tenant_id,
        name=f"transfers-{tenant_id}",
    )
    callers = {}
    for name, role in names:
        user_id = seed_user(db, tenant_id, role=role.value)
        callers[name] = session_caller(tenant_id, user_id, role)
    return tenant_id, callers


@pytest.fixture
async def w(migrated_db: ScratchDatabase, api_db: Database) -> AsyncIterator[World]:
    tenant_id, users = add_tenant(
        migrated_db, ("alice", Role.MEMBER), ("bob", Role.MEMBER), ("ada", Role.ADMIN)
    )
    _, outsiders = add_tenant(migrated_db, ("eve", Role.ADMIN))
    users.update(outsiders)
    objects = FakeObjects()
    limiter = RecordingLimiter()
    current: list[Caller | None] = [users["alice"]]
    app = app_for(
        api_db,
        lambda: current[0],
        limiter,
        objects,
        UploadPolicy(storage_quota=50 * MIB),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as client:
        yield World(migrated_db, objects, client, app, limiter, tenant_id, users, current)


async def draft(w: World) -> str:
    response = await w.client.post(
        "/v1/transfers", json={"recipients": [{"email": "partner@example.test"}]}
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["state"] == "draft"
    assert response.headers["Location"] == f"/v1/transfers/{body['id']}"
    return str(body["id"])


async def add(w: World, transfer_id: str, size: int) -> dict[str, object]:
    response = await w.client.post(
        f"/v1/transfers/{transfer_id}/files",
        json={"display_name": "report.pdf", "size": size, "content_type": "application/pdf"},
    )
    assert response.status_code == 201, response.text
    body: dict[str, object] = response.json()
    return body


def upload_everything(w: World, file_id: str, size: int, *, short_by: int = 0) -> None:
    upload_id = str(w.file_row(file_id)[1])
    part_size, count = upload_plan(size)
    for n in range(1, count + 1):
        part = part_size if n < count else size - part_size * (count - 1)
        w.objects.put_part(upload_id, n, part - (short_by if n == count else 0))


# ---- the happy path ----


async def test_a_file_uploads_in_parts_and_reaches_scanning_with_its_message(w: World) -> None:
    transfer_id = await draft(w)
    size = 12 * MIB + 7
    file = await add(w, transfer_id, size)
    file_id = str(file["id"])
    assert file["state"] == "uploading"
    assert file["display_name"] == "report.pdf"
    assert file["upload"] == {"part_size": 5 * MIB, "part_count": 3}
    assert w.reserved() == size

    parts = await w.client.post(f"/v1/files/{file_id}/parts", json={"part_numbers": [1, 3]})
    assert parts.status_code == 200, parts.text
    sizes = [(p["part_number"], p["size"]) for p in parts.json()["parts"]]
    assert sizes == [(1, 5 * MIB), (3, 2 * MIB + 7)]

    upload_everything(w, file_id, size)
    listed = await w.client.get(f"/v1/files/{file_id}/parts")
    assert listed.status_code == 200
    assert [p["part_number"] for p in listed.json()["parts"]] == [1, 2, 3]

    done = await w.client.post(f"/v1/files/{file_id}/complete")
    assert done.status_code == 200, done.text
    assert done.json()["state"] == "scanning"
    assert w.file_row(file_id)[2:] == (size, "version-1")
    [(topic, payload)] = w.db.sql(
        "SELECT topic, payload FROM outbox WHERE payload->>'file_id' = :id", id=file_id
    )
    assert (topic, payload) == ("file.scan", {"file_id": file_id})
    assert w.actions(file_id) == [
        "file.added",
        "file.part_urls_issued",
        "file.completion_started",
        "file.uploaded",
    ]
    # Completing again is safe and changes nothing.
    again = await w.client.post(f"/v1/files/{file_id}/complete")
    assert again.json()["state"] == "scanning"
    assert len(w.actions(file_id)) == 4


async def test_a_file_over_2_gb_goes_to_the_large_files_bucket(w: World) -> None:
    w.app.state.upload_policy = UploadPolicy(storage_quota=10**10)
    transfer_id = await draft(w)
    size = 2 * 10**9 + 1
    file_id = str((await add(w, transfer_id, size))["id"])
    [(storage_class,)] = w.db.sql("SELECT storage_class FROM files WHERE id = :id", id=file_id)
    assert storage_class == "large"
    upload_everything(w, file_id, size)
    assert (await w.client.post(f"/v1/files/{file_id}/complete")).json()["state"] == "scanning"
    [(topic,)] = w.db.sql("SELECT topic FROM outbox WHERE payload->>'file_id' = :id", id=file_id)
    assert topic == "file.scan_large"


# ---- completion's re-checks ----


async def test_completion_refuses_a_size_mismatch(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, 6 * MIB))["id"])
    upload_everything(w, file_id, 6 * MIB, short_by=1)
    response = await w.client.post(f"/v1/files/{file_id}/complete")
    assert response.status_code == 422
    assert response.json()["code"] == "upload_size_mismatch"
    assert response.headers["content-type"] == "application/problem+json"
    assert w.file_row(file_id)[0] == "rejected"
    assert w.reserved() == 0
    assert w.actions(file_id)[-1] == "file.rejected"


async def test_completion_refuses_a_revoked_transfer(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    upload_everything(w, file_id, MIB)
    w.db.sql("UPDATE transfers SET state = 'revoked' WHERE id = :id", id=uuid.UUID(transfer_id))
    response = await w.client.post(f"/v1/files/{file_id}/complete")
    assert response.status_code == 409
    assert response.json()["code"] == "transfer_revoked"
    assert w.file_row(file_id)[0] == "rejected"
    assert not w.db.sql("SELECT 1 FROM outbox WHERE payload->>'file_id' = :id", id=file_id)


async def test_a_revocation_during_assembly_wins_under_the_row_lock(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    upload_everything(w, file_id, MIB)

    def revoke() -> None:  # lands between phase 1 and phase 3
        w.db.sql("UPDATE transfers SET state = 'revoked' WHERE id = :id", id=uuid.UUID(transfer_id))

    w.objects.before_assemble = revoke
    response = await w.client.post(f"/v1/files/{file_id}/complete")
    assert response.status_code == 409
    assert response.json()["code"] == "transfer_revoked"
    assert w.file_row(file_id)[0] == "rejected"
    assert not w.db.sql("SELECT 1 FROM outbox WHERE payload->>'file_id' = :id", id=file_id)


async def test_a_removal_during_assembly_rejects_the_file(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    upload_everything(w, file_id, MIB)

    def remove() -> None:  # as deleteFile does, between phase 1 and phase 3
        w.db.sql(
            "UPDATE files SET removed_at = now(), delete_after = now() WHERE id = :id",
            id=uuid.UUID(file_id),
        )

    w.objects.before_assemble = remove
    response = await w.client.post(f"/v1/files/{file_id}/complete")
    assert response.status_code == 409
    assert w.file_row(file_id)[0] == "rejected"


async def test_missing_parts_send_the_file_back_to_uploading(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, 11 * MIB))["id"])
    w.objects.put_part(str(w.file_row(file_id)[1]), 1, 5 * MIB)
    response = await w.client.post(f"/v1/files/{file_id}/complete")
    assert response.status_code == 409
    assert response.json()["code"] == "upload_incomplete"
    assert response.json()["current_state"] == "uploading"
    assert w.file_row(file_id)[0] == "uploading"
    assert w.actions(file_id)[-1] == "file.upload_incomplete"


async def test_a_vanished_upload_rejects_the_file(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    w.objects.uploads.pop(str(w.file_row(file_id)[1]))
    response = await w.client.post(f"/v1/files/{file_id}/complete")
    assert response.status_code == 409
    assert w.file_row(file_id)[0] == "rejected"


async def test_an_object_store_outage_leaves_the_file_completing_for_a_retry(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    upload_everything(w, file_id, MIB)
    w.objects.failing = True
    assert (await w.client.post(f"/v1/files/{file_id}/complete")).status_code == 503
    assert w.file_row(file_id)[0] == "completing"
    w.objects.failing = False
    assert (await w.client.post(f"/v1/files/{file_id}/complete")).json()["state"] == "scanning"


# ---- limits and the other operations ----


async def test_a_file_beyond_the_quota_is_refused_and_its_upload_dropped(w: World) -> None:
    transfer_id = await draft(w)
    response = await w.client.post(
        f"/v1/transfers/{transfer_id}/files", json={"display_name": "big.bin", "size": 51 * MIB}
    )
    assert response.status_code == 413
    assert response.json()["code"] == "storage_quota_exceeded"
    assert w.objects.uploads == {}


async def test_an_outage_when_adding_a_file_answers_503(w: World) -> None:
    transfer_id = await draft(w)
    w.objects.failing = True
    response = await w.client.post(
        f"/v1/transfers/{transfer_id}/files", json={"display_name": "a.txt", "size": 10}
    )
    assert response.status_code == 503


async def test_part_numbers_must_be_within_the_plan(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    response = await w.client.post(f"/v1/files/{file_id}/parts", json={"part_numbers": [2]})
    assert response.status_code == 422
    assert response.json()["errors"][0]["pointer"] == "#/part_numbers/0"


async def test_deleting_a_file_releases_its_reservation(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    assert (await w.client.delete(f"/v1/files/{file_id}")).status_code == 204
    assert (await w.client.delete(f"/v1/files/{file_id}")).status_code == 204  # idempotent
    assert w.reserved() == 0
    assert w.actions(file_id)[-1] == "file.removed"
    assert (await w.client.get(f"/v1/files/{file_id}/parts")).status_code == 404
    assert (await w.client.post(f"/v1/files/{file_id}/complete")).status_code == 404


async def test_no_file_changes_on_a_revoked_transfer(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    w.db.sql("UPDATE transfers SET state = 'revoked' WHERE id = :id", id=uuid.UUID(transfer_id))
    for response in (
        await w.client.post(
            f"/v1/transfers/{transfer_id}/files", json={"display_name": "a", "size": 1}
        ),
        await w.client.post(f"/v1/files/{file_id}/parts", json={"part_numbers": [1]}),
        await w.client.delete(f"/v1/files/{file_id}"),
    ):
        assert response.status_code == 409, response.text
        assert response.json()["code"] == "transfer_revoked"


# ---- authorization: 401, then 404 for what the caller can't see, 403 for what it sees ----


async def test_every_operation_answers_401_without_a_caller(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    w.act_as(None)
    for method, path, body in operations(transfer_id, file_id):
        response = await w.client.request(method, path, json=body)
        assert response.status_code == 401, (method, path)


def operations(transfer_id: str, file_id: str) -> list[tuple[str, str, object]]:
    return [
        ("POST", f"/v1/transfers/{transfer_id}/files", {"display_name": "a", "size": 1}),
        ("POST", f"/v1/files/{file_id}/parts", {"part_numbers": [1]}),
        ("GET", f"/v1/files/{file_id}/parts", None),
        ("POST", f"/v1/files/{file_id}/complete", None),
        ("DELETE", f"/v1/files/{file_id}", None),
    ]


@pytest.mark.parametrize(("who", "status"), [("bob", 404), ("ada", 403), ("eve", 404)])
async def test_only_the_owner_changes_a_draft(w: World, who: str, status: int) -> None:
    # bob, a member, can't see alice's draft; ada, an admin, sees it but can't change it; eve is
    # another tenant's admin, and row-level security hides it.
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    w.act_as(who)
    for method, path, body in operations(transfer_id, file_id):
        response = await w.client.request(method, path, json=body)
        assert response.status_code == status, (method, path, response.text)
    w.act_as("alice")
    assert w.file_row(file_id)[0] == "uploading"


async def test_an_api_key_without_write_scope_is_refused(w: World) -> None:
    alice = w.users["alice"]
    key = Caller(
        CallerKind.API_KEY,
        tenant_id=alice.tenant_id,
        user_id=alice.user_id,
        credential_id=uuid.uuid4(),
        scopes=frozenset({"transfers:read"}),
    )
    w.act_with(key)
    response = await w.client.post(
        "/v1/transfers", json={"recipients": [{"email": "partner@example.test"}]}
    )
    assert response.status_code == 403


# ---- Idempotency-Key and rate limits ----


async def test_a_retried_create_transfer_with_its_key_makes_one_draft(w: World) -> None:
    body = {"recipients": [{"email": "partner@example.test"}], "message": "Q3"}
    headers = {"Idempotency-Key": "create-transfer-1"}
    first = await w.client.post("/v1/transfers", json=body, headers=headers)
    again = await w.client.post("/v1/transfers", json=body, headers=headers)
    assert (first.status_code, again.status_code) == (201, 201)
    assert again.json() == first.json()
    assert again.headers["Location"] == first.headers["Location"]
    transfer_id = first.json()["id"]
    assert w.actions(transfer_id) == ["transfer.created"]
    [(count,)] = w.db.sql(
        "SELECT count(*) FROM transfers WHERE tenant_id = :t AND created_by = :u",
        t=w.tenant_id,
        u=w.users["alice"].user_id,
    )
    assert count == 1
    other = await w.client.post("/v1/transfers", json={**body, "message": "Q4"}, headers=headers)
    assert other.status_code == 409
    assert other.json()["code"] == "idempotency_conflict"


async def test_a_retried_add_file_with_its_key_starts_no_second_upload(w: World) -> None:
    transfer_id = await draft(w)
    body = {"display_name": "report.pdf", "size": MIB}
    headers = {"Idempotency-Key": "add-file-1"}
    path = f"/v1/transfers/{transfer_id}/files"
    first = await w.client.post(path, json=body, headers=headers)
    assert first.status_code == 201, first.text
    uploads = dict(w.objects.uploads)
    again = await w.client.post(path, json=body, headers=headers)
    assert again.status_code == 201
    assert again.json()["id"] == first.json()["id"]
    assert again.headers["Location"] == f"/v1/files/{first.json()['id']}"
    assert w.objects.uploads == uploads, "a retry started another multipart upload"
    assert w.reserved() == MIB
    assert w.actions(str(first.json()["id"])) == ["file.added"]
    # The same key on another transfer is another request.
    elsewhere = await w.client.post(
        f"/v1/transfers/{await draft(w)}/files", json=body, headers=headers
    )
    assert elsewhere.status_code == 409
    assert elsewhere.json()["code"] == "idempotency_conflict"


async def test_a_refused_add_file_drops_its_upload_and_keeps_no_key(w: World) -> None:
    transfer_id = await draft(w)
    headers = {"Idempotency-Key": "add-file-quota"}
    body = {"display_name": "big.bin", "size": 51 * MIB}
    refused = await w.client.post(f"/v1/transfers/{transfer_id}/files", json=body, headers=headers)
    assert refused.status_code == 413
    assert len(w.objects.aborted) == 1
    w.app.state.upload_policy = UploadPolicy(storage_quota=60 * MIB)
    retried = await w.client.post(f"/v1/transfers/{transfer_id}/files", json=body, headers=headers)
    assert retried.status_code == 201, retried.text


async def test_uploads_count_against_group_f_and_the_tenant(w: World) -> None:
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    await w.client.get(f"/v1/files/{file_id}/parts")
    await w.client.delete(f"/v1/files/{file_id}")
    bundles = [ids for ids, _ in w.limiter.checks]
    tenant = ("H.caller_requests", "H.tenant_requests")
    upload = ("F.caller_requests", "F.ip_requests", "H.tenant_requests")
    assert bundles == [tenant, upload, upload, tenant]
    alice = w.users["alice"]
    assert {str(alice.user_id), str(alice.tenant_id)} <= set(w.limiter.checks[1][1].values())


async def test_no_part_urls_once_a_completion_moved_the_file_on(
    w: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review fix: a completeUpload that lands between the state check and the URLs wins: 409, no
    # URLs and no audit event.
    transfer_id = await draft(w)
    file_id = str((await add(w, transfer_id, MIB))["id"])
    checked = uploads._require_uploading

    def then_complete(file: object, transfer: object) -> None:
        checked(file, transfer)  # type: ignore[arg-type]
        w.db.sql(
            "UPDATE files SET state = 'completing', completion_started_at = now() WHERE id = :id",
            id=uuid.UUID(file_id),
        )

    monkeypatch.setattr(uploads, "_require_uploading", then_complete)
    response = await w.client.post(f"/v1/files/{file_id}/parts", json={"part_numbers": [1]})
    assert response.status_code == 409, response.text
    assert response.json()["code"] == "invalid_state"
    assert response.json()["current_state"] == "completing"
    assert "file.part_urls_issued" not in w.actions(file_id)
