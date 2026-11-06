"""`getFile` and `getFileInspection` through the routes (#175, #176; FR-16, FR-18, FR-19, FR-36,
FR-47, FR-53).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import httpx2 as httpx
import pytest

from member_fixtures import app_for, seed_user, session_caller
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.models import Role
from sft.service.caller import Caller, CallerKind
from transfer_fixtures import seed_file, seed_finding, seed_transfer

pytestmark = pytest.mark.anyio


@dataclass
class World:
    db: ScratchDatabase
    client: httpx.AsyncClient
    tenant_id: uuid.UUID
    users: dict[str, Caller]
    current: list[Caller | None] = field(default_factory=lambda: [None])

    def act_as(self, name: str) -> None:
        self.current[0] = self.users[name]

    def transfer(self, **options: object) -> uuid.UUID:
        owner = self.users["alice"].user_id
        assert owner is not None
        return seed_transfer(self.db, self.tenant_id, owner, **options)[0]  # type: ignore[arg-type]


def key(tenant_id: uuid.UUID, owner: uuid.UUID | None, *scopes: str) -> Caller:
    return Caller(
        CallerKind.API_KEY,
        tenant_id=tenant_id,
        user_id=owner,
        credential_id=uuid.uuid4(),
        scopes=frozenset(scopes),
    )


@pytest.fixture
async def w(migrated_db: ScratchDatabase, api_db: Database) -> AsyncIterator[World]:
    tenant_id = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id
    )
    users = {
        name: session_caller(tenant_id, seed_user(migrated_db, tenant_id, role=role.value), role)
        for name, role in (("alice", Role.MEMBER), ("bob", Role.MEMBER), ("ada", Role.ADMIN))
    }
    other = uuid.uuid4()
    migrated_db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=other)
    users["eve"] = session_caller(other, seed_user(migrated_db, other, role="admin"), Role.ADMIN)
    alice = users["alice"].user_id
    users["key_transfers"] = key(tenant_id, alice, "transfers:read")
    users["key_uploads"] = key(tenant_id, alice, "upload_requests:read")
    current: list[Caller | None] = [users["alice"]]
    transport = httpx.ASGITransport(app=app_for(api_db, lambda: current[0]))
    async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as client:
        yield World(migrated_db, client, tenant_id, users, current)


async def test_get_file_shows_the_state_shareable_and_the_scan_detail(w: World) -> None:
    transfer_id = w.transfer(state="held")
    large = seed_file(
        w.db,
        w.tenant_id,
        transfer_id,
        state="scan_failed",
        size=3_000_000_000,
        storage_class="large",
    )
    w.db.sql(
        "UPDATE files SET scan_detail = 'large_file_scanning_unavailable' WHERE id = :id", id=large
    )
    body = (await w.client.get(f"/v1/files/{large}")).json()
    assert (body["state"], body["shareable"], body["scan_detail"]) == (
        "scan_failed",
        False,
        "large_file_scanning_unavailable",
    )
    allowed = seed_file(
        w.db,
        w.tenant_id,
        transfer_id,
        state="unscannable",
        unscannable_allowed=True,
        inspection_state="not_inspected",
    )
    body = (await w.client.get(f"/v1/files/{allowed}")).json()
    # Shareable with FR-18's warning, which the web app shows from the state.
    assert (body["state"], body["shareable"], body["scan_engine"]) == (
        "unscannable",
        True,
        "clamav",
    )
    assert body["inspection"]["state"] == "not_inspected"


async def test_who_sees_a_file(w: World) -> None:
    transfer_id = w.transfer()
    file_id = seed_file(w.db, w.tenant_id, transfer_id, state="clean")
    expected = {
        "alice": 200,
        "bob": 404,
        "ada": 200,
        "eve": 404,
        "key_transfers": 200,
        "key_uploads": 404,  # its scope reaches received files only
    }
    for name, status in expected.items():
        w.act_as(name)
        for path in (f"/v1/files/{file_id}", f"/v1/files/{file_id}/inspection"):
            assert (await w.client.get(path)).status_code == status, (name, path)


async def test_get_file_inspection_gives_counts_and_reasons(w: World) -> None:
    transfer_id = w.transfer()
    file_id = seed_file(w.db, w.tenant_id, transfer_id, state="clean", inspection_state="partial")
    w.db.sql(
        "UPDATE files SET inspection_reasons = ARRAY['limit_exceeded'], "
        "inspection_engine_version = '2.banks-1' WHERE id = :id",
        id=file_id,
    )
    seed_finding(w.db, w.tenant_id, file_id, "jp_my_number", high=2)
    response = await w.client.get(f"/v1/files/{file_id}/inspection")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "partial"
    assert body["reasons"] == ["limit_exceeded"]
    assert body["engine_version"] == "2.banks-1"
    assert body["policy_version"] is None  # DLP-4 makes the tenant's policy and its versions
    assert body["findings"] == [
        {
            "detector": "jp_my_number",
            "detector_name": "My Number (Individual Number)",
            "count_low": 0,
            "count_medium": 0,
            "count_high": 2,
            "details_visible": False,
        }
    ]
    japanese = await w.client.get(
        f"/v1/files/{file_id}/inspection", headers={"Accept-Language": "ja"}
    )
    assert japanese.json()["findings"][0]["detector_name"] == "マイナンバー・個人番号"
    # The file shows its detectors, and stays shareable: partial counts (FR-47).
    summary = (await w.client.get(f"/v1/files/{file_id}")).json()
    assert summary["shareable"] is True
    assert summary["inspection"] == {
        "state": "partial",
        "reasons": ["limit_exceeded"],
        "dlp_blocked": False,
        "detectors": ["jp_my_number"],
    }


async def test_a_pending_inspection_has_no_time(w: World) -> None:
    transfer_id = w.transfer()
    file_id = seed_file(w.db, w.tenant_id, transfer_id, state="scanning")
    body = (await w.client.get(f"/v1/files/{file_id}/inspection")).json()
    assert (body["state"], body["inspected_at"], body["findings"]) == ("pending", None, [])


async def test_a_removed_file_is_gone(w: World) -> None:
    transfer_id = w.transfer()
    file_id = seed_file(w.db, w.tenant_id, transfer_id, state="clean", removed=True)
    assert (await w.client.get(f"/v1/files/{file_id}")).status_code == 404
