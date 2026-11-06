"""Sending, cancelling and reading transfers, the evaluation, the tenant's expiry policy and the
suppression list (#174; data model 2.2, 2.5, 3.2; architecture 4.1).

Real PostgreSQL as `sft_api` through the routes, with fixtures seeded as the superuser
(transfer_fixtures.py). The evaluation's table runs at the service level as the scan worker would,
and in parallel to show the row lock holds.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx2 as httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import event

from member_fixtures import EMAIL_KEYRING, RecordingLimiter, app_for, seed_user, session_caller
from object_fixtures import FakeObjects
from pg import ScratchDatabase
from sft.data import audit, suppressions
from sft.data.audit import Actor, Target
from sft.data.database import Database
from sft.data.models import ActorType, Role, SuppressionReason, TransferState
from sft.data.roles import API, NOTIFY, SCAN
from sft.data.scope import Scope
from sft.service import evaluation
from sft.service import transfers as transfers_service
from sft.service.caller import AuthMethod, Caller, CallerKind
from sft.service.evaluation import Outcome
from sft.service.rate_limits.limits import KeyType
from sft.service.transfers import describe_duration
from transfer_fixtures import (
    actions,
    outbox_topics,
    seed_file,
    seed_finding,
    seed_transfer,
    transfer_row,
)

pytestmark = pytest.mark.anyio


@dataclass
class World:
    db: ScratchDatabase
    client: httpx.AsyncClient
    app: FastAPI
    limiter: RecordingLimiter
    tenant_id: uuid.UUID
    users: dict[str, Caller]
    current: list[Caller | None] = field(default_factory=lambda: [None])

    def act_as(self, name: str) -> None:
        self.current[0] = self.users[name]

    def user(self, name: str) -> uuid.UUID:
        user_id = self.users[name].user_id
        assert user_id is not None
        return user_id

    def transfer(
        self, owner: str = "alice", **options: object
    ) -> tuple[uuid.UUID, list[uuid.UUID]]:
        return seed_transfer(self.db, self.tenant_id, self.user(owner), **options)  # type: ignore[arg-type]

    def file(self, transfer_id: uuid.UUID, **options: object) -> uuid.UUID:
        return seed_file(self.db, self.tenant_id, transfer_id, **options)  # type: ignore[arg-type]


def add_tenant(
    db: ScratchDatabase, *names: tuple[str, Role]
) -> tuple[uuid.UUID, dict[str, Caller]]:
    tenant_id = uuid.uuid4()
    db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id)
    callers = {}
    for name, role in names:
        callers[name] = session_caller(tenant_id, seed_user(db, tenant_id, role=role.value), role)
    return tenant_id, callers


@pytest.fixture
async def w(migrated_db: ScratchDatabase, api_db: Database) -> AsyncIterator[World]:
    tenant_id, users = add_tenant(
        migrated_db, ("alice", Role.MEMBER), ("bob", Role.MEMBER), ("ada", Role.ADMIN)
    )
    _, outsiders = add_tenant(migrated_db, ("eve", Role.ADMIN))
    users.update(outsiders)
    users["key"] = Caller(
        CallerKind.API_KEY,
        tenant_id=tenant_id,
        user_id=users["alice"].user_id,
        credential_id=uuid.uuid4(),
        scopes=frozenset({"transfers:read", "transfers:write"}),
    )
    users["ada_totp"] = session_caller(
        tenant_id, users["ada"].user_id or uuid.uuid4(), Role.ADMIN, AuthMethod.PASSWORD_TOTP
    )
    limiter = RecordingLimiter()
    current: list[Caller | None] = [users["alice"]]
    app = app_for(api_db, lambda: current[0], limiter, FakeObjects())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as client:
        yield World(migrated_db, client, app, limiter, tenant_id, users, current)


async def send(w: World, transfer_id: uuid.UUID) -> httpx.Response:
    return await w.client.post(f"/v1/transfers/{transfer_id}/send")


# ---- sendTransfer ----


async def test_a_draft_whose_files_are_scanning_is_submitted(w: World) -> None:
    transfer_id, _ = w.transfer(expires_in=timedelta(days=3))
    w.file(transfer_id, state="scanning")
    w.file(transfer_id, state="scanning")
    response = await send(w, transfer_id)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "submitted"
    row = transfer_row(w.db, transfer_id)
    assert row["state"] == "submitted"
    assert row["expires_at"] == row["submitted_at"] + timedelta(days=3)  # type: ignore[operator]
    assert body["expires_at"] is not None
    assert body["submitted_at"] is not None
    assert actions(w.db, transfer_id) == ["transfer.submitted"]
    # Sending again changes nothing.
    again = await send(w, transfer_id)
    assert again.status_code == 200
    assert again.json()["submitted_at"] == body["submitted_at"]
    assert actions(w.db, transfer_id) == ["transfer.submitted"]


@pytest.mark.parametrize("state", ["uploading", "completing"])
async def test_a_send_waits_for_every_upload(w: World, state: str) -> None:
    transfer_id, _ = w.transfer()
    w.file(transfer_id, state="scanning")
    w.file(transfer_id, state=state)
    response = await send(w, transfer_id)
    assert response.status_code == 409
    assert response.json()["code"] == "upload_incomplete"
    assert transfer_row(w.db, transfer_id)["state"] == "draft"


async def test_a_send_needs_a_counted_file(w: World) -> None:
    transfer_id, _ = w.transfer()
    w.file(transfer_id, state="rejected")
    w.file(transfer_id, state="scanning", removed=True)
    response = await send(w, transfer_id)
    assert response.status_code == 409
    assert response.json()["code"] == "transfer_empty"


@pytest.mark.parametrize("state", ["submitted", "held", "sent", "awaiting_confirmation"])
async def test_a_send_after_the_draft_returns_it_unchanged(w: World, state: str) -> None:
    transfer_id, _ = w.transfer(state=state)
    w.file(transfer_id, state="clean")
    before = transfer_row(w.db, transfer_id)
    response = await send(w, transfer_id)
    assert response.status_code == 200
    assert response.json()["state"] == state
    assert transfer_row(w.db, transfer_id) == before
    assert w.limiter.costs == [1]  # only the route's group H; no email counted


@pytest.mark.parametrize(
    ("state", "code"),
    [
        ("cancelled", "invalid_state"),
        ("revoked", "transfer_revoked"),
        ("expired", "transfer_expired"),
    ],
)
async def test_an_ended_transfer_isnt_sent(w: World, state: str, code: str) -> None:
    transfer_id, _ = w.transfer(state=state)
    response = await send(w, transfer_id)
    assert response.status_code == 409
    assert response.json()["code"] == code


async def test_a_draft_whose_files_are_shareable_is_sent_at_once(w: World) -> None:
    transfer_id, recipients = w.transfer(
        recipients=("a@example.test", "b@example.test"), download_limit=3
    )
    files = [w.file(transfer_id, state="clean") for _ in range(2)]
    w.file(transfer_id, state="rejected")
    response = await send(w, transfer_id)
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "sent"
    counters = w.db.sql(
        "SELECT recipient_id, file_id, download_limit, count FROM download_counters "
        "WHERE tenant_id = :t ORDER BY 1, 2",
        t=w.tenant_id,
    )
    assert counters == sorted((r, f, 3, 0) for r in recipients for f in files)
    states = w.db.sql(
        "SELECT delivery_state FROM transfer_recipients WHERE transfer_id = :id", id=transfer_id
    )
    assert states == [("queued",), ("queued",)]
    assert outbox_topics(w.db, "transfer_id", transfer_id) == ["transfer.sent"]
    assert actions(w.db, transfer_id) == ["transfer.submitted", "transfer.sent"]


async def test_a_draft_with_a_blocked_file_is_held(w: World) -> None:
    transfer_id, _ = w.transfer()
    w.file(transfer_id, state="clean")
    w.file(transfer_id, state="infected")
    response = await send(w, transfer_id)
    body = response.json()
    assert (body["state"], body["hold_reason"]) == ("held", "file_blocked")
    assert sorted((f["state"], f["shareable"]) for f in body["files"]) == [
        ("clean", True),
        ("infected", False),
    ]
    assert outbox_topics(w.db, "transfer_id", transfer_id) == ["transfer.held"]


async def test_findings_dont_gate_sending_before_dlp_4(w: World) -> None:
    transfer_id, _ = w.transfer()
    file_id = w.file(transfer_id, state="clean")
    seed_finding(w.db, w.tenant_id, file_id, "jp_my_number", high=3)
    response = await send(w, transfer_id)
    assert response.json()["state"] == "sent"
    assert response.json()["dlp"] is None  # no decision before DLP-4
    assert response.json()["files"][0]["inspection"]["detectors"] == ["jp_my_number"]


async def test_only_the_owner_sends(w: World) -> None:
    transfer_id, _ = w.transfer()
    w.file(transfer_id, state="scanning")
    w.act_as("bob")
    assert (await send(w, transfer_id)).status_code == 404
    w.act_as("ada")
    assert (await send(w, transfer_id)).status_code == 403
    w.act_as("eve")
    assert (await send(w, transfer_id)).status_code == 404
    assert transfer_row(w.db, transfer_id)["state"] == "draft"


async def test_a_send_counts_one_email_per_recipient_against_group_g(w: World) -> None:
    transfer_id, _ = w.transfer(recipients=("a@example.test", "b@example.test", "c@example.test"))
    w.file(transfer_id, state="scanning")
    assert (await send(w, transfer_id)).status_code == 200
    # Read first, without the row lock and charging nothing; then charged all at once.
    assert w.limiter.peeks == [
        [
            ("G.caller_emails", 3),
            ("G.address_link_emails", 1),
            ("G.address_link_emails", 1),
            ("G.address_link_emails", 1),
            ("G.tenant_emails", 3),
        ]
    ]
    ids = [ids for ids, _ in w.limiter.checks]
    assert ids == [
        ("H.caller_requests", "H.tenant_requests"),
        ("G.caller_emails",),
        ("G.address_link_emails",),
        ("G.address_link_emails",),
        ("G.address_link_emails",),
        ("G.tenant_emails",),
    ]
    assert w.limiter.costs == [1, 3, 1, 1, 1, 3]
    addresses = {str(keys[KeyType.TENANT_EMAIL]) for _, keys in w.limiter.checks[2:5]}
    assert len(addresses) == 3


async def test_a_refused_send_leaves_the_draft(w: World) -> None:
    transfer_id, _ = w.transfer()
    w.file(transfer_id, state="scanning")
    w.limiter.refuse = True
    response = await send(w, transfer_id)
    assert response.status_code == 429
    assert transfer_row(w.db, transfer_id)["state"] == "draft"


# ---- the evaluation's table (data model 3.2) ----

CASES = {
    # name: (transfer state, [(file state, unscannable_allowed, inspection, removed)], outcome)
    "neither_submitted_nor_held": ("draft", [("clean", False, None, False)], Outcome.UNCHANGED),
    "no_counted_file": ("submitted", [("clean", False, None, True)], Outcome.DRAFT),
    "only_rejected": ("held", [("rejected", False, None, False)], Outcome.DRAFT),
    "infected": (
        "submitted",
        [("clean", False, None, False), ("infected", False, None, False)],
        Outcome.HELD,
    ),
    "scan_failed": ("submitted", [("scan_failed", False, None, False)], Outcome.HELD),
    "unscannable_blocked": ("submitted", [("unscannable", False, None, False)], Outcome.HELD),
    "inspection_failed": ("submitted", [("clean", False, "failed", False)], Outcome.HELD),
    "held_and_still_blocked": ("held", [("infected", False, None, False)], Outcome.UNCHANGED),
    "still_scanning": (
        "submitted",
        [("clean", False, None, False), ("scanning", False, None, False)],
        Outcome.UNCHANGED,
    ),
    "held_back_to_submitted": (
        "held",
        [("scanning", False, None, False), ("infected", False, None, True)],
        Outcome.SUBMITTED,
    ),
    "every_file_shareable": (
        "submitted",
        [("clean", False, "partial", False), ("unscannable", True, "not_inspected", False)],
        Outcome.SENT,
    ),
    "held_then_shareable": (
        "held",
        [("clean", False, None, False), ("infected", False, None, True)],
        Outcome.SENT,
    ),
}


@pytest.mark.parametrize("name", list(CASES))
async def test_the_evaluation_table(migrated_db: ScratchDatabase, name: str) -> None:
    tenant_id, users = add_tenant(migrated_db, ("alice", Role.MEMBER))
    owner = users["alice"].user_id
    assert owner is not None
    state, file_states, expected = CASES[name]
    transfer_id, _ = seed_transfer(migrated_db, tenant_id, owner, state=state)
    for file_state, allowed, inspection, removed in file_states:
        seed_file(
            migrated_db,
            tenant_id,
            transfer_id,
            state=file_state,
            unscannable_allowed=allowed,
            inspection_state=inspection,
            removed=removed,
        )
    # As the scan worker would: its own role, which reads no ciphertext (revision 0009).
    database = Database.connect(migrated_db.url(SCAN), pool_size=1)
    try:
        async with database.transaction(Scope.tenant(tenant_id)) as session:
            outcome = await evaluation.evaluate(
                session, transfer_id, actor=Actor(ActorType.SYSTEM), now=datetime.now(UTC)
            )
    finally:
        await database.dispose()
    assert outcome is expected
    row = transfer_row(migrated_db, transfer_id)
    final = {
        Outcome.UNCHANGED: state,
        Outcome.DRAFT: "draft",
        Outcome.HELD: "held",
        Outcome.SUBMITTED: "submitted",
        Outcome.SENT: "sent",
    }[expected]
    assert row["state"] == final
    if expected is Outcome.DRAFT:
        assert (row["submitted_at"], row["expires_at"]) == (None, None)
        assert outbox_topics(migrated_db, "transfer_id", transfer_id) == [
            "transfer.returned_to_draft"
        ]


async def test_an_expired_transfer_is_left_to_the_lifecycle_job(
    migrated_db: ScratchDatabase,
) -> None:
    tenant_id, users = add_tenant(migrated_db, ("alice", Role.MEMBER))
    owner = users["alice"].user_id
    assert owner is not None
    transfer_id, _ = seed_transfer(
        migrated_db, tenant_id, owner, state="submitted", expires_at_offset=-timedelta(minutes=1)
    )
    seed_file(migrated_db, tenant_id, transfer_id, state="clean")
    database = Database.connect(migrated_db.url(SCAN), pool_size=1)
    try:
        async with database.transaction(Scope.tenant(tenant_id)) as session:
            outcome = await evaluation.evaluate(
                session, transfer_id, actor=Actor(ActorType.SYSTEM), now=datetime.now(UTC)
            )
    finally:
        await database.dispose()
    assert outcome is Outcome.EXPIRED
    assert transfer_row(migrated_db, transfer_id)["state"] == "submitted"


async def test_two_last_scans_finishing_together_send_once(migrated_db: ScratchDatabase) -> None:
    tenant_id, users = add_tenant(migrated_db, ("alice", Role.MEMBER))
    owner = users["alice"].user_id
    assert owner is not None
    transfer_id, _ = seed_transfer(migrated_db, tenant_id, owner, state="submitted")
    for _ in range(2):
        seed_file(migrated_db, tenant_id, transfer_id, state="clean")
    database = Database.connect(migrated_db.url(SCAN), pool_size=2)
    started = asyncio.Event()

    async def one() -> Outcome:
        async with database.transaction(Scope.tenant(tenant_id)) as session:
            started.set()
            return await evaluation.evaluate(
                session, transfer_id, actor=Actor(ActorType.SYSTEM), now=datetime.now(UTC)
            )

    try:
        outcomes = await asyncio.gather(one(), one())
    finally:
        await database.dispose()
    assert sorted(outcomes) == sorted([Outcome.SENT, Outcome.UNCHANGED])
    assert outbox_topics(migrated_db, "transfer_id", transfer_id) == ["transfer.sent"]
    [(count,)] = migrated_db.sql(
        "SELECT count(*) FROM download_counters WHERE tenant_id = :t", t=tenant_id
    )
    assert count == 2


# ---- deleteFile on a submitted or held transfer ----


async def test_removing_the_blocked_file_of_a_held_transfer_sends_the_rest(w: World) -> None:
    transfer_id, _ = w.transfer(state="held")
    w.file(transfer_id, state="clean")
    blocked = w.file(transfer_id, state="infected")
    response = await w.client.delete(f"/v1/files/{blocked}")
    assert response.status_code == 204, response.text
    assert transfer_row(w.db, transfer_id)["state"] == "sent"
    assert outbox_topics(w.db, "transfer_id", transfer_id) == ["transfer.sent"]


async def test_removing_the_last_file_returns_the_transfer_to_draft(w: World) -> None:
    transfer_id, _ = w.transfer(state="held")
    blocked = w.file(transfer_id, state="infected")
    assert (await w.client.delete(f"/v1/files/{blocked}")).status_code == 204
    row = transfer_row(w.db, transfer_id)
    assert (row["state"], row["submitted_at"], row["expires_at"]) == ("draft", None, None)
    assert outbox_topics(w.db, "transfer_id", transfer_id) == ["transfer.returned_to_draft"]
    assert actions(w.db, transfer_id) == ["transfer.returned_to_draft"]


async def test_no_file_is_removed_once_the_transfer_is_sent(w: World) -> None:
    transfer_id, _ = w.transfer(state="sent")
    file_id = w.file(transfer_id, state="clean")
    response = await w.client.delete(f"/v1/files/{file_id}")
    assert response.status_code == 409
    assert response.json()["code"] == "invalid_state"


# ---- cancelTransfer ----


@pytest.mark.parametrize("state", ["draft", "held", "awaiting_confirmation", "pending_approval"])
async def test_a_transfer_that_wasnt_sent_is_cancelled(w: World, state: str) -> None:
    transfer_id, _ = w.transfer(state=state)
    files = [w.file(transfer_id, state="clean"), w.file(transfer_id, state="infected")]
    response = await w.client.post(f"/v1/transfers/{transfer_id}/cancel")
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "cancelled"
    row = transfer_row(w.db, transfer_id)
    assert row["ended_at"] is not None
    assert row["hold_reason"] is None
    due = w.db.sql(
        "SELECT delete_after IS NOT NULL FROM files WHERE transfer_id = :id", id=transfer_id
    )
    assert due == [(True,)] * len(files)
    again = await w.client.post(f"/v1/transfers/{transfer_id}/cancel")
    assert again.status_code == 200
    assert actions(w.db, transfer_id) == ["transfer.cancelled"]


async def test_cancelling_a_draft_rejects_its_open_uploads(w: World) -> None:
    transfer_id, _ = w.transfer()
    uploading = w.file(transfer_id, state="uploading")
    completing = w.file(transfer_id, state="completing")
    reserved = w.db.sql(
        "SELECT bytes_reserved FROM tenant_usage WHERE tenant_id = :t", t=w.tenant_id
    )
    assert (await w.client.post(f"/v1/transfers/{transfer_id}/cancel")).status_code == 200
    states = w.db.sql("SELECT state FROM files WHERE id IN (:a, :b)", a=uploading, b=completing)
    assert states == [("rejected",), ("rejected",)]
    after = w.db.sql("SELECT bytes_reserved FROM tenant_usage WHERE tenant_id = :t", t=w.tenant_id)
    assert after[0][0] == reserved[0][0] - 20  # type: ignore[operator]
    assert actions(w.db, uploading) == ["file.rejected"]


@pytest.mark.parametrize("state", ["submitted", "sent", "revoked"])
async def test_a_transfer_in_flight_isnt_cancelled(w: World, state: str) -> None:
    transfer_id, _ = w.transfer(state=state)
    response = await w.client.post(f"/v1/transfers/{transfer_id}/cancel")
    assert response.status_code == 409
    assert response.json()["code"] == "invalid_state"


async def test_an_admin_cancels_no_other_members_transfer(w: World) -> None:
    transfer_id, _ = w.transfer()
    w.act_as("ada")
    response = await w.client.post(f"/v1/transfers/{transfer_id}/cancel")
    assert response.status_code == 403
    assert transfer_row(w.db, transfer_id)["state"] == "draft"


# ---- getTransfer, listTransfers ----


async def test_get_transfer_shows_each_files_state_and_reads_expiry(w: World) -> None:
    transfer_id, _ = w.transfer(state="sent", expires_at_offset=-timedelta(seconds=1))
    w.file(transfer_id, state="clean")
    w.file(
        transfer_id, state="unscannable", unscannable_allowed=True, inspection_state="not_inspected"
    )
    response = await w.client.get(f"/v1/transfers/{transfer_id}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "expired"  # before any job records it
    assert [(f["state"], f["shareable"]) for f in body["files"]] == [
        ("clean", True),
        ("unscannable", True),
    ]
    assert transfer_row(w.db, transfer_id)["state"] == "sent"


async def test_who_sees_a_transfer(w: World) -> None:
    transfer_id, _ = w.transfer()
    for name, status in (("alice", 200), ("bob", 404), ("ada", 200), ("eve", 404), ("key", 200)):
        w.act_as(name)
        assert (await w.client.get(f"/v1/transfers/{transfer_id}")).status_code == status, name


async def test_list_transfers_scope_tenant_is_for_admins_and_keys(w: World) -> None:
    mine, _ = w.transfer()
    theirs, _ = w.transfer(owner="bob", state="sent", expires_at_offset=-timedelta(minutes=1))
    w.act_as("alice")
    own = await w.client.get("/v1/transfers")
    assert [t["id"] for t in own.json()["items"]] == [str(mine)]
    assert (await w.client.get("/v1/transfers?scope=tenant")).status_code == 403
    w.act_as("ada_totp")
    refused = await w.client.get("/v1/transfers?scope=tenant")
    assert (refused.status_code, refused.json()["code"]) == (403, "passkey_required")
    for name in ("ada", "key"):
        w.act_as(name)
        page = (await w.client.get("/v1/transfers?scope=tenant")).json()
        assert [t["id"] for t in page["items"]] == [str(theirs), str(mine)]
        assert page["items"][0]["state"] == "expired"
    w.act_as("ada")
    expired = (await w.client.get("/v1/transfers?scope=tenant&state=expired")).json()
    assert [t["id"] for t in expired["items"]] == [str(theirs)]


async def test_list_transfers_pages(w: World) -> None:
    made = [w.transfer()[0] for _ in range(3)]
    first = (await w.client.get("/v1/transfers?limit=2")).json()
    assert [t["id"] for t in first["items"]] == [str(t) for t in reversed(made[1:])]
    rest = (await w.client.get(f"/v1/transfers?limit=2&cursor={first['next_cursor']}")).json()
    assert [t["id"] for t in rest["items"]] == [str(made[0])]
    assert rest["next_cursor"] is None
    bad = await w.client.get("/v1/transfers?cursor=%%%")
    assert (bad.status_code, bad.json()["code"]) == (400, "invalid_cursor")


# ---- the tenant's policy: expiry (FR-3, FR-23) ----


async def set_policy(w: World, **body: object) -> httpx.Response:
    w.act_as("ada")
    response = await w.client.patch("/v1/tenant/policy", json=body)
    w.act_as("alice")
    return response


async def create(w: World, **body: object) -> httpx.Response:
    return await w.client.post(
        "/v1/transfers", json={"recipients": [{"email": "partner@example.test"}], **body}
    )


async def test_the_default_expiry_is_7_days_or_the_tenants_maximum(w: World) -> None:
    assert (await create(w)).json()["expires_in"] == "P7D"
    assert (await set_policy(w, max_expiry="P2D")).status_code == 200
    assert (await create(w)).json()["expires_in"] == "P2D"
    refused = await create(w, expires_in="P3D")
    assert (refused.status_code, refused.json()["code"]) == (422, "expiry_out_of_range")
    assert (await create(w, expires_in="P31D")).status_code == 422


async def test_a_send_after_the_maximum_dropped_is_refused(w: World) -> None:
    transfer_id, _ = w.transfer(expires_in=timedelta(days=10))
    w.file(transfer_id, state="scanning")
    assert (await set_policy(w, max_expiry="P5D")).status_code == 200
    response = await send(w, transfer_id)
    assert (response.status_code, response.json()["code"]) == (422, "expiry_out_of_range")
    assert transfer_row(w.db, transfer_id)["state"] == "draft"


async def test_members_and_keys_read_the_policy_and_only_admins_change_it(w: World) -> None:
    for name in ("alice", "key", "ada"):
        w.act_as(name)
        policy = await w.client.get("/v1/tenant/policy")
        assert policy.status_code == 200, name
        assert policy.json()["max_expiry"] == "P30D"
        assert policy.json()["unscannable_policy"] == "block"
        assert policy.json()["received_file_retention_days"] == 30
        assert policy.json()["allowed_domains"] == []
    for name, status in (("alice", 403), ("ada_totp", 403), ("key", 401)):
        w.act_as(name)
        assert (
            await w.client.patch("/v1/tenant/policy", json={"max_expiry": "P1D"})
        ).status_code == status
    changed = await set_policy(
        w, unscannable_policy="allow_with_warning", received_file_retention_days=60
    )
    assert changed.status_code == 200
    assert changed.json()["unscannable_policy"] == "allow_with_warning"
    assert changed.json()["max_expiry"] == "P30D"
    [(details,)] = w.db.sql(
        "SELECT details FROM audit_events "
        "WHERE action = 'tenant_policy.updated' AND tenant_id = :t",
        t=w.tenant_id,
    )
    assert details == {
        "unscannable_policy": "allow_with_warning",
        "received_file_retention_days": 60,
    }


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"max_expiry": "PT30M"},
        {"received_file_retention_days": 91},
        {"allowed_domains": ["example.com"]},
    ],
)
async def test_a_bad_policy_change_is_refused(w: World, body: dict[str, object]) -> None:
    response = await set_policy(w, **body)
    assert response.status_code in (400, 422), response.text


# ---- the suppression list (data model 2.5, abuse 7.4) ----


async def suppress(db: ScratchDatabase, tenant_id: uuid.UUID, email: str) -> None:
    """As the notification worker will record a bounce (M4): its role, the tenant's scope."""
    database = Database.connect(db.url(NOTIFY), pool_size=1)
    try:
        async with database.transaction(Scope.tenant(tenant_id)) as session:
            entry = await suppressions.add_suppression(
                session,
                pseudonym=EMAIL_KEYRING.active(email.lower()),
                key_id=EMAIL_KEYRING.active_key_id,
                reason=SuppressionReason.HARD_BOUNCE,
                expires_at=datetime.now(UTC) + timedelta(days=90),
            )
            await audit.record(
                session,
                action="email_suppression.added",
                actor=Actor(ActorType.SYSTEM),
                target=Target("email_suppression", entry),
            )
    finally:
        await database.dispose()


async def test_a_suppressed_address_is_refused_at_create(w: World) -> None:
    await suppress(w.db, w.tenant_id, "Bounced@Example.test")
    response = await w.client.post(
        "/v1/transfers",
        json={"recipients": [{"email": "ok@example.test"}, {"email": "bounced@example.test"}]},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "recipient_undeliverable"
    assert body["errors"][0]["pointer"] == "#/recipients/1/email"
    stored = w.db.sql("SELECT email_hmac, hmac_key_id FROM email_suppressions")
    assert all("bounced" not in str(value).lower() for row in stored for value in row)


async def test_an_address_suppressed_after_the_draft_is_refused_at_send(w: World) -> None:
    transfer_id, _ = w.transfer(recipients=("late@example.test",))
    w.file(transfer_id, state="scanning")
    await suppress(w.db, w.tenant_id, "late@example.test")
    response = await send(w, transfer_id)
    assert (response.status_code, response.json()["code"]) == (422, "recipient_undeliverable")
    assert transfer_row(w.db, transfer_id)["state"] == "draft"


async def test_another_tenants_suppression_doesnt_count(w: World) -> None:
    other = w.users["eve"].tenant_id
    assert other is not None
    await suppress(w.db, other, "shared@example.test")
    response = await w.client.post(
        "/v1/transfers", json={"recipients": [{"email": "shared@example.test"}]}
    )
    assert response.status_code == 201, response.text


async def test_an_ended_suppression_no_longer_refuses(w: World) -> None:
    await suppress(w.db, w.tenant_id, "old@example.test")
    w.db.sql("UPDATE email_suppressions SET expires_at = now() - interval '1 day'")
    response = await w.client.post(
        "/v1/transfers", json={"recipients": [{"email": "old@example.test"}]}
    )
    assert response.status_code == 201


# ---- review fixes (#174) ----


@pytest.mark.parametrize(
    "body",
    [{"default_locale": "ja"}, {"default_locale": "ja", "max_expiry": "P5D"}],
)
async def test_the_default_locale_can_be_changed_alone_or_with_others(
    w: World, body: dict[str, object]
) -> None:
    response = await set_policy(w, **body)
    assert response.status_code == 200, response.text
    assert response.json()["default_locale"] == "ja"
    assert response.json()["max_expiry"] == body.get("max_expiry", "P30D")
    # New recipients take the tenant's language.
    created = await create(w)
    assert created.json()["recipients"][0]["locale"] == "ja"


@pytest.mark.parametrize(
    ("duration", "words"),
    [
        (timedelta(minutes=90), "1 hour 30 minutes"),
        (timedelta(days=1, hours=12), "1 day 12 hours"),
        (timedelta(hours=1), "1 hour"),
        (timedelta(days=30), "30 days"),
        (timedelta(hours=2, seconds=1), "2 hours 1 second"),
    ],
)
def test_durations_are_described_exactly(duration: timedelta, words: str) -> None:
    assert describe_duration(duration) == words


async def test_the_expiry_refusal_names_the_exact_maximum(w: World) -> None:
    assert (await set_policy(w, max_expiry="PT90M")).status_code == 200
    refused = await create(w, expires_in="PT2H")
    assert refused.status_code == 422
    assert "1 hour 30 minutes" in refused.json()["detail"]


async def test_a_filtered_page_is_one_query_and_pages_stay_right(
    w: World, migrated_db: ScratchDatabase
) -> None:
    # Many transfers that read as expired, around a few that are still sent.
    live = []
    for n in range(30):
        expired = n % 10 != 0
        transfer_id, _ = w.transfer(
            state="sent",
            expires_at_offset=-timedelta(minutes=1) if expired else timedelta(days=1),
        )
        if not expired:
            live.append(transfer_id)
    w.transfer(state="expired")
    database = Database.connect(migrated_db.url(API), pool_size=1)
    statements: list[str] = []

    def count(conn: object, cursor: object, statement: str, *args: object) -> None:
        if "FROM transfers" in statement:
            statements.append(statement)

    event.listen(database._engine.sync_engine, "before_cursor_execute", count)
    try:
        caller = w.users["alice"]
        now = datetime.now(UTC)
        first = await transfers_service.list_transfers(
            database, caller, states=[TransferState.SENT], limit=2, now=now
        )
        assert len(statements) == 1  # one query, however many rows read as expired
        rest = await transfers_service.list_transfers(
            database,
            caller,
            states=[TransferState.SENT],
            cursor=first.next_cursor,
            limit=2,
            now=now,
        )
        expired = await transfers_service.list_transfers(
            database, caller, states=[TransferState.EXPIRED], limit=100, now=now
        )
    finally:
        await database.dispose()
    assert [t.id for t in (*first.items, *rest.items)] == list(reversed(live))
    assert rest.next_cursor is None
    assert all(t.state is TransferState.SENT for t in (*first.items, *rest.items))
    assert len(expired.items) == 28  # 27 read as expired, 1 recorded
    assert {t.state for t in expired.items} == {TransferState.EXPIRED}
