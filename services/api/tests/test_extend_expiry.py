"""`extendTransferExpiry` (#214; FR-9, FR-3; API README 10; data model 2.2, 2.3, 2.4).

Real PostgreSQL as `sft_api` through the routes, with fixtures seeded as the superuser
(transfer_fixtures.py). The recipient's side runs in the link world of link_fixtures.py: the real
app, the notification worker's emails and a real Valkey, so a recipient verifies and downloads as a
person would, before and after the old expiry.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2 as httpx
import pytest

from link_fixtures import World, unique, w
from member_fixtures import Tenant, client, seed_tenant, session_caller
from pg import ScratchDatabase
from sft.data.models import Role
from sft.service.caller import AuthMethod, Caller, CallerKind
from test_downloads import content, grant, shared
from transfer_fixtures import actions, seed_transfer, transfer_row

pytestmark = pytest.mark.anyio
__all__ = ["w"]  # the link world's fixture, imported for this module's tests


@dataclass
class Api:
    db: ScratchDatabase
    tenant: Tenant
    http: httpx.AsyncClient
    current: list[Caller | None] = field(default_factory=lambda: [None])

    def act_as(self, caller: Caller) -> None:
        self.current[0] = caller

    @property
    def owner(self) -> Caller:
        return session_caller(self.tenant.id, self.tenant.target, Role.MEMBER)

    def transfer(self, state: str = "sent", **options: Any) -> uuid.UUID:
        transfer_id, _ = seed_transfer(
            self.db, self.tenant.id, self.tenant.target, state=state, **options
        )
        return transfer_id

    async def extend(
        self, transfer_id: uuid.UUID, to: datetime | str, **headers: str
    ) -> httpx.Response:
        value = to if isinstance(to, str) else to.isoformat()
        return await self.http.post(
            f"/v1/transfers/{transfer_id}/extend", json={"expires_at": value}, headers=headers
        )


@pytest.fixture
async def api(migrated_db: ScratchDatabase) -> AsyncIterator[Api]:
    tenant = seed_tenant(migrated_db)
    current: list[Caller | None] = [None]
    async with client(migrated_db, lambda: current[0]) as http:
        world = Api(migrated_db, tenant, http, current)
        world.act_as(world.owner)
        yield world


def expiry(db: ScratchDatabase, transfer_id: uuid.UUID) -> tuple[datetime, datetime]:
    row = transfer_row(db, transfer_id)
    submitted, expires = row["submitted_at"], row["expires_at"]
    assert isinstance(submitted, datetime)
    assert isinstance(expires, datetime)
    return submitted, expires


def parsed(response: httpx.Response) -> datetime:
    return datetime.fromisoformat(response.json()["expires_at"])


# ---- the rules ----


@pytest.mark.parametrize(
    "state", ["submitted", "awaiting_confirmation", "pending_approval", "held", "sent"]
)
async def test_extending_moves_expires_at_and_records_both_times(api: Api, state: str) -> None:
    transfer_id = api.transfer(state)
    submitted, before = expiry(api.db, transfer_id)
    later = submitted + timedelta(days=20)
    response = await api.extend(transfer_id, later)
    assert response.status_code == 200, response.text
    assert parsed(response) == later
    assert response.json()["state"] == state
    assert expiry(api.db, transfer_id)[1] == later
    assert actions(api.db, transfer_id) == ["transfer.expiry_extended"]
    [(details,)] = api.db.sql(
        "SELECT details FROM audit_events WHERE target_id = :id", id=transfer_id
    )
    assert isinstance(details, dict)
    assert datetime.fromisoformat(details["from_expires_at"]) == before
    assert datetime.fromisoformat(details["to_expires_at"]) == later


async def test_the_same_time_again_returns_the_transfer_unchanged(api: Api) -> None:
    transfer_id = api.transfer()
    submitted, _ = expiry(api.db, transfer_id)
    later = submitted + timedelta(days=10)
    first = await api.extend(transfer_id, later)
    assert first.status_code == 200, first.text
    # The same instant, written in another offset: a retry of the success.
    again = await api.extend(transfer_id, later.astimezone(UTC).isoformat())
    assert again.status_code == 200, again.text
    assert again.json() == first.json()
    assert actions(api.db, transfer_id) == ["transfer.expiry_extended"]
    # The current expiry of a transfer never extended is a no-op too, and isn't audited.
    untouched = api.transfer()
    current = expiry(api.db, untouched)[1]
    response = await api.extend(untouched, current)
    assert response.status_code == 200
    assert parsed(response) == current
    assert actions(api.db, untouched) == []


async def test_an_earlier_time_or_one_past_either_cap_is_422(api: Api) -> None:
    transfer_id = api.transfer()
    submitted, current = expiry(api.db, transfer_id)
    for wrong in (current - timedelta(seconds=1), submitted + timedelta(days=30, seconds=1)):
        response = await api.extend(transfer_id, wrong)
        assert response.status_code == 422, response.text
        body = response.json()
        assert body["code"] == "expiry_out_of_range"
        assert body["errors"][0]["pointer"] == "#/expires_at"
    # The whole lifetime, from `submitted_at`: 30 days exactly is the last allowed time.
    last = submitted + timedelta(days=30)
    assert (await api.extend(transfer_id, last)).status_code == 200
    # The tenant's `max_expiry` caps it too, as it is now.
    api.db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale, max_expiry) "
        "VALUES (:t, 'en', interval '10 days')",
        t=api.tenant.id,
    )
    capped = api.transfer()
    submitted, _ = expiry(api.db, capped)
    over = await api.extend(capped, submitted + timedelta(days=10, seconds=1))
    assert over.status_code == 422
    assert over.json()["code"] == "expiry_out_of_range"
    assert (await api.extend(capped, submitted + timedelta(days=10))).status_code == 200
    assert actions(api.db, capped) == ["transfer.expiry_extended"]


async def test_a_naive_time_is_refused(api: Api) -> None:
    transfer_id = api.transfer()
    response = await api.extend(transfer_id, "2030-01-01T00:00:00")
    assert response.status_code in (400, 422)
    assert actions(api.db, transfer_id) == []


@pytest.mark.parametrize(
    ("state", "offset", "code"),
    [
        ("draft", None, "invalid_state"),
        ("cancelled", None, "invalid_state"),
        ("revoked", None, "transfer_revoked"),
        ("expired", None, "transfer_expired"),
        # Past `expires_at`, before the expiry job records it.
        ("sent", -timedelta(seconds=1), "transfer_expired"),
    ],
)
async def test_a_transfer_that_isnt_open_is_409(
    api: Api, state: str, offset: timedelta | None, code: str
) -> None:
    options = {} if offset is None else {"expires_at_offset": offset}
    transfer_id = api.transfer(state, **options)
    response = await api.extend(transfer_id, datetime.now(UTC) + timedelta(days=3))
    assert response.status_code == 409, response.text
    assert response.json()["code"] == code
    assert actions(api.db, transfer_id) == []


async def test_only_the_owner_extends(api: Api) -> None:
    transfer_id = api.transfer()
    submitted, current = expiry(api.db, transfer_id)
    later = submitted + timedelta(days=9)
    tenant = api.tenant
    other = seed_tenant(api.db)
    refused: list[tuple[Caller, int]] = [
        (session_caller(tenant.id, tenant.member, Role.MEMBER), 404),
        (session_caller(tenant.id, tenant.admin, Role.ADMIN), 403),
        # A local admin without a passkey acts as a member.
        (session_caller(tenant.id, tenant.admin, Role.ADMIN, AuthMethod.PASSWORD_TOTP), 404),
        (session_caller(other.id, other.admin, Role.ADMIN), 404),
        (
            Caller(
                CallerKind.API_KEY,
                tenant_id=tenant.id,
                user_id=tenant.target,
                credential_id=uuid.uuid4(),
                scopes=frozenset({"transfers:read"}),
            ),
            403,
        ),
    ]
    for caller, status in refused:
        api.act_as(caller)
        response = await api.extend(transfer_id, later)
        assert response.status_code == status, (caller, response.text)
        if status == 403:
            assert response.json()["code"] == "permission_denied"
    assert expiry(api.db, transfer_id)[1] == current
    # The owner's API key with `transfers:write` acts for the owner.
    api.act_as(
        Caller(
            CallerKind.API_KEY,
            tenant_id=tenant.id,
            user_id=tenant.target,
            credential_id=uuid.uuid4(),
            scopes=frozenset({"transfers:write"}),
        )
    )
    assert (await api.extend(transfer_id, later)).status_code == 200
    assert expiry(api.db, transfer_id)[1] == later


async def test_an_idempotency_key_replays_and_refuses_another_body(api: Api) -> None:
    transfer_id = api.transfer()
    submitted, _ = expiry(api.db, transfer_id)
    key = {"idempotency-key": f"extend-{uuid.uuid4()}"}
    first = await api.extend(transfer_id, submitted + timedelta(days=12), **key)
    replay = await api.extend(transfer_id, submitted + timedelta(days=12), **key)
    assert (first.status_code, replay.status_code) == (200, 200)
    assert replay.json() == first.json()
    other = await api.extend(transfer_id, submitted + timedelta(days=14), **key)
    assert other.status_code == 409
    assert other.json()["code"] == "idempotency_conflict"
    assert actions(api.db, transfer_id) == ["transfer.expiry_extended"]


# ---- the recipient's side ----

OLD_EXPIRY = timedelta(seconds=8)
"""How long the recipient's transfer runs before it is extended: long enough to verify and take a
grant, short enough for the test to wait past it."""


def session_ends(w: World, session_id: object) -> datetime:
    [(ends,)] = w.db.sql(
        "SELECT expires_at FROM link_sessions WHERE id = :id", id=uuid.UUID(str(session_id))
    )
    assert isinstance(ends, datetime)
    return ends


def grant_ends(w: World, grant_id: object) -> datetime:
    [(ends,)] = w.db.sql(
        "SELECT expires_at FROM download_grants WHERE id = :id", id=uuid.UUID(str(grant_id))
    )
    assert isinstance(ends, datetime)
    return ends


async def wait_past(moment: datetime) -> None:
    """Until half a second after `moment`, on the clock the database and the API both read."""
    await asyncio.sleep(max(0.0, (moment - datetime.now(UTC)).total_seconds() + 0.5))


async def test_a_recipient_verifies_and_downloads_after_the_old_time(w: World) -> None:
    address, late = unique(), unique()
    transfer_id, _, [first, second], data = shared(w, address, late, files=2)
    w.db.sql(
        "UPDATE transfers SET expires_at = now() + CAST(:offset AS interval) WHERE id = :id",
        offset=OLD_EXPIRY,
        id=transfer_id,
    )
    old = transfer_row(w.db, transfer_id)["expires_at"]
    assert isinstance(old, datetime)
    browser = await w.browser()
    _, session = await w.verify(browser, address)
    assert session_ends(w, session["id"]) == old  # capped at the transfer's expiry
    granted = await grant(browser, session, first)
    assert granted.status_code == 200, granted.text
    grant_id = granted.json()["grant_id"]
    assert grant_ends(w, grant_id) == old

    owner = session_caller(w.tenant.id, w.tenant.target, Role.MEMBER)
    async with client(w.db, lambda: owner) as member:
        new = old + timedelta(days=2)
        response = await member.post(
            f"/v1/transfers/{transfer_id}/extend", json={"expires_at": new.isoformat()}
        )
        assert response.status_code == 200, response.text
    # The open session and its live grant run on to the new time, never past 24 hours.
    assert old < session_ends(w, session["id"]) <= new
    assert old < grant_ends(w, grant_id) <= new

    await wait_past(old)
    # The same session: the grant resumes, and a new grant counts the other file.
    got = await content(browser, granted.json()["url"])
    assert got.status_code == 200, got.text
    assert got.content == data[0]
    more = await grant(browser, session, second)
    assert more.status_code == 200, more.text
    # A recipient who verifies only now gets a session to the new time.
    other = await w.browser()
    _, fresh = await w.verify(other, late)
    assert old < session_ends(w, fresh["id"])
    assert (await grant(other, fresh, first)).status_code == 200
