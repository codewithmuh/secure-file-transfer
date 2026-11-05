"""The per-address invitation cap (#145; abuse and rate limits 2.2, G): `G.address_invites`, 3 a day
for one address within a tenant, counted under the address's `email-hmac` pseudonym, against
PostgreSQL and a real Valkey."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from prometheus_client import CollectorRegistry

from member_fixtures import EMAIL_KEYRING, client, seed_tenant, session_caller
from pg import ScratchDatabase
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.models import Role
from sft.service.rate_limits import RateLimiter

pytestmark = pytest.mark.anyio


def users_with(db: ScratchDatabase, tenant_id: uuid.UUID, address: str) -> int:
    rows = db.sql(
        "SELECT count(*) FROM users WHERE tenant_id = :tenant AND email_normalized = :address",
        tenant=tenant_id,
        address=address.lower(),
    )
    return int(str(rows[0][0]))


async def test_the_fourth_invitation_to_one_address_in_a_day_is_a_429(
    migrated_db: ScratchDatabase, counter_store: CounterStore
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()))
    address = f"Cap.{uuid.uuid4().hex}@Example.test"
    async with client(migrated_db, lambda: admin, limiter) as http:  # type: ignore[arg-type]
        for _ in range(3):
            made = await http.post("/v1/users", json={"email": address})
            assert made.status_code == 201, made.text
            # Re-invitation doesn't exist yet, so the test removes the user to invite them again.
            migrated_db.sql("DELETE FROM users WHERE id = :id", id=made.json()["id"])
        # The same address in another case is the same address.
        refused = await http.post("/v1/users", json={"email": address.lower()})
        assert refused.status_code == 429, refused.text
        assert refused.json()["code"] == "rate_limited"
        assert refused.headers["content-type"] == "application/problem+json"
        assert int(refused.headers["retry-after"]) >= 1
        assert users_with(migrated_db, tenant.id, address) == 0  # the refusal wrote nothing
        # Other addresses are unaffected.
        other = await http.post("/v1/users", json={"email": f"{uuid.uuid4().hex}@example.test"})
        assert other.status_code == 201, other.text

    # The counter holds the address's pseudonym only, never the address.
    keys = [key.decode() for key in await counter_store._client.keys("rl:G.address_invites:*")]
    pseudonym = EMAIL_KEYRING.for_limits(address.lower(), datetime.now(UTC)).active
    assert any(key.endswith(f"{tenant.id}:{pseudonym}") for key in keys), keys
    everything = [key.decode() for key in await counter_store._client.keys("*")]
    local_part = address.split("@")[0]
    assert not [key for key in everything if local_part.lower() in key.lower()]


async def test_the_cap_counts_within_one_tenant(
    migrated_db: ScratchDatabase, counter_store: CounterStore
) -> None:
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()))
    address = f"{uuid.uuid4().hex}@example.test"
    first, second = seed_tenant(migrated_db), seed_tenant(migrated_db)
    admin = session_caller(first.id, first.admin, Role.ADMIN)
    for _ in range(3):
        async with client(migrated_db, lambda: admin, limiter) as http:  # type: ignore[arg-type]
            made = await http.post("/v1/users", json={"email": address})
            assert made.status_code == 201
        migrated_db.sql("DELETE FROM users WHERE id = :id", id=made.json()["id"])
    async with client(migrated_db, lambda: admin, limiter) as http:  # type: ignore[arg-type]
        assert (await http.post("/v1/users", json={"email": address})).status_code == 429
    # Another tenant may still invite the address: the cap is per tenant (abuse 2.2, G).
    other = session_caller(second.id, second.admin, Role.ADMIN)
    async with client(migrated_db, lambda: other, limiter) as http:  # type: ignore[arg-type]
        assert (await http.post("/v1/users", json={"email": address})).status_code == 201
