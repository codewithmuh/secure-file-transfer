"""Group G's email caps on `sendTransfer`, against the real limiter (#174, #129; abuse and rate
limits 2.2, 4.5).

With a real Valkey (`TEST_VALKEY_URL`): the 21st link email to one address in a day from one tenant
is refused, and the draft stays a draft. With an unreachable store: the per-pod limits apply, and a
send to the contract's 50 recipients still passes.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx2 as httpx
import pytest
from prometheus_client import CollectorRegistry

from member_fixtures import EMAIL_KEYRING, app_for, ready_for_dlp, seed_user, session_caller
from pg import ScratchDatabase
from sft.api.rate_limits import get_rate_limiter
from sft.data.counters import CounterMetrics, CounterStore
from sft.data.database import Database
from sft.data.models import Role
from sft.service.rate_limits import Charge, RateLimiter
from sft.service.rate_limits.limits import G_ADDRESS_EMAILS, KeyType
from test_rate_limits import snapshot
from transfer_fixtures import seed_file, seed_transfer, transfer_row

pytestmark = pytest.mark.anyio


def _tenant(db: ScratchDatabase) -> tuple[uuid.UUID, uuid.UUID]:
    tenant_id = uuid.uuid4()
    db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id)
    user_id = seed_user(db, tenant_id)
    ready_for_dlp(db, tenant_id, user_id)  # the default policy, and example.test known (#219)
    return tenant_id, user_id


@asynccontextmanager
async def _client(
    api_db: Database, limiter: RateLimiter, tenant_id: uuid.UUID, user_id: uuid.UUID
) -> AsyncIterator[httpx.AsyncClient]:
    caller = session_caller(tenant_id, user_id, Role.MEMBER)
    app = app_for(api_db, lambda: caller)
    app.state.rate_limiter = limiter
    app.dependency_overrides.pop(get_rate_limiter, None)  # the real limiter, not the recorder
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as client:
        yield client


async def test_the_21st_link_email_to_one_address_in_a_day_is_refused(
    migrated_db: ScratchDatabase, api_db: Database, counter_store: CounterStore
) -> None:
    tenant_id, user_id = _tenant(migrated_db)
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()))
    async with _client(api_db, limiter, tenant_id, user_id) as client:
        for attempt in range(21):
            transfer_id, _ = seed_transfer(
                migrated_db, tenant_id, user_id, recipients=("same@example.test",)
            )
            seed_file(migrated_db, tenant_id, transfer_id, state="scanning")
            response = await client.post(f"/v1/transfers/{transfer_id}/send")
            if attempt < 20:
                assert response.status_code == 200, (attempt, response.text)
            else:
                assert response.status_code == 429
                assert int(response.headers["Retry-After"]) > 0
                assert transfer_row(migrated_db, transfer_id)["state"] == "draft"


async def test_a_send_to_50_recipients_passes_on_the_per_pod_limits(
    migrated_db: ScratchDatabase, api_db: Database
) -> None:
    tenant_id, user_id = _tenant(migrated_db)
    metrics = CounterMetrics.create(CollectorRegistry())
    store = CounterStore.connect("redis://u:p@127.0.0.1:1/0", metrics)  # nothing listens there
    try:
        async with _client(api_db, RateLimiter(store, metrics), tenant_id, user_id) as client:
            recipients = tuple(f"r{n}@example.test" for n in range(50))
            transfer_id, _ = seed_transfer(migrated_db, tenant_id, user_id, recipients=recipients)
            seed_file(migrated_db, tenant_id, transfer_id, state="scanning")
            response = await client.post(f"/v1/transfers/{transfer_id}/send")
            assert response.status_code == 200, response.text
            assert response.json()["state"] == "submitted"
    finally:
        await store.close()


async def test_a_refused_address_charges_no_counter_and_leaves_the_draft(
    migrated_db: ScratchDatabase, api_db: Database, counter_store: CounterStore
) -> None:
    # Review of #174: a refusal for one address used to leave the caller's count and the other
    # addresses' spent. Now nothing is charged unless everything is admitted.
    tenant_id, user_id = _tenant(migrated_db)
    limiter = RateLimiter(counter_store, CounterMetrics.create(CollectorRegistry()))
    full = EMAIL_KEYRING.for_limits("full@example.test", datetime.now(UTC)).within(str(tenant_id))
    for _ in range(20):
        await limiter.check_all([Charge(G_ADDRESS_EMAILS, {KeyType.TENANT_EMAIL: full})])
    before = await snapshot(counter_store)
    recipients = ("first@example.test", "full@example.test", "last@example.test")
    transfer_id, _ = seed_transfer(migrated_db, tenant_id, user_id, recipients=recipients)
    seed_file(migrated_db, tenant_id, transfer_id, state="scanning")
    async with _client(api_db, limiter, tenant_id, user_id) as client:
        response = await client.post(f"/v1/transfers/{transfer_id}/send")
    assert response.status_code == 429
    assert transfer_row(migrated_db, transfer_id)["state"] == "draft"
    after = await snapshot(counter_store)
    # Only the route's group H request counters moved; no group G counter did.
    assert {k: v for k, v in after.items() if b"rl:G." in k} == {
        k: v for k, v in before.items() if b"rl:G." in k
    }
