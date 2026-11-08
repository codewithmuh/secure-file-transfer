"""Break-glass in the service (#232; FR-35; authn and authz 8.3): a request, a second operator's
approval, a database role scoped to the grant's tenants that stops on time without anyone acting,
an early end, the sweep that records expiries and lapses, and an audit record at each step.

The acceptance criteria: break-glass access ends on time without anyone acting, and every step is
in the audit log. The alert rules have their promtool tests in deploy/alerts/tests.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry
from sqlalchemy import create_engine, text

from member_fixtures import seed_tenant
from operators import FakeSts, assumed_role
from pg import ScratchDatabase
from sft.api.operator.app import BreakGlassMetrics, create_operator_app
from sft.data.database import Database
from sft.data.roles import BREAK_GLASS, OPERATOR
from sft.service import break_glass
from test_operator_api import bearer, settings_for, token_request

SECOND = "bob@example.test"


@pytest.fixture
def operator_app(migrated_db: ScratchDatabase) -> Iterator[TestClient]:
    with TestClient(create_operator_app(settings_for(migrated_db), sts=FakeSts())) as client:
        yield client


def token_as(client: TestClient, name: str) -> str:
    client.app.state.sts.arn = assumed_role(name=name)  # type: ignore[attr-defined]
    response = client.post("/v1/operator/token", json=token_request())
    assert response.status_code == 201, response.text
    return str(response.json()["token"])


def ask(client: TestClient, token: str, tenant_ids: list[uuid.UUID], **fields: Any) -> Any:
    body = {
        "incident_id": "INC-42",
        "reason": "Restore a tenant's stuck transfer",
        "tenant_ids": [str(t) for t in tenant_ids],
        "duration_minutes": 30,
        **fields,
    }
    return client.post("/v1/operator/break-glass-requests", json=body, headers=bearer(token))


def as_break_glass(db: ScratchDatabase, grant: str | None, statement: str) -> list[Any]:
    """Run one statement as `sft_breakglass`, with `app.break_glass_grant` set, as a person
    would in psql."""
    engine = create_engine(db.url(BREAK_GLASS).replace("postgresql://", "postgresql+psycopg://"))
    try:
        with engine.begin() as connection:
            if grant is not None:
                connection.execute(
                    text("SELECT set_config('app.break_glass_grant', :g, true)"), {"g": grant}
                )
            return [tuple(row) for row in connection.execute(text(statement))]
    finally:
        engine.dispose()


def users_seen(db: ScratchDatabase, grant: str | None) -> set[uuid.UUID]:
    return {row[0] for row in as_break_glass(db, grant, "SELECT tenant_id FROM users")}


def events_of(db: ScratchDatabase, grant_id: str) -> list[tuple[Any, ...]]:
    return db.sql(
        "SELECT action, tenant_id IS NULL, security_critical FROM audit_events "
        "WHERE target_id = :g ORDER BY occurred_at, id",
        g=uuid.UUID(grant_id),
    )


def test_a_second_operator_approves_and_the_role_reads_only_the_grants_tenants(
    migrated_db: ScratchDatabase, operator_app: TestClient
) -> None:
    mine, other = seed_tenant(migrated_db), seed_tenant(migrated_db)
    alice = token_as(operator_app, "alice@example.test")
    asked = ask(operator_app, alice, [mine.id])
    assert asked.status_code == 201, asked.text
    grant = asked.json()
    assert (grant["state"], grant["requester"], grant["approver"]) == (
        "requested",
        "alice@example.test",
        None,
    )
    # Nothing is reachable before the approval, and the requester can't approve.
    assert users_seen(migrated_db, grant["id"]) == set()
    own = operator_app.post(
        f"/v1/operator/break-glass-requests/{grant['id']}/approve", headers=bearer(alice)
    )
    assert (own.status_code, own.json()["code"]) == (403, "self_approval_forbidden")

    bob = token_as(operator_app, SECOND)
    approved = operator_app.post(
        f"/v1/operator/break-glass-requests/{grant['id']}/approve", headers=bearer(bob)
    )
    assert approved.status_code == 200, approved.text
    active = approved.json()
    assert (active["state"], active["approver"], active["self_approved"]) == (
        "active",
        SECOND,
        False,
    )
    assert active["ends_at"] > active["starts_at"]
    again = operator_app.post(
        f"/v1/operator/break-glass-requests/{grant['id']}/approve", headers=bearer(bob)
    )
    assert (again.status_code, again.json()["code"]) == (409, "invalid_state")

    # The role reads the grant's tenant, read only, and nothing without the grant named.
    assert users_seen(migrated_db, grant["id"]) == {mine.id}
    assert other.id not in users_seen(migrated_db, grant["id"])
    assert users_seen(migrated_db, None) == set()
    assert users_seen(migrated_db, str(uuid.uuid4())) == set()
    with pytest.raises(Exception, match="permission denied"):
        as_break_glass(migrated_db, grant["id"], "UPDATE users SET role = 'admin'")
    with pytest.raises(Exception, match="permission denied"):
        as_break_glass(migrated_db, grant["id"], "SELECT * FROM api_keys")

    # Ending it early ends access with the transaction.
    ended = operator_app.post(
        f"/v1/operator/break-glass-requests/{grant['id']}/end", headers=bearer(alice)
    )
    assert (ended.status_code, ended.json()["state"]) == (200, "ended")
    assert users_seen(migrated_db, grant["id"]) == set()
    assert (
        operator_app.post(
            f"/v1/operator/break-glass-requests/{grant['id']}/end", headers=bearer(alice)
        ).json()["state"]
        == "ended"
    )  # idempotent

    # Every step: the platform's record, and the tenant's own for the approval and the end.
    assert events_of(migrated_db, grant["id"]) == [
        ("break_glass.requested", True, True),
        ("break_glass.approved", True, True),
        ("break_glass.approved", False, True),
        ("break_glass.ended", True, True),
        ("break_glass.ended", False, True),
    ]
    assert migrated_db.sql(
        "SELECT count(*) FROM audit_events WHERE target_id = :g AND tenant_id = :t",
        g=uuid.UUID(grant["id"]),
        t=mine.id,
    ) == [(2,)]
    # No record holds the incident or the reason, which are free text.
    assert not migrated_db.sql(
        "SELECT 1 FROM audit_events WHERE target_id = :g AND details::text LIKE '%INC-42%'",
        g=uuid.UUID(grant["id"]),
    )

    listed = operator_app.get(
        "/v1/operator/break-glass-requests", params={"state": "ended"}, headers=bearer(alice)
    )
    assert grant["id"] in {item["id"] for item in listed.json()["items"]}


def test_a_request_is_checked(migrated_db: ScratchDatabase, operator_app: TestClient) -> None:
    tenant = seed_tenant(migrated_db)
    alice = token_as(operator_app, "alice@example.test")
    assert ask(operator_app, alice, [tenant.id], duration_minutes=61).status_code == 422
    assert ask(operator_app, alice, []).status_code == 422
    unknown = ask(operator_app, alice, [uuid.uuid4()])
    assert (unknown.status_code, unknown.json()["code"]) == (422, "validation_failed")
    missing = operator_app.post(
        f"/v1/operator/break-glass-requests/{uuid.uuid4()}/approve", headers=bearer(alice)
    )
    assert missing.status_code == 404


def test_self_approval_where_the_environment_allows_it_is_marked(
    migrated_db: ScratchDatabase, operator_app: TestClient
) -> None:
    tenant = seed_tenant(migrated_db)
    operator_app.app.state.break_glass_self_approval = True  # type: ignore[attr-defined]
    alice = token_as(operator_app, "alice@example.test")
    grant = ask(operator_app, alice, [tenant.id]).json()
    approved = operator_app.post(
        f"/v1/operator/break-glass-requests/{grant['id']}/approve", headers=bearer(alice)
    )
    assert approved.status_code == 200
    assert approved.json()["self_approved"] is True


@pytest.mark.anyio
async def test_access_ends_on_time_and_the_sweep_records_it(
    migrated_db: ScratchDatabase, operator_app: TestClient
) -> None:
    tenant = seed_tenant(migrated_db)
    alice, bob = token_as(operator_app, "alice@example.test"), token_as(operator_app, SECOND)
    grant = ask(operator_app, alice, [tenant.id], duration_minutes=5).json()
    operator_app.post(
        f"/v1/operator/break-glass-requests/{grant['id']}/approve", headers=bearer(bob)
    )
    stale = ask(operator_app, alice, [tenant.id]).json()
    assert users_seen(migrated_db, grant["id"]) == {tenant.id}
    # Six minutes later: nobody has acted, and the role already reads nothing.
    gid, sid = uuid.UUID(grant["id"]), uuid.UUID(stale["id"])
    migrated_db.sql(
        "UPDATE break_glass_grants SET requested_at = requested_at - interval '6 minutes', "
        "approved_at = approved_at - interval '6 minutes', "
        "starts_at = starts_at - interval '6 minutes', ends_at = ends_at - interval '6 minutes' "
        "WHERE id = :g",
        g=gid,
    )
    migrated_db.sql(
        "UPDATE break_glass_grants SET requested_at = now() - interval '61 minutes' WHERE id = :s",
        s=sid,
    )
    assert users_seen(migrated_db, grant["id"]) == set()
    lapsed = operator_app.post(
        f"/v1/operator/break-glass-requests/{stale['id']}/approve", headers=bearer(bob)
    )
    assert (lapsed.status_code, lapsed.json()["current_state"]) == (409, "lapsed")

    database = Database.connect(migrated_db.url(OPERATOR), pool_size=1)
    try:
        result = await break_glass.sweep(database)
        assert gid in {g.id for g in result.expired}
        assert sid in {g.id for g in result.lapsed}
        assert result.tenant_records_missed == 0
        again = await break_glass.sweep(database)  # each row changes once
        assert gid not in {g.id for g in again.expired}
    finally:
        await database.dispose()
    assert migrated_db.sql(
        "SELECT state, ended_at = ends_at, ended_by FROM break_glass_grants WHERE id = :g", g=gid
    ) == [("expired", True, None)]
    assert events_of(migrated_db, grant["id"])[-2:] == [
        ("break_glass.expired", True, True),
        ("break_glass.expired", False, True),
    ]
    assert events_of(migrated_db, stale["id"])[-1] == ("break_glass.lapsed", True, True)
    [(details,)] = migrated_db.sql(
        "SELECT details FROM audit_events WHERE target_id = :g AND tenant_id IS NULL "
        "AND action = 'break_glass.expired'",
        g=gid,
    )
    assert details["job"] == "break_glass_sweep"


def test_the_metrics_follow_the_sweep() -> None:
    registry = CollectorRegistry()
    metrics = BreakGlassMetrics.create(registry)
    assert (
        registry.get_sample_value("sft_break_glass_active_grants", {"self_approved": "true"}) == 0
    )
    metrics.observe(break_glass.SweepResult(active={True: 1, False: 2}, tenant_records_missed=1))
    assert (
        registry.get_sample_value("sft_break_glass_active_grants", {"self_approved": "true"}) == 1
    )
    assert (
        registry.get_sample_value("sft_break_glass_active_grants", {"self_approved": "false"}) == 2
    )
    assert registry.get_sample_value("sft_break_glass_tenant_records_missed_total") == 1
    stamp = registry.get_sample_value("sft_break_glass_sweep_last_success_timestamp_seconds")
    assert stamp is not None
    assert stamp > 0
