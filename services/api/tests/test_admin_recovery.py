"""Operator-assisted recovery of a tenant admin: `recoverTenantAdmin` (#239; authn and authz 2.5).

Over the operator API as `sft_operator`, against PostgreSQL. A local admin's sign-in is reset as
`resetUserSignIn` resets it; an admin of a tenant with an active SSO connection gets a temporary
local sign-in, whose identity expires after 72 hours and which the daily job then removes. Each is
a security-critical record in the tenant's log, archived in both regions before the `202`, and a
retry with the same `Idempotency-Key` starts nothing again.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from starlette.testclient import TestClient

from archive_fixtures import FakeArchiveStore, fake_archive
from member_fixtures import Tenant, seed_tenant
from operators import OPERATOR_NAME, FakeSts
from pg import ScratchDatabase
from sft.api.operator.app import create_operator_app
from sft.data import audit
from sft.data.audit import Actor, ActorType
from sft.data.database import Database
from sft.data.identities import record_identity
from sft.data.roles import JOBS, NOTIFY
from sft.data.scope import Scope
from sft.service.admin_recovery import end_temporary_sign_ins
from sft.service.audit_archive import Region
from sft.service.lifecycle import SystemActor
from test_operator_api import bearer, settings_for, token_request

pytestmark = pytest.mark.anyio


class Operator:
    def __init__(self, client: TestClient, store: FakeArchiveStore) -> None:
        self.client = client
        self.store = store
        response = client.post("/v1/operator/token", json=token_request())
        assert response.status_code == 201, response.text
        self.token = str(response.json()["token"])

    def recover(self, tenant_id: uuid.UUID, user_id: uuid.UUID, key: str | None = None) -> Any:
        headers = bearer(self.token)
        if key is not None:
            headers["Idempotency-Key"] = key
        return self.client.post(
            f"/v1/operator/tenants/{tenant_id}/admin-recovery",
            json={"user_id": str(user_id), "confirmed_via": "Called the recovery contact back"},
            headers=headers,
        )


@pytest.fixture
def operator(migrated_db: ScratchDatabase) -> Iterator[Operator]:
    app = create_operator_app(settings_for(migrated_db), sts=FakeSts())
    store = FakeArchiveStore()
    with TestClient(app) as client:
        app.state.audit_archive = fake_archive(store)
        yield Operator(client, store)


def seed_with_sessions(db: ScratchDatabase) -> Tenant:
    """A tenant whose admin has a session and an identity on a pool's connection."""
    tenant = seed_tenant(db)
    pool = uuid.uuid4()
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, NULL, 'local', :name, 'https://pool.example', 'active')",
        id=pool,
        name=f"pool-{pool}",
    )
    identity = uuid.uuid4()
    db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :t, :u, :c, :s)",
        id=identity,
        t=tenant.id,
        u=tenant.admin,
        c=pool,
        s=f"sub-{identity}",
    )
    db.sql(
        "INSERT INTO member_sessions (id, tenant_id, user_id, identity_id, session_hash, "
        "auth_time, auth_method, expires_at) VALUES (:id, :t, :u, :i, :h, now(), 'passkey', "
        "now() + interval '1 hour')",
        id=uuid.uuid4(),
        t=tenant.id,
        u=tenant.admin,
        i=identity,
        h=uuid.uuid4().bytes * 2,
    )
    return tenant


def make_sso_tenant(db: ScratchDatabase, tenant_id: uuid.UUID) -> None:
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, :t, 'oidc', :p, 'https://idp.corp.example', 'active')",
        id=uuid.uuid4(),
        t=tenant_id,
        p=tenant_id.hex,
    )


def recoveries(db: ScratchDatabase, tenant_id: uuid.UUID) -> list[tuple[object, ...]]:
    return db.sql("SELECT count(*) FROM admin_recoveries WHERE tenant_id = :t", t=tenant_id)


def test_a_local_admins_sign_in_is_reset(operator: Operator, migrated_db: ScratchDatabase) -> None:
    tenant = seed_with_sessions(migrated_db)
    response = operator.recover(tenant.id, tenant.admin)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["kind"] == "sign_in_reset"
    assert body["temporary_sign_in_expires_at"] is None
    assert (body["tenant_id"], body["user_id"]) == (str(tenant.id), str(tenant.admin))
    # As resetUserSignIn: sessions ended, pool identities gone, a new reset and its message.
    assert migrated_db.sql(
        "SELECT revoked_reason FROM member_sessions WHERE user_id = :u", u=tenant.admin
    ) == [("sign_in_reset",)]
    assert migrated_db.sql(
        "SELECT count(*) FROM user_identities WHERE user_id = :u", u=tenant.admin
    ) == [(0,)]
    [(reset_id,)] = migrated_db.sql(
        "SELECT sign_in_reset_id FROM users WHERE id = :u", u=tenant.admin
    )
    assert migrated_db.sql(
        "SELECT topic, payload FROM outbox WHERE tenant_id = :t", t=tenant.id
    ) == [("member.sign_in_reset", {"user_id": str(tenant.admin), "reset_id": str(reset_id)})]
    # The confirmation stays in the row, never in an event.
    assert migrated_db.sql(
        "SELECT confirmed_via, operator_name FROM admin_recoveries WHERE id = :id",
        id=uuid.UUID(body["id"]),
    ) == [("Called the recovery contact back", OPERATOR_NAME)]
    # A security-critical record in the tenant's log, archived in both regions, and a platform
    # event.
    [(actor, critical, details)] = migrated_db.sql(
        "SELECT actor_type, security_critical, details FROM audit_events "
        "WHERE tenant_id = :t AND action = 'user.sign_in_reset'",
        t=tenant.id,
    )
    assert (actor, critical) == ("operator", True)
    assert details["admin_recovery_id"] == body["id"]
    assert details["admin_recovery_kind"] == "sign_in_reset"
    assert details["sessions_ended"] == 1
    assert details["identities_removed"] == 1
    assert "Called" not in str(details)
    for region in (Region.TOKYO, Region.OSAKA):
        assert operator.store.actions(region) == ["user.sign_in_reset"]
    assert migrated_db.sql(
        "SELECT count(*) FROM audit_events WHERE tenant_id IS NULL "
        "AND action = 'tenant.admin_recovered' AND target_id = :t",
        t=tenant.id,
    ) == [(1,)]


async def test_an_sso_tenants_admin_gets_a_temporary_sign_in_that_ends(
    operator: Operator, migrated_db: ScratchDatabase
) -> None:
    tenant = seed_with_sessions(migrated_db)
    make_sso_tenant(migrated_db, tenant.id)
    response = operator.recover(tenant.id, tenant.admin)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["kind"] == "temporary_local_sign_in"
    ends = datetime.fromisoformat(body["temporary_sign_in_expires_at"])
    assert timedelta(hours=71) < ends - datetime.now(UTC) <= timedelta(hours=72)
    # The identity the notification worker records for this reset expires with it.
    [(pool,)] = migrated_db.sql(
        "SELECT id FROM idp_connections WHERE tenant_id IS NULL AND provider_name LIKE 'pool-%' "
        "ORDER BY created_at DESC LIMIT 1"
    )
    notify = Database.connect(migrated_db.url(NOTIFY), pool_size=1)
    try:
        async with notify.transaction(Scope.tenant(tenant.id)) as session:
            await record_identity(
                session, user_id=tenant.admin, connection_id=pool, subject="sub-temporary"
            )
            await audit.record(session, action="email.sent", actor=Actor(ActorType.SYSTEM))
    finally:
        await notify.dispose()
    assert migrated_db.sql(
        "SELECT expires_at FROM user_identities WHERE subject = 'sub-temporary'"
    ) == [(ends,)]
    # The daily job removes it once it has ended, with its event; nothing before.
    jobs = Database.connect(migrated_db.url(JOBS), pool_size=1)
    job: dict[str, audit.Detail] = {"system_actor": SystemActor.CLEANUP_JOB}
    try:
        assert await end_temporary_sign_ins(jobs, now=datetime.now(UTC), job=job) == 0
        later = ends + timedelta(seconds=1)
        assert await end_temporary_sign_ins(jobs, now=later, job=job) == 1
        assert await end_temporary_sign_ins(jobs, now=later, job=job) == 0
    finally:
        await jobs.dispose()
    assert migrated_db.sql(
        "SELECT count(*) FROM user_identities WHERE subject = 'sub-temporary'"
    ) == [(0,)]
    assert migrated_db.sql(
        "SELECT ended_at IS NOT NULL FROM admin_recoveries WHERE id = :id",
        id=uuid.UUID(body["id"]),
    ) == [(True,)]
    [(details,)] = migrated_db.sql(
        "SELECT details FROM audit_events WHERE action = 'user.temporary_sign_in_ended' "
        "AND tenant_id = :t",
        t=tenant.id,
    )
    assert details["admin_recovery_id"] == body["id"]
    assert details["identities_removed"] == 1


def test_a_fallback_admin_of_an_sso_tenant_is_reset(
    operator: Operator, migrated_db: ScratchDatabase
) -> None:
    tenant = seed_with_sessions(migrated_db)
    make_sso_tenant(migrated_db, tenant.id)
    migrated_db.sql("UPDATE users SET sso_fallback = true WHERE id = :u", u=tenant.admin)
    response = operator.recover(tenant.id, tenant.admin)
    assert (response.status_code, response.json()["kind"]) == (202, "sign_in_reset")


def test_only_an_active_admin_of_the_tenant_is_recovered(
    operator: Operator, migrated_db: ScratchDatabase
) -> None:
    tenant = seed_tenant(migrated_db)
    other = seed_tenant(migrated_db)
    member = operator.recover(tenant.id, tenant.member)
    assert (member.status_code, member.json()["code"]) == (409, "invalid_state")
    # Another tenant's admin, a user who doesn't exist, a tenant that doesn't exist: 404.
    assert operator.recover(tenant.id, other.admin).status_code == 404
    assert operator.recover(tenant.id, uuid.uuid4()).status_code == 404
    assert operator.recover(uuid.uuid4(), tenant.admin).status_code == 404
    assert recoveries(migrated_db, tenant.id) == [(0,)]
    assert operator.store.actions() == []


def test_a_retry_with_the_key_archives_the_record_and_starts_nothing(
    operator: Operator, migrated_db: ScratchDatabase
) -> None:
    tenant = seed_with_sessions(migrated_db)
    operator.store.fail.add(Region.OSAKA)
    failed = operator.recover(tenant.id, tenant.admin, key="recover-1")
    assert (failed.status_code, failed.json()["code"]) == (503, "service_unavailable")
    # It took effect all the same.
    assert recoveries(migrated_db, tenant.id) == [(1,)]
    operator.store.fail.clear()
    retried = operator.recover(tenant.id, tenant.admin, key="recover-1")
    assert retried.status_code == 202, retried.text
    assert operator.store.actions(Region.OSAKA) == ["user.sign_in_reset"]
    assert recoveries(migrated_db, tenant.id) == [(1,)]
    assert migrated_db.sql(
        "SELECT count(*) FROM outbox WHERE tenant_id = :t AND topic = 'member.sign_in_reset'",
        t=tenant.id,
    ) == [(1,)]
    again = operator.recover(tenant.id, tenant.admin, key="recover-1")
    assert again.json() == retried.json()
    # The same key for another admin is a conflict.
    other = operator.recover(tenant.id, tenant.member, key="recover-1")
    assert (other.status_code, other.json()["code"]) == (409, "idempotency_conflict")


def test_without_an_archive_the_recovery_stands_and_answers_503(
    operator: Operator, migrated_db: ScratchDatabase
) -> None:
    tenant = seed_with_sessions(migrated_db)
    operator.client.app.state.audit_archive = None  # type: ignore[attr-defined]
    response = operator.recover(tenant.id, tenant.admin)
    assert (response.status_code, response.json()["code"]) == (503, "service_unavailable")
    assert recoveries(migrated_db, tenant.id) == [(1,)]
