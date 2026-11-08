"""`signOutUser` and `resetUserSignIn` end to end against PostgreSQL (#197; FR-22, authn and authz
2.5, 3.3): sessions end, a reset removes the pool identities and queues a new invitation, both are
security-critical records, and a retry after a `503` sends no second invitation."""

from __future__ import annotations

import secrets
import uuid

import httpx2 as httpx
import pytest

from archive_fixtures import FakeArchiveStore, fake_archive
from member_fixtures import Tenant, app_for, client, events, seed_tenant, seed_user, session_caller
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.models import Role
from sft.data.roles import API
from sft.service.audit_archive import Region

pytestmark = pytest.mark.anyio


def seed_pool(db: ScratchDatabase, name: str) -> uuid.UUID:
    """A user pool's connection: no tenant, `kind = 'local'`."""
    connection_id = uuid.uuid4()
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, NULL, 'local', :name, 'https://pool.example.test', 'active')",
        id=connection_id,
        name=name,
    )
    return connection_id


def seed_identity(
    db: ScratchDatabase, tenant_id: uuid.UUID, user_id: uuid.UUID, pool: uuid.UUID
) -> uuid.UUID:
    identity_id = uuid.uuid4()
    db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :tenant, :user, :pool, :subject)",
        id=identity_id,
        tenant=tenant_id,
        user=user_id,
        pool=pool,
        subject=secrets.token_hex(8),
    )
    return identity_id


def seed_sessions(
    db: ScratchDatabase, tenant_id: uuid.UUID, user_id: uuid.UUID, identity_id: uuid.UUID, n: int
) -> None:
    for _ in range(n):
        db.sql(
            "INSERT INTO member_sessions (id, tenant_id, user_id, identity_id, session_hash, "
            "auth_time, auth_method, expires_at) VALUES (:id, :tenant, :user, :identity, "
            "sha256(convert_to(:token, 'UTF8')), now(), 'passkey', now() + interval '12 hours')",
            id=uuid.uuid4(),
            tenant=tenant_id,
            user=user_id,
            identity=identity_id,
            token=secrets.token_urlsafe(32),
        )


def live_sessions(db: ScratchDatabase, user_id: uuid.UUID) -> list[tuple[object, ...]]:
    return db.sql(
        "SELECT revoked_reason FROM member_sessions WHERE user_id = :user ORDER BY revoked_reason",
        user=user_id,
    )


def identity_count(db: ScratchDatabase, user_id: uuid.UUID) -> int:
    [(count,)] = db.sql("SELECT count(*) FROM user_identities WHERE user_id = :user", user=user_id)
    return int(count)


def resets_queued(db: ScratchDatabase, user_id: uuid.UUID) -> int:
    [(count,)] = db.sql(
        "SELECT count(*) FROM outbox WHERE topic = 'member.sign_in_reset' "
        "AND payload ->> 'user_id' = :user",
        user=str(user_id),
    )
    return int(count)


def with_pool(tenant: Tenant, db: ScratchDatabase) -> tuple[str, uuid.UUID]:
    """A pool of this test's own, the target's identity on it and two live sessions."""
    name = f"pool-{uuid.uuid4().hex[:12]}"
    pool = seed_pool(db, name)
    identity = seed_identity(db, tenant.id, tenant.target, pool)
    seed_sessions(db, tenant.id, tenant.target, identity, 2)
    return name, pool


def reset_ids(db: ScratchDatabase, user_id: uuid.UUID) -> list[str]:
    """The reset IDs of the user's `member.sign_in_reset` messages, oldest first."""
    return [
        str(row[0])
        for row in db.sql(
            "SELECT payload ->> 'reset_id' FROM outbox WHERE topic = 'member.sign_in_reset' "
            "AND payload ->> 'user_id' = :user ORDER BY created_at, id",
            user=str(user_id),
        )
    ]


def pending_reset(db: ScratchDatabase, user_id: uuid.UUID) -> str | None:
    [(reset_id,)] = db.sql("SELECT sign_in_reset_id FROM users WHERE id = :u", u=user_id)
    return None if reset_id is None else str(reset_id)


def details(db: ScratchDatabase, user_id: uuid.UUID, action: str) -> list[dict[str, object]]:
    return [
        row[0]  # type: ignore[misc]
        for row in db.sql(
            "SELECT details FROM audit_events WHERE target_id = :u AND action = :a "
            "ORDER BY occurred_at, id",
            u=user_id,
            a=action,
        )
    ]


async def test_every_forced_sign_out_is_its_own_audited_action(
    migrated_db: ScratchDatabase,
) -> None:
    """Two admins sign the same user out: two events, each naming its admin and the sessions it
    ended, even none (#197 review)."""
    tenant = seed_tenant(migrated_db)
    with_pool(tenant, migrated_db)
    second_admin = seed_user(migrated_db, tenant.id, role="admin")
    for admin_id in (tenant.admin, second_admin):
        admin = session_caller(tenant.id, admin_id, Role.ADMIN)
        async with client(migrated_db, lambda admin=admin: admin) as http:  # type: ignore[misc]
            response = await http.post(f"/v1/users/{tenant.target}/sign-out")
            assert (response.status_code, response.json()["status"]) == (200, "active")
    async with client(
        migrated_db, lambda: session_caller(tenant.id, tenant.admin, Role.ADMIN)
    ) as http:
        assert (await http.post(f"/v1/users/{uuid.uuid4()}/sign-out")).status_code == 404
    assert live_sessions(migrated_db, tenant.target) == [("signed_out_by_admin",)] * 2
    assert identity_count(migrated_db, tenant.target) == 1  # they can sign in again
    assert events(migrated_db, tenant.target) == [
        ("user.signed_out_by_admin", "admin", tenant.admin, True),
        ("user.signed_out_by_admin", "admin", second_admin, True),
    ]
    ended = [
        d["sessions_ended"] for d in details(migrated_db, tenant.target, "user.signed_out_by_admin")
    ]
    assert ended == [2, 0]


async def test_a_forced_sign_out_answers_200_only_once_both_archives_hold_it(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    with_pool(tenant, migrated_db)
    store = FakeArchiveStore(fail={Region.OSAKA})
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    path = f"/v1/users/{tenant.target}/sign-out"
    async with client(migrated_db, lambda: admin, archive=fake_archive(store)) as http:
        refused = await http.post(path)
        assert (refused.status_code, refused.json()["code"]) == (503, "service_unavailable")
        assert live_sessions(migrated_db, tenant.target) == [("signed_out_by_admin",)] * 2
        store.fail.clear()
        assert (await http.post(path)).status_code == 200
    # The retry is an action of its own, and completes the first call's record too.
    assert store.actions(Region.OSAKA) == ["user.signed_out_by_admin"] * 2
    assert len(events(migrated_db, tenant.target)) == 2


def reset_app(db: ScratchDatabase, database: Database, tenant: Tenant, name: str, **kwargs: object):  # type: ignore[no-untyped-def]
    app = app_for(database, lambda: session_caller(tenant.id, tenant.admin, Role.ADMIN), **kwargs)  # type: ignore[arg-type]
    app.state.pool_provider = name
    return app


async def test_a_reset_ends_sessions_removes_the_pool_identities_and_queues_an_invitation(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    name, pool = with_pool(tenant, migrated_db)
    other_pool = seed_pool(migrated_db, f"other-{uuid.uuid4().hex[:12]}")
    seed_identity(migrated_db, tenant.id, tenant.target, other_pool)
    database = Database.connect(migrated_db.url(API), pool_size=2)
    try:
        app = reset_app(migrated_db, database, tenant, name)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://api.test"
        ) as http:
            response = await http.post(f"/v1/users/{tenant.target}/reset-sign-in")
            assert (response.status_code, response.json()["id"]) == (202, str(tenant.target))
    finally:
        await database.dispose()
    assert live_sessions(migrated_db, tenant.target) == [("sign_in_reset",)] * 2
    # Only the pool's identity went; another connection's stays.
    [(left,)] = migrated_db.sql(
        "SELECT idp_connection_id FROM user_identities WHERE user_id = :u", u=tenant.target
    )
    assert left == other_pool
    assert left != pool
    [reset_id] = reset_ids(migrated_db, tenant.target)
    assert pending_reset(migrated_db, tenant.target) == reset_id
    assert events(migrated_db, tenant.target) == [
        ("user.sign_in_reset", "admin", tenant.admin, True)
    ]


async def test_a_new_reset_supersedes_one_still_being_processed(
    migrated_db: ScratchDatabase,
) -> None:
    """Each reset ends the sessions again and gets a new ID; the user's pending reset is the newest,
    so the worker sends only its invitation (test_notify_pool.py) (#197 review)."""
    tenant = seed_tenant(migrated_db)
    name, pool = with_pool(tenant, migrated_db)
    database = Database.connect(migrated_db.url(API), pool_size=2)
    try:
        app = reset_app(migrated_db, database, tenant, name)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://api.test"
        ) as http:
            assert (await http.post(f"/v1/users/{tenant.target}/reset-sign-in")).status_code == 202
            # They signed in again meanwhile (a session on a fresh identity), then the admin resets
            # again: the new reset ends that session too.
            identity = seed_identity(migrated_db, tenant.id, tenant.target, pool)
            seed_sessions(migrated_db, tenant.id, tenant.target, identity, 1)
            assert (await http.post(f"/v1/users/{tenant.target}/reset-sign-in")).status_code == 202
    finally:
        await database.dispose()
    first, second = reset_ids(migrated_db, tenant.target)
    assert first != second
    assert pending_reset(migrated_db, tenant.target) == second
    assert live_sessions(migrated_db, tenant.target) == [("sign_in_reset",)] * 3
    assert identity_count(migrated_db, tenant.target) == 0
    assert len(events(migrated_db, tenant.target)) == 2


async def test_a_dead_lettered_reset_never_blocks_the_next(migrated_db: ScratchDatabase) -> None:
    """Without a pool (none configured, or the message dead-lettered and never handled), a second
    reset still ends sessions and queues its own message (#197 review)."""
    tenant = seed_tenant(migrated_db)
    _, pool = with_pool(tenant, migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:  # no pool provider: no identities go
        assert (await http.post(f"/v1/users/{tenant.target}/reset-sign-in")).status_code == 202
        identity = seed_identity(migrated_db, tenant.id, tenant.target, pool)
        seed_sessions(migrated_db, tenant.id, tenant.target, identity, 1)
        assert (await http.post(f"/v1/users/{tenant.target}/reset-sign-in")).status_code == 202
    assert len(reset_ids(migrated_db, tenant.target)) == 2
    assert live_sessions(migrated_db, tenant.target) == [("sign_in_reset",)] * 3


async def test_a_reset_answers_503_with_the_change_kept_then_202(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    name, _ = with_pool(tenant, migrated_db)
    store = FakeArchiveStore(fail={Region.TOKYO})
    database = Database.connect(migrated_db.url(API), pool_size=2)
    try:
        app = reset_app(migrated_db, database, tenant, name, archive=fake_archive(store))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://api.test"
        ) as http:
            refused = await http.post(f"/v1/users/{tenant.target}/reset-sign-in")
            assert (refused.status_code, refused.json()["code"]) == (503, "service_unavailable")
            assert identity_count(migrated_db, tenant.target) == 0  # the reset stands
            store.fail.clear()
            assert (await http.post(f"/v1/users/{tenant.target}/reset-sign-in")).status_code == 202
    finally:
        await database.dispose()
    # The retry supersedes the first reset (only its message invites) and completes its record.
    first, second = reset_ids(migrated_db, tenant.target)
    assert pending_reset(migrated_db, tenant.target) == second != first
    for region in Region:
        assert store.actions(region) == ["user.sign_in_reset"] * 2


async def test_a_member_is_refused_before_any_pool_lookup(migrated_db: ScratchDatabase) -> None:
    """The pool connection is looked up once per process, and only after the caller may reset
    (#197 review)."""
    tenant = seed_tenant(migrated_db)
    name, _ = with_pool(tenant, migrated_db)
    database = Database.connect(migrated_db.url(API), pool_size=2)
    try:
        caller = {"now": session_caller(tenant.id, tenant.member, Role.MEMBER)}
        app = app_for(database, lambda: caller["now"])
        app.state.pool_provider = name
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://api.test"
        ) as http:
            refused = await http.post(f"/v1/users/{tenant.target}/reset-sign-in")
            assert (refused.status_code, refused.json()["code"]) == (403, "permission_denied")
            assert app.state.pool_connections.lookups == 0
            caller["now"] = session_caller(tenant.id, tenant.admin, Role.ADMIN)
            for _ in range(2):
                assert (
                    await http.post(f"/v1/users/{tenant.target}/reset-sign-in")
                ).status_code == 202
            assert app.state.pool_connections.lookups == 1
    finally:
        await database.dispose()


async def test_a_deactivated_user_cant_be_reset(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    gone = seed_user(migrated_db, tenant.id, status="deactivated")
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        response = await http.post(f"/v1/users/{gone}/reset-sign-in")
        assert (response.status_code, response.json()["code"]) == (409, "invalid_state")
        assert (await http.post(f"/v1/users/{uuid.uuid4()}/reset-sign-in")).status_code == 404
    assert events(migrated_db, gone) == []


async def test_a_reset_of_an_invited_user_sends_the_invitation_again(
    migrated_db: ScratchDatabase,
) -> None:
    """Without any identity yet (never joined), a first reset is a new invitation."""
    tenant = seed_tenant(migrated_db)
    invited = seed_user(migrated_db, tenant.id, status="invited")
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        assert (await http.post(f"/v1/users/{invited}/reset-sign-in")).status_code == 202
    assert resets_queued(migrated_db, invited) == 1


async def test_a_member_can_neither_sign_out_nor_reset_another_user(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    member = session_caller(tenant.id, tenant.member, Role.MEMBER)
    async with client(migrated_db, lambda: member) as http:
        for action in ("sign-out", "reset-sign-in"):
            response = await http.post(f"/v1/users/{tenant.target}/{action}")
            assert (response.status_code, response.json()["code"]) == (403, "permission_denied")
    assert events(migrated_db, tenant.target) == []
