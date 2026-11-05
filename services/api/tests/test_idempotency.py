"""`Idempotency-Key` on the creating operations (#144; architecture 5.4, API README 5), through
`inviteUser`, the first operation that uses it, against PostgreSQL."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from member_fixtures import RecordingLimiter, client, events, seed_tenant, session_caller
from pg import ScratchDatabase
from sft.core.errors import Conflict
from sft.data import idempotency as keys
from sft.data.database import Database
from sft.data.models import Role
from sft.data.roles import API, JOBS
from sft.data.scope import Scope
from sft.service.caller import Caller, CallerKind
from sft.service.idempotency import (
    IdempotentRequest,
    delete_expired_keys,
    fingerprint,
    key_owner,
    once,
)

pytestmark = pytest.mark.anyio

PROBLEM = "application/problem+json"


def an_address() -> str:
    return f"{uuid.uuid4().hex}@example.test"


def stored_keys(db: ScratchDatabase, tenant_id: uuid.UUID) -> list[tuple[object, ...]]:
    return db.sql(
        "SELECT caller_type, caller_id, key, response_status, resource_type, resource_id "
        "FROM idempotency_keys WHERE tenant_id = :tenant ORDER BY created_at",
        tenant=tenant_id,
    )


def invitations(db: ScratchDatabase, user_id: object) -> int:
    rows = db.sql(
        "SELECT count(*) FROM outbox WHERE topic = 'member.invited' "
        "AND payload->>'user_id' = CAST(:user AS text)",
        user=str(user_id),
    )
    return int(str(rows[0][0]))


# ---- the fingerprint and the key's owner ----


def test_the_fingerprint_reads_a_json_body_as_json() -> None:
    one = fingerprint("POST", "/v1/users", b'{"email": "a@x.test", "role": "admin"}')
    assert one == fingerprint("post", "/v1/users", b'{"role":"admin","email":"a@x.test"}')
    assert len(one) == 32
    assert one != fingerprint("POST", "/v1/users", b'{"email": "b@x.test", "role": "admin"}')
    assert one != fingerprint("POST", "/v1/transfers", b'{"email": "a@x.test", "role": "admin"}')
    assert one != fingerprint("PUT", "/v1/users", b'{"email": "a@x.test", "role": "admin"}')
    # Not JSON: compared byte for byte; the parts can't run into each other.
    assert fingerprint("POST", "/v1/a", b"x") != fingerprint("POST", "/v1/ax", b"")
    assert fingerprint("POST", "/v1/a", b"") == fingerprint("POST", "/v1/a", b"")


def test_a_key_belongs_to_the_member_or_the_credential() -> None:
    user, tenant, key_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    member = session_caller(tenant, user, Role.MEMBER)
    assert key_owner(member) == ("member", user)  # not the session: it survives a new sign-in
    api_key = Caller(CallerKind.API_KEY, tenant_id=tenant, user_id=user, credential_id=key_id)
    assert key_owner(api_key) == ("api_key", key_id)
    with pytest.raises(ValueError, match="no idempotency keys"):
        key_owner(Caller(CallerKind.OPERATOR, credential_id=key_id))


# ---- inviteUser ----


async def test_a_retry_replays_the_first_answer_and_invites_no_one_again(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    limiter = RecordingLimiter()
    body = {"email": an_address(), "role": "admin"}
    async with client(migrated_db, lambda: admin, limiter) as http:
        first = await http.post("/v1/users", json=body, headers={"Idempotency-Key": "retry-1"})
        assert first.status_code == 201, first.text
        charged = len(limiter.checks)
        # The same body with its members in another order is the same request.
        again = await http.post(
            "/v1/users",
            content=f'{{"role": "admin", "email": "{body["email"]}"}}',
            headers={"Idempotency-Key": "retry-1", "Content-Type": "application/json"},
        )
    assert again.status_code == 201, again.text
    assert again.json() == first.json()
    assert again.headers["location"] == first.headers["location"]
    user_id = uuid.UUID(first.json()["id"])
    # One user, one audit event, one email, one charge of the invitation limits.
    assert events(migrated_db, user_id) == [("user.invited", "admin", tenant.admin, False)]
    assert invitations(migrated_db, user_id) == 1
    assert [ids for ids, _ in limiter.checks[charged:]] == [
        ("H.caller_requests", "H.tenant_requests")
    ]
    assert stored_keys(migrated_db, tenant.id) == [
        ("member", tenant.admin, "retry-1", 201, "user", user_id)
    ]


async def test_a_replay_shows_the_user_as_they_are_now(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    body = {"email": an_address()}
    async with client(migrated_db, lambda: admin) as http:
        first = await http.post("/v1/users", json=body, headers={"Idempotency-Key": "now"})
        migrated_db.sql("UPDATE users SET status = 'active' WHERE id = :id", id=first.json()["id"])
        again = await http.post("/v1/users", json=body, headers={"Idempotency-Key": "now"})
    assert (again.status_code, again.json()["status"]) == (201, "active")


async def test_the_same_key_with_another_body_is_a_conflict(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        first = await http.post(
            "/v1/users", json={"email": an_address()}, headers={"Idempotency-Key": "k"}
        )
        assert first.status_code == 201
        other = an_address()
        refused = await http.post(
            "/v1/users", json={"email": other}, headers={"Idempotency-Key": "k"}
        )
    assert (refused.status_code, refused.json()["code"]) == (409, "idempotency_conflict")
    assert refused.headers["content-type"] == PROBLEM
    assert migrated_db.sql("SELECT id FROM users WHERE email_normalized = :e", e=other) == []


async def test_a_retry_while_the_first_still_runs_is_in_progress(
    migrated_db: ScratchDatabase, api_db: Database
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    email = an_address()
    async with client(migrated_db, lambda: admin) as http:
        # The first request's transaction holds the key's lock until it ends.
        async with api_db.transaction(Scope.tenant(tenant.id)) as session:
            assert await keys.lock(session, "member", tenant.admin, "busy")
            busy = await http.post(
                "/v1/users", json={"email": email}, headers={"Idempotency-Key": "busy"}
            )
        assert (busy.status_code, busy.json()["code"]) == (409, "idempotency_in_progress")
        assert migrated_db.sql("SELECT id FROM users WHERE email_normalized = :e", e=email) == []
        # Once it has ended, the key is free.
        done = await http.post(
            "/v1/users", json={"email": email}, headers={"Idempotency-Key": "busy"}
        )
    assert done.status_code == 201, done.text


async def test_keys_belong_to_their_caller(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    other_admin = seed_tenant(migrated_db)
    for admin_id, tenant_id in ((tenant.admin, tenant.id), (other_admin.admin, other_admin.id)):
        admin = session_caller(tenant_id, admin_id, Role.ADMIN)
        async with client(migrated_db, lambda admin=admin: admin) as http:  # type: ignore[misc]
            made = await http.post(
                "/v1/users", json={"email": an_address()}, headers={"Idempotency-Key": "shared"}
            )
            assert made.status_code == 201, made.text
    # Two callers, one key each: neither replays nor refuses the other's request.
    for admin_id, tenant_id in ((tenant.admin, tenant.id), (other_admin.admin, other_admin.id)):
        [(caller_type, caller_id, key, *_)] = stored_keys(migrated_db, tenant_id)
        assert (caller_type, caller_id, key) == ("member", admin_id, "shared")


async def test_a_refused_request_keeps_no_key(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    taken = migrated_db.sql("SELECT email FROM users WHERE id = :id", id=tenant.member)[0][0]
    async with client(migrated_db, lambda: admin) as http:
        for _ in range(2):
            exists = await http.post(
                "/v1/users", json={"email": taken}, headers={"Idempotency-Key": "taken"}
            )
            assert (exists.status_code, exists.json()["code"]) == (409, "user_exists")
    assert stored_keys(migrated_db, tenant.id) == []


async def test_an_expired_key_can_be_used_again(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        first = await http.post(
            "/v1/users", json={"email": an_address()}, headers={"Idempotency-Key": "daily"}
        )
        migrated_db.sql(
            "UPDATE idempotency_keys SET created_at = now() - interval '2 days', "
            "expires_at = now() - interval '1 day' WHERE tenant_id = :tenant",
            tenant=tenant.id,
        )
        second = await http.post(
            "/v1/users", json={"email": an_address()}, headers={"Idempotency-Key": "daily"}
        )
    assert second.status_code == 201, second.text
    assert second.json()["id"] != first.json()["id"]
    [row] = stored_keys(migrated_db, tenant.id)
    assert row[-1] == uuid.UUID(second.json()["id"])


async def test_a_request_without_a_key_keeps_nothing(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        made = await http.post("/v1/users", json={"email": an_address()})
    assert made.status_code == 201
    assert stored_keys(migrated_db, tenant.id) == []


async def test_a_bad_key_is_a_400(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        for bad in ("has space", "x" * 256):
            response = await http.post(
                "/v1/users", json={"email": an_address()}, headers={"Idempotency-Key": bad}
            )
            assert (response.status_code, response.json()["code"]) == (400, "malformed_request")


# ---- the helper itself ----


async def test_a_key_used_for_another_kind_of_resource_is_a_conflict(
    migrated_db: ScratchDatabase, api_db: Database
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    request = IdempotentRequest("kind", fingerprint("POST", "/v1/x", b"{}"))
    made = uuid.uuid4()

    async def create() -> uuid.UUID:
        return made

    async def rebuild(found: uuid.UUID) -> uuid.UUID:
        return found

    async with api_db.transaction(Scope.tenant(tenant.id)) as session:
        await once(
            session,
            admin,
            request,
            status=201,
            resource_type="user",
            create=create,
            rebuild=rebuild,
            resource_id=lambda value: value,
        )
    async with api_db.transaction(Scope.tenant(tenant.id)) as session:
        with pytest.raises(Conflict) as caught:
            await once(
                session,
                admin,
                request,
                status=201,
                resource_type="transfer",
                create=create,
                rebuild=rebuild,
                resource_id=lambda value: value,
            )
    assert caught.value.code == "idempotency_conflict"


# ---- the daily job ----


async def test_the_daily_job_deletes_expired_keys_only(migrated_db: ScratchDatabase) -> None:
    tenants = [seed_tenant(migrated_db), seed_tenant(migrated_db)]
    for n, tenant in enumerate(tenants):
        for state, expires in (("live", timedelta(hours=1)), ("old", -timedelta(hours=1))):
            migrated_db.sql(
                "INSERT INTO idempotency_keys (tenant_id, caller_type, caller_id, key, "
                "request_fingerprint, response_status, resource_type, resource_id, created_at, "
                "expires_at) VALUES (:tenant, 'member', :caller, :key, "
                "sha256(convert_to(:key, 'UTF8')), 201, 'user', :caller, :created, :expires)",
                tenant=tenant.id,
                caller=tenant.admin,
                key=f"{state}-{n}",
                created=datetime.now(UTC) - timedelta(days=2),
                expires=datetime.now(UTC) + expires,
            )
    jobs = Database.connect(migrated_db.url(JOBS), pool_size=1)
    try:
        deleted = await delete_expired_keys(jobs, batch=1)
    finally:
        await jobs.dispose()
    assert deleted >= 2  # other tests' expired keys may share the database
    for n, tenant in enumerate(tenants):
        assert [row[2] for row in stored_keys(migrated_db, tenant.id)] == [f"live-{n}"]
    assert migrated_db.sql("SELECT count(*) FROM idempotency_keys WHERE expires_at <= now()") == [
        (0,)
    ]


async def test_the_api_role_cannot_run_the_job(migrated_db: ScratchDatabase) -> None:
    database = Database.connect(migrated_db.url(API), pool_size=1)
    try:
        with pytest.raises(Exception, match="system"):
            await delete_expired_keys(database)
    finally:
        await database.dispose()
