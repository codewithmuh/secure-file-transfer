"""The member routes end to end against PostgreSQL: the rules of the contract's member operations,
their audit events and the invitation's outbox message (FR-22, FR-27)."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime

import httpx2 as httpx
import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind
from sqlalchemy.ext.asyncio import AsyncSession

from member_fixtures import (
    RecordingLimiter,
    app_for,
    client,
    events,
    seed_tenant,
    seed_user,
    session_caller,
)
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.api.observability import HttpMetrics, RequestContextMiddleware
from sft.api.rate_limits import get_rate_limiter
from sft.core.errors import Conflict, Forbidden
from sft.data import users
from sft.data.audit import Origin
from sft.data.database import Database
from sft.data.models import Role
from sft.data.roles import API
from sft.service import members
from sft.service.caller import Caller, CallerKind
from sft.service.rate_limits.limits import KeyType

pytestmark = pytest.mark.anyio

PROBLEM = "application/problem+json"
ANY_ID = "01890000-0000-7000-8000-000000000000"
ROUTES = [
    ("POST", "/v1/users"),
    ("GET", "/v1/users"),
    ("GET", f"/v1/users/{ANY_ID}"),
    ("PATCH", f"/v1/users/{ANY_ID}"),
    ("POST", f"/v1/users/{ANY_ID}/deactivate"),
]


async def test_an_admin_invites_a_member_and_the_email_is_queued(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        response = await http.post(
            "/v1/users",
            json={"email": "New.Person@Example.com"},
            headers={"User-Agent": "matrix/1", "Idempotency-Key": "k-1"},
        )
        assert response.status_code == 201, response.text
        user = response.json()
        assert response.headers["location"] == f"/v1/users/{user['id']}"
        assert {k: v for k, v in user.items() if k not in ("id", "created_at")} == {
            "email": "New.Person@Example.com",
            "role": "member",
            "status": "invited",
            "sso_fallback": False,
            "dlp_approver": False,
        }
        again = await http.post("/v1/users", json={"email": "new.person@example.com"})
        assert (again.status_code, again.json()["code"]) == (409, "user_exists")
        plus = await http.post("/v1/users", json={"email": "first.last+tag@sub.example.co.jp"})
        assert plus.status_code == 201, plus.text
    user_id = uuid.UUID(user["id"])
    assert events(migrated_db, user_id) == [("user.invited", "admin", tenant.admin, False)]
    [(user_agent,)] = migrated_db.sql(
        "SELECT user_agent FROM audit_events WHERE target_id = :id", id=user_id
    )
    assert user_agent == "matrix/1"
    assert migrated_db.sql(
        "SELECT topic, tenant_id FROM outbox WHERE payload ->> 'user_id' = :id", id=str(user_id)
    ) == [("member.invited", tenant.id)]


@pytest.mark.parametrize(
    "body",
    [
        {"email": "not-an-address"},
        {"email": "a@b"},
        {"email": "a b@example.com"},
        {"email": "a@example.com", "role": "owner"},
        {"email": "a@example.com", "extra": True},
        {"email": "x" * 250 + "@example.com"},
        {"email": "x" * 65 + "@example.com"},
        {"email": "a@example."},
        # What the mail adapter refuses in a header (sft.core.addresses), so it's never invited.
        *({"email": f"a{c}b@example.com"} for c in ',;<>"'),
        *(
            {"email": f"ab{c}@example.com"}
            for c in ("\u202a", "\u202e", "\u200b", "\u200f", "\u2060", "\u206f", "\ufeff")
        ),
        {"email": "a\u00adb@example.com"},
        {},
    ],
)
async def test_an_invitation_is_validated(
    body: dict[str, object], migrated_db: ScratchDatabase
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        assert (await http.post("/v1/users", json=body)).status_code == 422


async def test_an_admin_lists_filters_and_pages_the_tenants_users(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    other = seed_tenant(migrated_db)
    invited = seed_user(migrated_db, tenant.id, status="invited")
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        everyone = (await http.get("/v1/users")).json()
        ids = [u["id"] for u in everyone["items"]]
        assert ids == [str(i) for i in (tenant.admin, tenant.member, tenant.target, invited)]
        assert everyone["next_cursor"] is None
        assert str(other.admin) not in str(everyone)

        first = (await http.get("/v1/users", params={"limit": 2})).json()
        assert [u["id"] for u in first["items"]] == ids[:2]
        second = (
            await http.get("/v1/users", params={"limit": 2, "cursor": first["next_cursor"]})
        ).json()
        assert [u["id"] for u in second["items"]] == ids[2:]
        assert second["next_cursor"] is None

        admins = (await http.get("/v1/users", params={"role": "admin"})).json()
        assert [u["id"] for u in admins["items"]] == [str(tenant.admin)]
        pending = (await http.get("/v1/users", params={"status": "invited"})).json()
        assert [u["id"] for u in pending["items"]] == [str(invited)]
        approvers = (await http.get("/v1/users", params={"dlp_approver": "true"})).json()
        assert approvers["items"] == []

        bad = await http.get("/v1/users", params={"cursor": "!!"})
        assert (bad.status_code, bad.json()["code"]) == (400, "invalid_cursor")
        # A bad query parameter is a 400 (API README 3.1).
        for limit in (0, 101):
            low = await http.get("/v1/users", params={"limit": limit})
            assert (low.status_code, low.json()["code"]) == (400, "malformed_request")

        one = await http.get(f"/v1/users/{tenant.member}")
        assert one.json()["id"] == str(tenant.member)
        assert (await http.get(f"/v1/users/{uuid.uuid4()}")).status_code == 404
        assert (await http.get(f"/v1/users/{other.admin}")).status_code == 404


async def test_role_and_approver_changes_are_audited_and_unchanged_values_write_nothing(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    path = f"/v1/users/{tenant.target}"
    async with client(migrated_db, lambda: admin) as http:
        promoted = await http.patch(path, json={"role": "admin", "dlp_approver": True})
        assert promoted.status_code == 200, promoted.text
        assert (promoted.json()["role"], promoted.json()["dlp_approver"]) == ("admin", True)
        same = await http.patch(path, json={"role": "admin", "sso_fallback": False})
        assert same.status_code == 200
        demoted = await http.patch(path, json={"role": "member", "dlp_approver": False})
        assert demoted.json()["role"] == "member"
    assert [(e[0], e[3]) for e in events(migrated_db, tenant.target)] == [
        ("user.role_changed", False),
        ("user.dlp_approver_changed", False),
        ("user.role_changed", True),  # a demotion is security-critical
        ("user.dlp_approver_changed", False),
    ]


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        ({}, 422, None),
        ({"role": None}, 422, None),
        ({"nickname": "x"}, 422, None),
        ({"sso_fallback": True}, 422, "validation_failed"),  # no tenant uses SSO before M6
    ],
)
async def test_an_update_is_validated(
    body: dict[str, object], status: int, code: str | None, migrated_db: ScratchDatabase
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        response = await http.patch(f"/v1/users/{tenant.target}", json=body)
    assert response.status_code == status
    if code:
        assert response.json()["code"] == code
    assert events(migrated_db, tenant.target) == []


async def test_only_an_active_user_becomes_an_approver(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    invited = seed_user(migrated_db, tenant.id, status="invited")
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        response = await http.patch(f"/v1/users/{invited}", json={"dlp_approver": True})
        assert (response.status_code, response.json()["code"]) == (422, "validation_failed")
        member = await http.patch(
            f"/v1/users/{invited}", json={"role": "admin", "sso_fallback": True}
        )
        assert member.status_code == 422


async def test_the_tenant_keeps_an_active_admin(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        demote = await http.patch(f"/v1/users/{tenant.admin}", json={"role": "member"})
        assert (demote.status_code, demote.json()["code"]) == (409, "last_admin")
        leave = await http.post(f"/v1/users/{tenant.admin}/deactivate")
        assert (leave.status_code, leave.json()["code"]) == (409, "last_admin")
        # With a second active admin, the first may step down.
        assert (await http.patch(f"/v1/users/{tenant.target}", json={"role": "admin"})).is_success
        assert (await http.patch(f"/v1/users/{tenant.admin}", json={"role": "member"})).is_success
    assert migrated_db.sql("SELECT role FROM users WHERE id = :id", id=tenant.admin) == [
        ("member",)
    ]


async def test_two_admins_demoting_each_other_at_once_leave_one_admin(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    second = seed_user(migrated_db, tenant.id, role="admin")
    database = Database.connect(migrated_db.url(API), pool_size=2)
    origin = Origin()
    try:

        async def demote(by: uuid.UUID, target: uuid.UUID) -> object:
            caller = session_caller(tenant.id, by, Role.ADMIN)
            try:
                return await members.update_user(
                    database, caller, target, role=Role.MEMBER, origin=origin, now=datetime.now(UTC)
                )
            except Conflict as exc:
                return exc

        results = await asyncio.gather(demote(tenant.admin, second), demote(second, tenant.admin))
    finally:
        await database.dispose()
    assert [r.code for r in results if isinstance(r, Conflict)] == ["last_admin"]
    assert migrated_db.sql(
        "SELECT count(*) FROM users WHERE tenant_id = :t AND role = 'admin' AND status = 'active'",
        t=tenant.id,
    ) == [(1,)]


async def test_deactivation_is_security_critical_and_safe_to_retry(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    path = f"/v1/users/{tenant.target}"
    async with client(migrated_db, lambda: admin) as http:
        first = await http.post(f"{path}/deactivate")
        assert (first.status_code, first.json()["status"]) == (200, "deactivated")
        again = await http.post(f"{path}/deactivate")
        assert (again.status_code, again.json()["status"]) == (200, "deactivated")
        change = await http.patch(path, json={"role": "admin"})
        assert (change.status_code, change.json()["code"]) == (409, "invalid_state")
        assert (await http.post(f"/v1/users/{uuid.uuid4()}/deactivate")).status_code == 404
    assert events(migrated_db, tenant.target) == [("user.deactivated", "admin", tenant.admin, True)]


async def test_without_a_session_every_member_route_answers_401(
    migrated_db: ScratchDatabase,
) -> None:
    # The real caller dependency (#113): no session cookie, no caller.
    app = create_app()
    limiter = RecordingLimiter()
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as http:
        for method, path in ROUTES:
            response = await http.request(method, path, json={})
            assert response.status_code == 401, path
            assert response.json()["code"] == "authentication_required"
    assert limiter.checks == [], "a request without a caller counted against no limit"


async def test_a_refusal_is_a_problem_document(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    deactivated = seed_user(migrated_db, tenant.id, status="deactivated")
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        response = await http.patch(f"/v1/users/{deactivated}", json={"dlp_approver": True})
        missing = await http.patch(f"/v1/users/{uuid.uuid4()}", json={"dlp_approver": True})
    assert response.headers["content-type"] == PROBLEM
    problem = response.json()
    assert (problem["status"], problem["code"]) == (409, "invalid_state")
    assert problem["current_state"] == "deactivated"
    assert problem["type"].endswith("/invalid_state")
    assert (missing.status_code, missing.json()["code"]) == (404, "not_found")


async def test_only_an_admin_stays_a_fallback_admin(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    fallback = seed_user(migrated_db, tenant.id, role="admin")
    migrated_db.sql("UPDATE users SET sso_fallback = true WHERE id = :id", id=fallback)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    path = f"/v1/users/{fallback}"
    async with client(migrated_db, lambda: admin) as http:
        demote = await http.patch(path, json={"role": "member", "sso_fallback": True})
        assert (demote.status_code, demote.json()["code"]) == (422, "validation_failed")
        assert [e["pointer"] for e in demote.json()["errors"]] == ["#/sso_fallback"]
        cleared = await http.patch(path, json={"sso_fallback": False})
        assert (cleared.status_code, cleared.json()["sso_fallback"]) == (200, False)
    assert [e[0] for e in events(migrated_db, fallback)] == ["user.sso_fallback_changed"]


async def test_the_service_guards_what_the_route_already_refuses(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    now = datetime.now(UTC)
    database = Database.connect(migrated_db.url(API), pool_size=1)
    try:
        # The route refuses a bad limit with a 400; one that gets past it is a bug.
        with pytest.raises(ValueError, match="page"):
            await members.list_users(database, admin, limit=0, now=now)
        # The system actor passes authorize; without a tenant it reaches no user.
        with pytest.raises(Forbidden):
            await members.list_users(database, Caller(CallerKind.SYSTEM), now=now)
    finally:
        await database.dispose()


async def test_every_member_route_counts_against_the_callers_limits(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    limiter = RecordingLimiter()
    path = f"/v1/users/{tenant.target}"
    async with client(migrated_db, lambda: admin, limiter) as http:
        assert (await http.get("/v1/users")).is_success
        assert (await http.get(path)).is_success
        assert (await http.patch(path, json={"dlp_approver": True})).is_success
        assert (await http.post("/v1/users", json={"email": "n@example.test"})).is_success
        assert (await http.post(f"{path}/deactivate")).is_success
    tenant_api = ("H.caller_requests", "H.tenant_requests")
    assert [limits for limits, _ in limiter.checks] == [
        tenant_api,
        tenant_api,
        tenant_api,
        tenant_api,
        ("G.caller_emails", "G.address_invites", "G.tenant_invites"),  # once the address is known
        ("H.caller_requests",),  # a safety action never uses the tenant's budget
    ]
    keys = {KeyType.ACCOUNT: str(tenant.admin), KeyType.TENANT: str(tenant.id)}
    assert all(seen.items() >= keys.items() for _, seen in limiter.checks)


async def test_a_refused_invitation_is_a_429_and_writes_nothing(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin, RecordingLimiter(refuse=True)) as http:
        response = await http.post("/v1/users", json={"email": "n@example.test"})
    assert (response.status_code, response.json()["code"]) == (429, "rate_limited")
    assert response.headers["retry-after"] == "30"
    assert migrated_db.sql(
        "SELECT count(*) FROM users WHERE tenant_id = :t AND email = 'n@example.test'",
        t=tenant.id,
    ) == [(0,)]


async def test_a_member_refused_an_invitation_uses_none_of_the_tenants_invitations(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    member = session_caller(tenant.id, tenant.member, Role.MEMBER)
    limiter = RecordingLimiter()
    async with client(migrated_db, lambda: member, limiter) as http:
        response = await http.post("/v1/users", json={"email": "n@example.test"})
    assert (response.status_code, response.json()["code"]) == (403, "permission_denied")
    assert [limits for limits, _ in limiter.checks] == [("H.caller_requests", "H.tenant_requests")]


async def test_an_invitation_is_one_trace_without_the_address(
    migrated_db: ScratchDatabase, spans: InMemorySpanExporter
) -> None:
    # The member routes get #121's spans as every route does: the server's middleware makes the
    # request's span, the database its statements' and the outbox its message's.
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    database = Database.connect(migrated_db.url(API), pool_size=1)
    try:
        app = RequestContextMiddleware(app_for(database, lambda: admin), HttpMetrics.create())
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as http:
            response = await asyncio.create_task(
                http.post("/v1/users", json={"email": "traced@example.test"})
            )
    finally:
        await database.dispose()
    assert response.status_code == 201
    finished = spans.get_finished_spans()
    [server] = [span for span in finished if span.name == "POST /v1/users"]
    [create] = [span for span in finished if span.name == "create notify"]
    assert server.kind is SpanKind.SERVER
    assert server.attributes is not None
    assert server.attributes["http.route"] == "/v1/users"
    assert create.kind is SpanKind.PRODUCER
    trace_id = server.context.trace_id if server.context else None
    assert {span.context.trace_id for span in finished if span.context} == {trace_id}
    assert any(span.kind is SpanKind.CLIENT for span in finished), "no database spans"
    assert "traced@example.test" not in str([span.to_json() for span in finished])


async def test_an_existing_address_uses_none_of_the_invitations(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    seed_user(migrated_db, tenant.id, email="taken@example.test")
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    limiter = RecordingLimiter()
    async with client(migrated_db, lambda: admin, limiter) as http:
        response = await http.post("/v1/users", json={"email": "Taken@example.test"})
    assert (response.status_code, response.json()["code"]) == (409, "user_exists")
    assert [limits for limits, _ in limiter.checks] == [("H.caller_requests", "H.tenant_requests")]


async def test_deactivation_clears_the_approver_and_fallback_flags(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    flagged = seed_user(migrated_db, tenant.id, role="admin")
    migrated_db.sql(
        "UPDATE users SET dlp_approver = true, sso_fallback = true WHERE id = :id", id=flagged
    )
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        response = await http.post(f"/v1/users/{flagged}/deactivate")
    body = response.json()
    assert (body["status"], body["dlp_approver"], body["sso_fallback"]) == (
        "deactivated",
        False,
        False,
    )
    assert migrated_db.sql(
        "SELECT dlp_approver, sso_fallback FROM users WHERE id = :id", id=flagged
    ) == [(False, False)]


async def test_an_operator_token_on_a_member_route_gets_the_bearer_challenge(
    migrated_db: ScratchDatabase,
) -> None:
    operator = Caller(CallerKind.OPERATOR, credential_id=uuid.uuid4())
    async with client(migrated_db, lambda: operator) as http:
        response = await http.get("/v1/users")
    assert (response.status_code, response.json()["code"]) == (401, "authentication_required")
    assert response.headers["www-authenticate"] == "Bearer"


class LockSpy:
    """Counts `lock_active_admins`, and can promote the target between the read and the lock."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, before_lock: Callable[[], None]) -> None:
        self.admin_locks = 0
        self.reads = 0
        lock, get = users.lock_active_admins, users.get_user

        async def counted_lock(session: AsyncSession) -> Sequence[uuid.UUID]:
            self.admin_locks += 1
            return await lock(session)

        async def read(session: AsyncSession, user_id: uuid.UUID, **kwargs: bool) -> object:
            found = await get(session, user_id, **kwargs)
            self.reads += 1
            if self.reads == 1:
                before_lock()
            return found

        monkeypatch.setattr(users, "lock_active_admins", counted_lock)
        monkeypatch.setattr(users, "get_user", read)


async def test_only_a_change_that_can_lose_an_admin_locks_the_admins(
    migrated_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = seed_tenant(migrated_db)
    spy = LockSpy(monkeypatch, lambda: None)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        assert (await http.patch(f"/v1/users/{tenant.target}", json={"role": "admin"})).is_success
        assert (await http.post(f"/v1/users/{tenant.member}/deactivate")).is_success
        assert spy.admin_locks == 0
        # Demoting an active admin locks them, so it can be refused as the last one.
        demote = await http.patch(f"/v1/users/{tenant.admin}", json={"role": "member"})
        assert demote.is_success
        assert spy.admin_locks == 1


async def test_a_user_promoted_meanwhile_is_locked_again_with_the_admins(
    migrated_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant = seed_tenant(migrated_db)

    def promote() -> None:
        # Another admin's promotion commits between this request's first read and its lock.
        migrated_db.sql("UPDATE users SET role = 'admin' WHERE id = :id", id=tenant.target)

    spy = LockSpy(monkeypatch, promote)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        response = await http.post(f"/v1/users/{tenant.target}/deactivate")
    assert (response.status_code, response.json()["status"]) == (200, "deactivated")
    # Read, lock (now an admin, so start again), then the admins and the user, locked.
    assert (spy.reads, spy.admin_locks) == (3, 1)
