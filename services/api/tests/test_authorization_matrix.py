"""The authorization matrix (authn and authz 9.2): every implemented operation with every caller.

Each operation the app serves has a row in `EXPECTED`, with the status every caller of 9.2 gets:
no credential, a member, the member acting on themselves, an admin signed in with a passkey, a local
admin signed in with TOTP, an admin whose sign-in is too old for step-up, an admin of another
tenant, an API key with each scope and with none, a recipient, an uploader and an operator.
A test fails if the app serves an operation the matrix doesn't list, so every later endpoint
extends it (delivery plan 2, point 3). The expectations are written out, not derived from the
registry, so the matrix checks the registry too.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta

import pytest
from fastapi.routing import iter_route_contexts

from member_fixtures import Tenant, client, seed_tenant, session_caller
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.data.models import Role
from sft.data.scope import Subject
from sft.service.caller import AuthMethod, Caller, CallerKind

pytestmark = pytest.mark.anyio

API_KEY_SCOPES = (
    "transfers:read",
    "transfers:write",
    "upload_requests:read",
    "upload_requests:write",
    "audit:read",
)


@dataclass(frozen=True)
class World:
    mine: Tenant
    theirs: Tenant


CallerFor = Callable[[World], Caller | None]

CALLERS: dict[str, CallerFor] = {
    "no_credential": lambda w: None,
    "member": lambda w: session_caller(w.mine.id, w.mine.member, Role.MEMBER),
    "member_self": lambda w: session_caller(w.mine.id, w.mine.target, Role.MEMBER),
    "admin_passkey": lambda w: session_caller(w.mine.id, w.mine.admin, Role.ADMIN),
    "admin_totp": lambda w: session_caller(
        w.mine.id, w.mine.admin, Role.ADMIN, AuthMethod.PASSWORD_TOTP
    ),
    "admin_stale": lambda w: session_caller(
        w.mine.id, w.mine.admin, Role.ADMIN, signed_in=timedelta(minutes=16)
    ),
    "admin_other_tenant": lambda w: session_caller(w.theirs.id, w.theirs.admin, Role.ADMIN),
    **{
        f"api_key_{scope}": (
            lambda w, s=scope: Caller(  # type: ignore[misc]
                CallerKind.API_KEY,
                tenant_id=w.mine.id,
                user_id=w.mine.admin,
                credential_id=uuid.uuid4(),
                scopes=frozenset({s}),
            )
        )
        for scope in API_KEY_SCOPES
    },
    "api_key_no_scope": lambda w: Caller(
        CallerKind.API_KEY, tenant_id=w.mine.id, user_id=w.mine.admin, credential_id=uuid.uuid4()
    ),
    "recipient": lambda w: Caller(
        CallerKind.RECIPIENT,
        tenant_id=w.mine.id,
        subject=Subject.recipient(uuid.uuid4()),
        credential_id=uuid.uuid4(),
    ),
    "uploader": lambda w: Caller(
        CallerKind.UPLOADER,
        tenant_id=w.mine.id,
        subject=Subject.upload_request(uuid.uuid4()),
        credential_id=uuid.uuid4(),
    ),
    "operator": lambda w: Caller(CallerKind.OPERATOR, credential_id=uuid.uuid4()),
}

# Callers the member routes don't accept at all: no credential they read, so 401 (table 6.3).
NOT_A_MEMBER = {
    name: 401
    for name in CALLERS
    if name.startswith("api_key") or name in ("no_credential", "recipient", "uploader", "operator")
}


def admin_row(ok: int, *, step_up: bool, item: bool) -> dict[str, int]:
    """A `user.*` operation: admins only, with a passkey if local; another tenant's user is 404."""
    return {
        **NOT_A_MEMBER,
        "member": 403,
        "member_self": 403,
        "admin_passkey": ok,
        "admin_totp": 403,
        "admin_stale": 401 if step_up else ok,
        "admin_other_tenant": 404 if item else ok,
    }


EXPECTED: dict[str, dict[str, int]] = {
    "inviteUser": admin_row(201, step_up=True, item=False),
    "listUsers": admin_row(200, step_up=False, item=False),
    "getUser": admin_row(200, step_up=False, item=True),
    "updateUser": admin_row(200, step_up=True, item=True),
    "deactivateUser": admin_row(200, step_up=True, item=True),
}

# The session's own operations read the session cookie itself, not a caller the matrix can put in
# its place, and two are public. tests/test_signin.py runs them with real sessions: no credential,
# a bearer, both, a revoked or expired session, a missing CSRF token, and the sign-in refusals.
COVERED_BY_SIGN_IN_TESTS = frozenset(
    {"startSignIn", "completeSignIn", "signOut", "getCurrentMember"}
)

# The problem code each refusal carries.
CODES = {401: {"authentication_required", "reauthentication_required"}, 404: {"not_found"}}


def request_for(operation: str, world: World) -> tuple[str, str, dict[str, object] | None]:
    target = f"/v1/users/{world.mine.target}"
    return {
        "inviteUser": ("POST", "/v1/users", {"email": f"{uuid.uuid4().hex}@example.test"}),
        "listUsers": ("GET", "/v1/users", None),
        "getUser": ("GET", target, None),
        "updateUser": ("PATCH", target, {"role": "admin"}),
        "deactivateUser": ("POST", f"{target}/deactivate", None),
    }[operation]


def test_the_matrix_covers_every_operation_the_app_serves_and_every_caller() -> None:
    served = {
        context.original_route.operation_id  # type: ignore[attr-defined]
        for context in iter_route_contexts(create_app().routes)
    }
    assert served == set(EXPECTED) | COVERED_BY_SIGN_IN_TESTS
    for operation, row in EXPECTED.items():
        assert set(row) == set(CALLERS), operation


CELLS = [(op, caller) for op, row in EXPECTED.items() for caller in row]


@pytest.mark.parametrize(("operation", "caller_name"), CELLS, ids=[f"{o}-{c}" for o, c in CELLS])
async def test_authorization_matrix(
    operation: str, caller_name: str, migrated_db: ScratchDatabase
) -> None:
    world = World(seed_tenant(migrated_db), seed_tenant(migrated_db))
    caller = CALLERS[caller_name](world)
    method, path, body = request_for(operation, world)
    before = migrated_db.sql(
        "SELECT id, role, status FROM users WHERE tenant_id = :t ORDER BY id", t=world.mine.id
    )
    async with client(migrated_db, lambda: caller) as http:
        response = await http.request(method, path, json=body)
    expected = EXPECTED[operation][caller_name]
    assert response.status_code == expected, response.text
    if expected >= 400:
        if expected == 403:
            assert response.json()["code"] in ("permission_denied", "passkey_required")
        else:
            assert response.json()["code"] in CODES[expected]
        assert response.headers["content-type"] == "application/problem+json"
        after = migrated_db.sql(
            "SELECT id, role, status FROM users WHERE tenant_id = :t ORDER BY id",
            t=world.mine.id,
        )
        assert after == before, "a refused call changed users"
    if caller_name == "admin_totp":
        assert response.json()["code"] == "passkey_required"
    if caller_name == "admin_other_tenant":
        # Another tenant's admin never sees or changes this tenant's users.
        assert str(world.mine.target) not in response.text
        assert str(world.mine.admin) not in response.text
