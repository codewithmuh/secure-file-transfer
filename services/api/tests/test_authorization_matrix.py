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
from object_fixtures import FakeObjects
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.data.models import Role
from sft.data.scope import Subject
from sft.service.caller import AuthMethod, Caller, CallerKind
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio

API_KEY_SCOPES = (
    "transfers:read",
    "transfers:write",
    "upload_requests:read",
    "upload_requests:write",
    "audit:read",
)


@dataclass(frozen=True)
class Draft:
    """A draft of `Tenant.target` with one file whose single part is uploaded (#114), and a
    second draft of theirs, `ready`, whose one file is scanning, so it can be sent (#174)."""

    transfer: uuid.UUID
    file: uuid.UUID
    upload: str
    ready: uuid.UUID
    recipient: uuid.UUID
    sent: uuid.UUID
    """A sent transfer of theirs, which can be revoked (#180)."""


@dataclass(frozen=True)
class World:
    mine: Tenant
    theirs: Tenant
    draft: Draft


FILE_SIZE = 10


def seed_draft(db: ScratchDatabase, tenant: Tenant, objects: FakeObjects) -> Draft:
    """As the superuser, like the isolation suite's seed; the part is in `objects`."""
    ready, _ = seed_transfer(db, tenant.id, tenant.target)
    seed_file(db, tenant.id, ready, state="scanning")
    sent, _ = seed_transfer(db, tenant.id, tenant.target, state="sent")
    draft = Draft(uuid.uuid4(), uuid.uuid4(), f"upload-{uuid.uuid4()}", ready, uuid.uuid4(), sent)
    db.sql(
        "INSERT INTO transfers (id, tenant_id, created_by, state, expires_in) "
        "VALUES (:id, :tenant, :owner, 'draft', interval '7 days')",
        id=draft.transfer,
        tenant=tenant.id,
        owner=tenant.target,
    )
    db.sql(
        "INSERT INTO transfer_recipients (id, tenant_id, transfer_id, email, email_normalized, "
        "locale) VALUES (:id, :tenant, :transfer, 'partner@example.test', "
        "'partner@example.test', 'en')",
        id=draft.recipient,
        tenant=tenant.id,
        transfer=draft.transfer,
    )
    db.sql(
        "INSERT INTO files (id, tenant_id, transfer_id, display_name_ct, content_type, "
        "declared_size, storage_class, storage_key, s3_upload_id, part_size, part_count, state) "
        "VALUES (:id, :tenant, :transfer, '\\x0061', 'text/plain', :size, 'standard', "
        "'tenants/' || :tenant || '/files/' || :id, :upload, 5242880, 1, 'uploading')",
        id=draft.file,
        tenant=tenant.id,
        transfer=draft.transfer,
        size=FILE_SIZE,
        upload=draft.upload,
    )
    db.sql(
        "UPDATE tenant_usage SET bytes_reserved = bytes_reserved + :size WHERE tenant_id = :tenant",
        tenant=tenant.id,
        size=FILE_SIZE,
    )
    objects.put_part(draft.upload, 1, FILE_SIZE)
    return draft


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


# Callers the tenant routes don't accept at all; API keys are told apart by their scopes.
NOT_A_TENANT_CALLER = {name: 401 for name in ("no_credential", "recipient", "uploader", "operator")}
NO_KEY_SCOPE = {name: 403 for name in CALLERS if name.startswith("api_key")}


def create_row(ok: int) -> dict[str, int]:
    """`transfer.create`: any member or admin, and a key with `transfers:write`."""
    members = ("member", "member_self", "admin_passkey", "admin_totp", "admin_stale")
    return {
        **NOT_A_TENANT_CALLER,
        **NO_KEY_SCOPE,
        **dict.fromkeys(members, ok),
        "admin_other_tenant": ok,  # a draft of their own tenant
        "api_key_transfers:write": ok,
    }


def own_row(ok: int, *, scopes: tuple[str, ...] = ("transfers:write",)) -> dict[str, int]:
    """A `file.*` operation on the target's draft: Own for everyone (authn and authz 6.3, 6.4).

    Another member, and an admin signed in without a passkey (who acts as a member), can't see
    the draft: 404. An admin acting as one sees the tenant's transfers, so 403; a key with a scope
    of the operation is the admin's, sees no transfer without `transfers:read`, so 404.
    """
    return {
        **NOT_A_TENANT_CALLER,
        **NO_KEY_SCOPE,
        "member": 404,
        "member_self": ok,
        "admin_passkey": 403,
        "admin_totp": 404,
        "admin_stale": 403,
        "admin_other_tenant": 404,
        **{f"api_key_{scope}": 404 for scope in scopes},
    }


def read_row(
    ok: int, *, item: bool, scopes: tuple[str, ...] = ("transfers:read",)
) -> dict[str, int]:
    """A `transfer.read` or `file.read` operation: Own for a member, Tenant for an admin acting
    as one and for a key with a read scope (authn and authz 6.3). An item another member owns is
    404 to a member and to an admin signed in without a passkey, who acts as a member."""
    return {
        **NOT_A_TENANT_CALLER,
        **NO_KEY_SCOPE,
        "member": 404 if item else ok,
        "member_self": ok,
        "admin_passkey": ok,
        "admin_totp": 404 if item else ok,
        "admin_stale": ok,
        "admin_other_tenant": 404 if item else ok,
        **dict.fromkeys((f"api_key_{scope}" for scope in scopes), ok),
    }


def file_read_row(ok: int) -> dict[str, int]:
    """`file.read` and `dlp_findings.read` on a transfer's file: a key with only
    `upload_requests:read` gets 404, the scope of received files (contract, `getFile`)."""
    return {**read_row(ok, item=True), "api_key_upload_requests:read": 404}


def policy_read_row() -> dict[str, int]:
    """`tenant_policy.read`: every member and admin, and a key with a read scope."""
    members = ("member", "member_self", "admin_passkey", "admin_totp", "admin_stale")
    return {
        **NOT_A_TENANT_CALLER,
        **NO_KEY_SCOPE,
        **dict.fromkeys(members, 200),
        "admin_other_tenant": 200,  # their own tenant's policy
        "api_key_transfers:read": 200,
        "api_key_upload_requests:read": 200,
    }


def unlock_row() -> dict[str, int]:
    """`recipient.unlock`: Own for a member, Tenant for an admin acting as one, never a key
    (authn and authz 4.4). A local admin without a passkey gets `403 passkey_required` on another
    member's transfer, as the contract says; API keys get `403`."""
    return {
        **NOT_A_TENANT_CALLER,
        **{name: 403 for name in CALLERS if name.startswith("api_key")},
        "member": 404,
        "member_self": 200,
        "admin_passkey": 200,
        "admin_totp": 403,
        "admin_stale": 200,
        "admin_other_tenant": 404,
    }


def revoke_row() -> dict[str, int]:
    """`transfer.revoke`: Own for a member, Tenant for an admin and a key with `transfers:write`.
    A revocation needs no passkey (authn and authz 3.3), so a local admin signed in with TOTP acts
    as an admin, and it takes no step-up."""
    return {
        **NOT_A_TENANT_CALLER,
        **NO_KEY_SCOPE,
        "member": 404,
        "member_self": 200,
        "admin_passkey": 200,
        "admin_totp": 200,
        "admin_stale": 200,
        "admin_other_tenant": 404,
        "api_key_transfers:write": 200,
    }


USER_OPERATIONS = frozenset({"inviteUser", "listUsers", "getUser", "updateUser", "deactivateUser"})

EXPECTED: dict[str, dict[str, int]] = {
    "inviteUser": admin_row(201, step_up=True, item=False),
    "listUsers": admin_row(200, step_up=False, item=False),
    "getUser": admin_row(200, step_up=False, item=True),
    "updateUser": admin_row(200, step_up=True, item=True),
    "deactivateUser": admin_row(200, step_up=True, item=True),
    "createTransfer": create_row(201),
    "addTransferFile": own_row(201),
    "requestUploadPartUrls": own_row(200),
    "listUploadedParts": own_row(200),
    "completeUpload": own_row(200),
    "deleteFile": own_row(204, scopes=("transfers:write", "upload_requests:write")),
    "listTransfers": read_row(200, item=False),
    "getTransfer": read_row(200, item=True),
    "sendTransfer": own_row(200),
    "cancelTransfer": own_row(200),
    "getFile": file_read_row(200),
    "getFileInspection": file_read_row(200),
    "getTenantPolicy": policy_read_row(),
    "updateTenantPolicy": admin_row(200, step_up=True, item=False),
    "listTransferRecipients": read_row(200, item=True),
    "unlockRecipient": unlock_row(),
    "revokeTransfer": revoke_row(),
}

# The session's own operations read the session cookie itself, not a caller the matrix can put in
# its place, and two are public. tests/test_signin.py runs them with real sessions: no credential,
# a bearer, both, a revoked or expired session, a missing CSRF token, and the sign-in refusals.
COVERED_BY_SIGN_IN_TESTS = frozenset(
    {"startSignIn", "completeSignIn", "signOut", "getCurrentMember"}
)
# The link steps are public, and the /session routes read the link cookie and `X-Link-Session`
# themselves (#179): tests/test_links.py runs each with every caller of authn and authz 9.2 that
# can reach them (no credential, a member's session cookie, a bearer token, a recipient's link
# session, another recipient's and another tenant's), with real links and sessions.
COVERED_BY_LINK_TESTS = frozenset(
    {
        "resolveLink",
        "requestVerificationCode",
        "createLinkSession",
        "getLinkSession",
        "endLinkSession",
        "listSessionFiles",
    }
)
# The download routes read the link cookie themselves too (#180): tests/test_downloads.py runs
# them with no credential, a member's session cookie, a bearer token, the grant's own session,
# another recipient's and another tenant's, and without the CSRF token.
COVERED_BY_DOWNLOAD_TESTS = frozenset({"createSessionDownload", "getSessionDownloadContent"})

# The problem code each refusal carries.
CODES = {401: {"authentication_required", "reauthentication_required"}, 404: {"not_found"}}


def request_for(operation: str, world: World) -> tuple[str, str, dict[str, object] | None]:
    target = f"/v1/users/{world.mine.target}"
    file = f"/v1/files/{world.draft.file}"
    return {
        "inviteUser": ("POST", "/v1/users", {"email": f"{uuid.uuid4().hex}@example.test"}),
        "listUsers": ("GET", "/v1/users", None),
        "getUser": ("GET", target, None),
        "updateUser": ("PATCH", target, {"role": "admin"}),
        "deactivateUser": ("POST", f"{target}/deactivate", None),
        "createTransfer": (
            "POST",
            "/v1/transfers",
            {"recipients": [{"email": "partner@example.test"}]},
        ),
        "addTransferFile": (
            "POST",
            f"/v1/transfers/{world.draft.transfer}/files",
            {"display_name": "a.txt", "size": FILE_SIZE},
        ),
        "requestUploadPartUrls": ("POST", f"{file}/parts", {"part_numbers": [1]}),
        "listUploadedParts": ("GET", f"{file}/parts", None),
        "completeUpload": ("POST", f"{file}/complete", None),
        "deleteFile": ("DELETE", file, None),
        "listTransfers": ("GET", "/v1/transfers", None),
        "getTransfer": ("GET", f"/v1/transfers/{world.draft.transfer}", None),
        "sendTransfer": ("POST", f"/v1/transfers/{world.draft.ready}/send", None),
        "cancelTransfer": ("POST", f"/v1/transfers/{world.draft.ready}/cancel", None),
        "getFile": ("GET", file, None),
        "getFileInspection": ("GET", f"{file}/inspection", None),
        "getTenantPolicy": ("GET", "/v1/tenant/policy", None),
        "updateTenantPolicy": ("PATCH", "/v1/tenant/policy", {"max_expiry": "P10D"}),
        "listTransferRecipients": ("GET", f"/v1/transfers/{world.draft.transfer}/recipients", None),
        "unlockRecipient": (
            "POST",
            f"/v1/transfers/{world.draft.transfer}/recipients/{world.draft.recipient}/unlock",
            None,
        ),
        "revokeTransfer": ("POST", f"/v1/transfers/{world.draft.sent}/revoke", None),
    }[operation]


STATE = """
    SELECT 'user', id, role || '/' || status FROM users WHERE tenant_id = :t
    UNION ALL SELECT 'transfer', id, state FROM transfers WHERE tenant_id = :t
    UNION ALL SELECT 'file', id, state || '/' || (removed_at IS NULL)
                FROM files WHERE tenant_id = :t
    UNION ALL SELECT 'usage', tenant_id, bytes_reserved::text FROM tenant_usage WHERE tenant_id = :t
    UNION ALL SELECT 'policy', tenant_id, max_expiry::text FROM tenant_policies WHERE tenant_id = :t
    UNION ALL SELECT 'recipient', id, failed_attempts || '/' || (locked_at IS NULL)
                FROM transfer_recipients WHERE tenant_id = :t
    ORDER BY 1, 2
"""


def test_the_matrix_covers_every_operation_the_app_serves_and_every_caller() -> None:
    served = {
        context.original_route.operation_id  # type: ignore[attr-defined]
        for context in iter_route_contexts(create_app().routes)
    }
    assert served == (
        set(EXPECTED) | COVERED_BY_SIGN_IN_TESTS | COVERED_BY_LINK_TESTS | COVERED_BY_DOWNLOAD_TESTS
    )
    for operation, row in EXPECTED.items():
        assert set(row) == set(CALLERS), operation


CELLS = [(op, caller) for op, row in EXPECTED.items() for caller in row]


@pytest.mark.parametrize(("operation", "caller_name"), CELLS, ids=[f"{o}-{c}" for o, c in CELLS])
async def test_authorization_matrix(
    operation: str, caller_name: str, migrated_db: ScratchDatabase
) -> None:
    objects = FakeObjects()
    mine = seed_tenant(migrated_db)
    world = World(mine, seed_tenant(migrated_db), seed_draft(migrated_db, mine, objects))
    caller = CALLERS[caller_name](world)
    method, path, body = request_for(operation, world)
    before = migrated_db.sql(STATE, t=world.mine.id)
    async with client(migrated_db, lambda: caller, objects=objects) as http:
        response = await http.request(method, path, json=body)
    expected = EXPECTED[operation][caller_name]
    assert response.status_code == expected, response.text
    if expected >= 400:
        if expected == 403:
            assert response.json()["code"] in ("permission_denied", "passkey_required")
        else:
            assert response.json()["code"] in CODES[expected]
        assert response.headers["content-type"] == "application/problem+json"
        after = migrated_db.sql(STATE, t=world.mine.id)
        assert after == before, "a refused call changed users, transfers or files"
    if caller_name == "admin_totp" and operation in (*USER_OPERATIONS, "updateTenantPolicy"):
        assert response.json()["code"] == "passkey_required"
    if caller_name == "admin_other_tenant":
        # Another tenant's admin never sees or changes this tenant's users or transfers.
        assert str(world.mine.target) not in response.text
        assert str(world.mine.admin) not in response.text
        assert str(world.draft.file) not in response.text
        assert str(world.draft.ready) not in response.text
        assert str(world.draft.sent) not in response.text
