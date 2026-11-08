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
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.routing import iter_route_contexts

from member_fixtures import Tenant, client, seed_tenant, session_caller
from object_fixtures import FakeObjects
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.core.ids import uuid7
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
    api_key: uuid.UUID
    """A live API key of the tenant's admin, which can be revoked (#215)."""
    upload_request: uuid.UUID = field(default_factory=uuid.uuid4)
    """An open upload request of theirs, which can be read, revoked and unlocked (#212)."""


@dataclass(frozen=True)
class DlpItems:
    """One of the tenant's default rules, and a keyword list of its own that no rule uses (#218)."""

    rule: uuid.UUID
    detector: uuid.UUID


def seed_dlp_items(db: ScratchDatabase, tenant: Tenant) -> DlpItems:
    """As the superuser; seed_tenant wrote the default policy."""
    [(rule,)] = db.sql(
        "SELECT id FROM dlp_rules WHERE tenant_id = :t AND condition = 'new_domain'", t=tenant.id
    )
    detector = uuid.uuid4()
    db.sql(
        "INSERT INTO dlp_detectors (id, revision, tenant_id, name, kind, definition_ct, "
        "created_by) VALUES (:id, 1, :tenant, 'Projects', 'keywords', :definition, :admin)",
        id=detector,
        tenant=tenant.id,
        definition=b'\x00{"kind":"keywords","terms":["orion"]}',
        admin=tenant.admin,
    )
    return DlpItems(rule, detector)  # type: ignore[arg-type]


@dataclass(frozen=True)
class Decided:
    """A transfer of `Tenant.target` awaiting confirmation of a warning, its decision, and its
    clean file (#219)."""

    transfer: uuid.UUID
    decision: uuid.UUID
    file: uuid.UUID


def seed_decided(db: ScratchDatabase, tenant: Tenant, rule: uuid.UUID) -> Decided:
    """As the superuser: the new-domain rule's warning, as the evaluation would have made it."""
    transfer, _ = seed_transfer(
        db, tenant.id, tenant.target, state="awaiting_confirmation", recipients=("a@new.example",)
    )
    file = seed_file(db, tenant.id, transfer, state="clean")
    decision = uuid.uuid4()
    db.sql(
        "INSERT INTO dlp_decisions (id, tenant_id, transfer_id, policy_version, mode, outcome, "
        "enforced, untrusted_recipients, new_domains) "
        "VALUES (:id, :tenant, :transfer, 1, 'enforce', 'warn', true, 1, 1)",
        id=decision,
        tenant=tenant.id,
        transfer=transfer,
    )
    db.sql(
        "INSERT INTO dlp_decision_rules (decision_id, tenant_id, rule_id, rule_revision, action, "
        "matched_count) VALUES (:decision, :tenant, :rule, 1, 'warn', 1)",
        decision=decision,
        tenant=tenant.id,
        rule=rule,
    )
    db.sql(
        "UPDATE transfers SET dlp_decision_id = :decision WHERE id = :transfer",
        decision=decision,
        transfer=transfer,
    )
    return Decided(transfer, decision, file)


@dataclass(frozen=True)
class Pending:
    """A transfer of `Tenant.target` pending approval, and its request (#220). Both tenants'
    admins are approvers, so the admin columns are approvers too; the members aren't."""

    transfer: uuid.UUID
    request: uuid.UUID


def seed_pending(db: ScratchDatabase, tenant: Tenant, other: Tenant, rule: uuid.UUID) -> Pending:
    """As the superuser: a required approval the target asked for, as confirmTransfer makes it."""
    db.sql(
        "UPDATE users SET dlp_approver = true WHERE id IN (:mine, :theirs)",
        mine=tenant.admin,
        theirs=other.admin,
    )
    transfer, _ = seed_transfer(
        db, tenant.id, tenant.target, state="pending_approval", recipients=("a@new.example",)
    )
    seed_file(db, tenant.id, transfer, state="clean")
    decision, confirmation, request = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    db.sql(
        "INSERT INTO dlp_decisions (id, tenant_id, transfer_id, policy_version, mode, outcome, "
        "enforced, untrusted_recipients, new_domains) "
        "VALUES (:id, :tenant, :transfer, 1, 'enforce', 'require_approval', true, 1, 1)",
        id=decision,
        tenant=tenant.id,
        transfer=transfer,
    )
    db.sql(
        "INSERT INTO dlp_decision_rules (decision_id, tenant_id, rule_id, rule_revision, action, "
        "matched_count) VALUES (:decision, :tenant, :rule, 1, 'require_approval', 1)",
        decision=decision,
        tenant=tenant.id,
        rule=rule,
    )
    db.sql(
        "UPDATE transfers SET dlp_decision_id = :decision WHERE id = :transfer",
        decision=decision,
        transfer=transfer,
    )
    db.sql(
        "INSERT INTO dlp_confirmations (id, tenant_id, transfer_id, decision_id, confirmed_by, "
        "justification_ct) VALUES (:id, :tenant, :transfer, :decision, :user, '\\x0061')",
        id=confirmation,
        tenant=tenant.id,
        transfer=transfer,
        decision=decision,
        user=tenant.target,
    )
    db.sql(
        "INSERT INTO dlp_approval_requests (id, tenant_id, transfer_id, decision_id, "
        "confirmation_id, requested_by, approvals_required, expires_at) VALUES (:id, :tenant, "
        ":transfer, :decision, :confirmation, :user, 1, now() + interval '1 day')",
        id=request,
        tenant=tenant.id,
        transfer=transfer,
        decision=decision,
        confirmation=confirmation,
        user=tenant.target,
    )
    return Pending(transfer, request)


@dataclass(frozen=True)
class World:
    mine: Tenant
    theirs: Tenant
    draft: Draft
    dlp: DlpItems | None = None
    decided: Decided | None = None
    pending: Pending | None = None


FILE_SIZE = 10


def seed_draft(db: ScratchDatabase, tenant: Tenant, objects: FakeObjects) -> Draft:
    """As the superuser, like the isolation suite's seed; the part is in `objects`."""
    ready, _ = seed_transfer(db, tenant.id, tenant.target)
    seed_file(db, tenant.id, ready, state="scanning")
    sent, _ = seed_transfer(db, tenant.id, tenant.target, state="sent")
    draft = Draft(
        uuid.uuid4(), uuid.uuid4(), f"upload-{uuid.uuid4()}", ready, uuid.uuid4(), sent, uuid7()
    )
    db.sql(
        "INSERT INTO api_keys (id, tenant_id, created_by, name, key_prefix, key_hash, scopes, "
        "expires_at) VALUES (:id, :tenant, :admin, 'matrix', 'sft_dev_Matrix00', "
        "sha256(convert_to(CAST(:id AS text), 'UTF8')), ARRAY['transfers:read'], "
        "now() + interval '30 days')",
        id=draft.api_key,
        tenant=tenant.id,
        admin=tenant.admin,
    )
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
    db.sql(
        "INSERT INTO upload_requests (id, tenant_id, created_by, state, uploader_email, "
        "email_normalized, locale, expires_at, delivery_state) VALUES (:id, :tenant, :owner, "
        "'open', 'uploader@example.test', 'uploader@example.test', 'en', "
        "now() + interval '7 days', 'sent')",
        id=draft.upload_request,
        tenant=tenant.id,
        owner=tenant.target,
    )
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

# Callers the member routes don't accept at all: no credential they read, so 401 (table 6.3). A
# live API key is a credential they read (#215), refused with 403 on an operation for web sessions
# only (T-55).
NOT_A_MEMBER = {
    **{name: 401 for name in ("no_credential", "recipient", "uploader", "operator")},
    **{name: 403 for name in CALLERS if name.startswith("api_key")},
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


def dlp_row(ok: int, *, step_up: bool, item: bool) -> dict[str, int]:
    """A `dlp_policy.*` operation: admins only, with a passkey if local; API keys `403` whatever
    their scopes (authn and authz 5.3); another tenant's rule or detector is 404 (#218)."""
    return {
        **admin_row(ok, step_up=step_up, item=item),
        **{name: 403 for name in CALLERS if name.startswith("api_key")},
    }


def confirm_row() -> dict[str, int]:
    """`transfer.confirm`: Own for a member and an admin, web sessions only (authn and authz 5.3,
    6.3). An admin acting as one sees another member's transfer, so `403`; a local admin without
    a passkey acts as a member, so 404; every API key `403`, whatever its scopes (#219)."""
    return {**own_row(200), **{name: 403 for name in CALLERS if name.startswith("api_key")}}


def approval_read_row(*, item: bool) -> dict[str, int]:
    """`dlp_approval.read`: Own for a member, Tenant for an admin, and every request for an
    approver; never a key (authn and authz 5.3, 6.3; #220). The list's default scope is the
    approver's queue or the caller's own requests, so every person gets a page. The request is
    the target's: another member, neither sender nor approver, gets 404, as does another
    tenant's admin; the admins here are approvers, so a TOTP sign-in sees it too."""
    return {
        **NOT_A_TENANT_CALLER,
        **{name: 403 for name in CALLERS if name.startswith("api_key")},
        "member": 404 if item else 200,
        "member_self": 200,
        "admin_passkey": 200,
        "admin_totp": 200,
        "admin_stale": 200,
        "admin_other_tenant": 404 if item else 200,
    }


def decide_row(*, step_up: bool) -> dict[str, int]:
    """`dlp_approval.decide`: approvers only, not an admin right, so no passkey rule (#220). A
    member who isn't an approver gets 403, the sender (the target, no approver either) too;
    another tenant's approver 404; approving needs a recent sign-in, rejecting doesn't."""
    return {
        **NOT_A_TENANT_CALLER,
        **{name: 403 for name in CALLERS if name.startswith("api_key")},
        "member": 403,
        "member_self": 403,
        "admin_passkey": 200,
        "admin_totp": 200,
        "admin_stale": 401 if step_up else 200,
        "admin_other_tenant": 404,
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


def upload_request_create_row() -> dict[str, int]:
    """`upload_request.create`: any member or admin, and a key with `upload_requests:write`."""
    return {**create_row(201), "api_key_transfers:write": 403, "api_key_upload_requests:write": 201}


def upload_request_revoke_row() -> dict[str, int]:
    """`upload_request.revoke` (#212): as `transfer.revoke`, with `upload_requests:write`. Exempt
    from the passkey rule, so a local admin signed in with TOTP acts as an admin."""
    return {**revoke_row(), "api_key_transfers:write": 403, "api_key_upload_requests:write": 200}


USER_OPERATIONS = frozenset(
    {
        "inviteUser",
        "listUsers",
        "getUser",
        "updateUser",
        "deactivateUser",
        "signOutUser",
        "resetUserSignIn",
    }
)


def key_revoke_row() -> dict[str, int]:
    """`api_key.revoke`: any admin of the tenant, without a passkey or step-up (authn and authz
    3.3); never a member or a key."""
    return {
        **NOT_A_MEMBER,
        "member": 403,
        "member_self": 403,
        "admin_passkey": 200,
        "admin_totp": 200,
        "admin_stale": 200,
        "admin_other_tenant": 404,
    }


def audit_row(ok: int, *, step_up: bool) -> dict[str, int]:
    """`audit.search` and `audit.export`: an admin acting as one, or a key with `audit:read`
    (table 6.3); another tenant's admin reads their own tenant's log."""
    return {
        **NOT_A_TENANT_CALLER,
        **NO_KEY_SCOPE,
        "member": 403,
        "member_self": 403,
        "admin_passkey": ok,
        "admin_totp": 403,
        "admin_stale": 401 if step_up else ok,
        "admin_other_tenant": ok,
        "api_key_audit:read": ok,
    }


ADMIN_ONLY = frozenset(
    {
        "updateTenantPolicy",
        "createApiKey",
        "listApiKeys",
        "searchAuditEvents",
        "exportAuditEvents",
        "clearEmailSuppression",
    }
)

EXPECTED: dict[str, dict[str, int]] = {
    "inviteUser": admin_row(201, step_up=True, item=False),
    "listUsers": admin_row(200, step_up=False, item=False),
    "getUser": admin_row(200, step_up=False, item=True),
    "updateUser": admin_row(200, step_up=True, item=True),
    "deactivateUser": admin_row(200, step_up=True, item=True),
    "signOutUser": admin_row(200, step_up=False, item=True),
    "resetUserSignIn": admin_row(202, step_up=True, item=True),
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
    # `transfer.extend`: Own for everyone; an admin acting as one sees it, so 403 (#214).
    "extendTransferExpiry": own_row(200),
    # Upload requests (#212): Own for a member, Tenant for an admin acting as one and a key with
    # the matching scope; revoke needs no passkey; unlock is a person's alone (authn and authz
    # 4.4). Recipients' and uploaders' sessions are no tenant caller: 401.
    "createUploadRequest": upload_request_create_row(),
    "listUploadRequests": read_row(200, item=False, scopes=("upload_requests:read",)),
    "getUploadRequest": read_row(200, item=True, scopes=("upload_requests:read",)),
    "revokeUploadRequest": upload_request_revoke_row(),
    "unlockUploader": unlock_row(),
    # Received files (#213): as `getUploadRequest`, admins and keys see the metadata.
    "listUploadRequestFiles": read_row(200, item=True, scopes=("upload_requests:read",)),
    "createApiKey": admin_row(201, step_up=True, item=False),
    "listApiKeys": admin_row(200, step_up=False, item=False),
    "revokeApiKey": key_revoke_row(),
    "searchAuditEvents": audit_row(200, step_up=False),
    "exportAuditEvents": audit_row(200, step_up=True),
    "clearEmailSuppression": admin_row(204, step_up=False, item=False),
    "getDlpPolicy": dlp_row(200, step_up=False, item=False),
    "updateDlpPolicy": dlp_row(200, step_up=True, item=False),
    "listDlpRules": dlp_row(200, step_up=False, item=False),
    "createDlpRule": dlp_row(201, step_up=True, item=False),
    "getDlpRule": dlp_row(200, step_up=False, item=True),
    "updateDlpRule": dlp_row(200, step_up=True, item=True),
    "deleteDlpRule": dlp_row(204, step_up=True, item=True),
    "listDlpDetectors": dlp_row(200, step_up=False, item=False),
    "createDlpDetector": dlp_row(201, step_up=True, item=False),
    "getDlpDetector": dlp_row(200, step_up=False, item=True),
    "updateDlpDetector": dlp_row(200, step_up=True, item=True),
    "deleteDlpDetector": dlp_row(204, step_up=True, item=True),
    "getTransferDlp": file_read_row(200),
    "confirmTransfer": confirm_row(),
    "listApprovalRequests": approval_read_row(item=False),
    "getApprovalRequest": approval_read_row(item=True),
    "approveTransfer": decide_row(step_up=True),
    "rejectTransfer": decide_row(step_up=False),
}

# The policy operations, which need the admin role; a transfer's decision (#219) is the owner's.
DLP_OPERATIONS = frozenset(name for name in EXPECTED if "Dlp" in name) - {"getTransferDlp"}

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
# Received files (#213): the uploader's operations read the link cookie and `X-Link-Session`, and
# the member's download needs a member session that exists, which a grant belongs to.
# tests/test_received_files.py runs them with every caller of authn and authz 9.2 that can reach
# them, with real sessions: no credential, each kind of member and admin, another tenant's admin,
# an API key, a recipient's and another uploader's link session, the grant's own member session
# and another of the same member's.
COVERED_BY_RECEIVED_FILE_TESTS = frozenset(
    {
        "addSessionUploadFile",
        "requestSessionUploadPartUrls",
        "listSessionUploadedParts",
        "completeSessionUpload",
        "createReceivedFileDownload",
        "getReceivedFileDownloadContent",
    }
)

# The problem code each refusal carries.
CODES = {401: {"authentication_required", "reauthentication_required"}, 404: {"not_found"}}


def request_for(operation: str, world: World) -> tuple[str, str, dict[str, object] | None]:
    target = f"/v1/users/{world.mine.target}"
    file = f"/v1/files/{world.draft.file}"
    dlp = world.dlp or DlpItems(uuid.uuid4(), uuid.uuid4())
    rule = f"/v1/dlp/rules/{dlp.rule}"
    detector = f"/v1/dlp/detectors/custom:{dlp.detector}"
    decided = world.decided or Decided(uuid.uuid4(), uuid.uuid4(), uuid.uuid4())
    pending = world.pending or Pending(uuid.uuid4(), uuid.uuid4())
    approval = f"/v1/dlp/approval-requests/{pending.request}"
    return {
        "inviteUser": ("POST", "/v1/users", {"email": f"{uuid.uuid4().hex}@example.test"}),
        "listUsers": ("GET", "/v1/users", None),
        "getUser": ("GET", target, None),
        "updateUser": ("PATCH", target, {"role": "admin"}),
        "deactivateUser": ("POST", f"{target}/deactivate", None),
        "signOutUser": ("POST", f"{target}/sign-out", None),
        "resetUserSignIn": ("POST", f"{target}/reset-sign-in", None),
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
        "extendTransferExpiry": (
            "POST",
            f"/v1/transfers/{world.draft.sent}/extend",
            # Within 30 days of the send, after its 7: a real extension for the owner.
            {"expires_at": (datetime.now(UTC) + timedelta(days=10)).isoformat()},
        ),
        "createUploadRequest": (
            "POST",
            "/v1/upload-requests",
            {"uploader_email": "u@example.test"},
        ),
        "listUploadRequests": ("GET", "/v1/upload-requests", None),
        "getUploadRequest": ("GET", f"/v1/upload-requests/{world.draft.upload_request}", None),
        "revokeUploadRequest": (
            "POST",
            f"/v1/upload-requests/{world.draft.upload_request}/revoke",
            None,
        ),
        "unlockUploader": (
            "POST",
            f"/v1/upload-requests/{world.draft.upload_request}/unlock",
            None,
        ),
        "listUploadRequestFiles": (
            "GET",
            f"/v1/upload-requests/{world.draft.upload_request}/files",
            None,
        ),
        "createApiKey": ("POST", "/v1/api-keys", {"name": "ci", "scopes": ["transfers:read"]}),
        "listApiKeys": ("GET", "/v1/api-keys", None),
        "revokeApiKey": ("POST", f"/v1/api-keys/{world.draft.api_key}/revoke", None),
        "searchAuditEvents": ("POST", "/v1/audit/events/search", {"limit": 10}),
        "exportAuditEvents": ("POST", "/v1/audit/exports", {"format": "json"}),
        "clearEmailSuppression": (
            "POST",
            "/v1/email-suppressions/clear",
            {"email": "someone@example.test"},
        ),
        "getDlpPolicy": ("GET", "/v1/dlp/policy", None),
        "updateDlpPolicy": ("PATCH", "/v1/dlp/policy", {"trusted_domains": ["partner.example"]}),
        "listDlpRules": ("GET", "/v1/dlp/rules", None),
        "createDlpRule": (
            "POST",
            "/v1/dlp/rules",
            {
                "name": "New domains",
                "direction": "sent",
                "condition": "new_domain",
                "action": "warn",
            },
        ),
        "getDlpRule": ("GET", rule, None),
        "updateDlpRule": ("PATCH", rule, {"name": "Renamed"}),
        "deleteDlpRule": ("DELETE", rule, None),
        "listDlpDetectors": ("GET", "/v1/dlp/detectors", None),
        "createDlpDetector": (
            "POST",
            "/v1/dlp/detectors",
            {"name": "Codenames", "kind": "keywords", "keywords": ["vega"]},
        ),
        "getDlpDetector": ("GET", detector, None),
        "updateDlpDetector": ("PATCH", detector, {"name": "Renamed"}),
        "deleteDlpDetector": ("DELETE", detector, None),
        "getTransferDlp": ("GET", f"/v1/transfers/{decided.transfer}/dlp", None),
        "confirmTransfer": (
            "POST",
            f"/v1/transfers/{decided.transfer}/confirm",
            {"decision_id": str(decided.decision)},
        ),
        "listApprovalRequests": ("GET", "/v1/dlp/approval-requests", None),
        "getApprovalRequest": ("GET", approval, None),
        "approveTransfer": ("POST", f"{approval}/approve", {}),
        "rejectTransfer": ("POST", f"{approval}/reject", {"comment": "Not this one"}),
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
    UNION ALL SELECT 'upload_request', id, state || '/' || failed_attempts
                FROM upload_requests WHERE tenant_id = :t
    UNION ALL SELECT 'api_key', id, (revoked_at IS NULL)::text FROM api_keys WHERE tenant_id = :t
    UNION ALL SELECT 'suppression', id, coalesce(expires_at::text, '-')
                FROM email_suppressions WHERE tenant_id = :t
    UNION ALL SELECT 'dlp_policy', tenant_id, version::text FROM dlp_policies WHERE tenant_id = :t
    UNION ALL SELECT 'dlp_rule', id, revision || '/' || (retired_at IS NULL)
                FROM dlp_rules WHERE tenant_id = :t
    UNION ALL SELECT 'dlp_detector', id, revision || '/' || (retired_at IS NULL)
                FROM dlp_detectors WHERE tenant_id = :t
    UNION ALL SELECT 'dlp_decision', id, outcome FROM dlp_decisions WHERE tenant_id = :t
    UNION ALL SELECT 'dlp_confirmation', id, decision_id::text
                FROM dlp_confirmations WHERE tenant_id = :t
    UNION ALL SELECT 'dlp_known_domain', tenant_id, domain || '/' || last_sent_at::text
                FROM dlp_known_domains WHERE tenant_id = :t
    UNION ALL SELECT 'dlp_approval_request', id, state FROM dlp_approval_requests
                WHERE tenant_id = :t
    UNION ALL SELECT 'dlp_approval_decision', id, decision FROM dlp_approval_decisions
                WHERE tenant_id = :t
    ORDER BY 1, 2
"""


def test_the_matrix_covers_every_operation_the_app_serves_and_every_caller() -> None:
    served = {
        context.original_route.operation_id  # type: ignore[attr-defined]
        for context in iter_route_contexts(create_app().routes)
    }
    assert served == (
        set(EXPECTED)
        | COVERED_BY_SIGN_IN_TESTS
        | COVERED_BY_LINK_TESTS
        | COVERED_BY_DOWNLOAD_TESTS
        | COVERED_BY_RECEIVED_FILE_TESTS
    )
    for operation, row in EXPECTED.items():
        assert set(row) == set(CALLERS), operation


CELLS = [(op, caller) for op, row in EXPECTED.items() for caller in row]


@pytest.mark.parametrize(("operation", "caller_name"), CELLS, ids=[f"{o}-{c}" for o, c in CELLS])
async def test_authorization_matrix(
    operation: str, caller_name: str, migrated_db: ScratchDatabase
) -> None:
    objects = FakeObjects()
    mine, theirs = seed_tenant(migrated_db), seed_tenant(migrated_db)
    dlp = seed_dlp_items(migrated_db, mine)
    world = World(
        mine,
        theirs,
        seed_draft(migrated_db, mine, objects),
        dlp,
        seed_decided(migrated_db, mine, dlp.rule),
        seed_pending(migrated_db, mine, theirs, dlp.rule),
    )
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
    if caller_name == "admin_totp" and operation in (
        *USER_OPERATIONS,
        *ADMIN_ONLY,
        *DLP_OPERATIONS,
    ):
        assert response.json()["code"] == "passkey_required"
    if caller_name == "admin_other_tenant":
        # Another tenant's admin never sees or changes this tenant's users or transfers.
        assert str(world.mine.target) not in response.text
        assert str(world.mine.admin) not in response.text
        assert str(world.draft.file) not in response.text
        assert str(world.draft.ready) not in response.text
        assert str(world.draft.sent) not in response.text
        assert str(world.draft.upload_request) not in response.text
        if world.dlp is not None:
            assert str(world.dlp.rule) not in response.text
            assert str(world.dlp.detector) not in response.text
        if world.decided is not None:
            assert str(world.decided.transfer) not in response.text
            assert str(world.decided.decision) not in response.text
        if world.pending is not None:
            assert str(world.pending.transfer) not in response.text
            assert str(world.pending.request) not in response.text
