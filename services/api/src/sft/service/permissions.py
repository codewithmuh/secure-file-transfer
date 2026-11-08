"""The permission registry: table 6.3 of authentication and authorization, as data (6.5).

Every operation of the API contract names one permission (`x-permission`), and every service
function checks it with `authorize` before it acts (6.1, point 3). Tests hold this registry to the
contract's `x-permission` values and to table 6.3, and the authorization matrix test (9.2) runs
every implemented operation with every kind of caller against it.

A permission says what each caller type may reach:

- `member` and `admin`: a member's and an admin's reach (`Reach`). Wherever the admin column gives
  more than the member column, the admin role needs a passkey or SSO sign-in (3.3), except for the
  revocations in `PASSKEY_EXEMPT`; without one, the admin acts as a member and an operation that
  needs the admin role answers `403 passkey_required`.
- `api_key`: the scopes that admit a key, any one of them, and what the key then reaches;
  `None` refuses keys.
- `recipient`, `uploader`, `operator`: whether that caller may call it at all.

A caller with no credential the operation accepts gets `401`; one with a credential it accepts
but no right gets `403` (table 6.3: "a dash means the caller is refused"). The member routes read
API keys too (#215), so a key gets `403 permission_denied` on every operation for web sessions
only (T-55). The resource rule
(Own, Tenant, 6.4) is the service function's, using the reach `authorize` returns.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final

from sft.core.errors import Forbidden, Unauthenticated
from sft.service.caller import Caller, CallerKind


class Reach(StrEnum):
    """What a caller may act on, as table 6.3 writes it."""

    NONE = "none"
    """A dash: refused."""
    SELF = "self"
    """Only the caller's own user and tenant."""
    ANY = "any"
    """Yes: anyone of that caller type, e.g. to create an item they then own."""
    OWN = "own"
    """Items the caller created (for a key, its owner; for a link session, its subject)."""
    TENANT = "tenant"
    """Every item of the caller's tenant."""
    APPROVER = "approver"
    """Only callers with the DLP approver designation (FR-43)."""


NONE, SELF, ANY, OWN, TENANT, APPROVER = tuple(Reach)


@dataclass(frozen=True, slots=True)
class Permission:
    """One row of table 6.3."""

    name: str
    operations: tuple[str, ...]
    member: Reach = NONE
    admin: Reach = NONE
    api_key: tuple[str, ...] | None = None
    api_key_reach: Reach = NONE
    recipient: bool = False
    uploader: bool = False
    operator: bool = False
    public: bool = False

    def accepts(self, kind: CallerKind) -> bool:
        """Whether a caller of this kind holds a credential the operation accepts at all."""
        if self.public or kind is CallerKind.SYSTEM:
            return True
        if kind is CallerKind.MEMBER:
            return self.member is not NONE or self.admin is not NONE
        if kind is CallerKind.API_KEY:
            return self.api_key is not None
        if kind in (CallerKind.RECIPIENT, CallerKind.UPLOADER):
            # A link session is accepted on every /session route, even one its kind is refused on
            # (an uploader downloading gets 403, not 401).
            return self.recipient or self.uploader
        return self.operator


REGISTRY: Final[tuple[Permission, ...]] = (
    Permission("account.read", ("getCurrentMember",), member=SELF, admin=SELF),
    Permission(
        "transfer.create",
        ("createTransfer",),
        member=ANY,
        admin=ANY,
        api_key=("transfers:write",),
        api_key_reach=ANY,
    ),
    Permission(
        "transfer.read",
        ("listTransfers", "getTransfer", "listTransferRecipients"),
        member=OWN,
        admin=TENANT,
        api_key=("transfers:read",),
        api_key_reach=TENANT,
    ),
    Permission(
        "transfer.send",
        ("sendTransfer",),
        member=OWN,
        admin=OWN,
        api_key=("transfers:write",),
        api_key_reach=OWN,
    ),
    Permission(
        "transfer.cancel",
        ("cancelTransfer",),
        member=OWN,
        admin=OWN,
        api_key=("transfers:write",),
        api_key_reach=OWN,
    ),
    Permission(
        "transfer.revoke",
        ("revokeTransfer",),
        member=OWN,
        admin=TENANT,
        api_key=("transfers:write",),
        api_key_reach=TENANT,
    ),
    Permission(
        "transfer.extend",
        ("extendTransferExpiry",),
        member=OWN,
        admin=OWN,
        api_key=("transfers:write",),
        api_key_reach=OWN,
    ),
    Permission("recipient.unlock", ("unlockRecipient",), member=OWN, admin=TENANT),
    Permission(
        "file.upload",
        ("addTransferFile", "requestUploadPartUrls", "listUploadedParts", "completeUpload"),
        member=OWN,
        admin=OWN,
        api_key=("transfers:write",),
        api_key_reach=OWN,
    ),
    Permission(
        "file.read",
        ("getFile",),
        member=OWN,
        admin=TENANT,
        api_key=("transfers:read", "upload_requests:read"),
        api_key_reach=TENANT,
    ),
    Permission(
        "file.delete",
        ("deleteFile",),
        member=OWN,
        admin=OWN,
        api_key=("transfers:write", "upload_requests:write"),
        api_key_reach=OWN,
    ),
    Permission(
        "file.download_received",
        ("createReceivedFileDownload", "getReceivedFileDownloadContent"),
        member=OWN,
        admin=OWN,
    ),
    Permission(
        "upload_request.create",
        ("createUploadRequest",),
        member=ANY,
        admin=ANY,
        api_key=("upload_requests:write",),
        api_key_reach=ANY,
    ),
    Permission(
        "upload_request.read",
        ("listUploadRequests", "getUploadRequest", "listUploadRequestFiles"),
        member=OWN,
        admin=TENANT,
        api_key=("upload_requests:read",),
        api_key_reach=TENANT,
    ),
    Permission(
        "upload_request.revoke",
        ("revokeUploadRequest",),
        member=OWN,
        admin=TENANT,
        api_key=("upload_requests:write",),
        api_key_reach=TENANT,
    ),
    Permission("uploader.unlock", ("unlockUploader",), member=OWN, admin=TENANT),
    Permission(
        "public",
        (
            "resolveLink",
            "requestVerificationCode",
            "createLinkSession",
            "startSignIn",
            "completeSignIn",
            "startInvitationSignIn",
            "createOperatorToken",
        ),
        public=True,
    ),
    Permission(
        "session.read", ("getLinkSession", "listSessionFiles"), recipient=True, uploader=True
    ),
    Permission("session.end", ("endLinkSession",), recipient=True, uploader=True),
    Permission(
        "session.upload",
        (
            "addSessionUploadFile",
            "requestSessionUploadPartUrls",
            "listSessionUploadedParts",
            "completeSessionUpload",
            "deleteSessionUploadFile",
        ),
        uploader=True,
    ),
    Permission(
        "session.download", ("createSessionDownload", "getSessionDownloadContent"), recipient=True
    ),
    Permission(
        "audit.search",
        ("searchAuditEvents",),
        admin=TENANT,
        api_key=("audit:read",),
        api_key_reach=ANY,
    ),
    Permission(
        "audit.export",
        ("exportAuditEvents",),
        admin=TENANT,
        api_key=("audit:read",),
        api_key_reach=ANY,
    ),
    Permission("user.invite", ("inviteUser",), admin=TENANT),
    Permission("user.read", ("listUsers", "getUser"), admin=TENANT),
    Permission("user.update_role", ("updateUser",), admin=TENANT),
    Permission("user.deactivate", ("deactivateUser",), admin=TENANT),
    Permission(
        "tenant_policy.read",
        ("getTenantPolicy",),
        member=ANY,
        admin=ANY,
        api_key=("transfers:read", "upload_requests:read"),
        api_key_reach=ANY,
    ),
    Permission("tenant_policy.update", ("updateTenantPolicy",), admin=TENANT),
    Permission("email_suppression.clear", ("clearEmailSuppression",), admin=TENANT),
    Permission("api_key.create", ("createApiKey",), admin=TENANT),
    Permission("api_key.read", ("listApiKeys",), admin=TENANT),
    Permission("api_key.revoke", ("revokeApiKey",), admin=TENANT),
    Permission(
        "dlp_findings.read",
        ("getTransferDlp", "getFileInspection"),
        member=OWN,
        admin=TENANT,
        api_key=("transfers:read", "upload_requests:read"),
        api_key_reach=TENANT,
    ),
    Permission("transfer.confirm", ("confirmTransfer",), member=OWN, admin=OWN),
    Permission(
        "dlp_approval.read",
        ("listApprovalRequests", "getApprovalRequest"),
        member=OWN,
        admin=TENANT,
    ),
    Permission(
        "dlp_approval.decide",
        ("approveTransfer", "rejectTransfer"),
        member=APPROVER,
        admin=APPROVER,
    ),
    Permission(
        "dlp_policy.read",
        ("getDlpPolicy", "listDlpRules", "getDlpRule", "listDlpDetectors", "getDlpDetector"),
        admin=TENANT,
    ),
    Permission(
        "dlp_policy.update",
        (
            "updateDlpPolicy",
            "createDlpRule",
            "updateDlpRule",
            "deleteDlpRule",
            "createDlpDetector",
            "updateDlpDetector",
            "deleteDlpDetector",
        ),
        admin=TENANT,
    ),
    Permission("dlp_policy.test", ("testDlpDetectors",), admin=TENANT),
    Permission(
        "dlp_report.read",
        ("listDlpDecisions", "getDlpReport"),
        admin=TENANT,
        api_key=("audit:read",),
        api_key_reach=ANY,
    ),
    Permission("operator.tenant.create", ("createTenant",), operator=True),
    Permission("operator.tenant.read", ("listTenants", "getTenant"), operator=True),
    Permission("operator.tenant.suspend", ("suspendTenant",), operator=True),
    Permission("account.sign_out", ("signOut",), member=SELF, admin=SELF),
    Permission("user.sign_out", ("signOutUser",), admin=TENANT),
    Permission("user.reset_sign_in", ("resetUserSignIn",), admin=TENANT),
    Permission("operator.tenant.sso.update", ("configureTenantSso",), operator=True),
    Permission("operator.tenant.admin_recovery", ("recoverTenantAdmin",), operator=True),
    Permission("operator.break_glass.record", ("recordBreakGlassGrant",), operator=True),
    # Tenant SSO (#231): the tenant admin's settings and domains, web sessions only.
    Permission("sso.read", ("getTenantSso",), admin=TENANT),
    Permission(
        "sso.update",
        ("updateTenantSso", "claimSsoDomain", "verifySsoDomain", "deleteSsoDomain"),
        admin=TENANT,
    ),
    # Break-glass in the service (#232): any operator asks, lists and ends; a second approves.
    Permission(
        "operator.break_glass.request",
        ("requestBreakGlass", "listBreakGlassRequests", "endBreakGlass"),
        operator=True,
    ),
    Permission("operator.break_glass.approve", ("approveBreakGlass",), operator=True),
)
"""Table 6.3, row by row."""

STEP_UP: Final = frozenset(
    {
        # authn and authz 3.3: a sign-in in the last 15 minutes, otherwise
        # 401 reauthentication_required.
        "inviteUser",
        "updateUser",
        "deactivateUser",
        "updateTenantPolicy",
        "createApiKey",
        "resetUserSignIn",
        "exportAuditEvents",
        "updateDlpPolicy",
        "createDlpRule",
        "updateDlpRule",
        "deleteDlpRule",
        "createDlpDetector",
        "updateDlpDetector",
        "deleteDlpDetector",
        "approveTransfer",
        # #231: the SSO settings and domains decide who signs in, and how.
        "updateTenantSso",
        "claimSsoDomain",
        "verifySsoDomain",
        "deleteSsoDomain",
    }
)
"""The step-up policy (authn and authz 3.3, #232): the operations that need a recent sign-in, so a
recent MFA, and answer `401 reauthentication_required` without one. One list, read by `authorize`
for every caller; the web app re-authenticates and retries the request (web/src/lib/stepUp.ts)."""

PASSKEY_EXEMPT: Final = frozenset({"revokeTransfer", "revokeUploadRequest", "revokeApiKey"})
"""Revocations keep working in an admin's TOTP session: they can only stop sharing (3.3)."""

PEOPLE_ONLY: Final = frozenset({"unlockRecipient", "unlockUploader"})
"""Operations an API key is refused with `403`, not `401`: a lockout signals a possible attack, so
a person decides (authn and authz 4.4, the contract's `unlockRecipient`)."""

DLP_PEOPLE_ONLY: Final = frozenset(
    {
        "getDlpPolicy",
        "updateDlpPolicy",
        "listDlpRules",
        "createDlpRule",
        "getDlpRule",
        "updateDlpRule",
        "deleteDlpRule",
        "listDlpDetectors",
        "createDlpDetector",
        "getDlpDetector",
        "updateDlpDetector",
        "deleteDlpDetector",
        "testDlpDetectors",
        "confirmTransfer",
        "approveTransfer",
        "rejectTransfer",
        "listApprovalRequests",
        "getApprovalRequest",
    }
)
"""DLP operations an API key is refused with `403`, not `401`: the policy, its rules and detectors
need a web session, and every DLP decision on record is a person's (authn and authz 5.3, 6.1
point 4)."""


def _by_operation(permissions: tuple[Permission, ...]) -> Mapping[str, Permission]:
    found: dict[str, Permission] = {}
    for permission in permissions:
        for operation in permission.operations:
            if operation in found:
                raise ValueError(f"{operation} is in {found[operation].name} and {permission.name}")
            found[operation] = permission
    return found


BY_OPERATION: Final[Mapping[str, Permission]] = _by_operation(REGISTRY)
"""Each operation ID's permission."""


def permission_for(operation_id: str) -> Permission:
    """The permission `operation_id` declares. A `KeyError` means a route nobody registered."""
    return BY_OPERATION[operation_id]


def authorize(caller: Caller | None, operation_id: str, *, now: datetime) -> Reach:
    """Check `caller` against the permission of `operation_id`, and return what it may reach.

    Raises `Unauthenticated("authentication_required")` (401) when the caller holds no credential
    the operation accepts, `Forbidden("permission_denied")` or `Forbidden("passkey_required")`
    (403) when it may not, and `Unauthenticated("reauthentication_required")` (401) when a step-up
    operation's sign-in is too old. The
    order is that of authn and authz 6.1: who it is, what it may do, then how recently it signed
    in.
    """
    permission = permission_for(operation_id)
    if permission.public:
        return ANY
    if caller is not None and caller.kind is CallerKind.API_KEY and operation_id in PEOPLE_ONLY:
        raise Forbidden("permission_denied", "API keys can't unlock: a person decides.")
    if caller is not None and caller.kind is CallerKind.API_KEY and operation_id in DLP_PEOPLE_ONLY:
        raise Forbidden("permission_denied", "API keys can't manage or decide DLP: a person does.")
    if caller is not None and caller.kind is CallerKind.API_KEY and _web_only(permission):
        # A live key is a credential the member routes read (#215), so one that may not use an
        # operation is refused with 403, not 401 (table 6.3, T-55).
        raise Forbidden("permission_denied", "This operation needs a person in the web app.")
    if caller is None or not permission.accepts(caller.kind):
        raise Unauthenticated(
            "authentication_required", bearer=caller is not None and caller.bearer
        )
    if caller.kind is CallerKind.SYSTEM:
        return TENANT
    if caller.kind is CallerKind.MEMBER:
        return _member(permission, caller, operation_id, now)
    if caller.kind is CallerKind.API_KEY:
        if not set(permission.api_key or ()) & caller.scopes:
            raise Forbidden("permission_denied", "The key has no scope this operation takes.")
        return permission.api_key_reach
    if caller.kind is CallerKind.RECIPIENT:
        return _allowed(permission.recipient, OWN)
    if caller.kind is CallerKind.UPLOADER:
        return _allowed(permission.uploader, OWN)
    return ANY  # an operator, on the operator API


def _web_only(permission: Permission) -> bool:
    """A member route that takes no API key: downloads, unlocks, DLP decisions, administration."""
    if permission.api_key is not None:
        return False
    return permission.member is not NONE or permission.admin is not NONE


def _allowed(allowed: bool, reach: Reach) -> Reach:
    if not allowed:
        raise Forbidden("permission_denied")
    return reach


def _member(permission: Permission, caller: Caller, operation_id: str, now: datetime) -> Reach:
    as_admin = caller.acts_as_admin or (caller.is_admin and operation_id in PASSKEY_EXEMPT)
    reach = permission.admin if as_admin else permission.member
    if reach is NONE:
        if caller.is_admin and permission.admin is not NONE:
            raise Forbidden("passkey_required", "The admin role needs a passkey sign-in.")
        raise Forbidden("permission_denied")
    if operation_id in STEP_UP and not caller.signed_in_since(now):
        raise Unauthenticated("reauthentication_required")
    return reach
