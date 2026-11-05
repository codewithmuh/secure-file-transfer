"""Every email the service sends, and what each one may contain (FR-33, abuse 7.1 and 7.5).

One class per email. Its fields are the only values its templates get, and `context()` turns them
into exactly the keys the templates use; a test checks both languages and both parts against it.

What an email may hold (abuse 7.5, architecture 4.6):

- No file names, message text or other sender-written content, no findings, no attachments.
- Links only to our web app, built here from `WEB_APP_URL`; a template never writes a URL itself.
- A link token only in the link emails (transfer, upload request, SSO invitation), a code only in
  the code email, a temporary password only in the invitation and re-enrolment emails.
- The tenant's name as the operator recorded it, and for link emails the sender's verified address.
- DLP notices go only to the tenant's own people and link to the web app, never to an approve
  action: decisions are made only there, signed in.

Fields that are secrets or personal data stay out of the repr, so a logged object leaks nothing.
"""

from __future__ import annotations

import enum
import re
import unicodedata
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from typing import ClassVar, Literal
from uuid import UUID

from sft.core.addresses import is_plain_address


class Locale(enum.StrEnum):
    """The `Locale` of the API contract (FR-33)."""

    EN = "en"
    JA = "ja"


class EmailType(enum.StrEnum):
    """Also the `email_type` message tag on every send and its delivery events (ADR-0015)."""

    MEMBER_INVITATION = "member_invitation"
    MEMBER_INVITATION_SSO = "member_invitation_sso"
    INVITATION_ADDRESS_IN_USE = "invitation_address_in_use"
    MEMBER_REENROLMENT = "member_reenrolment"
    TRANSFER_LINK = "transfer_link"
    UPLOAD_REQUEST = "upload_request"
    VERIFICATION_CODE = "verification_code"
    FIRST_DOWNLOAD = "first_download"
    FILES_ARRIVED = "files_arrived"
    FILES_BLOCKED_MEMBER = "files_blocked_member"
    FILES_BLOCKED_UPLOADER = "files_blocked_uploader"
    TRANSFER_HELD = "transfer_held"
    RECIPIENT_LOCKED = "recipient_locked"
    DLP_CONFIRMATION_NEEDED = "dlp_confirmation_needed"
    DLP_APPROVAL_REQUESTED = "dlp_approval_requested"
    DLP_APPROVAL_DECIDED = "dlp_approval_decided"
    DLP_APPROVAL_EXPIRED = "dlp_approval_expired"
    DLP_NO_ELIGIBLE_APPROVER = "dlp_no_eligible_approver"
    DLP_POLICY_CHANGED = "dlp_policy_changed"


class PolicyChange(enum.StrEnum):
    """What a DLP policy change email lists (FR-54); each has a label in both languages."""

    RULE_ADDED = "rule_added"
    RULE_CHANGED = "rule_changed"
    RULE_REMOVED = "rule_removed"
    DETECTOR_ADDED = "detector_added"
    DETECTOR_CHANGED = "detector_changed"
    DETECTOR_REMOVED = "detector_removed"
    TRUSTED_DOMAINS_CHANGED = "trusted_domains_changed"
    MODE_CHANGED = "mode_changed"
    APPROVERS_CHANGED = "approvers_changed"
    APPROVAL_TIMEOUT_CHANGED = "approval_timeout_changed"


# ---- links: the web app's routes, the only places an email points to ----


@dataclass(frozen=True)
class Links:
    """URLs on the web app's origin (`WEB_APP_URL`). Tokens go in the fragment (authn-authz 4.1)."""

    origin: str

    def recipient(self, token: str) -> str:
        return f"{self.origin}/t#{token}"

    def uploader(self, token: str) -> str:
        return f"{self.origin}/u#{token}"

    def invitation(self, token: str) -> str:
        return f"{self.origin}/invite#{token}"

    def sign_in(self) -> str:
        return f"{self.origin}/sign-in"

    def transfer(self, transfer_id: UUID) -> str:
        return f"{self.origin}/transfers/{transfer_id}"

    def upload_request(self, upload_request_id: UUID) -> str:
        return f"{self.origin}/upload-requests/{upload_request_id}"

    def approvals(self) -> str:
        return f"{self.origin}/approvals"

    def dlp_policy(self) -> str:
        return f"{self.origin}/admin/dlp"


# ---- formatting ----

# Japan has no daylight saving time, so a fixed offset needs no time zone database in the image.
_JST = timezone(timedelta(hours=9), "JST")


def format_time(value: datetime, locale: Locale) -> str:
    """A time in Japan time, the service's region, named so a reader abroad can convert it."""
    local = value.astimezone(_JST)
    if locale is Locale.JA:
        return f"{local.year}年{local.month}月{local.day}日 {local:%H:%M}（日本時間）"  # noqa: RUF001 - Japanese brackets
    return f"{local.day} {local:%B %Y, %H:%M} Japan time (UTC+9)"


# ---- checks: messages name the field, never the value ----

_TOKEN = re.compile(r"[A-Za-z0-9_-]{22,128}")  # base64url, at least 128 bits (NFR-14)
_CODE = re.compile(r"[0-9]{6,10}")  # at least 6 digits (NFR-14)
_PASSWORD = re.compile(r"[!-~]{8,128}")  # printable ASCII, no spaces


def _check(name: str, ok: bool) -> None:
    if not ok:
        raise ValueError(f"{name} is not valid")


def _one_line(value: str, limit: int) -> bool:
    """Non-empty, at most `limit` long, and no control, format, line or paragraph separator."""
    # Zl and Zp are U+2028 and U+2029, which break a header as \n does.
    return 0 < len(value) <= limit and not any(
        unicodedata.category(c)[0] == "C" or unicodedata.category(c) in ("Zl", "Zp") for c in value
    )


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


# ---- the emails ----


@dataclass(frozen=True, kw_only=True)
class Email:
    """What every email has: the tenant, by the name the operator recorded."""

    TYPE: ClassVar[EmailType]
    # Fields that are secrets: a test checks each appears only in its own email.
    SECRETS: ClassVar[tuple[str, ...]] = ()

    tenant_name: str

    def __post_init__(self) -> None:
        _check("tenant_name", _one_line(self.tenant_name, 200))
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name.endswith("_email"):
                _check(f.name, isinstance(value, str) and is_plain_address(value))
            elif f.name == "token":
                _check(f.name, bool(_TOKEN.fullmatch(value)))
            elif f.name == "code":
                _check(f.name, bool(_CODE.fullmatch(value)))
            elif f.name == "temporary_password":
                _check(f.name, bool(_PASSWORD.fullmatch(value)))
            elif isinstance(value, datetime):
                _check(f.name, _aware(value))
            elif isinstance(value, int) and not isinstance(value, bool):
                _check(f.name, 1 <= value <= 10_000)

    @property
    def reply_to(self) -> str | None:
        """`Reply-To`: the sender, on the emails that name one (abuse 7.5)."""
        return None

    def context(self, links: Links, locale: Locale) -> dict[str, object]:
        """The template keys: `tenant_name` plus each email's own."""
        return {"tenant_name": self.tenant_name, **self._context(links, locale)}

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        raise NotImplementedError


# Members and admins


@dataclass(frozen=True, kw_only=True)
class MemberInvitation(Email):
    """A local member's invitation, with the temporary password the worker set (authn-authz 2.5).

    Also sent after a sign-in reset and for operator-assisted recovery, which create the user again.
    """

    TYPE = EmailType.MEMBER_INVITATION
    SECRETS = ("temporary_password",)
    temporary_password: str = field(repr=False)
    valid_days: int

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "sign_in_url": links.sign_in(),
            "temporary_password": self.temporary_password,
            "valid_days": self.valid_days,
        }


@dataclass(frozen=True, kw_only=True)
class MemberInvitationSso(Email):
    """An SSO member's one-time invitation link, valid 7 days (authn-authz 2.5)."""

    TYPE = EmailType.MEMBER_INVITATION_SSO
    SECRETS = ("token",)
    token: str = field(repr=False)
    expires_at: datetime

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "invitation_url": links.invitation(self.token),
            "expires_at": format_time(self.expires_at, locale),
        }


@dataclass(frozen=True, kw_only=True)
class InvitationAddressInUse(Email):
    """An invited address that already signs in locally for another tenant (authn-authz 2.5).

    It names no other tenant, and holds no link or password.
    """

    TYPE = EmailType.INVITATION_ADDRESS_IN_USE

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {}


@dataclass(frozen=True, kw_only=True)
class MemberReenrolment(Email):
    """After a regional failover, a member without SSO sets up sign-in in Osaka (NFR-11)."""

    TYPE = EmailType.MEMBER_REENROLMENT
    SECRETS = ("temporary_password",)
    temporary_password: str = field(repr=False)
    valid_days: int

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "sign_in_url": links.sign_in(),
            "temporary_password": self.temporary_password,
            "valid_days": self.valid_days,
        }


# Recipients and uploaders


@dataclass(frozen=True, kw_only=True)
class TransferLink(Email):
    """A recipient's link to a transfer (UC-1). No file names, no message (FR-14)."""

    TYPE = EmailType.TRANSFER_LINK
    SECRETS = ("token",)
    sender_email: str = field(repr=False)
    token: str = field(repr=False)
    expires_at: datetime

    @property
    def reply_to(self) -> str | None:
        return self.sender_email

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "sender_email": self.sender_email,
            "link_url": links.recipient(self.token),
            "expires_at": format_time(self.expires_at, locale),
        }


@dataclass(frozen=True, kw_only=True)
class UploadRequest(Email):
    """An uploader's link to an upload request (UC-2)."""

    TYPE = EmailType.UPLOAD_REQUEST
    SECRETS = ("token",)
    sender_email: str = field(repr=False)
    token: str = field(repr=False)
    expires_at: datetime

    @property
    def reply_to(self) -> str | None:
        return self.sender_email

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "sender_email": self.sender_email,
            "link_url": links.uploader(self.token),
            "expires_at": format_time(self.expires_at, locale),
        }


@dataclass(frozen=True, kw_only=True)
class VerificationCode(Email):
    """The one-time code (FR-14, authn-authz 4.2). No link: a forwarded code email opens nothing."""

    TYPE = EmailType.VERIFICATION_CODE
    SECRETS = ("code",)
    code: str = field(repr=False)
    valid_minutes: int = 10

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {"code": self.code, "valid_minutes": self.valid_minutes}


@dataclass(frozen=True, kw_only=True)
class FilesBlockedUploader(Email):
    """To an uploader: the company's policy blocked a file, and nothing more (FR-12, FR-51)."""

    TYPE = EmailType.FILES_BLOCKED_UPLOADER
    sender_email: str = field(repr=False)

    @property
    def reply_to(self) -> str | None:
        return self.sender_email

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {"sender_email": self.sender_email}


# Notices to the member, coalesced or once per event by the worker (abuse 7.1)


@dataclass(frozen=True, kw_only=True)
class FirstDownload(Email):
    """FR-8: the first download of a transfer whose sender asked to be told."""

    TYPE = EmailType.FIRST_DOWNLOAD
    transfer_id: UUID

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {"transfer_url": links.transfer(self.transfer_id)}


@dataclass(frozen=True, kw_only=True)
class FilesArrived(Email):
    """FR-12: files available on an upload request since the last notice."""

    TYPE = EmailType.FILES_ARRIVED
    upload_request_id: UUID
    file_count: int

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "upload_request_url": links.upload_request(self.upload_request_id),
            "file_count": self.file_count,
        }


@dataclass(frozen=True, kw_only=True)
class FilesBlockedMember(Email):
    """FR-12, FR-51: received files that were blocked; the reasons are on the request page."""

    TYPE = EmailType.FILES_BLOCKED_MEMBER
    upload_request_id: UUID
    file_count: int

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "upload_request_url": links.upload_request(self.upload_request_id),
            "file_count": self.file_count,
        }


@dataclass(frozen=True, kw_only=True)
class TransferHeld(Email):
    """UC-1: a held transfer; no recipient was notified. The reason is on the transfer page."""

    TYPE = EmailType.TRANSFER_HELD
    transfer_id: UUID

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {"transfer_url": links.transfer(self.transfer_id)}


@dataclass(frozen=True, kw_only=True)
class RecipientLocked(Email):
    """NFR-14, authn-authz 4.4: to the owner and every tenant admin. Names no address."""

    TYPE = EmailType.RECIPIENT_LOCKED
    subject_kind: Literal["transfer", "upload_request"]
    subject_id: UUID

    def __post_init__(self) -> None:
        super().__post_init__()
        _check("subject_kind", self.subject_kind in ("transfer", "upload_request"))

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        if self.subject_kind == "transfer":
            url = links.transfer(self.subject_id)
        else:
            url = links.upload_request(self.subject_id)
        return {"is_transfer": self.subject_kind == "transfer", "page_url": url}


# DLP notices (FR-42, FR-43, FR-54; architecture 4.6): no file names, findings or approve links


@dataclass(frozen=True, kw_only=True)
class DlpConfirmationNeeded(Email):
    TYPE = EmailType.DLP_CONFIRMATION_NEEDED
    transfer_id: UUID

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {"transfer_url": links.transfer(self.transfer_id)}


@dataclass(frozen=True, kw_only=True)
class DlpApprovalRequested(Email):
    """To an eligible approver; `request_count` above 1 is the hourly digest (abuse 7.1)."""

    TYPE = EmailType.DLP_APPROVAL_REQUESTED
    request_count: int = 1

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {"approvals_url": links.approvals(), "request_count": self.request_count}


@dataclass(frozen=True, kw_only=True)
class DlpApprovalDecided(Email):
    """To the sender. A rejection's comment stays in the web app."""

    TYPE = EmailType.DLP_APPROVAL_DECIDED
    transfer_id: UUID
    decision: Literal["approved", "rejected"]

    def __post_init__(self) -> None:
        super().__post_init__()
        _check("decision", self.decision in ("approved", "rejected"))

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "transfer_url": links.transfer(self.transfer_id),
            "approved": self.decision == "approved",
        }


@dataclass(frozen=True, kw_only=True)
class DlpApprovalExpired(Email):
    TYPE = EmailType.DLP_APPROVAL_EXPIRED
    transfer_id: UUID

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {"transfer_url": links.transfer(self.transfer_id)}


@dataclass(frozen=True, kw_only=True)
class DlpNoEligibleApprover(Email):
    """To the tenant admins: an approval was refused because nobody could approve it."""

    TYPE = EmailType.DLP_NO_ELIGIBLE_APPROVER

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {"dlp_policy_url": links.dlp_policy()}


@dataclass(frozen=True, kw_only=True)
class DlpPolicyChanged(Email):
    """To every tenant admin, at most one per 10 minutes, listing each change (FR-54)."""

    TYPE = EmailType.DLP_POLICY_CHANGED
    changes: tuple[PolicyChange, ...]

    def __post_init__(self) -> None:
        super().__post_init__()
        _check("changes", 1 <= len(self.changes) <= 1_000)
        for change in self.changes:
            _check("changes", isinstance(change, PolicyChange))

    def _context(self, links: Links, locale: Locale) -> dict[str, object]:
        return {
            "dlp_policy_url": links.dlp_policy(),
            "changes": [change.value for change in self.changes],
        }


EMAILS: dict[EmailType, type[Email]] = {
    cls.TYPE: cls
    for cls in (
        MemberInvitation,
        MemberInvitationSso,
        InvitationAddressInUse,
        MemberReenrolment,
        TransferLink,
        UploadRequest,
        VerificationCode,
        FilesBlockedUploader,
        FirstDownload,
        FilesArrived,
        FilesBlockedMember,
        TransferHeld,
        RecipientLocked,
        DlpConfirmationNeeded,
        DlpApprovalRequested,
        DlpApprovalDecided,
        DlpApprovalExpired,
        DlpNoEligibleApprover,
        DlpPolicyChanged,
    )
}
"""Every email type and its class; a test checks it covers `EmailType`."""
