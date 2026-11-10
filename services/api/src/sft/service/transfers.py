"""Transfers: create a draft, read and list them, and the views the API returns (UC-1, FR-1 to
FR-5; data model 2.2). Sending and cancelling are `sft.service.sending`; files are
`sft.service.uploads` and `sft.service.file_reads`.

Every function checks the caller against the permission registry first (`authorize`, authn and
authz 6.1), then the resource rule (6.4): an item the caller can't see answers 404, one it can see
but may not act on 403, and a state that doesn't allow the change 409, in that order. The change,
its audit event and any outbox message commit in one transaction (architecture 5.2, 5.3).

Permissions here (authn and authz 6.3, `sft.service.permissions`):

- `transfer.create`: any member or admin; an API key with `transfers:write`. The member, or the
  key's owner, owns the new transfer.
- `transfer.read` (`getTransfer`, `listTransfers`): Own for a member, Tenant for an admin acting as
  one and for a key with `transfers:read`. Admins see metadata, never file contents (UC-3).
- `file.upload` and `file.delete` (`sft.service.uploads`): Own for everyone. A caller who isn't the
  owner gets 404 unless it may read every transfer of its tenant (`transfer.read` at Tenant reach:
  an admin acting as one, or a key with `transfers:read`), which gets 403.

**The tenant's policy** (FR-3, FR-23): `expires_in` defaults to 7 days, or the tenant's
`max_expiry` if that is shorter, and may not exceed it. **The suppression list** (data model 2.5,
abuse 7.4): an address this tenant suppresses is refused with `422 recipient_undeliverable`,
pointing at the recipient; another tenant's entry for the same address never counts (NFR-12).

**Expiry is read, not waited for.** A transfer past `expires_at` shows as `expired` at once, before
the lifecycle job records it (architecture 4.2).

**The domain rules** (FR-24, FR-45, #217; `sft.service.domain_rules`) apply first: an address
outside the tenant's allowed domains, or in a blocked one, is refused with
`422 recipient_domain_not_allowed`, pointing at the recipient. The default locale is the tenant's
`default_locale`.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import (
    Conflict,
    FieldError,
    Forbidden,
    InvalidRequest,
    NotFound,
    ProblemError,
    Unprocessable,
    json_pointer,
)
from sft.core.ids import uuid7
from sft.core.pseudonyms import EmailKeyring
from sft.data import (
    audit,
    dlp_approvals,
    dlp_decisions,
    files,
    findings,
    suppressions,
    tenants,
    transfers,
)
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import (
    File,
    FileState,
    InspectionReason,
    InspectionState,
    ScanDetail,
    ScanEngine,
    Transfer,
    TransferState,
)
from sft.data.scope import Scope
from sft.service import domain_rules, fields, message_inspection
from sft.service.caller import Caller, CallerKind
from sft.service.evaluation import is_shareable
from sft.service.idempotency import IdempotentRequest, Outcome, once
from sft.service.permissions import Reach, authorize

MIN_EXPIRY: Final = timedelta(hours=1)
MAX_EXPIRY: Final = timedelta(days=30)
DEFAULT_EXPIRY: Final = timedelta(days=7)
"""FR-3: 1 hour to 30 days, 7 by default; the tenant's `max_expiry` caps both (FR-23)."""

MAX_PAGE: Final = 100
"""`listTransfers` returns at most this many per page (the contract's `Limit`)."""

EXPIRES: Final = transfers.EXPIRES_FROM
"""The states a transfer leaves for `expired` once `expires_at` passes (data model 3.2)."""

TRANSFER: Final = "transfer"
"""The audit target and idempotency resource type of a transfer."""


@dataclass(frozen=True, slots=True)
class RecipientRequest:
    email: str
    locale: str | None = None


@dataclass(frozen=True, slots=True)
class TransferRequest:
    recipients: Sequence[RecipientRequest]
    expires_in: timedelta | None = None
    message: str | None = None
    download_limit: int | None = None
    notify_on_first_download: bool = False


@dataclass(frozen=True, slots=True)
class FileView:
    id: UUID
    transfer_id: UUID | None
    display_name: str
    content_type: str
    declared_size: int
    actual_size: int | None
    state: FileState
    created_at: datetime
    part_size: int
    part_count: int
    scanned_at: datetime | None = None
    scan_engine: ScanEngine | None = None
    scan_detail: ScanDetail | None = None
    unscannable_allowed: bool = False
    inspection_state: InspectionState = InspectionState.PENDING
    inspection_reasons: tuple[InspectionReason, ...] = ()
    detectors: tuple[str, ...] = ()
    """The detectors that matched in the file (`File.inspection`), counts in `getFileInspection`."""
    sha256: str | None = None
    """The scanned version's SHA-256, in hex, once the scan worker has read it (#180)."""
    upload_request_id: UUID | None = None
    """A received file's upload request (#213); exactly one of it and `transfer_id` is set."""
    retention_until: datetime | None = None
    """When a received file is deleted (FR-13)."""
    dlp_blocked: bool = False
    """A received file a DLP rule blocked (FR-51, #221)."""

    @property
    def shareable(self) -> bool:
        """FR-16, data model 3.1. An `unscannable` file allowed by policy is shareable, and the
        web app shows FR-18's warning from its state. A received file a DLP rule blocked isn't."""
        return (
            is_shareable(self.state, self.unscannable_allowed, self.inspection_state)
            and not self.dlp_blocked
        )


@dataclass(frozen=True, slots=True)
class RecipientView:
    id: UUID
    email: str
    locale: str


@dataclass(frozen=True, slots=True)
class DlpSummaryView:
    """The transfer's current DLP decision in brief (the contract's `TransferDlpSummary`)."""

    outcome: str
    mode: str
    enforced: bool
    approval_request_id: UUID | None = None
    """The transfer's latest approval request, in whatever state (#220)."""


@dataclass(frozen=True, slots=True)
class TransferView:
    id: UUID
    state: TransferState
    created_by: UUID
    created_at: datetime
    expires_in: timedelta
    expires_at: datetime | None
    message: str | None
    download_limit: int | None
    notify_on_first_download: bool
    submitted_at: datetime | None
    sent_at: datetime | None
    revoked_at: datetime | None
    revoked_by: UUID | None
    hold_reason: str | None
    files: tuple[FileView, ...]
    recipients: tuple[RecipientView, ...]
    dlp: DlpSummaryView | None = None
    """The current DLP decision in brief, once there is one (#219)."""

    @property
    def total_size(self) -> int:
        """The declared bytes of the files that count (data model 3.2)."""
        return sum(f.declared_size for f in self.files if f.state is not FileState.REJECTED)


def effective_state(
    state: TransferState, expires_at: datetime | None, now: datetime
) -> TransferState:
    """The state as the API shows it: `expired` once `expires_at` has passed, before the lifecycle
    job records it (data model 3.2)."""
    if state in EXPIRES and expires_at is not None and expires_at <= now:
        return TransferState.EXPIRED
    return state


# ---- checks every operation shares ----


def tenant_scope(caller: Caller) -> Scope:
    if caller.tenant_id is None or caller.user_id is None:
        # authorize admits only tenant callers to these operations; this is a guard.
        raise Forbidden("permission_denied")
    return Scope.tenant(caller.tenant_id)


def sees_tenant(caller: Caller, now: datetime) -> bool:
    """Whether the caller may read every transfer of its tenant: `transfer.read` at Tenant reach,
    so an admin acting as one, or a key with `transfers:read` (authn and authz 6.3)."""
    try:
        return authorize(caller, "getTransfer", now=now) is Reach.TENANT
    except ProblemError:
        return False


def require_reach(caller: Caller, reach: Reach, transfer: Transfer, now: datetime) -> None:
    """The resource rule (authn and authz 6.4) for `reach`, from `authorize`: Own is the
    transfer's creator, for a key its owner; 404 for a transfer the caller can't see, 403 for one
    it sees but may not act on."""
    if reach is Reach.TENANT or transfer.created_by == caller.user_id:
        return
    if sees_tenant(caller, now):
        raise Forbidden("permission_denied", "Only the transfer's sender may change it.")
    raise NotFound


def require_visible(caller: Caller, reach: Reach, transfer: Transfer) -> None:
    """The resource rule of a read (authn and authz 6.4): Own is the creator, for a key its
    owner; Tenant sees every transfer of the tenant. Anything else is 404."""
    if reach is not Reach.TENANT and transfer.created_by != caller.user_id:
        raise NotFound


def state_conflict(state: TransferState, detail: str) -> Conflict:
    """The 409 for an operation the transfer's state doesn't allow (#188): `transfer_revoked` and
    `transfer_expired` name the terminal state, anything else is `invalid_state` with `detail`.
    Every operation that refuses on the state answers through here, so the same state gets the
    same code whatever was asked."""
    if state is TransferState.REVOKED:
        return Conflict("transfer_revoked", current_state=state.value)
    if state is TransferState.EXPIRED:
        return Conflict("transfer_expired", current_state=state.value)
    return Conflict("invalid_state", detail, current_state=state.value)


def draft_conflict(transfer: Transfer) -> ProblemError | None:
    """None for a draft; otherwise the 409 a change to its files answers."""
    state = TransferState(transfer.state)
    if state is TransferState.DRAFT:
        return None
    return state_conflict(state, "Files change only while the transfer is a draft.")


def audit_details(caller: Caller, **details: audit.Detail) -> dict[str, audit.Detail]:
    """An API key's events name its owner too (authn and authz 5.2)."""
    if caller.kind is CallerKind.API_KEY:
        details["owner_id"] = caller.user_id
    return details


def invalid(pointer: str, detail: str) -> Unprocessable:
    """`422 validation_failed`, pointing at the body field that breaks the rule."""
    return Unprocessable("validation_failed", detail, errors=[FieldError(detail, pointer=pointer)])


# ---- views ----


def file_view(keys: fields.TenantKeys, file: File, detectors: Sequence[str] = ()) -> FileView:
    """The file as the contract shows it, its name opened with the caller's tenant's keys."""
    return FileView(
        id=file.id,
        transfer_id=file.transfer_id,
        display_name=keys.open(fields.FILE_NAME, file.id, file.display_name_ct),
        content_type=file.content_type,
        declared_size=file.declared_size,
        actual_size=file.actual_size,
        state=FileState(file.state),
        created_at=file.created_at,
        part_size=file.part_size,
        part_count=file.part_count,
        scanned_at=file.scanned_at,
        scan_engine=None if file.scan_engine is None else ScanEngine(file.scan_engine),
        scan_detail=None if file.scan_detail is None else ScanDetail(file.scan_detail),
        unscannable_allowed=file.unscannable_allowed,
        inspection_state=InspectionState(file.inspection_state),
        inspection_reasons=tuple(InspectionReason(r) for r in file.inspection_reasons),
        detectors=tuple(detectors),
        sha256=None if file.sha256 is None else file.sha256.hex(),
        upload_request_id=file.upload_request_id,
        retention_until=file.retention_until,
        dlp_blocked=file.dlp_blocked,
    )


async def transfer_view(
    session: AsyncSession, tenant_id: UUID, transfer: Transfer, now: datetime | None = None
) -> TransferView:
    keys = await fields.tenant_keys(session, tenant_id)
    recipients = await transfers.list_recipients(session, transfer.id)
    transfer_files = await files.list_transfer_files(session, transfer.id)
    detectors = await findings.detectors_by_file(session, [f.id for f in transfer_files])
    state = TransferState(transfer.state)
    if now is not None:
        state = effective_state(state, transfer.expires_at, now)
    dlp = None
    if transfer.dlp_decision_id is not None:
        summary = await dlp_decisions.decision_summary(session, transfer.dlp_decision_id)
        if summary is not None:
            latest = await dlp_approvals.latest_request(session, transfer.id)
            dlp = DlpSummaryView(
                summary.outcome,
                summary.mode,
                summary.enforced,
                approval_request_id=None if latest is None else latest.id,
            )
    return TransferView(
        id=transfer.id,
        state=state,
        created_by=transfer.created_by,
        created_at=transfer.created_at,
        expires_in=transfer.expires_in,
        expires_at=transfer.expires_at,
        message=keys.open_optional(fields.TRANSFER_MESSAGE, transfer.id, transfer.message_ct),
        download_limit=transfer.download_limit,
        notify_on_first_download=transfer.notify_on_first_download,
        submitted_at=transfer.submitted_at,
        sent_at=transfer.sent_at,
        revoked_at=transfer.ended_at if state is TransferState.REVOKED else None,
        revoked_by=transfer.revoked_by,
        hold_reason=transfer.hold_reason,
        files=tuple(file_view(keys, f, detectors.get(f.id, ())) for f in transfer_files),
        recipients=tuple(RecipientView(r.id, r.email, r.locale) for r in recipients),
        dlp=dlp,
    )


# ---- the tenant's policy and the suppression list ----


def check_expiry(expires_in: timedelta, max_expiry: timedelta, *, pointer: str | None) -> None:
    """FR-3, FR-23: 1 hour to 30 days, and within the tenant's `max_expiry`."""
    longest = min(MAX_EXPIRY, max_expiry)
    if not MIN_EXPIRY <= expires_in <= longest:
        detail = (
            f"expires_in is between 1 hour and {describe_duration(longest)}, the tenant's maximum."
        )
        raise Unprocessable(
            "expiry_out_of_range",
            detail,
            errors=[FieldError(detail, pointer=pointer)] if pointer else [],
        )


def describe_duration(value: timedelta) -> str:
    """A duration in words, exactly: `1 hour`, `1 hour 30 minutes`, `1 day 12 hours`."""
    seconds = int(value.total_seconds())
    parts = []
    for size, unit in ((86400, "day"), (3600, "hour"), (60, "minute"), (1, "second")):
        count, seconds = divmod(seconds, size)
        if count:
            parts.append(f"{count} {unit}" + ("" if count == 1 else "s"))
    return " ".join(parts) or "0 seconds"


async def undeliverable(
    session: AsyncSession, emails: EmailKeyring, addresses: Sequence[str]
) -> int | None:
    """The index of the first address this tenant suppresses, or None (data model 2.5)."""
    by_pseudonym: dict[str, int] = {}
    for index, address in enumerate(addresses):
        for pseudonym in emails.every_version(address.lower()):
            by_pseudonym.setdefault(pseudonym, index)
    found = await suppressions.suppressed(session, by_pseudonym)
    return min((by_pseudonym[p] for p in found), default=None)


def recipient_pointer(index: int) -> str:
    """Where a recipient's address is in `TransferCreate`, for a refusal of it."""
    return json_pointer("recipients", index, "email")


def undeliverable_error(index: int) -> Unprocessable:
    detail = "The recipient's address bounced or complained; a tenant admin can clear it."
    return Unprocessable(
        "recipient_undeliverable",
        detail,
        errors=[FieldError(detail, pointer=json_pointer("recipients", index, "email"))],
    )


# ---- createTransfer ----


def _expiry(requested: timedelta | None, max_expiry: timedelta) -> timedelta:
    """The draft's `expires_in`: as asked, or min(7 days, the tenant's maximum) (FR-3)."""
    expires_in = min(DEFAULT_EXPIRY, max_expiry) if requested is None else requested
    check_expiry(expires_in, max_expiry, pointer=json_pointer("expires_in"))
    return expires_in


def _recipients(
    requested: Sequence[RecipientRequest], default_locale: str
) -> list[transfers.NewRecipient]:
    seen: set[str] = set()
    out = []
    for index, recipient in enumerate(requested):
        normalized = recipient.email.lower()
        if normalized in seen:
            raise invalid(
                json_pointer("recipients", index, "email"), "An address appears more than once."
            )
        seen.add(normalized)
        out.append(
            transfers.NewRecipient(uuid7(), recipient.email, recipient.locale or default_locale)
        )
    return out


async def create_transfer(
    database: Database,
    caller: Caller,
    request: TransferRequest,
    *,
    emails: EmailKeyring,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[TransferView]:
    """`createTransfer`: a new draft with its recipients (FR-1, FR-3, FR-4, FR-8).

    The expiry is checked against the tenant's policy, and every address against its suppression
    list, under every key version of `emails` (data model 2.5). With an `Idempotency-Key`, a retry
    of the same request gets the first answer, with the transfer as it is now, and creates
    nothing again (`sft.service.idempotency`).
    """
    authorize(caller, "createTransfer", now=now)
    scope = tenant_scope(caller)
    tenant_id, user_id = scope.tenant_id, caller.user_id
    assert tenant_id is not None  # noqa: S101 - checked by tenant_scope
    assert user_id is not None  # noqa: S101 - checked by tenant_scope
    async with database.transaction(scope) as session:

        async def create() -> TransferView:
            policy = await tenants.get_policy(session)
            expires_in = _expiry(request.expires_in, policy.max_expiry)
            recipients = _recipients(request.recipients, policy.default_locale)
            # The domain rules first (FR-45), then the suppression list.
            domain_rules.check(
                domain_rules.DomainRules.of(policy),
                [r.email for r in recipients],
                recipient_pointer,
            )
            refused = await undeliverable(session, emails, [r.email for r in recipients])
            if refused is not None:
                raise undeliverable_error(refused)
            transfer_id = uuid7()
            message_ct = None
            if request.message is not None:
                keys = await fields.tenant_keys(session, tenant_id, write=True)
                message_ct = keys.seal(fields.TRANSFER_MESSAGE, transfer_id, request.message)
            transfer = await transfers.insert_transfer(
                session,
                transfer_id=transfer_id,
                created_by=user_id,
                expires_in=expires_in,
                message_ct=message_ct,
                download_limit=request.download_limit,
                notify_on_first_download=request.notify_on_first_download,
            )
            await transfers.insert_recipients(session, transfer.id, recipients)
            message_findings = 0
            if request.message is not None:
                # FR-50: the message is inspected now, with the files' detectors (#221).
                message_findings = await message_inspection.inspect_message(
                    session, tenant_id, transfer.id, request.message
                )
            await audit.record(
                session,
                action="transfer.created",
                actor=caller.actor(),
                target=Target(TRANSFER, transfer.id),
                origin=origin,
                details=audit_details(
                    caller,
                    recipients=len(recipients),
                    expires_in_seconds=int(expires_in.total_seconds()),
                    download_limit=request.download_limit,
                    has_message=request.message is not None,
                    message_findings=message_findings,
                ),
            )
            return await transfer_view(session, tenant_id, transfer, now)

        async def rebuild(transfer_id: UUID) -> TransferView | None:
            try:
                transfer = await transfers.get_transfer(session, transfer_id)
            except NotFoundError:
                return None
            return await transfer_view(session, tenant_id, transfer, now)

        return await once(
            session,
            caller,
            idempotency,
            status=201,
            resource_type=TRANSFER,
            create=create,
            rebuild=rebuild,
            resource_id=lambda view: view.id,
        )


# ---- getTransfer, listTransfers ----


async def get_transfer(
    database: Database, caller: Caller, transfer_id: UUID, *, now: datetime
) -> TransferView:
    """`getTransfer`: the transfer with its files and recipients, each file with its state, so a
    held transfer shows which file isn't shareable and why (UC-1)."""
    reach = authorize(caller, "getTransfer", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        try:
            transfer = await transfers.get_transfer(session, transfer_id)
        except NotFoundError:
            raise NotFound from None
        require_visible(caller, reach, transfer)
        return await transfer_view(session, tenant_id, transfer, now)


@dataclass(frozen=True, slots=True)
class SummaryView:
    id: UUID
    state: TransferState
    created_by: UUID
    created_at: datetime
    expires_at: datetime | None
    sent_at: datetime | None
    revoked_at: datetime | None
    file_count: int
    recipient_count: int
    total_size: int
    dlp_outcome: str | None = None


@dataclass(frozen=True, slots=True)
class TransferPage:
    items: tuple[SummaryView, ...]
    next_cursor: str | None


def encode_cursor(transfer_id: UUID) -> str:
    """An opaque cursor: the last transfer of the page."""
    return base64.urlsafe_b64encode(transfer_id.bytes).decode().rstrip("=")


def decode_cursor(cursor: str) -> UUID:
    try:
        return UUID(bytes=base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    except (binascii.Error, ValueError) as exc:
        raise InvalidRequest("invalid_cursor") from exc


async def list_transfers(
    database: Database,
    caller: Caller,
    *,
    tenant_wide: bool = False,
    states: Collection[TransferState] = (),
    cursor: str | None = None,
    limit: int = 25,
    now: datetime,
) -> TransferPage:
    """`listTransfers`, newest first. `scope=tenant` (`tenant_wide`) needs Tenant reach: an admin
    acting as one, or an API key; a member gets 403 and a local admin without a passkey
    `403 passkey_required`. `scope=own` is the caller's own, for a key its owner's."""
    reach = authorize(caller, "listTransfers", now=now)
    if tenant_wide and reach is not Reach.TENANT:
        if caller.is_admin and caller.kind is CallerKind.MEMBER:
            raise Forbidden("passkey_required", "The admin role needs a passkey sign-in.")
        raise Forbidden("permission_denied", "scope=tenant needs the admin role or an API key.")
    if not 1 <= limit <= MAX_PAGE:
        raise ValueError("a page holds 1 to 100 transfers")
    before = None if cursor is None else decode_cursor(cursor)
    async with database.transaction(tenant_scope(caller)) as session:
        # One query a page: the filter reads expiry from `expires_at`, as the states shown do.
        found = await transfers.list_transfers(
            session,
            created_by=None if tenant_wide else caller.user_id,
            states=set(states),
            before=before,
            limit=limit + 1,
            now=now,
        )
    items = [
        SummaryView(
            id=summary.id,
            state=effective_state(summary.state, summary.expires_at, now),
            created_by=summary.created_by,
            created_at=summary.created_at,
            expires_at=summary.expires_at,
            sent_at=summary.sent_at,
            revoked_at=summary.ended_at if summary.state is TransferState.REVOKED else None,
            file_count=summary.file_count,
            recipient_count=summary.recipient_count,
            total_size=summary.total_size,
            dlp_outcome=summary.dlp_outcome,
        )
        for summary in found
    ]
    more = len(items) > limit
    page = tuple(items[:limit])
    return TransferPage(page, encode_cursor(page[-1].id) if more else None)
