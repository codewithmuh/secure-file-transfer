"""Draft transfers: create one, and the views the API returns (UC-1, FR-1 to FR-4; data model 2.2).

Every function checks the caller against the permission registry first (`authorize`, authn and
authz 6.1), then the resource rule (6.4): an item the caller can't see answers 404, one it can see
but may not act on 403, and a state that doesn't allow the change 409, in that order. The change,
its audit event and any outbox message commit in one transaction (architecture 5.2, 5.3).

Permissions here (authn and authz 6.3, `sft.service.permissions`):

- `transfer.create`: any member or admin; an API key with `transfers:write`. The member, or the
  key's owner, owns the new transfer.
- `file.upload` and `file.delete` (`sft.service.uploads`): Own for everyone. A caller who isn't the
  owner gets 404 unless it may read every transfer of its tenant (`transfer.read` at Tenant reach:
  an admin acting as one, or a key with `transfers:read`), which gets 403.

Not here yet, and why: a recipient domain isn't checked against the tenant's allowed and blocked
domains, nor an address against the suppression list, and `expires_in` isn't capped by the tenant's
`max_expiry`, because the tenant policy's transfer fields and `email_suppressions` arrive with M2's
policy and email issues. The default locale is `en` until the tenant's `default_locale` exists.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import (
    Conflict,
    FieldError,
    Forbidden,
    NotFound,
    ProblemError,
    Unprocessable,
    json_pointer,
)
from sft.core.ids import uuid7
from sft.data import audit, files, transfers
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import File, FileState, Transfer, TransferState
from sft.data.scope import Scope
from sft.service import fields
from sft.service.caller import Caller, CallerKind
from sft.service.idempotency import IdempotentRequest, Outcome, once
from sft.service.permissions import Reach, authorize

MIN_EXPIRY: Final = timedelta(hours=1)
MAX_EXPIRY: Final = timedelta(days=30)
DEFAULT_EXPIRY: Final = timedelta(days=7)
"""FR-3. The tenant's `max_expiry` caps both once tenant policies hold it."""

DEFAULT_LOCALE: Final = "en"

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
    transfer_id: UUID
    display_name: str
    content_type: str
    declared_size: int
    actual_size: int | None
    state: FileState
    created_at: datetime
    part_size: int
    part_count: int

    @property
    def shareable(self) -> bool:
        # A file is shareable once its scan and inspection allow it (data model 3.1); neither runs
        # yet, so no file of this step is.
        return False


@dataclass(frozen=True, slots=True)
class RecipientView:
    id: UUID
    email: str
    locale: str


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

    @property
    def total_size(self) -> int:
        """The declared bytes of the files that count (data model 3.2)."""
        return sum(f.declared_size for f in self.files if f.state is not FileState.REJECTED)


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


def draft_conflict(transfer: Transfer) -> ProblemError | None:
    """None for a draft; otherwise the 409 a change to its files answers."""
    state = TransferState(transfer.state)
    if state is TransferState.DRAFT:
        return None
    if state is TransferState.REVOKED:
        return Conflict("transfer_revoked", current_state=state.value)
    if state is TransferState.EXPIRED:
        return Conflict("transfer_expired", current_state=state.value)
    return Conflict(
        "invalid_state",
        "Files change only while the transfer is a draft.",
        current_state=state.value,
    )


def audit_details(caller: Caller, **details: audit.Detail) -> dict[str, audit.Detail]:
    """An API key's events name its owner too (authn and authz 5.2)."""
    if caller.kind is CallerKind.API_KEY:
        details["owner_id"] = caller.user_id
    return details


def invalid(pointer: str, detail: str) -> Unprocessable:
    """`422 validation_failed`, pointing at the body field that breaks the rule."""
    return Unprocessable("validation_failed", detail, errors=[FieldError(detail, pointer=pointer)])


# ---- views ----


def file_view(tenant_id: UUID, file: File) -> FileView:
    return FileView(
        id=file.id,
        transfer_id=file.transfer_id,
        display_name=fields.open_sealed(tenant_id, file.display_name_ct),
        content_type=file.content_type,
        declared_size=file.declared_size,
        actual_size=file.actual_size,
        state=FileState(file.state),
        created_at=file.created_at,
        part_size=file.part_size,
        part_count=file.part_count,
    )


async def transfer_view(session: AsyncSession, tenant_id: UUID, transfer: Transfer) -> TransferView:
    recipients = await transfers.list_recipients(session, transfer.id)
    transfer_files = await files.list_transfer_files(session, transfer.id)
    state = TransferState(transfer.state)
    return TransferView(
        id=transfer.id,
        state=state,
        created_by=transfer.created_by,
        created_at=transfer.created_at,
        expires_in=transfer.expires_in,
        expires_at=transfer.expires_at,
        message=(
            None
            if transfer.message_ct is None
            else fields.open_sealed(tenant_id, transfer.message_ct)
        ),
        download_limit=transfer.download_limit,
        notify_on_first_download=transfer.notify_on_first_download,
        submitted_at=transfer.submitted_at,
        sent_at=transfer.sent_at,
        revoked_at=transfer.ended_at if state is TransferState.REVOKED else None,
        revoked_by=transfer.revoked_by,
        hold_reason=transfer.hold_reason,
        files=tuple(file_view(tenant_id, f) for f in transfer_files),
        recipients=tuple(RecipientView(r.id, r.email, r.locale) for r in recipients),
    )


# ---- createTransfer ----


def _expiry(requested: timedelta | None) -> timedelta:
    expires_in = DEFAULT_EXPIRY if requested is None else requested
    if not MIN_EXPIRY <= expires_in <= MAX_EXPIRY:
        detail = "expires_in is between 1 hour and 30 days."
        raise Unprocessable(
            "expiry_out_of_range",
            detail,
            errors=[FieldError(detail, pointer=json_pointer("expires_in"))],
        )
    return expires_in


def _recipients(requested: Sequence[RecipientRequest]) -> list[transfers.NewRecipient]:
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
            transfers.NewRecipient(uuid7(), recipient.email, recipient.locale or DEFAULT_LOCALE)
        )
    return out


async def create_transfer(
    database: Database,
    caller: Caller,
    request: TransferRequest,
    *,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[TransferView]:
    """`createTransfer`: a new draft with its recipients (FR-1, FR-3, FR-4, FR-8).

    With an `Idempotency-Key`, a retry of the same request gets the first answer, with the
    transfer as it is now, and creates nothing again (`sft.service.idempotency`).
    """
    authorize(caller, "createTransfer", now=now)
    expires_in = _expiry(request.expires_in)
    recipients = _recipients(request.recipients)
    scope = tenant_scope(caller)
    tenant_id, user_id = scope.tenant_id, caller.user_id
    assert tenant_id is not None  # noqa: S101 - checked by tenant_scope
    assert user_id is not None  # noqa: S101 - checked by tenant_scope
    async with database.transaction(scope) as session:

        async def create() -> TransferView:
            transfer = await transfers.insert_transfer(
                session,
                transfer_id=uuid7(),
                created_by=user_id,
                expires_in=expires_in,
                message_ct=None
                if request.message is None
                else fields.seal(tenant_id, request.message),
                download_limit=request.download_limit,
                notify_on_first_download=request.notify_on_first_download,
            )
            await transfers.insert_recipients(session, transfer.id, recipients)
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
                ),
            )
            return await transfer_view(session, tenant_id, transfer)

        async def rebuild(transfer_id: UUID) -> TransferView | None:
            try:
                transfer = await transfers.get_transfer(session, transfer_id)
            except NotFoundError:
                return None
            return await transfer_view(session, tenant_id, transfer)

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
