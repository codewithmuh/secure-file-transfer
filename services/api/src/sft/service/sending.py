"""Sending and cancelling a transfer: `sendTransfer` and `cancelTransfer` (UC-1, FR-1, FR-3, FR-5,
FR-21; data model 2.2, 3.2; architecture 4.1).

**Sending** locks the draft, checks it and submits it, then runs the evaluation
(`sft.service.evaluation`) in the same transaction, so a transfer whose files are all shareable is
sent at once, and one with a file still scanning waits for the scan worker's evaluation. The checks,
in order:

1. Only the owner sends (`transfer.send` is Own for everyone): another member gets 404, an admin or
   a key that sees the tenant's transfers 403.
2. A transfer already `submitted`, `awaiting_confirmation`, `pending_approval`, `held` or `sent`
   comes back unchanged, so a retry is safe. `cancelled` is `409 invalid_state`, `revoked` and
   `expired` their own 409s.
3. `409 upload_incomplete` while a file is `uploading` or `completing`; `409 transfer_empty`
   without a counted file (FR-1).
4. `422 expiry_out_of_range` if the tenant's `max_expiry` has dropped below `expires_in` since the
   draft was made (data model 2.2). The draft is unchanged.
5. `422 recipient_undeliverable` if this tenant has suppressed an address since the draft was made
   (abuse 7.4), pointing at the recipient.
6. Group G's email caps (abuse 2.2), counted only for a send that passes every check above: each
   recipient is one email against the caller's 200 an hour and the tenant's 2,000, and one link
   email a day of the 20 to that address within the tenant. They are charged all or nothing, in
   batched calls to the counter store (`RateLimiter.check_all`): a `429` charges no limit, and the
   draft is unchanged. During a counter store outage the per-pod limits apply, sized so a send to
   the contract's 50 recipients still passes (#129).

Then `submitted_at = now()` and `expires_at = submitted_at + expires_in`, under the row lock: time
spent as a draft never shortens the transfer.

**Cancelling** works from `draft`, `held`, `awaiting_confirmation` and `pending_approval`; a
cancelled transfer comes back unchanged, any other state is `409 invalid_state`. It sets
`ended_at`, and `delete_after` on every file, which the deletion job acts on (data model 6). A file
still `uploading` or `completing` is rejected and its reservation released: cancelling wins over
the upload, whose next call gets `409 invalid_state`. Only the owner cancels; a tenant admin gets
403 and revokes instead.

Every change writes its audit event in its transaction: `transfer.submitted`, the evaluation's
events, `transfer.cancelled`, and `file.rejected` for each upload a cancellation stops.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import Conflict, NotFound
from sft.core.pseudonyms import EmailKeyring
from sft.data import audit, files, tenants, transfers
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import FileState, Transfer, TransferState
from sft.service.caller import Caller
from sft.service.evaluation import evaluate
from sft.service.permissions import Reach, authorize
from sft.service.rate_limits import Charge, RateLimiter
from sft.service.rate_limits.limits import ADDRESS_LINK_EMAILS, LINK_EMAILS, KeyType
from sft.service.transfers import (
    TRANSFER,
    TransferView,
    audit_details,
    check_expiry,
    effective_state,
    require_reach,
    tenant_scope,
    transfer_view,
    undeliverable,
    undeliverable_error,
)
from sft.service.uploads import RejectReason, reject

UNCHANGED_ON_SEND: Final = frozenset(
    {
        TransferState.SUBMITTED,
        TransferState.AWAITING_CONFIRMATION,
        TransferState.PENDING_APPROVAL,
        TransferState.HELD,
        TransferState.SENT,
    }
)
CANCELLABLE: Final = frozenset(
    {
        TransferState.DRAFT,
        TransferState.HELD,
        TransferState.AWAITING_CONFIRMATION,
        TransferState.PENDING_APPROVAL,
    }
)


async def _locked(
    session: AsyncSession, caller: Caller, transfer_id: UUID, reach: Reach, now: datetime
) -> Transfer:
    try:
        transfer = await transfers.get_transfer(session, transfer_id, lock=True)
    except NotFoundError:
        raise NotFound from None
    require_reach(caller, reach, transfer, now)
    return transfer


def _not_sendable(state: TransferState) -> Conflict:
    if state is TransferState.REVOKED:
        return Conflict("transfer_revoked", current_state=state.value)
    if state is TransferState.EXPIRED:
        return Conflict("transfer_expired", current_state=state.value)
    return Conflict(
        "invalid_state", "A cancelled transfer can't be sent.", current_state=state.value
    )


async def _sendable(
    session: AsyncSession, transfer: Transfer, emails: EmailKeyring, now: datetime
) -> tuple[TransferState, list[str], int] | None:
    """Checks 2 to 5 of the module docstring on the transfer as read in `session`.

    None for a transfer that comes back unchanged; otherwise the state, the recipients'
    normalized addresses and the number of counted files. Raises the refusal.
    """
    state = effective_state(TransferState(transfer.state), transfer.expires_at, now)
    if state in UNCHANGED_ON_SEND:
        return None
    if state is not TransferState.DRAFT:
        raise _not_sendable(state)
    counted = await files.counted_states(session, transfer.id)
    if any(f.state in (FileState.UPLOADING, FileState.COMPLETING) for f in counted):
        raise Conflict(
            "upload_incomplete",
            "Every file must finish uploading first.",
            current_state=state.value,
        )
    if not counted:
        raise Conflict(
            "transfer_empty", "A transfer needs at least one file.", current_state=state.value
        )
    policy = await tenants.get_policy(session)
    check_expiry(transfer.expires_in, policy.max_expiry, pointer=None)
    recipients = await transfers.list_recipients(session, transfer.id)
    refused = await undeliverable(session, emails, [r.email for r in recipients])
    if refused is not None:
        raise undeliverable_error(refused)
    return state, [r.email_normalized for r in recipients], len(counted)


async def send_transfer(
    database: Database,
    caller: Caller,
    transfer_id: UUID,
    *,
    emails: EmailKeyring,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
) -> TransferView:
    """`sendTransfer`: submit a draft and evaluate it (module docstring).

    The checks run first without the row lock, and the email caps are only read (one pipelined
    call), so a refusal holds no lock and charges nothing. Then, under the lock, the checks run
    again and the caps are charged, all or nothing, in two pipelined calls; a refusal there rolls
    the transaction back with nothing charged.
    """
    reach = authorize(caller, "sendTransfer", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        try:
            transfer = await transfers.get_transfer(session, transfer_id)
        except NotFoundError:
            raise NotFound from None
        require_reach(caller, reach, transfer, now)
        checked = await _sendable(session, transfer, emails, now)
        if checked is None:
            return await transfer_view(session, tenant_id, transfer, now)
    await limiter.peek_all(_email_charges(caller, emails, checked[1], now))

    async with database.transaction(scope) as session:
        transfer = await _locked(session, caller, transfer_id, reach, now)
        checked = await _sendable(session, transfer, emails, now)
        if checked is None:  # another call sent it meanwhile
            return await transfer_view(session, tenant_id, transfer, now)
        _, addresses, file_count = checked
        await limiter.check_all(_email_charges(caller, emails, addresses, now))
        await transfers.change_state(
            session,
            transfer.id,
            from_states=(TransferState.DRAFT,),
            to=TransferState.SUBMITTED,
            submitted_at=func.now(),
            expires_at=func.now() + transfer.expires_in,
        )
        details = audit_details(
            caller,
            files=file_count,
            recipients=len(addresses),
            expires_in_seconds=int(transfer.expires_in.total_seconds()),
        )
        await audit.record(
            session,
            action="transfer.submitted",
            actor=caller.actor(),
            target=Target(TRANSFER, transfer.id),
            origin=origin,
            details={**details, "from_state": TransferState.DRAFT},
        )
        await evaluate(
            session,
            transfer.id,
            actor=caller.actor(),
            now=now,
            origin=origin,
            details=audit_details(caller),
        )
        sent = await transfers.get_transfer(session, transfer.id)
        return await transfer_view(session, tenant_id, sent, now)


def _email_charges(
    caller: Caller, emails: EmailKeyring, addresses: list[str], now: datetime
) -> list[Charge]:
    """Group G (abuse 2.2): the caller's and the tenant's recipient emails, one per address, and
    each address's link emails within the tenant, narrowest first."""
    keys = caller.rate_limit_keys()
    count = max(1, len(addresses))
    caller_limit, tenant_limit = LINK_EMAILS
    return [
        Charge(caller_limit, keys, count),
        *(
            Charge(
                limit,
                {KeyType.TENANT_EMAIL: emails.for_limits(a, now).within(str(caller.tenant_id))},
            )
            for a in addresses
            for limit in ADDRESS_LINK_EMAILS
        ),
        Charge(tenant_limit, keys, count),
    ]


async def cancel_transfer(
    database: Database, caller: Caller, transfer_id: UUID, *, origin: Origin, now: datetime
) -> TransferView:
    """`cancelTransfer` (module docstring)."""
    reach = authorize(caller, "cancelTransfer", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        transfer = await _locked(session, caller, transfer_id, reach, now)
        state = effective_state(TransferState(transfer.state), transfer.expires_at, now)
        if state is TransferState.CANCELLED:
            return await transfer_view(session, tenant_id, transfer, now)
        if state not in CANCELLABLE:
            raise Conflict(
                "invalid_state",
                "Only a transfer that wasn't sent can be cancelled; revoke a sent one.",
                current_state=state.value,
            )
        await transfers.change_state(
            session,
            transfer.id,
            from_states=(state,),
            to=TransferState.CANCELLED,
            ended_at=func.now(),
            hold_reason=None,
        )
        open_uploads = await files.cancel_files(session, transfer.id)
        for file in open_uploads:
            await reject(session, caller, file, RejectReason.TRANSFER_NOT_OPEN, origin)
        await audit.record(
            session,
            action="transfer.cancelled",
            actor=caller.actor(),
            target=Target(TRANSFER, transfer.id),
            origin=origin,
            details=audit_details(caller, from_state=state, rejected_files=len(open_uploads)),
        )
        cancelled = await transfers.get_transfer(session, transfer.id)
        return await transfer_view(session, tenant_id, cancelled, now)
