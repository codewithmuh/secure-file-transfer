"""Recipients' status and unlock, for members and admins (#178, #179; FR-7, NFR-14; authn and
authz 4.4, 6.3).

- **`listTransferRecipients`** (`transfer.read`): each recipient's delivery state, when the link
  email was sent, when they verified, whether they are locked out, and their downloads. The same
  people see it as `getTransfer`: the owner, and every admin acting as one and every key with
  `transfers:read` for any transfer of the tenant. `delivery_state` is `queued` for every kind of
  delay and never says which (NFR-12).
- **`unlockRecipient`** (`recipient.unlock`): the owner, or an admin acting as one for any
  transfer of the tenant. A local admin without a passkey sign-in gets `403 passkey_required` on
  another member's transfer, and API keys get `403`: a lockout signals a possible attack, so a
  person decides. Unlocking resets the count, clears the lock and the whole link, and queues a new
  link email: the old link is `404` from then on (data model 2.4). A security-critical record
  (#177): the unlock commits first, then its record goes to both regions' archive, and the call
  answers `200` only once both hold it, `503` otherwise, with the unlock kept. A recipient who
  isn't locked is returned unchanged, with nothing sent, and a retry writes a missing record of
  their last unlock. A revoked or expired transfer can't be unlocked (`409`).
"""

from __future__ import annotations

from datetime import datetime
from typing import Final
from uuid import UUID

from sft.core.errors import Forbidden, NotFound
from sft.data import audit, recipients, transfers
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import TransferState
from sft.data.outbox import RECIPIENT_LINK_DUE, enqueue
from sft.data.recipients import RecipientStatus
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller
from sft.service.permissions import Reach, authorize
from sft.service.transfers import (
    audit_details,
    effective_state,
    require_visible,
    sees_tenant,
    tenant_scope,
    terminal_conflict,
)

RECIPIENT: Final = "recipient"


async def list_recipients(
    database: Database, caller: Caller, transfer_id: UUID, *, now: datetime
) -> list[RecipientStatus]:
    """`listTransferRecipients`: every recipient of a transfer the caller may read."""
    reach = authorize(caller, "listTransferRecipients", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        try:
            transfer = await transfers.get_transfer(session, transfer_id)
        except NotFoundError:
            raise NotFound from None
        require_visible(caller, reach, transfer)
        return await recipients.statuses(session, transfer_id)


async def unlock_recipient(
    database: Database,
    caller: Caller,
    transfer_id: UUID,
    recipient_id: UUID,
    *,
    archive: AuditArchive,
    origin: Origin,
    now: datetime,
) -> RecipientStatus:
    """`unlockRecipient` (module docstring)."""
    reach = authorize(caller, "unlockRecipient", now=now)
    target = Target(RECIPIENT, recipient_id)
    async with database.transaction(tenant_scope(caller)) as session:
        try:
            transfer = await transfers.get_transfer(session, transfer_id, lock=True)
        except NotFoundError:
            raise NotFound from None
        if reach is not Reach.TENANT and transfer.created_by != caller.user_id:
            if caller.is_admin:
                raise Forbidden("passkey_required", "The admin role needs a passkey sign-in.")
            if sees_tenant(caller, now):
                raise Forbidden("permission_denied", "Only the sender or an admin may unlock.")
            raise NotFound
        try:
            locked_at = await recipients.lock_recipient(session, transfer_id, recipient_id)
        except NotFoundError:
            raise NotFound from None
        # 404, then 403, then 409 (authn and authz 6.4).
        # Only the terminal states refuse: unlocking a recipient of any other transfer is allowed.
        state = effective_state(TransferState(transfer.state), transfer.expires_at, now)
        if (ended := terminal_conflict(state)) is not None:
            raise ended
        if locked_at is not None and caller.user_id is not None:
            await recipients.unlock(session, recipient_id, by=caller.user_id)
            await audit.record(
                session,
                action="recipient.unlocked",
                actor=caller.actor(),
                target=target,
                origin=origin,
                security_critical=True,
                details=audit_details(caller, transfer_id=transfer_id),
            )
            await enqueue(session, RECIPIENT_LINK_DUE, {"recipient_id": recipient_id})
        # The unlock's record, just written or written by an earlier call (#177).
        event = await audit.latest_critical_event(
            session, action="recipient.unlocked", target=target
        )
        [status] = await recipients.statuses(session, transfer_id, recipient_id)
    await archive.confirm([event] if event else [])
    return status
