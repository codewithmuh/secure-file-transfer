"""`revokeTransfer` (#180; UC-3, FR-20, NFR-6, NFR-10; architecture 4.4; data model 2.4, 3.2).

**Commit, then archive.** One transaction, under the transfer's row lock: the transfer becomes
`revoked` with `ended_at` and `revoked_by`; every link session of its recipients ends; every file
gets `delete_after`, so the deletion job removes it (#181), and an upload still open is rejected;
`transfer.revoked` is written, marked security-critical. The revocation takes effect at that
commit: new grants, content requests and link steps answer `410 link_revoked`, and a running stream
stops at its next re-check. Then the record goes to the audit archive in both regions before the
`200`; if either write fails the call answers `503`, which means "done, not confirmed", and a
retry finds the transfer revoked, writes the record if it is still missing and answers `200`.

Who may revoke: the transfer's sender, any tenant admin (a local admin without a passkey too:
`PASSKEY_EXEMPT`), and an API key with `transfers:write`. It is a safety action: it never counts
against the tenant's request budget (`SAFETY_ACTION`, abuse 2.2 H).

States (data model 3.2): `submitted`, `awaiting_confirmation`, `pending_approval`, `held` and
`sent` can be revoked; a draft or a cancelled transfer is `409 invalid_state`, an expired one
`409 transfer_expired`. A pending DLP approval request is withdrawn in the same transaction
(`dlp_approval.withdrawn`, #220; data model 3.6).
"""

from __future__ import annotations

from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import func

from sft.core.errors import NotFound
from sft.data import audit, files, link_sessions, transfers
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import TransferState
from sft.service.audit_archive import AuditArchive
from sft.service.caller import Caller
from sft.service.evaluation import WithdrawReason, withdraw_approval_request
from sft.service.permissions import authorize
from sft.service.transfers import (
    TRANSFER,
    TransferView,
    audit_details,
    effective_state,
    require_reach,
    state_conflict,
    tenant_scope,
    transfer_view,
)
from sft.service.uploads import RejectReason, reject

REVOCABLE: Final = frozenset(
    {
        TransferState.SUBMITTED,
        TransferState.AWAITING_CONFIRMATION,
        TransferState.PENDING_APPROVAL,
        TransferState.HELD,
        TransferState.SENT,
    }
)
ACTION: Final = "transfer.revoked"


async def revoke_transfer(
    database: Database,
    archive: AuditArchive,
    caller: Caller,
    transfer_id: UUID,
    *,
    origin: Origin,
    now: datetime,
) -> TransferView:
    """`revokeTransfer` (module docstring)."""
    reach = authorize(caller, "revokeTransfer", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        try:
            transfer = await transfers.get_transfer(session, transfer_id, lock=True)
        except NotFoundError:
            raise NotFound from None
        require_reach(caller, reach, transfer, now)
        stored = TransferState(transfer.state)
        if stored is TransferState.REVOKED:
            # A retry: the revocation stands; its record is written if it is still missing.
            event = await audit.latest_critical_event(
                session, action=ACTION, target=Target(TRANSFER, transfer.id)
            )
            view = await transfer_view(session, tenant_id, transfer, now)
        else:
            state = effective_state(stored, transfer.expires_at, now)
            if state not in REVOCABLE:
                raise state_conflict(
                    state, "Only a transfer that was submitted can be revoked; cancel a draft."
                )
            await transfers.change_state(
                session,
                transfer.id,
                from_states=(state,),
                to=TransferState.REVOKED,
                ended_at=func.now(),
                revoked_by=caller.user_id,
                hold_reason=None,
            )
            if state is TransferState.PENDING_APPROVAL:
                await withdraw_approval_request(
                    session,
                    transfer.id,
                    reason=WithdrawReason.REVOKED,
                    actor=caller.actor(),
                    origin=origin,
                    details=audit_details(caller),
                    now=now,
                )
            sessions = await link_sessions.revoke_for_transfer(session, transfer.id)
            open_uploads = await files.cancel_files(session, transfer.id)
            for file in open_uploads:
                await reject(session, caller, file, RejectReason.TRANSFER_NOT_OPEN, origin)
            event_id = await audit.record(
                session,
                action=ACTION,
                actor=caller.actor(),
                target=Target(TRANSFER, transfer.id),
                origin=origin,
                security_critical=True,
                details=audit_details(
                    caller,
                    from_state=state,
                    link_sessions_ended=sessions,
                    rejected_files=len(open_uploads),
                ),
            )
            event = await audit.archived_event(session, event_id)
            revoked = await transfers.get_transfer(session, transfer.id)
            view = await transfer_view(session, tenant_id, revoked, now)
    if event is not None:
        await archive.confirm([event])
    return view
