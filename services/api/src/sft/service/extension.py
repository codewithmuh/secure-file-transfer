"""`extendTransferExpiry` (#214; FR-9, FR-3; API README 10; data model 2.2, 2.3, 2.4).

**The limits are over the whole lifetime.** The new `expires_at` is at most 30 days, and at most
the tenant's `max_expiry` as it is now, after `submitted_at`, when the expiry was first set; so
repeated extensions can't keep a transfer alive beyond that. An earlier time than the current one
is `422 expiry_out_of_range`, as is one past either cap. The current time itself returns the
transfer unchanged, writes nothing and is not audited, so a retry of a successful extension is
safe even without an `Idempotency-Key`; with one, a retry gets the first answer
(`sft.service.idempotency`).

**One transaction, under the transfer's row lock** (which a download's grant and the expiry job
take too): `expires_at` moves; the open link sessions of its recipients run on to the new time,
each still at most 24 hours after it was made (data model 2.4); their live download grants run on
with them, each still at most 24 hours after it was made (2.3); and `transfer.expiry_extended`
records the old and the new time. So a recipient verified before the old time keeps their session
past it, a resume keeps its grant, and the expiry job, which re-reads `expires_at` under the lock,
finds the transfer no longer due.

Who may extend: the transfer's owner only, for a key its owner (`transfer.extend`, Own for
everyone). Another member gets `404`; a tenant admin, who sees every transfer, `403
permission_denied` (authn and authz 6.4). It counts against group H (`TENANT_OPERATION`).

States (data model 3.2): `submitted`, `awaiting_confirmation`, `pending_approval`, `held` and
`sent` can be extended. A draft has no `expires_at` yet, and a cancelled transfer has ended:
`409 invalid_state`. A revoked one is `409 transfer_revoked`, an expired one (also before the job
records it) `409 transfer_expired`.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final
from uuid import UUID

from sft.core.errors import Conflict, FieldError, NotFound, Unprocessable, json_pointer
from sft.data import audit, downloads, link_sessions, tenants, transfers
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import Transfer, TransferState
from sft.service.caller import Caller
from sft.service.idempotency import IdempotentRequest, Outcome, once
from sft.service.permissions import authorize
from sft.service.transfers import (
    MAX_EXPIRY,
    TRANSFER,
    TransferView,
    audit_details,
    effective_state,
    require_reach,
    tenant_scope,
    transfer_view,
)

EXTENDABLE: Final = frozenset(
    {
        TransferState.SUBMITTED,
        TransferState.AWAITING_CONFIRMATION,
        TransferState.PENDING_APPROVAL,
        TransferState.HELD,
        TransferState.SENT,
    }
)
ACTION: Final = "transfer.expiry_extended"


def _out_of_range(detail: str) -> Unprocessable:
    return Unprocessable(
        "expiry_out_of_range",
        detail,
        errors=[FieldError(detail, pointer=json_pointer("expires_at"))],
    )


def _check_state(transfer: Transfer, now: datetime) -> None:
    state = effective_state(TransferState(transfer.state), transfer.expires_at, now)
    if state is TransferState.REVOKED:
        raise Conflict("transfer_revoked", current_state=state.value)
    if state is TransferState.EXPIRED:
        raise Conflict("transfer_expired", current_state=state.value)
    if state not in EXTENDABLE:
        raise Conflict(
            "invalid_state",
            "Only a transfer that was submitted and hasn't ended can be extended.",
            current_state=state.value,
        )


async def extend_expiry(
    database: Database,
    caller: Caller,
    transfer_id: UUID,
    expires_at: datetime,
    *,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[TransferView]:
    """`extendTransferExpiry` (module docstring). `expires_at` is an aware time."""
    reach = authorize(caller, "extendTransferExpiry", now=now)
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:

        async def extend() -> TransferView:
            try:
                transfer = await transfers.get_transfer(session, transfer_id, lock=True)
            except NotFoundError:
                raise NotFound from None
            require_reach(caller, reach, transfer, now)
            _check_state(transfer, now)
            current, submitted = transfer.expires_at, transfer.submitted_at
            if current is None or submitted is None:  # pragma: no cover - every extendable state
                raise Conflict("invalid_state", current_state=transfer.state)
            if expires_at == current:
                return await transfer_view(session, tenant_id, transfer, now)
            if expires_at < current:
                raise _out_of_range("The new expiry can't be earlier than the current one.")
            policy = await tenants.get_policy(session)
            if expires_at > submitted + min(MAX_EXPIRY, policy.max_expiry):
                raise _out_of_range(
                    "The new expiry is at most 30 days, or the tenant's maximum if shorter, "
                    "after the transfer was sent."
                )
            await transfers.extend_expiry(session, transfer.id, expires_at)
            sessions = await link_sessions.extend_for_transfer(session, transfer.id, expires_at)
            grants = await downloads.extend_for_transfer(session, transfer.id)
            await audit.record(
                session,
                action=ACTION,
                actor=caller.actor(),
                target=Target(TRANSFER, transfer.id),
                origin=origin,
                details=audit_details(
                    caller,
                    from_expires_at=current,
                    to_expires_at=expires_at,
                    link_sessions_extended=sessions,
                    download_grants_extended=grants,
                ),
            )
            extended = await transfers.get_transfer(session, transfer.id)
            return await transfer_view(session, tenant_id, extended, now)

        async def rebuild(found: UUID) -> TransferView | None:
            try:
                transfer = await transfers.get_transfer(session, found)
            except NotFoundError:
                return None
            return await transfer_view(session, tenant_id, transfer, now)

        return await once(
            session,
            caller,
            idempotency,
            status=200,
            resource_type=TRANSFER,
            create=extend,
            rebuild=rebuild,
            resource_id=lambda view: view.id,
        )
