"""Data access for `transfers` and `transfer_recipients` (data model 2.2, 3.2).

Every function filters with `in_scope`, and every write takes its tenant from the transaction's
scope (`tenant_of`), never from an argument. Writes run in tenant scope only: a member or an API
key acts on its own tenant's transfers, and no link session or job creates one through here.
State rules and permissions are the service layer's (`sft.service.transfers`); these functions
only read and write rows. A row the scope doesn't reach is `NotFoundError`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import NotFoundError, in_scope, require_scope, tenant_of
from sft.data.models import DeliveryState, Transfer, TransferRecipient, TransferState
from sft.data.scope import ScopeKind


@dataclass(frozen=True, slots=True)
class NewRecipient:
    id: UUID
    email: str
    locale: str


async def insert_transfer(
    session: AsyncSession,
    *,
    transfer_id: UUID,
    created_by: UUID,
    expires_in: timedelta,
    message_ct: bytes | None,
    download_limit: int | None,
    notify_on_first_download: bool,
) -> Transfer:
    """A new draft of the scope's tenant, owned by `created_by` (a user of that tenant)."""
    require_scope(session, ScopeKind.TENANT)
    transfer: Transfer | None = await session.scalar(
        insert(Transfer)
        .values(
            id=transfer_id,
            tenant_id=tenant_of(session),
            created_by=created_by,
            state=TransferState.DRAFT.value,
            message_ct=message_ct,
            expires_in=expires_in,
            download_limit=download_limit,
            notify_on_first_download=notify_on_first_download,
        )
        .returning(Transfer)
    )
    if transfer is None:  # pragma: no cover - INSERT … RETURNING always returns the row
        raise RuntimeError("the insert returned no row")
    return transfer


async def insert_recipients(
    session: AsyncSession, transfer_id: UUID, recipients: Sequence[NewRecipient]
) -> list[TransferRecipient]:
    """The recipients of a transfer of the scope's tenant, each address once (data model 2.2)."""
    require_scope(session, ScopeKind.TENANT)
    if not recipients:
        return []
    tenant_id = tenant_of(session)
    rows = await session.scalars(
        insert(TransferRecipient)
        .values(
            [
                {
                    "id": r.id,
                    "tenant_id": tenant_id,
                    "transfer_id": transfer_id,
                    "email": r.email,
                    "email_normalized": r.email.lower(),
                    "locale": r.locale,
                    "delivery_state": DeliveryState.PENDING.value,
                }
                for r in recipients
            ]
        )
        .returning(TransferRecipient)
    )
    return list(rows)


async def get_transfer(session: AsyncSession, transfer_id: UUID, *, lock: bool = False) -> Transfer:
    """The transfer, if the scope reaches it. `lock` takes its row lock (`FOR UPDATE`), which every
    state change and every file completion holds while it re-checks the transfer (architecture
    4.1)."""
    statement = select(Transfer).where(Transfer.id == transfer_id, in_scope(Transfer, session))
    if lock:
        statement = statement.with_for_update()
    transfer: Transfer | None = await session.scalar(
        statement.execution_options(populate_existing=True)
    )
    if transfer is None:
        raise NotFoundError("transfer")
    return transfer


async def list_recipients(session: AsyncSession, transfer_id: UUID) -> list[TransferRecipient]:
    rows = await session.scalars(
        select(TransferRecipient)
        .where(
            TransferRecipient.transfer_id == transfer_id,
            in_scope(TransferRecipient, session),
        )
        .order_by(TransferRecipient.id)
    )
    return list(rows)


async def touch_draft(session: AsyncSession, transfer_id: UUID) -> bool:
    """Move a draft's `last_activity_at` to now (data model 2.2); False if it isn't a draft."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        update(Transfer)
        .where(
            Transfer.id == transfer_id,
            Transfer.state == TransferState.DRAFT.value,
            in_scope(Transfer, session),
        )
        .values(last_activity_at=func.now())
        .returning(Transfer.id)
    )
    return result.first() is not None
