"""Data access for `transfers` and `transfer_recipients` (data model 2.2, 3.2).

Every function filters with `in_scope`, and every write takes its tenant from the transaction's
scope (`tenant_of`), never from an argument. Writes run in tenant scope only: a member or an API
key acts on its own tenant's transfers, and no link session or job creates one through here.
State rules and permissions are the service layer's (`sft.service.transfers`); these functions
only read and write rows. A row the scope doesn't reach is `NotFoundError`.

**The evaluation's functions** (`lock_for_evaluation`, `change_state`, `recipient_ids`,
`queue_recipients`, `insert_download_counters`; data model 3.2) also run as the scan worker and
the lifecycle jobs, whose roles may read neither the message nor an address (revision 0009). So
they name their columns, and never select a whole row.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final
from uuid import UUID

from sqlalchemy import ColumnElement, and_, func, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import NotFoundError, in_scope, require_scope, tenant_of
from sft.data.models import (
    DeliveryState,
    DownloadCounter,
    File,
    FileState,
    Transfer,
    TransferRecipient,
    TransferState,
)
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


# ---- listTransfers ----


@dataclass(frozen=True, slots=True)
class Summary:
    """A transfer as `listTransfers` shows it (the contract's `TransferSummary`)."""

    id: UUID
    state: TransferState
    created_by: UUID
    created_at: datetime
    expires_at: datetime | None
    sent_at: datetime | None
    ended_at: datetime | None
    file_count: int
    recipient_count: int
    total_size: int


EXPIRES_FROM: Final = frozenset(
    {
        TransferState.SUBMITTED,
        TransferState.AWAITING_CONFIRMATION,
        TransferState.PENDING_APPROVAL,
        TransferState.SENT,
        TransferState.HELD,
    }
)
"""The states a transfer leaves for `expired` once `expires_at` passes (data model 3.2)."""


def _shows_as(state: TransferState, now: datetime) -> ColumnElement[bool]:
    """Rows the API shows in `state` at `now`: expiry is read from `expires_at`, before the
    lifecycle job records it, so `expired` takes the rows past it, and the states it ends lose
    them."""
    past = and_(
        Transfer.state.in_([s.value for s in EXPIRES_FROM]),
        Transfer.expires_at <= now,
    )
    if state is TransferState.EXPIRED:
        return or_(Transfer.state == state.value, past)
    if state in EXPIRES_FROM:
        return and_(
            Transfer.state == state.value,
            or_(Transfer.expires_at.is_(None), Transfer.expires_at > now),
        )
    return Transfer.state == state.value


async def list_transfers(
    session: AsyncSession,
    *,
    created_by: UUID | None,
    states: Collection[TransferState] = (),
    before: UUID | None = None,
    limit: int,
    now: datetime,
) -> list[Summary]:
    """Up to `limit` transfers of the scope's tenant, newest first, before the transfer `before`;
    only `created_by`'s if given, and only those that show in one of `states` at `now`, in one
    query. Counts are of the counted files (data model 3.2)."""
    require_scope(session, ScopeKind.TENANT)
    counted = (
        File.transfer_id == Transfer.id,
        File.state != FileState.REJECTED.value,
        File.removed_at.is_(None),
        in_scope(File, session),
    )
    file_count = select(func.count()).where(*counted).correlate(Transfer).scalar_subquery()
    total_size = (
        select(func.coalesce(func.sum(File.declared_size), 0))
        .where(*counted)
        .correlate(Transfer)
        .scalar_subquery()
    )
    recipient_count = (
        select(func.count())
        .where(
            TransferRecipient.transfer_id == Transfer.id,
            in_scope(TransferRecipient, session),
        )
        .correlate(Transfer)
        .scalar_subquery()
    )
    statement = (
        select(Transfer, file_count, recipient_count, total_size)
        .where(in_scope(Transfer, session))
        .order_by(Transfer.id.desc())
        .limit(limit)
    )
    if created_by is not None:
        statement = statement.where(Transfer.created_by == created_by)
    if states:
        statement = statement.where(or_(*(_shows_as(state, now) for state in states)))
    if before is not None:
        statement = statement.where(Transfer.id < before)
    rows = await session.execute(statement)
    return [
        Summary(
            id=t.id,
            state=TransferState(t.state),
            created_by=t.created_by,
            created_at=t.created_at,
            expires_at=t.expires_at,
            sent_at=t.sent_at,
            ended_at=t.ended_at,
            file_count=int(files_),
            recipient_count=int(recipients),
            total_size=int(size),
        )
        for t, files_, recipients, size in rows.tuples()
    ]


# ---- state changes, and the evaluation's reads and writes (data model 3.2) ----


@dataclass(frozen=True, slots=True)
class Locked:
    """The columns of a transfer the evaluation reads, under its row lock."""

    id: UUID
    created_by: UUID
    state: TransferState
    hold_reason: str | None
    expires_in: timedelta
    expires_at: datetime | None
    download_limit: int | None


async def lock_for_evaluation(session: AsyncSession, transfer_id: UUID) -> Locked:
    """Take the transfer's row lock (`FOR UPDATE`) and read what the evaluation needs."""
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            select(
                Transfer.id,
                Transfer.created_by,
                Transfer.state,
                Transfer.hold_reason,
                Transfer.expires_in,
                Transfer.expires_at,
                Transfer.download_limit,
            )
            .where(Transfer.id == transfer_id, in_scope(Transfer, session))
            .with_for_update()
        )
    ).first()
    if row is None:
        raise NotFoundError("transfer")
    return Locked(
        id=row.id,
        created_by=row.created_by,
        state=TransferState(row.state),
        hold_reason=row.hold_reason,
        expires_in=row.expires_in,
        expires_at=row.expires_at,
        download_limit=row.download_limit,
    )


async def change_state(
    session: AsyncSession,
    transfer_id: UUID,
    *,
    from_states: Collection[TransferState],
    to: TransferState,
    **values: Any,
) -> bool:
    """Move the transfer to `to` if it is in one of `from_states`, setting `values` too; False if
    it wasn't. The caller holds the row lock and writes the audit event."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        update(Transfer)
        .where(
            Transfer.id == transfer_id,
            Transfer.state.in_([s.value for s in from_states]),
            in_scope(Transfer, session),
        )
        .values(state=to.value, **values)
        .returning(Transfer.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def recipient_ids(session: AsyncSession, transfer_id: UUID) -> list[UUID]:
    require_scope(session, ScopeKind.TENANT)
    rows = await session.scalars(
        select(TransferRecipient.id)
        .where(
            TransferRecipient.transfer_id == transfer_id,
            in_scope(TransferRecipient, session),
        )
        .order_by(TransferRecipient.id)
    )
    return list(rows)


async def queue_recipients(session: AsyncSession, transfer_id: UUID) -> int:
    """Set every recipient's `delivery_state` to `queued`: a link email is due (data model 2.2)."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        update(TransferRecipient)
        .where(
            TransferRecipient.transfer_id == transfer_id,
            in_scope(TransferRecipient, session),
        )
        .values(delivery_state=DeliveryState.QUEUED.value)
        .returning(TransferRecipient.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())


async def insert_download_counters(
    session: AsyncSession,
    *,
    recipient_ids: Sequence[UUID],
    file_ids: Sequence[UUID],
    download_limit: int | None,
) -> int:
    """One counter per recipient per file, with the transfer's limit copied (data model 2.3)."""
    require_scope(session, ScopeKind.TENANT)
    tenant_id = tenant_of(session)
    rows = [
        {
            "tenant_id": tenant_id,
            "recipient_id": recipient,
            "file_id": file,
            "download_limit": download_limit,
        }
        for recipient in recipient_ids
        for file in file_ids
    ]
    if rows:
        await session.execute(insert(DownloadCounter), rows)
    return len(rows)
