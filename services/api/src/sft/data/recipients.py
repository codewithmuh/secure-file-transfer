"""Data access for a recipient's link, delivery and lockout (data model 2.2, 2.4; #178, #179).

Every function filters with `in_scope` and runs in a tenant scope: the notification worker's, from
its message, or the API's, from the member, the API key or, on the link steps, the tenant the link
token's credential lookup found. No link session's resource scope reaches these writes.

- **The notification worker** (`sft_notify`) reads a recipient's address, locale, link and status
  with the transfer's owner, state and expiry, never a ciphertext column (revision 0012): so
  `link_target` names its columns. It sets the link once (`issue_link`, a conditional update, so a
  retry rebuilds the same token), and records where the email stands (`set_delivery`).
- **The link steps** (`sft_api`) find a recipient by the SHA-256 of its token through the
  credential lookup (`find_by_token`, lookup scope), then work in the tenant's scope: the lockout
  check takes the recipient's row lock (`lock_unlocked`), a failure counts with one conditional
  update that also locks at 20 (`count_failure`), and a match records the verification
  (`mark_verified`). Unlocking clears the link, so the worker derives a new one (`unlock`).

Every change here commits only with an audit event (`audit_required`); the caller writes it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy import Row, case, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import NotFoundError, in_scope, require_scope
from sft.data.models import (
    DeliveryState,
    DownloadCounter,
    LinkSession,
    Tenant,
    Transfer,
    TransferRecipient,
)
from sft.data.scope import ScopeKind

LOCKOUT_AFTER: Final = 20
"""Failed attempts in total before a recipient is locked until a member unlocks them (NFR-14)."""
IDLE: Final = text("interval '1 hour'")


def token_hash(token: str) -> bytes:
    """What `link_token_hash` holds: the SHA-256 of the token (data model 2.2)."""
    return hashlib.sha256(token.encode()).digest()


# ---- the notification worker ----


@dataclass(frozen=True, slots=True)
class LinkTarget:
    """What the link email needs: the recipient and their transfer, never the message."""

    id: UUID
    transfer_id: UUID
    email: str
    email_normalized: str
    locale: str
    delivery_state: DeliveryState
    notified_at: datetime | None
    link_key_id: str | None
    link_issued_at: datetime | None
    locked_at: datetime | None
    transfer_state: str
    expires_at: datetime | None
    owner_id: UUID


async def link_target(
    session: AsyncSession, recipient_id: UUID, *, lock: bool = False
) -> LinkTarget | None:
    """The recipient and their transfer, if the scope reaches them; `lock` takes the recipient's
    row lock, so two copies of one message don't issue or send at once."""
    require_scope(session, ScopeKind.TENANT)
    statement = (
        select(
            TransferRecipient.id,
            TransferRecipient.transfer_id,
            TransferRecipient.email,
            TransferRecipient.email_normalized,
            TransferRecipient.locale,
            TransferRecipient.delivery_state,
            TransferRecipient.notified_at,
            TransferRecipient.link_key_id,
            TransferRecipient.link_issued_at,
            TransferRecipient.locked_at,
            Transfer.state,
            Transfer.expires_at,
            Transfer.created_by,
        )
        .join(
            Transfer,
            (Transfer.tenant_id == TransferRecipient.tenant_id)
            & (Transfer.id == TransferRecipient.transfer_id),
        )
        .where(
            TransferRecipient.id == recipient_id,
            in_scope(TransferRecipient, session),
            in_scope(Transfer, session),
        )
    )
    if lock:
        statement = statement.with_for_update(of=TransferRecipient)
    row = (await session.execute(statement)).first()
    if row is None:
        return None
    return LinkTarget(
        id=row[0],
        transfer_id=row[1],
        email=row[2],
        email_normalized=row[3],
        locale=row[4],
        delivery_state=DeliveryState(row[5]),
        notified_at=row[6],
        link_key_id=row[7],
        link_issued_at=row[8],
        locked_at=row[9],
        transfer_state=row[10],
        expires_at=row[11],
        owner_id=row[12],
    )


async def issue_link(
    session: AsyncSession,
    recipient_id: UUID,
    *,
    key_id: str,
    issued_at: datetime,
    hashed: bytes,
    replace: bool = False,
) -> bool:
    """Set the recipient's link if it has none yet (or, with `replace`, whatever it had): False
    if another attempt set one first, whose token a retry then rebuilds (data model 2.2)."""
    require_scope(session, ScopeKind.TENANT)
    conditions = [TransferRecipient.id == recipient_id, in_scope(TransferRecipient, session)]
    if not replace:
        conditions.append(TransferRecipient.link_issued_at.is_(None))
    result = await session.execute(
        update(TransferRecipient)
        .where(*conditions)
        .values(link_issued_at=issued_at, link_key_id=key_id, link_token_hash=hashed)
        .returning(TransferRecipient.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def set_delivery(
    session: AsyncSession, recipient_id: UUID, state: DeliveryState, *, notified: bool = False
) -> None:
    """Record where the recipient's latest link email stands; `notified` sets `notified_at`."""
    require_scope(session, ScopeKind.TENANT)
    values: dict[str, object] = {"delivery_state": DeliveryState(state).value}
    if notified:
        values["notified_at"] = func.now()
    await session.execute(
        update(TransferRecipient)
        .where(TransferRecipient.id == recipient_id, in_scope(TransferRecipient, session))
        .values(**values)
        .execution_options(synchronize_session=False)
    )


# ---- the link steps ----


@dataclass(frozen=True, slots=True)
class FoundLink:
    """What the credential lookup returns for a link token: IDs only."""

    recipient_id: UUID
    tenant_id: UUID


async def find_by_token(session: AsyncSession, token: str) -> FoundLink | None:
    """The recipient whose link token this is, and its tenant: the credential lookup (data model
    4.2), in lookup scope. None for a token no live link has."""
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text("SELECT recipient_id, owner_tenant_id FROM lookup_link_token(:hash)"),
            {"hash": token_hash(token)},
        )
    ).first()
    return None if row is None else FoundLink(row[0], row[1])


@dataclass(frozen=True, slots=True)
class LinkView:
    """A recipient as the link steps see it, with their transfer and tenant."""

    id: UUID
    transfer_id: UUID
    email: str
    email_normalized: str
    locale: str
    link_issued_at: datetime | None
    failed_attempts: int
    locked_at: datetime | None
    transfer_state: str
    expires_at: datetime | None
    tenant_active: bool


async def link_view(session: AsyncSession, recipient_id: UUID) -> LinkView:
    """The recipient, their transfer and whether their tenant is active, or `NotFoundError`. In a
    tenant scope (the link steps) or the recipient's own resource scope (a link session)."""
    require_scope(session, ScopeKind.TENANT, ScopeKind.RESOURCE)
    row: Row[Any] | None = (
        await session.execute(
            select(
                TransferRecipient.id,
                TransferRecipient.transfer_id,
                TransferRecipient.email,
                TransferRecipient.email_normalized,
                TransferRecipient.locale,
                TransferRecipient.link_issued_at,
                TransferRecipient.failed_attempts,
                TransferRecipient.locked_at,
                Transfer.state,
                Transfer.expires_at,
                Tenant.status,
            )
            .join(
                Transfer,
                (Transfer.tenant_id == TransferRecipient.tenant_id)
                & (Transfer.id == TransferRecipient.transfer_id),
            )
            .join(Tenant, Tenant.id == TransferRecipient.tenant_id)
            .where(
                TransferRecipient.id == recipient_id,
                in_scope(TransferRecipient, session),
                in_scope(Transfer, session),
                in_scope(Tenant, session),
            )
        )
    ).first()
    if row is None:
        raise NotFoundError("recipient")
    return LinkView(
        id=row[0],
        transfer_id=row[1],
        email=row[2],
        email_normalized=row[3],
        locale=row[4],
        link_issued_at=row[5],
        failed_attempts=row[6],
        locked_at=row[7],
        transfer_state=row[8],
        expires_at=row[9],
        tenant_active=row[10] == "active",
    )


async def lock_unlocked(session: AsyncSession, recipient_id: UUID) -> bool:
    """Step 1 of a code check (data model 2.4): take the recipient's row lock, if they aren't
    locked. False means locked, and no code is checked. Parallel attempts queue on the lock."""
    require_scope(session, ScopeKind.TENANT)
    found = await session.scalar(
        select(TransferRecipient.id)
        .where(
            TransferRecipient.id == recipient_id,
            TransferRecipient.locked_at.is_(None),
            in_scope(TransferRecipient, session),
        )
        .with_for_update()
    )
    return found is not None


@dataclass(frozen=True, slots=True)
class Failure:
    failed_attempts: int
    locked: bool
    """This failure locked the recipient: the 20th."""


async def count_failure(session: AsyncSession, recipient_id: UUID) -> Failure:
    """Step 5 (data model 2.4): one more failed attempt, and the lock at the 20th, in one
    statement. The caller holds the row lock from `lock_unlocked`."""
    require_scope(session, ScopeKind.TENANT)
    after = TransferRecipient.failed_attempts + 1
    row = (
        await session.execute(
            update(TransferRecipient)
            .where(TransferRecipient.id == recipient_id, in_scope(TransferRecipient, session))
            .values(
                failed_attempts=after,
                locked_at=case(
                    (after >= LOCKOUT_AFTER, func.now()), else_=TransferRecipient.locked_at
                ),
            )
            .returning(TransferRecipient.failed_attempts, TransferRecipient.locked_at)
            .execution_options(synchronize_session=False)
        )
    ).first()
    if row is None:
        raise NotFoundError("recipient")
    return Failure(int(row[0]), row[1] is not None)


async def mark_verified(session: AsyncSession, recipient_id: UUID) -> None:
    """Step 4: the recipient proved their address (`first_verified_at` once, `last_verified_at`
    every time)."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(TransferRecipient)
        .where(TransferRecipient.id == recipient_id, in_scope(TransferRecipient, session))
        .values(
            first_verified_at=func.coalesce(TransferRecipient.first_verified_at, func.now()),
            last_verified_at=func.now(),
        )
        .execution_options(synchronize_session=False)
    )


# ---- status and unlock, for members ----


@dataclass(frozen=True, slots=True)
class Download:
    file_id: UUID
    count: int
    first_downloaded_at: datetime
    last_downloaded_at: datetime


@dataclass(frozen=True, slots=True)
class RecipientStatus:
    """A recipient's status as `listTransferRecipients` shows it (FR-7)."""

    id: UUID
    email: str
    locale: str
    delivery_state: DeliveryState
    notified_at: datetime | None
    first_verified_at: datetime | None
    last_verified_at: datetime | None
    failed_attempts: int
    locked_at: datetime | None
    verified: bool
    """A live link session exists for them."""
    downloads: Sequence[Download]


async def statuses(
    session: AsyncSession, transfer_id: UUID, recipient_id: UUID | None = None
) -> list[RecipientStatus]:
    """The status of every recipient of the transfer (or of one), ordered by ID."""
    require_scope(session, ScopeKind.TENANT)
    live = (
        select(LinkSession.id)
        .where(
            LinkSession.recipient_id == TransferRecipient.id,
            LinkSession.revoked_at.is_(None),
            LinkSession.expires_at > func.now(),
            LinkSession.last_seen_at > func.now() - IDLE,
            in_scope(LinkSession, session),
        )
        .exists()
    )
    statement = (
        select(TransferRecipient, live)
        .where(
            TransferRecipient.transfer_id == transfer_id,
            in_scope(TransferRecipient, session),
        )
        .order_by(TransferRecipient.id)
    )
    if recipient_id is not None:
        statement = statement.where(TransferRecipient.id == recipient_id)
    rows = (await session.execute(statement.execution_options(populate_existing=True))).all()
    ids = [row[0].id for row in rows]
    counted = await session.execute(
        select(
            DownloadCounter.recipient_id,
            DownloadCounter.file_id,
            DownloadCounter.count,
            DownloadCounter.first_downloaded_at,
            DownloadCounter.last_downloaded_at,
        )
        .where(
            DownloadCounter.recipient_id.in_(ids),
            DownloadCounter.count > 0,
            in_scope(DownloadCounter, session),
        )
        .order_by(DownloadCounter.file_id)
    )
    downloads: dict[UUID, list[Download]] = {}
    for recipient, file_id, count, first, last in counted:
        downloads.setdefault(recipient, []).append(Download(file_id, count, first, last))
    return [
        RecipientStatus(
            id=r.id,
            email=r.email,
            locale=r.locale,
            delivery_state=DeliveryState(r.delivery_state),
            notified_at=r.notified_at,
            first_verified_at=r.first_verified_at,
            last_verified_at=r.last_verified_at,
            failed_attempts=r.failed_attempts,
            locked_at=r.locked_at,
            verified=bool(verified),
            downloads=tuple(downloads.get(r.id, ())),
        )
        for r, verified in rows
    ]


async def lock_recipient(
    session: AsyncSession, transfer_id: UUID, recipient_id: UUID
) -> datetime | None:
    """Take the recipient's row lock; their `locked_at`. `NotFoundError` unless the scope reaches
    a recipient of that transfer."""
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            select(TransferRecipient.locked_at)
            .where(
                TransferRecipient.id == recipient_id,
                TransferRecipient.transfer_id == transfer_id,
                in_scope(TransferRecipient, session),
            )
            .with_for_update()
        )
    ).first()
    if row is None:
        raise NotFoundError("recipient")
    locked_at: datetime | None = row[0]
    return locked_at


async def unlock(session: AsyncSession, recipient_id: UUID, *, by: UUID) -> None:
    """Unlock and issue a new link (data model 2.4, authn and authz 4.4): reset the count, clear
    the lock and the whole link, so the worker derives a new token and the old one is `404`, and
    queue the email."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(TransferRecipient)
        .where(TransferRecipient.id == recipient_id, in_scope(TransferRecipient, session))
        .values(
            failed_attempts=0,
            locked_at=None,
            unlocked_by=by,
            link_token_hash=None,
            link_issued_at=None,
            link_key_id=None,
            delivery_state=DeliveryState.QUEUED.value,
            notified_at=None,
        )
        .execution_options(synchronize_session=False)
    )


@dataclass(frozen=True, slots=True)
class Counter:
    count: int
    download_limit: int | None


async def counters(session: AsyncSession, recipient_id: UUID) -> dict[UUID, Counter]:
    """The recipient's download count and limit for each file (data model 2.3), by file."""
    rows = await session.execute(
        select(
            DownloadCounter.file_id, DownloadCounter.count, DownloadCounter.download_limit
        ).where(DownloadCounter.recipient_id == recipient_id, in_scope(DownloadCounter, session))
    )
    return {file_id: Counter(count, limit) for file_id, count, limit in rows}
