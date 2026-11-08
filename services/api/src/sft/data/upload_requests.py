"""Data access for `upload_requests`: a member's request for files, and its uploader's link,
delivery and lockout (data model 2.2, 2.4, 3.3; #212).

Every function filters with `in_scope`, and every write takes its tenant from the transaction's
scope (`tenant_of`), never from an argument. State rules and permissions are the service layer's
(`sft.service.upload_requests`, `sft.service.links`); these functions only read and write rows. A
row the scope doesn't reach is `NotFoundError`.

- **Members and API keys** (`sft_api`, tenant scope) create, read, list, revoke and unlock
  requests (`insert_request`, `get_request`, `list_requests`, `live_session_ids`,
  `change_state`, `unlock`).
- **The link steps** (`sft_api`) find a request by its token through the credential lookup
  (`sft.data.link_subjects`), then work in the tenant's scope as for a recipient: the lockout check
  takes the request's row lock (`lock_unlocked`), a failure counts with one conditional update
  that also locks at 20 (`count_failure`). `link_view` is readable in the uploader's own resource
  scope too, which is how a link session sees its request.
- **The notification worker** (`sft_notify`) reads the uploader's address, locale, link and
  status with the request's owner, state and expiry, never `message_ct` (revision 0019): so
  `link_target` names its columns. It sets the link once (`issue_link`) and records where the
  email stands (`set_delivery`).
- **The expiry job** (`sft_jobs`) finds open requests past `expires_at` across tenants in system
  scope (`due_for_expiry`), then locks and expires each in its tenant's scope (`lock_for_expiry`,
  `change_state`). Its role reads only the columns those name.
- **The batched notices of received files** (#213, architecture 4.3, revision 0020). A scan result
  of a received file adds one to the request's shareable or blocked count and, if no notice is due
  yet, makes one due in 5 minutes (`note_settled`): its caller writes the one delayed outbox
  message, so the request is the dedup key. The scan worker (`sft_scan`) and the jobs (`sft_jobs`,
  the scan sweep and a completion over 2 GB) do this. The notification worker reads the counts
  under the row lock (`notice`) and, once its emails are out, takes off what it sent
  (`settle_notice`); counts that arrived meanwhile make the next notice due.

Every change here commits only with an audit event (`audit_required`); the caller writes it.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Final
from uuid import UUID

from sqlalchemy import ColumnElement, and_, case, func, insert, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import NotFoundError, in_scope, require_scope, tenant_of
from sft.data.models import (
    DeliveryState,
    LinkSession,
    Tenant,
    UploadRequest,
    UploadRequestState,
)
from sft.data.recipients import IDLE, LOCKOUT_AFTER
from sft.data.scope import ScopeKind

TARGET: Final = "upload_request"
"""The audit target and idempotency resource type of a request (and of its uploader)."""


# ---- members and API keys ----


async def insert_request(
    session: AsyncSession,
    *,
    request_id: UUID,
    created_by: UUID,
    email: str,
    locale: str,
    message_ct: bytes | None,
    expires_at: datetime,
) -> UploadRequest:
    """A new `open` request of the scope's tenant, owned by `created_by`, its link email `queued`
    (data model 2.2: a request is open, and its email due, from creation)."""
    require_scope(session, ScopeKind.TENANT)
    row: UploadRequest | None = await session.scalar(
        insert(UploadRequest)
        .values(
            id=request_id,
            tenant_id=tenant_of(session),
            created_by=created_by,
            state=UploadRequestState.OPEN.value,
            uploader_email=email,
            email_normalized=email.lower(),
            locale=locale,
            message_ct=message_ct,
            expires_at=expires_at,
            delivery_state=DeliveryState.QUEUED.value,
        )
        .returning(UploadRequest)
    )
    if row is None:  # pragma: no cover - INSERT … RETURNING always returns the row
        raise RuntimeError("the insert returned no row")
    return row


async def get_request(
    session: AsyncSession, request_id: UUID, *, lock: bool = False
) -> UploadRequest:
    """The request, if the scope reaches it; `lock` takes its row lock (`FOR UPDATE`), which a
    revocation, an unlock and the expiry job hold while they re-check it."""
    statement = select(UploadRequest).where(
        UploadRequest.id == request_id, in_scope(UploadRequest, session)
    )
    if lock:
        statement = statement.with_for_update()
    row: UploadRequest | None = await session.scalar(
        statement.execution_options(populate_existing=True)
    )
    if row is None:
        raise NotFoundError("upload request")
    return row


EXPIRES_FROM: Final = frozenset({UploadRequestState.OPEN})
"""The states a request leaves for `expired` once `expires_at` passes (data model 3.3)."""


def _shows_as(state: UploadRequestState, now: datetime) -> ColumnElement[bool]:
    """Rows the API shows in `state` at `now`: expiry is read from `expires_at`, before the job
    records it, so `expired` takes the open rows past it and `open` loses them."""
    if state is UploadRequestState.EXPIRED:
        return or_(
            UploadRequest.state == state.value,
            and_(
                UploadRequest.state == UploadRequestState.OPEN.value,
                UploadRequest.expires_at <= now,
            ),
        )
    if state is UploadRequestState.OPEN:
        return and_(UploadRequest.state == state.value, UploadRequest.expires_at > now)
    return UploadRequest.state == state.value


async def list_requests(
    session: AsyncSession,
    *,
    created_by: UUID | None,
    states: Collection[UploadRequestState] = (),
    before: UUID | None = None,
    limit: int,
    now: datetime,
) -> list[UploadRequest]:
    """Up to `limit` requests of the scope's tenant, newest first, before the request `before`;
    only `created_by`'s if given, and only those that show in one of `states` at `now`."""
    require_scope(session, ScopeKind.TENANT)
    statement = (
        select(UploadRequest)
        .where(in_scope(UploadRequest, session))
        .order_by(UploadRequest.id.desc())
        .limit(limit)
    )
    if created_by is not None:
        statement = statement.where(UploadRequest.created_by == created_by)
    if states:
        statement = statement.where(or_(*(_shows_as(state, now) for state in states)))
    if before is not None:
        statement = statement.where(UploadRequest.id < before)
    return list(await session.scalars(statement.execution_options(populate_existing=True)))


async def live_session_ids(session: AsyncSession, request_ids: Sequence[UUID]) -> set[UUID]:
    """The requests among `request_ids` whose uploader holds a live link session: not revoked,
    not past its expiry, seen in the last hour (the access state `verified`, data model 3.4)."""
    if not request_ids:
        return set()
    now = func.now()
    rows = await session.scalars(
        select(LinkSession.upload_request_id)
        .where(
            LinkSession.upload_request_id.in_(request_ids),
            LinkSession.revoked_at.is_(None),
            LinkSession.expires_at > now,
            LinkSession.last_seen_at > now - IDLE,
            in_scope(LinkSession, session),
        )
        .distinct()
    )
    return {found for found in rows if found is not None}


async def change_state(
    session: AsyncSession,
    request_id: UUID,
    *,
    from_states: Collection[UploadRequestState],
    to: UploadRequestState,
    **values: Any,
) -> bool:
    """Move the request to `to` if it is in one of `from_states`, setting `values` too; False if
    it wasn't. The caller holds the row lock and writes the audit event."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        update(UploadRequest)
        .where(
            UploadRequest.id == request_id,
            UploadRequest.state.in_([s.value for s in from_states]),
            in_scope(UploadRequest, session),
        )
        .values(state=to.value, **values)
        .returning(UploadRequest.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def unlock(session: AsyncSession, request_id: UUID, *, by: UUID) -> None:
    """Unlock the uploader and issue a new link (data model 2.4, authn and authz 4.4): reset the
    count, clear the lock and the whole link, so the worker derives a new token and the old one is
    `404`, and queue the email."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(UploadRequest)
        .where(UploadRequest.id == request_id, in_scope(UploadRequest, session))
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


# ---- the link steps ----


@dataclass(frozen=True, slots=True)
class LinkView:
    """A request as the link steps and its link session see it, with whether its tenant is
    active. No message: `get_request` reads that, in the uploader's resource scope."""

    id: UUID
    created_by: UUID
    state: UploadRequestState
    email: str
    email_normalized: str
    locale: str
    expires_at: datetime
    link_issued_at: datetime | None
    failed_attempts: int
    locked_at: datetime | None
    tenant_active: bool


async def link_view(session: AsyncSession, request_id: UUID) -> LinkView:
    """The request and whether its tenant is active, or `NotFoundError`. In a tenant scope (the
    link steps) or the uploader's own resource scope (a link session)."""
    require_scope(session, ScopeKind.TENANT, ScopeKind.RESOURCE)
    row = (
        await session.execute(
            select(
                UploadRequest.id,
                UploadRequest.created_by,
                UploadRequest.state,
                UploadRequest.uploader_email,
                UploadRequest.email_normalized,
                UploadRequest.locale,
                UploadRequest.expires_at,
                UploadRequest.link_issued_at,
                UploadRequest.failed_attempts,
                UploadRequest.locked_at,
                Tenant.status,
            )
            .join(Tenant, Tenant.id == UploadRequest.tenant_id)
            .where(
                UploadRequest.id == request_id,
                in_scope(UploadRequest, session),
                in_scope(Tenant, session),
            )
        )
    ).first()
    if row is None:
        raise NotFoundError("upload request")
    return LinkView(
        id=row[0],
        created_by=row[1],
        state=UploadRequestState(row[2]),
        email=row[3],
        email_normalized=row[4],
        locale=row[5],
        expires_at=row[6],
        link_issued_at=row[7],
        failed_attempts=row[8],
        locked_at=row[9],
        tenant_active=row[10] == "active",
    )


async def lock_unlocked(session: AsyncSession, request_id: UUID) -> bool:
    """Step 1 of a code check (data model 2.4): take the request's row lock, if its uploader isn't
    locked. False means locked, and no code is checked. Parallel attempts queue on the lock."""
    require_scope(session, ScopeKind.TENANT)
    found = await session.scalar(
        select(UploadRequest.id)
        .where(
            UploadRequest.id == request_id,
            UploadRequest.locked_at.is_(None),
            in_scope(UploadRequest, session),
        )
        .with_for_update()
    )
    return found is not None


@dataclass(frozen=True, slots=True)
class Failure:
    failed_attempts: int
    locked: bool
    """This failure locked the uploader: the 20th."""


async def count_failure(session: AsyncSession, request_id: UUID) -> Failure:
    """Step 5 (data model 2.4): one more failed attempt, and the lock at the 20th, in one
    statement. The caller holds the row lock from `lock_unlocked`."""
    require_scope(session, ScopeKind.TENANT)
    after = UploadRequest.failed_attempts + 1
    row = (
        await session.execute(
            update(UploadRequest)
            .where(UploadRequest.id == request_id, in_scope(UploadRequest, session))
            .values(
                failed_attempts=after,
                locked_at=case((after >= LOCKOUT_AFTER, func.now()), else_=UploadRequest.locked_at),
            )
            .returning(UploadRequest.failed_attempts, UploadRequest.locked_at)
            .execution_options(synchronize_session=False)
        )
    ).first()
    if row is None:
        raise NotFoundError("upload request")
    return Failure(int(row[0]), row[1] is not None)


# ---- the notification worker ----


@dataclass(frozen=True, slots=True)
class LinkTarget:
    """What the uploader's emails need: the request's address, link and status, never its
    message."""

    id: UUID
    created_by: UUID
    state: UploadRequestState
    email: str
    email_normalized: str
    locale: str
    expires_at: datetime
    delivery_state: DeliveryState
    notified_at: datetime | None
    link_key_id: str | None
    link_issued_at: datetime | None
    locked_at: datetime | None


async def link_target(
    session: AsyncSession, request_id: UUID, *, lock: bool = False
) -> LinkTarget | None:
    """The request, if the scope reaches it; `lock` takes its row lock, so two copies of one
    message don't issue or send at once."""
    require_scope(session, ScopeKind.TENANT)
    statement = select(
        UploadRequest.id,
        UploadRequest.created_by,
        UploadRequest.state,
        UploadRequest.uploader_email,
        UploadRequest.email_normalized,
        UploadRequest.locale,
        UploadRequest.expires_at,
        UploadRequest.delivery_state,
        UploadRequest.notified_at,
        UploadRequest.link_key_id,
        UploadRequest.link_issued_at,
        UploadRequest.locked_at,
    ).where(UploadRequest.id == request_id, in_scope(UploadRequest, session))
    if lock:
        statement = statement.with_for_update()
    row = (await session.execute(statement)).first()
    if row is None:
        return None
    return LinkTarget(
        id=row[0],
        created_by=row[1],
        state=UploadRequestState(row[2]),
        email=row[3],
        email_normalized=row[4],
        locale=row[5],
        expires_at=row[6],
        delivery_state=DeliveryState(row[7]),
        notified_at=row[8],
        link_key_id=row[9],
        link_issued_at=row[10],
        locked_at=row[11],
    )


async def issue_link(
    session: AsyncSession,
    request_id: UUID,
    *,
    key_id: str,
    issued_at: datetime,
    hashed: bytes,
    replace: bool = False,
) -> bool:
    """Set the uploader's link if it has none yet (or, with `replace`, whatever it had): False if
    another attempt set one first, whose token a retry then rebuilds (data model 2.2)."""
    require_scope(session, ScopeKind.TENANT)
    conditions = [UploadRequest.id == request_id, in_scope(UploadRequest, session)]
    if not replace:
        conditions.append(UploadRequest.link_issued_at.is_(None))
    result = await session.execute(
        update(UploadRequest)
        .where(*conditions)
        .values(link_issued_at=issued_at, link_key_id=key_id, link_token_hash=hashed)
        .returning(UploadRequest.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def set_delivery(
    session: AsyncSession, request_id: UUID, state: DeliveryState, *, notified: bool = False
) -> None:
    """Record where the uploader's latest link email stands; `notified` sets `notified_at`."""
    require_scope(session, ScopeKind.TENANT)
    values: dict[str, object] = {"delivery_state": DeliveryState(state).value}
    if notified:
        values["notified_at"] = func.now()
    await session.execute(
        update(UploadRequest)
        .where(UploadRequest.id == request_id, in_scope(UploadRequest, session))
        .values(**values)
        .execution_options(synchronize_session=False)
    )


# ---- the expiry job (sft_jobs, data model 3.3, 6) ----


@dataclass(frozen=True, slots=True)
class Due:
    tenant_id: UUID
    request_id: UUID


async def due_for_expiry(session: AsyncSession, *, now: datetime, limit: int) -> list[Due]:
    """Open requests past `expires_at`, across tenants: the expiry job's find step, in system
    scope, by the partial index on open requests (data model 5)."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.execute(
        select(UploadRequest.tenant_id, UploadRequest.id)
        .where(
            UploadRequest.state == UploadRequestState.OPEN.value,
            UploadRequest.expires_at <= now,
            in_scope(UploadRequest, session),
        )
        .order_by(UploadRequest.expires_at)
        .limit(limit)
    )
    return [Due(r.tenant_id, r.id) for r in rows]


@dataclass(frozen=True, slots=True)
class Expiring:
    """The columns of a request the expiry job reads, under its row lock."""

    id: UUID
    state: UploadRequestState
    expires_at: datetime


async def lock_for_expiry(session: AsyncSession, request_id: UUID) -> Expiring:
    """Take the request's row lock and read what the expiry job needs, or `NotFoundError`."""
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            select(UploadRequest.id, UploadRequest.state, UploadRequest.expires_at)
            .where(UploadRequest.id == request_id, in_scope(UploadRequest, session))
            .with_for_update()
        )
    ).first()
    if row is None:
        raise NotFoundError("upload request")
    return Expiring(row[0], UploadRequestState(row[1]), row[2])


# ---- the batched notices of received files (#213, architecture 4.3) ----

NOTICE_WINDOW: Final = timedelta(minutes=5)
"""One notice per request per window: the delay of its outbox message."""
NOTICE_STALE: Final = timedelta(minutes=15)
"""A notice still due this long after its time lost its message (a suspended tenant's, say): the
next result makes a new one due rather than wait for it for good."""


async def note_settled(session: AsyncSession, request_id: UUID, *, shareable: bool) -> bool:
    """One received file of the request settled, shareable or blocked: count it towards the next
    notice, and make that notice due in `NOTICE_WINDOW` if none is due yet. True when this call
    made it due, and its caller writes the notice's delayed outbox message in the same
    transaction; False when a notice is due already, whose message carries this file too. One
    statement under the row's lock, so two results at once make one notice."""
    require_scope(session, ScopeKind.TENANT)
    now = func.now()
    fresh = or_(
        UploadRequest.notice_due_at.is_(None), UploadRequest.notice_due_at < now - NOTICE_STALE
    )
    counter = "arrived_since_notice" if shareable else "blocked_since_notice"
    made: bool | None = await session.scalar(
        update(UploadRequest)
        .where(UploadRequest.id == request_id, in_scope(UploadRequest, session))
        .values(
            {
                counter: getattr(UploadRequest, counter) + 1,
                "notice_due_at": case(
                    (fresh, now + NOTICE_WINDOW), else_=UploadRequest.notice_due_at
                ),
            }
        )
        .returning(UploadRequest.notice_due_at == now + NOTICE_WINDOW)
        .execution_options(synchronize_session=False)
    )
    return bool(made)


@dataclass(frozen=True, slots=True)
class Notice:
    """What the notification worker needs for a request's notice: the counts, the owner and the
    uploader's address and language, never the message."""

    id: UUID
    created_by: UUID
    email: str
    email_normalized: str
    locale: str
    arrived: int
    blocked: int


async def notice(session: AsyncSession, request_id: UUID, *, lock: bool = False) -> Notice | None:
    """The request's notice counts, if the scope reaches it; `lock` takes its row lock, so two
    copies of one message don't send at once."""
    require_scope(session, ScopeKind.TENANT)
    statement = select(
        UploadRequest.id,
        UploadRequest.created_by,
        UploadRequest.uploader_email,
        UploadRequest.email_normalized,
        UploadRequest.locale,
        UploadRequest.arrived_since_notice,
        UploadRequest.blocked_since_notice,
    ).where(UploadRequest.id == request_id, in_scope(UploadRequest, session))
    if lock:
        statement = statement.with_for_update()
    row = (await session.execute(statement)).first()
    if row is None:
        return None
    return Notice(row[0], row[1], row[2], row[3], row[4], int(row[5]), int(row[6]))


async def settle_notice(
    session: AsyncSession, request_id: UUID, *, arrived: int, blocked: int
) -> bool:
    """The notice of `arrived` and `blocked` files went out: take them off. True when files
    settled meanwhile, so the next notice is due in `NOTICE_WINDOW` and the caller writes its
    message; False when nothing is left, and no notice is due."""
    require_scope(session, ScopeKind.TENANT)
    left_arrived = func.greatest(0, UploadRequest.arrived_since_notice - arrived)
    left_blocked = func.greatest(0, UploadRequest.blocked_since_notice - blocked)
    more: bool | None = await session.scalar(
        update(UploadRequest)
        .where(UploadRequest.id == request_id, in_scope(UploadRequest, session))
        .values(
            arrived_since_notice=left_arrived,
            blocked_since_notice=left_blocked,
            notice_due_at=case(
                (or_(left_arrived > 0, left_blocked > 0), func.now() + NOTICE_WINDOW), else_=None
            ),
        )
        .returning(UploadRequest.notice_due_at.is_not(None))
        .execution_options(synchronize_session=False)
    )
    return bool(more)
