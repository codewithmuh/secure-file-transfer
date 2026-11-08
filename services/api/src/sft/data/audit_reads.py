"""Reading the tenant's audit log: the search and the export (#216; FR-28, FR-29, UC-4; data
model 2.5, 5).

`sft_api` reads `audit_events` in tenant scope only (revision 0002's `audit_tenant_read` policy),
and every query here also names the scope's tenant itself, the first isolation layer. Newest first,
by `(occurred_at, id)`, so a page continues exactly where the last one ended (`after`) even when
many events share a time. The per-partition indexes of data model 5 serve the filters: tenant and
time, tenant and actor, tenant and target.

**An email address** is matched by ID, never as text in the log: `people_with_email` finds the
users, recipients and upload requests (their uploaders, #212) of the tenant with that address,
and the filter then matches events whose actor or target is one of them: an uploader acts, and is
targeted, as its upload request's ID. Recipients' addresses leave with their transfer's metadata
(at most 365 days, data model 6), so an old event is found by ID after that, no longer by
address.

**A transfer as the target** (`target_type` `transfer` with its ID) also finds the events on its
files and recipients, such as `download.granted` on a file, so UC-4's "who downloaded the contract
we sent on Monday" is one filter.

`actor_emails` fills `actor_email` at read time for people still known: members and admins from
`users`, recipients from `transfer_recipients`, uploaders from `upload_requests`.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Final
from uuid import UUID

from sqlalchemy import ColumnElement, Select, and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import ActorType, AuditEvent, File, TransferRecipient, UploadRequest, User
from sft.data.scope import ScopeKind

__all__ = [
    "MAX_ACTIONS",
    "EventFilter",
    "EventRow",
    "actor_emails",
    "count_events",
    "people_with_email",
    "read_events",
]

MAX_ACTIONS: Final = 20
"""The contract's `AuditFilter.actions`: at most 20."""
_READS: Final = (ScopeKind.TENANT,)
TRANSFER: Final = "transfer"
"""`sft_api` reads the log in tenant scope only: never a link session's resource scope."""


@dataclass(frozen=True, slots=True)
class EventFilter:
    """The contract's `AuditFilter`, parsed. Every field is optional and they combine with AND.

    `people` is what an email address resolved to: None when no address was given, an empty set
    when it matched nobody (then nothing matches)."""

    occurred_after: datetime | None = None
    occurred_before: datetime | None = None
    actor_type: ActorType | None = None
    actor_id: UUID | None = None
    people: frozenset[UUID] | None = None
    actions: tuple[str, ...] = ()
    target_type: str | None = None
    target_id: UUID | None = None
    source_ip: IPv4Address | IPv6Address | None = None

    def fields(self) -> tuple[str, ...]:
        """Which filters are set, by the contract's names: what the audit record of a search
        holds instead of their values (T-47)."""
        named = {
            "occurred_after": self.occurred_after,
            "occurred_before": self.occurred_before,
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "email": self.people,
            "actions": self.actions or None,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "source_ip": self.source_ip,
        }
        return tuple(name for name, value in named.items() if value is not None)


@dataclass(frozen=True, slots=True)
class EventRow:
    """One event, as the contract's `AuditEvent` shows it, before `actor_email`."""

    id: UUID
    occurred_at: datetime
    actor_type: str
    actor_id: UUID | None
    action: str
    target_type: str | None
    target_id: UUID | None
    source_ip: IPv4Address | IPv6Address | None
    user_agent: str | None
    request_id: str | None
    security_critical: bool
    details: dict[str, Any]


_COLUMNS = (
    AuditEvent.id,
    AuditEvent.occurred_at,
    AuditEvent.actor_type,
    AuditEvent.actor_id,
    AuditEvent.action,
    AuditEvent.target_type,
    AuditEvent.target_id,
    AuditEvent.source_ip,
    AuditEvent.user_agent,
    AuditEvent.request_id,
    AuditEvent.security_critical,
    AuditEvent.details,
)


def _conditions(session: AsyncSession, events: EventFilter) -> list[ColumnElement[bool]]:
    conditions: list[ColumnElement[bool]] = [AuditEvent.tenant_id == tenant_of(session)]
    if events.occurred_after is not None:
        conditions.append(AuditEvent.occurred_at >= events.occurred_after)
    if events.occurred_before is not None:
        conditions.append(AuditEvent.occurred_at < events.occurred_before)
    if events.actor_type is not None:
        conditions.append(AuditEvent.actor_type == events.actor_type.value)
    if events.actor_id is not None:
        conditions.append(AuditEvent.actor_id == events.actor_id)
    if events.people is not None:
        people = list(events.people)
        conditions.append(
            or_(AuditEvent.actor_id.in_(people), AuditEvent.target_id.in_(people))
            if people
            else AuditEvent.id.is_(None)  # nobody has the address: nothing matches
        )
    if events.actions:
        conditions.append(AuditEvent.action.in_(list(events.actions)))
    if events.target_type == TRANSFER and events.target_id is not None:
        conditions.append(_transfer_and_its_parts(session, events.target_id))
    else:
        if events.target_type is not None:
            conditions.append(AuditEvent.target_type == events.target_type)
        if events.target_id is not None:
            conditions.append(AuditEvent.target_id == events.target_id)
    if events.source_ip is not None:
        conditions.append(AuditEvent.source_ip == events.source_ip)
    return conditions


def _transfer_and_its_parts(session: AsyncSession, transfer_id: UUID) -> ColumnElement[bool]:
    """Events on the transfer, its files and its recipients: a download is recorded on its file,
    an unlock on its recipient, so "this transfer" finds them too (UC-4)."""
    files = select(File.id).where(File.transfer_id == transfer_id, in_scope(File, session))
    recipients = select(TransferRecipient.id).where(
        TransferRecipient.transfer_id == transfer_id, in_scope(TransferRecipient, session)
    )
    return or_(
        and_(AuditEvent.target_type == TRANSFER, AuditEvent.target_id == transfer_id),
        and_(AuditEvent.target_type == "file", AuditEvent.target_id.in_(files)),
        and_(AuditEvent.target_type == "recipient", AuditEvent.target_id.in_(recipients)),
    )


def _query(
    session: AsyncSession,
    events: EventFilter,
    *,
    after: tuple[datetime, UUID] | None,
    until: datetime,
) -> Select[Any]:
    require_scope(session, *_READS)
    conditions = _conditions(session, events)
    # The read's upper bound: an export streams the log as it was when it began, so the events
    # written meanwhile (its own record among them) never shift its pages.
    conditions.append(AuditEvent.occurred_at <= until)
    if after is not None:
        at, last = after
        conditions.append(
            or_(
                AuditEvent.occurred_at < at,
                and_(AuditEvent.occurred_at == at, AuditEvent.id < last),
            )
        )
    return select(*_COLUMNS).where(and_(*conditions))


async def read_events(
    session: AsyncSession,
    events: EventFilter,
    *,
    after: tuple[datetime, UUID] | None,
    until: datetime,
    limit: int,
) -> list[EventRow]:
    """Up to `limit` of the scope's tenant's events that match, newest first, older than `after`
    (the last row of the previous page) and no newer than `until`."""
    statement = _query(session, events, after=after, until=until).order_by(
        AuditEvent.occurred_at.desc(), AuditEvent.id.desc()
    )
    rows = await session.execute(statement.limit(limit))
    return [
        EventRow(
            id=row[0],
            occurred_at=row[1],
            actor_type=row[2],
            actor_id=row[3],
            action=row[4],
            target_type=row[5],
            target_id=row[6],
            source_ip=row[7],
            user_agent=row[8],
            request_id=row[9],
            security_critical=bool(row[10]),
            details=dict(row[11] or {}),
        )
        for row in rows
    ]


async def count_events(
    session: AsyncSession, events: EventFilter, *, until: datetime, cap: int
) -> int:
    """How many events match, counted up to `cap` + 1, so an export too large stops early."""
    inner = _query(session, events, after=None, until=until).limit(cap + 1).subquery()
    value = await session.scalar(select(func.count()).select_from(inner))
    return int(value or 0)


async def people_with_email(session: AsyncSession, normalized: str) -> frozenset[UUID]:
    """The IDs of the scope's tenant's users, recipients and upload requests (their uploaders)
    with this lower-case address."""
    require_scope(session, *_READS)
    users = select(User.id).where(User.email_normalized == normalized, in_scope(User, session))
    recipients = select(TransferRecipient.id).where(
        TransferRecipient.email_normalized == normalized, in_scope(TransferRecipient, session)
    )
    uploaders = select(UploadRequest.id).where(
        UploadRequest.email_normalized == normalized, in_scope(UploadRequest, session)
    )
    rows = await session.scalars(users.union_all(recipients, uploaders))
    return frozenset(rows.all())


async def actor_emails(session: AsyncSession, rows: Sequence[EventRow]) -> dict[UUID, str]:
    """The address of each person who acted in `rows` and is still known, by actor ID."""
    require_scope(session, *_READS)
    people = _actors(rows, (ActorType.MEMBER, ActorType.ADMIN))
    recipients = _actors(rows, (ActorType.RECIPIENT,))
    uploaders = _actors(rows, (ActorType.UPLOADER,))
    found: dict[UUID, str] = {}
    if people:
        statement = select(User.id, User.email).where(User.id.in_(people), in_scope(User, session))
        found.update({row[0]: row[1] for row in await session.execute(statement)})
    if recipients:
        statement = select(TransferRecipient.id, TransferRecipient.email).where(
            TransferRecipient.id.in_(recipients), in_scope(TransferRecipient, session)
        )
        found.update({row[0]: row[1] for row in await session.execute(statement)})
    if uploaders:
        statement = select(UploadRequest.id, UploadRequest.uploader_email).where(
            UploadRequest.id.in_(uploaders), in_scope(UploadRequest, session)
        )
        found.update({row[0]: row[1] for row in await session.execute(statement)})
    return found


def _actors(rows: Sequence[EventRow], types: Collection[ActorType]) -> list[UUID]:
    wanted = {t.value for t in types}
    return list({r.actor_id for r in rows if r.actor_id is not None and r.actor_type in wanted})
