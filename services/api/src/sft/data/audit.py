"""Writing audit events, inside the transaction of the change they describe (FR-27, NFR-15).

    async with database.transaction(Scope.tenant(tenant_id)) as session:
        await session.execute(update(Transfer).where(...).values(state="revoked"))
        await audit.record(
            session,
            action="transfer.revoked",
            actor=Actor(ActorType.MEMBER, user_id),
            target=Target("transfer", transfer_id),
            origin=Origin(source_ip=client_ip, user_agent=user_agent),
            security_critical=True,
        )
    # Committed together, or not at all. Without the record, the commit fails (audit_required).

The tenant comes from the transaction's scope, never from the caller: a tenant or resource scope
writes that tenant's event, platform scope a platform event with no tenant. The request and trace
IDs come from the log context (`sft.core.logs`). The database sets `tx_id` and `occurred_at`, so
code can't backdate an event or pin it on another transaction.

Nothing secret or personal beyond FR-27's fields goes in: `details` takes IDs, enums, numbers,
flags, times and an operator's name (`OperatorName`), never free text, so a file name, message,
email address, token or code can't reach it by accident (data model 2.5). Action names and
target types are short lower-case codes.

Security-critical events (architecture 5.2) are also written straight to the audit archive of both
regions (`sft.service.audit_archive`). `archived_event` and `latest_critical_event` read one back,
in the tenant's scope, as the archive record carries it (`ArchivedEvent`): IDs, enums, times and
`details`, never the source IP or the user agent.

Partition upkeep for the lifecycle job (data model 6) is here too: `create_partitions`,
`partition_status`, and the retention's `drop_expired_partitions` and `expired_partitions` (#255),
as `sft_jobs` in system scope.
"""

from __future__ import annotations

import re
import secrets
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum, IntEnum, StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any, Final

from sqlalchemy import Row, insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.logs import request_id_var, trace_id_var
from sft.data.access import require_scope
from sft.data.models import ActorType, AuditEvent, Outcome
from sft.data.scope import ScopeKind

USER_AGENT_MAX: Final = 512
"""Longer user agents are cut to this many characters; only the first part says anything."""

_ACTION = re.compile(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+")
_CODE = re.compile(r"[a-z][a-z_]*")
_CODE_MAX = 64
# C0 and C1 control characters and DEL. PostgreSQL text can't hold NUL, so one in a header would
# fail the insert, and with it the audited change; the others have no place in a log either.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

__all__ = [
    "USER_AGENT_MAX",
    "Actor",
    "ActorType",
    "ArchivedEvent",
    "Detail",
    "OperatorName",
    "Origin",
    "Outcome",
    "PartitionStatus",
    "Target",
    "archived_event",
    "create_partitions",
    "drop_expired_partitions",
    "expired_partitions",
    "latest_critical_event",
    "partition_status",
    "record",
    "uuid7",
]

# Tenant and resource scopes write their tenant's events; platform scope, events with no tenant.
_WRITES_EVENTS = (ScopeKind.TENANT, ScopeKind.RESOURCE, ScopeKind.PLATFORM)


@dataclass(frozen=True, slots=True)
class Actor:
    """The user, recipient, uploader, API key or operator session that acted, by ID.

    A system actor, a named job, has no ID; it names itself in `details`, with an enum.
    """

    type: ActorType
    id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.type, ActorType):
            raise TypeError("type must be an ActorType")
        if (self.type is ActorType.SYSTEM) != (self.id is None):
            raise ValueError("a system actor has no ID, and every other actor has one")
        if self.id is not None and not isinstance(self.id, uuid.UUID):
            raise TypeError("an actor's ID is a UUID")


@dataclass(frozen=True, slots=True)
class Target:
    """What was acted on, such as `Target("transfer", transfer_id)`. Referred to by ID only, with
    no foreign key, so the record outlives the row (data model 2)."""

    type: str
    id: uuid.UUID

    def __post_init__(self) -> None:
        _code("target type", self.type)
        if not isinstance(self.id, uuid.UUID):
            raise TypeError("a target's ID is a UUID")


@dataclass(frozen=True, slots=True)
class Origin:
    """Where a request came from (FR-27): the client IP from the trusted header (threat model
    T-04) and the user agent. Workers and jobs have none."""

    source_ip: IPv4Address | IPv6Address | None = None
    user_agent: str | None = None

    def __post_init__(self) -> None:
        if self.source_ip is not None and not isinstance(self.source_ip, IPv4Address | IPv6Address):
            raise TypeError("source_ip is an ipaddress address, parsed by the caller")


# An IAM role session name: what STS allows, 2 to 64 of these characters.
_ROLE_SESSION_NAME = re.compile(r"[\w+=,.@-]{2,64}", re.ASCII)


class OperatorName(str):
    """An operator's IAM Identity Center user name, the role session name STS returned.

    The one text value `details` takes (authentication and authorization 8.2): every operator
    event names the person, because the operator session it refers to is deleted after a day.
    It is an identifier STS checked, never text from a request.
    """

    __slots__ = ()

    def __new__(cls, value: str) -> OperatorName:
        if not isinstance(value, str) or not _ROLE_SESSION_NAME.fullmatch(value):
            raise ValueError("an operator name is an IAM role session name")
        return super().__new__(cls, value)


Detail = uuid.UUID | int | bool | datetime | StrEnum | IntEnum | OperatorName | None
"""A value in `details`: an ID, a `StrEnum` or `IntEnum` member, a number, a flag, a time or an
operator's name. Never free text."""


@dataclass(frozen=True, slots=True)
class PartitionStatus:
    """What the audit partition alerts watch (data model 6)."""

    default_rows: int
    """Rows in the default partition: their month had no partition. Should be 0."""
    months_covered: int
    """Months from this one on with a partition, without a gap. 4 after the job has run."""
    blocked: tuple[str, ...] = field(default=())
    """Partitions `create_partitions` couldn't create, because the default partition holds rows
    for their month."""
    failed: tuple[str, ...] = field(default=())
    """Partitions `create_partitions` couldn't create for another reason, such as a lock timeout;
    the database's log has the error. The next run tries again."""
    expired: int = 0
    """Monthly partitions past the 365-day retention still there (NFR-9, #255). Should be 0."""
    dropped: tuple[str, ...] = field(default=())
    """Partitions `drop_expired_partitions` dropped in this run."""
    unarchived: tuple[str, ...] = field(default=())
    """Expired partitions kept because a row isn't archived in both regions yet."""
    drop_failed: tuple[str, ...] = field(default=())
    """Expired partitions that couldn't be locked or dropped; the next run tries again."""


async def record(
    session: AsyncSession,
    *,
    action: str,
    actor: Actor,
    target: Target | None = None,
    outcome: Outcome = Outcome.SUCCESS,
    origin: Origin | None = None,
    security_critical: bool = False,
    details: Mapping[str, Detail] | None = None,
) -> uuid.UUID:
    """Insert one audit event in `session`'s transaction and return its ID.

    `action` is a dotted lower-case code, such as `transfer.revoked`. `security_critical` marks
    the records of architecture 5.2, which the caller also writes to the archive in both regions.
    """
    _action(action)
    if not isinstance(actor, Actor):
        raise TypeError("actor must be an Actor")
    # System scope finds work and acts on each item in that item's tenant scope (data model 4.2);
    # lookup and recovery scopes write no events through this function.
    scope = require_scope(session, *_WRITES_EVENTS)
    origin = origin or Origin()
    event_id = uuid7()
    await session.execute(
        insert(AuditEvent).values(
            id=event_id,
            tenant_id=scope.tenant_id,
            actor_type=actor.type.value,
            actor_id=actor.id,
            action=action,
            target_type=None if target is None else target.type,
            target_id=None if target is None else target.id,
            outcome=Outcome(outcome).value,
            source_ip=origin.source_ip,
            user_agent=_user_agent(origin.user_agent),
            request_id=request_id_var.get(),
            trace_id=trace_id_var.get(),
            security_critical=bool(security_critical),
            details=_details(details or {}),
        )
    )
    return event_id


@dataclass(frozen=True, slots=True)
class ArchivedEvent:
    """A security-critical event as its archive record holds it (#177): only IDs, enums, times and
    `details`, which holds nothing else (data model 2.5). No source IP, user agent or request ID:
    what the failover and restore runbooks re-apply needs none of them, and the archive job's
    copy of the row carries them (architecture 5.2)."""

    id: uuid.UUID
    tenant_id: uuid.UUID | None
    occurred_at: datetime
    action: str
    actor_type: str
    actor_id: uuid.UUID | None
    target_type: str | None
    target_id: uuid.UUID | None
    outcome: str
    details: Mapping[str, object] = field(default_factory=dict)

    def as_json(self) -> dict[str, object]:
        """The record's JSON object, its keys sorted when serialised."""
        return {
            "id": str(self.id),
            "tenant_id": None if self.tenant_id is None else str(self.tenant_id),
            "occurred_at": self.occurred_at.isoformat(),
            "action": self.action,
            "actor_type": self.actor_type,
            "actor_id": None if self.actor_id is None else str(self.actor_id),
            "target_type": self.target_type,
            "target_id": None if self.target_id is None else str(self.target_id),
            "outcome": self.outcome,
            "security_critical": True,
            "details": dict(self.details),
        }


_ARCHIVED_COLUMNS = (
    AuditEvent.id,
    AuditEvent.tenant_id,
    AuditEvent.occurred_at,
    AuditEvent.action,
    AuditEvent.actor_type,
    AuditEvent.actor_id,
    AuditEvent.target_type,
    AuditEvent.target_id,
    AuditEvent.outcome,
    AuditEvent.details,
)


def _archived(row: Row[Any]) -> ArchivedEvent:
    return ArchivedEvent(
        id=row[0],
        tenant_id=row[1],
        occurred_at=row[2],
        action=row[3],
        actor_type=row[4],
        actor_id=row[5],
        target_type=row[6],
        target_id=row[7],
        outcome=row[8],
        details=dict(row[9] or {}),
    )


async def archived_event(session: AsyncSession, event_id: uuid.UUID) -> ArchivedEvent | None:
    """One security-critical event of the scope's tenant, as its archive record holds it. The
    transaction that wrote it sees it before it commits."""
    scope = require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            select(*_ARCHIVED_COLUMNS).where(
                AuditEvent.id == event_id,
                AuditEvent.tenant_id == scope.tenant_id,
                AuditEvent.security_critical.is_(True),
            )
        )
    ).first()
    return None if row is None else _archived(row)


async def latest_critical_event(
    session: AsyncSession, *, action: str, target: Target
) -> ArchivedEvent | None:
    """The newest security-critical `action` event on `target` in the scope's tenant: what a
    retry of a change already made writes to the archive if it is still missing (API README 5)."""
    _action(action)
    scope = require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            select(*_ARCHIVED_COLUMNS)
            .where(
                AuditEvent.tenant_id == scope.tenant_id,
                AuditEvent.target_type == target.type,
                AuditEvent.target_id == target.id,
                AuditEvent.action == action,
                AuditEvent.security_critical.is_(True),
            )
            .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc())
            .limit(1)
        )
    ).first()
    return None if row is None else _archived(row)


async def create_partitions(
    session: AsyncSession, months_ahead: int = 3, from_month: date | None = None
) -> dict[str, str]:
    """Create the missing monthly partitions, `from_month` (default: this month) through
    `months_ahead` months after this one.

    Returns each partition's name with `created`, `exists`, `blocked` or `failed`. A blocked month
    has rows in the default partition; an operator moves them before its partition can exist. A
    failed month, on a lock timeout say, is tried again by the next run; the months after it are
    still made. An empty result means another run holds the lock and is doing the same work.
    The restore and failover runbooks pass `from_month`, the month of the oldest event they
    re-import, as `sft_recovery` (data model 6).
    """
    rows = await session.execute(
        text("SELECT partition_name, status FROM audit_create_partitions(:months, :from_month)"),
        {"months": months_ahead, "from_month": from_month},
    )
    return {name: status for name, status in rows.tuples()}


async def drop_expired_partitions(
    session: AsyncSession, as_of: datetime | None = None
) -> dict[str, str]:
    """Drop the monthly partitions past the 365-day retention (NFR-9, #255, revision 0040): each
    expired month's name with `dropped`, `unarchived` (kept: a row isn't in both regions' archive
    yet) or `failed` (kept: a lock or the drop failed). A month expires when its end is 365 days
    before `as_of`, the jobs' clock; a time later than the database's own counts as the
    database's, so the clock can never drop a month early. An empty result means another run
    holds the partition lock, or nothing has expired."""
    rows = await session.execute(
        text("SELECT partition_name, status FROM audit_drop_expired_partitions(:as_of)"),
        {"as_of": as_of},
    )
    return {name: status for name, status in rows.tuples()}


async def expired_partitions(session: AsyncSession, as_of: datetime | None = None) -> int:
    """How many monthly partitions past the retention are still there, by the same rule."""
    count = await session.scalar(text("SELECT audit_expired_partitions(:as_of)"), {"as_of": as_of})
    return int(count or 0)


async def partition_status(session: AsyncSession) -> PartitionStatus:
    row = (
        await session.execute(
            text("SELECT default_rows, months_covered FROM audit_partition_status()")
        )
    ).one()
    return PartitionStatus(default_rows=row.default_rows, months_covered=row.months_covered)


def uuid7() -> uuid.UUID:
    """A UUIDv7 (RFC 9562): 48 bits of Unix milliseconds, then 74 random bits (data model 1)."""
    millis = time.time_ns() // 1_000_000
    rand = secrets.randbits(74)
    value = (
        (millis & (2**48 - 1)) << 80
        | 0x7 << 76
        | (rand >> 62) << 64
        | 0b10 << 62
        | (rand & (2**62 - 1))
    )
    return uuid.UUID(int=value)


def _user_agent(value: str | None) -> str | None:
    """The user agent without control characters, cut to `USER_AGENT_MAX`; None if none is left."""
    if value is None:
        return None
    cleaned = _CONTROL.sub("", value)[:USER_AGENT_MAX]
    return cleaned or None


def _code(what: str, value: object) -> None:
    if not isinstance(value, str) or len(value) > _CODE_MAX or not _CODE.fullmatch(value):
        raise ValueError(f"{what} must be a lower-case code like 'transfer', not {value!r}")


def _action(value: object) -> None:
    if not isinstance(value, str) or len(value) > _CODE_MAX or not _ACTION.fullmatch(value):
        raise ValueError(
            f"action must be a dotted lower-case code like 'transfer.revoked', not {value!r}"
        )


def _details(details: Mapping[str, Detail]) -> dict[str, object]:
    """`details` as JSON values, refusing anything that could carry free text."""
    out: dict[str, object] = {}
    for key, value in details.items():
        _code("a details key", key)
        if isinstance(value, StrEnum | IntEnum):
            out[key] = value.value
        elif isinstance(value, OperatorName):
            out[key] = str(value)
        elif isinstance(value, Enum):
            raise TypeError(
                f"details[{key!r}] is a {type(value).__name__}: use a StrEnum or IntEnum"
            )
        elif value is None or isinstance(value, bool | int):
            out[key] = value
        elif isinstance(value, uuid.UUID):
            out[key] = str(value)
        elif isinstance(value, datetime):
            if value.tzinfo is None:
                raise ValueError(f"details[{key!r}] must be an aware datetime")
            out[key] = value.isoformat()
        else:
            raise TypeError(
                f"details[{key!r}] is a {type(value).__name__}: use an ID, enum, number, flag or "
                "time, never free text (data model 2.5)"
            )
    return out
