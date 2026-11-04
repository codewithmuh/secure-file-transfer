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
flags and times, never free text, so a file name, message, email address, token or code can't
reach it by accident (data model 2.5). Action names and target types are short lower-case codes.

Partition upkeep for the lifecycle job (data model 6) is here too: `create_partitions` and
`partition_status`, as `sft_jobs` in system scope.
"""

from __future__ import annotations

import re
import secrets
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Final

from sqlalchemy import insert, text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.logs import request_id_var, trace_id_var
from sft.data.models import AuditEvent
from sft.data.scope import Scope, ScopeKind

USER_AGENT_MAX: Final = 512
"""Longer user agents are cut to this many characters; only the first part says anything."""

_ACTION = re.compile(r"[a-z][a-z_]*(\.[a-z][a-z_]*)+")
_CODE = re.compile(r"[a-z][a-z_]*")
_CODE_MAX = 64

# Tenant and resource scopes write their tenant's events; platform scope, events with no tenant.
_WRITES_EVENTS = frozenset({ScopeKind.TENANT, ScopeKind.RESOURCE, ScopeKind.PLATFORM})


class ActorType(StrEnum):
    """Who acted (data model 2.5)."""

    MEMBER = "member"
    ADMIN = "admin"
    RECIPIENT = "recipient"
    UPLOADER = "uploader"
    API_KEY = "api_key"
    OPERATOR = "operator"
    SYSTEM = "system"


class Outcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


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


Detail = uuid.UUID | int | bool | datetime | StrEnum | None
"""A value in `details`: an ID, an enum, a number, a flag or a time. Never free text."""


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
    scope = session.info.get("scope")
    if not isinstance(scope, Scope) or scope.kind not in _WRITES_EVENTS:
        # System scope finds work and acts on each item in that item's tenant scope (data model
        # 4.2); lookup and recovery scopes write no events through this function.
        raise ValueError("audit events are written in a tenant, resource or platform scope")
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
            user_agent=None if origin.user_agent is None else origin.user_agent[:USER_AGENT_MAX],
            request_id=request_id_var.get(),
            trace_id=trace_id_var.get(),
            security_critical=bool(security_critical),
            details=_details(details or {}),
        )
    )
    return event_id


async def create_partitions(session: AsyncSession, months_ahead: int = 3) -> dict[str, str]:
    """Create the missing monthly partitions, this month through `months_ahead` months on.

    Returns each partition's name with `created`, `exists` or `blocked`. A blocked month has rows
    in the default partition; an operator moves them before its partition can exist.
    """
    rows = await session.execute(
        text("SELECT partition_name, status FROM audit_create_partitions(:months)"),
        {"months": months_ahead},
    )
    return {name: status for name, status in rows.tuples()}


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
        if value is None or isinstance(value, bool | int):
            out[key] = value
        elif isinstance(value, Enum):
            out[key] = value.value
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
