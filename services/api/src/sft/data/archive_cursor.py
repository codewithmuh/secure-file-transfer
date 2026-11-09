"""The audit archive job's reads: its cursor and the events it copies (#183; data model 2.5).

`sft_archive` reads every audit event and the cursor in system scope, and moves the cursor on; it
writes nothing else (revision 0034, authn and authz 7.3). Each function is one short transaction's
work, so the job never holds a transaction open while it writes to S3 (data model 2.5).

**Archiving without gaps.** IDs and `occurred_at` follow insert time, not commit time, so the job
follows transaction IDs instead: it archives `archived_up_to_tx <= tx_id < xmin`, where `xmin` is
the oldest transaction still running (`pg_snapshot_xmin(pg_current_snapshot())`). Nothing below
`xmin` can still commit, so no row is ever skipped, however long its transaction ran (threat model
T-44).

**One range at a time, the same range after a crash.** `claim` fixes the next range,
`[archived_up_to_tx, claimed_up_to_tx)`, of at most about `max_rows` events, whole transactions
only, and records its end before any object is written. `advance` moves the cursor to that end and
clears the claim, only if the cursor is still where the claim began. A run that dies between the two
leaves the claim, and the next run takes the same range, reads the same committed rows and writes
the same objects again, which the conditional write keeps once: nothing is missed or duplicated.

Transaction IDs are `xid8`, 64 bits that never wrap; they cross the driver as text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Final

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import require_scope
from sft.data.scope import ScopeKind

_SYSTEM: Final = ScopeKind.SYSTEM

_EVENT_COLUMNS: Final = (
    "id, tenant_id, tx_id::text AS tx_id, occurred_at, actor_type, actor_id, action, "
    "target_type, target_id, outcome, host(source_ip) AS source_ip, user_agent, request_id, "
    "trace_id, security_critical, details"
)


@dataclass(frozen=True, slots=True)
class Claim:
    """A range of transactions to archive under `generation`: `from_tx <= tx_id < up_to_tx`."""

    generation: int
    from_tx: int
    up_to_tx: int
    more: bool = False
    """Events past the range were ready too: the run takes another range at once."""


@dataclass(frozen=True, slots=True)
class ArchiveRow:
    """One audit event as the archive keeps it: every column, the source IP and the user agent
    included, which the security-critical records leave out (architecture 5.2). `details` holds
    IDs, enums, numbers, flags and times only (data model 2.5)."""

    id: str
    tenant_id: str | None
    tx_id: int
    occurred_at: datetime
    actor_type: str
    actor_id: str | None
    action: str
    target_type: str | None
    target_id: str | None
    outcome: str
    source_ip: str | None
    user_agent: str | None
    request_id: str | None
    trace_id: str | None
    security_critical: bool
    details: Mapping[str, object] = field(default_factory=dict)

    def as_json(self) -> dict[str, object]:
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "tx_id": str(self.tx_id),
            "occurred_at": self.occurred_at.isoformat(),
            "actor_type": self.actor_type,
            "actor_id": self.actor_id,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "outcome": self.outcome,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "security_critical": self.security_critical,
            "details": dict(self.details),
        }


def _str(value: object) -> str | None:
    return None if value is None else str(value)


def _row(row: Any) -> ArchiveRow:
    return ArchiveRow(
        id=str(row.id),
        tenant_id=_str(row.tenant_id),
        tx_id=int(row.tx_id),
        occurred_at=row.occurred_at,
        actor_type=row.actor_type,
        actor_id=_str(row.actor_id),
        action=row.action,
        target_type=row.target_type,
        target_id=_str(row.target_id),
        outcome=row.outcome,
        source_ip=row.source_ip,
        user_agent=row.user_agent,
        request_id=row.request_id,
        trace_id=row.trace_id,
        security_critical=row.security_critical,
        details=dict(row.details or {}),
    )


async def claim(session: AsyncSession, *, max_rows: int) -> Claim | None:
    """The range to archive next, recorded as claimed; None when nothing is ready.

    A claim left by a run that didn't finish is returned as it is. Otherwise the range runs from
    the cursor to the oldest running transaction, cut after about `max_rows` events at a
    transaction's end; one transaction with more events than that is taken whole. A range with no
    event at all moves the cursor at once, so the next find starts later.
    """
    require_scope(session, _SYSTEM)
    # First, before this transaction takes a transaction ID of its own with the row lock below.
    snapshot = await session.execute(text("SELECT pg_snapshot_xmin(pg_current_snapshot())::text"))
    xmin = int(snapshot.scalar_one())
    cursor = (
        await session.execute(
            text(
                "SELECT generation, archived_up_to_tx::text AS done, "
                "claimed_up_to_tx::text AS claimed FROM audit_archive_cursor FOR UPDATE"
            )
        )
    ).one()
    start = int(cursor.done)
    if cursor.claimed is not None:
        return Claim(cursor.generation, start, int(cursor.claimed), more=True)
    if xmin <= start:
        return None
    bounds = {"start": str(start), "xmin": str(xmin)}
    # The transaction of the event after the first `max_rows`: the range ends before it.
    cut = (
        await session.execute(
            text(
                "SELECT tx_id::text FROM audit_events "
                "WHERE tx_id >= CAST(:start AS xid8) AND tx_id < CAST(:xmin AS xid8) "
                "ORDER BY tx_id, id OFFSET :n LIMIT 1"
            ),
            {**bounds, "n": max_rows},
        )
    ).scalar_one_or_none()
    end = xmin if cut is None else int(cut)
    if end == start:
        # One transaction holds more than `max_rows` events: take it whole.
        after = (
            await session.execute(
                text(
                    "SELECT min(tx_id)::text FROM audit_events "
                    "WHERE tx_id > CAST(:start AS xid8) AND tx_id < CAST(:xmin AS xid8)"
                ),
                bounds,
            )
        ).scalar_one_or_none()
        end = xmin if after is None else int(after)
    first = (
        await session.execute(
            text(
                "SELECT 1 FROM audit_events "
                "WHERE tx_id >= CAST(:start AS xid8) AND tx_id < CAST(:end AS xid8) LIMIT 1"
            ),
            {"start": str(start), "end": str(end)},
        )
    ).scalar_one_or_none()
    if first is None:
        await session.execute(
            text(
                "UPDATE audit_archive_cursor SET archived_up_to_tx = CAST(:end AS xid8), "
                "archived_at = now() WHERE archived_up_to_tx = CAST(:start AS xid8) "
                "AND claimed_up_to_tx IS NULL"
            ),
            {"start": str(start), "end": str(end)},
        )
        return None
    await session.execute(
        text(
            "UPDATE audit_archive_cursor SET claimed_up_to_tx = CAST(:end AS xid8) "
            "WHERE archived_up_to_tx = CAST(:start AS xid8) AND claimed_up_to_tx IS NULL"
        ),
        {"start": str(start), "end": str(end)},
    )
    return Claim(cursor.generation, start, end, more=end < xmin)


async def events(session: AsyncSession, claimed: Claim) -> list[ArchiveRow]:
    """Every event of the claimed range, in `(tx_id, id)` order. All of them have committed."""
    require_scope(session, _SYSTEM)
    rows = await session.execute(
        text(
            f"SELECT {_EVENT_COLUMNS} FROM audit_events "  # noqa: S608 - a constant
            "WHERE tx_id >= CAST(:start AS xid8) AND tx_id < CAST(:end AS xid8) "
            "ORDER BY tx_id, id"
        ),
        {"start": str(claimed.from_tx), "end": str(claimed.up_to_tx)},
    )
    return [_row(row) for row in rows]


async def advance(session: AsyncSession, claimed: Claim) -> bool:
    """Move the cursor to the claim's end and clear it; False if another run moved it first."""
    require_scope(session, _SYSTEM)
    result = await session.execute(
        text(
            "UPDATE audit_archive_cursor SET archived_up_to_tx = CAST(:end AS xid8), "
            "claimed_up_to_tx = NULL, archived_at = now() "
            "WHERE archived_up_to_tx = CAST(:start AS xid8) "
            "AND claimed_up_to_tx = CAST(:end AS xid8)"
        ),
        {"start": str(claimed.from_tx), "end": str(claimed.up_to_tx)},
    )
    return bool(getattr(result, "rowcount", 0))


async def unarchived_age(session: AsyncSession) -> float:
    """Seconds since the oldest committed event the archive doesn't hold yet occurred, by the
    database's clock, which set it: an event at or past the cursor, a claimed range included.
    0 when the archive is up to date."""
    require_scope(session, _SYSTEM)
    age = (
        await session.execute(
            text(
                "SELECT extract(epoch FROM now() - min(occurred_at)) FROM audit_events "
                "WHERE tx_id >= (SELECT archived_up_to_tx FROM audit_archive_cursor)"
            )
        )
    ).scalar_one_or_none()
    return 0.0 if age is None else max(0.0, float(age))
