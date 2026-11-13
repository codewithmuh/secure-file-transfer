"""The service's record of Identity Center break-glass grants (#239; FR-35; authn and authz 8.3).

The Identity Center path of 8.3 works without the service: a `BreakGlassApprover` assigns
`BreakGlass` for an hour, and the assignment plus CloudTrail is the record. The service keeps a
copy so tenants see the access in their audit logs (UC-4), in two ways:

- **`recordBreakGlassGrant`** (`record`): the break-glass tool calls it after the assignment, as
  best effort. A grant longer than an hour, or one naming a tenant that doesn't exist, is
  `422 validation_failed`. A retry with the same `assignment_request_id` finds the first record and
  answers `200` with it, whoever made it.
- **The reconciliation job** (`reconcile`, every 15 minutes in the operator API): it reads the
  `BreakGlass` assignments of the last day from CloudTrail (`AssignmentTrail`, an adapter) and
  records any the tool didn't, as `recorded_by: reconciliation`. It drops tenant IDs that don't
  exist rather than lose the record, and counts what it couldn't write: an assignment still
  unrecorded an hour after it started alerts (deploy/alerts/break-glass-records.rules.yaml).

Each record is a security-critical platform event, `break_glass.recorded`, and one in each named
tenant's log, as break-glass in the service writes them (`sft.service.break_glass`). Events carry
IDs, flags and times; the requester, approver, incident and reason stay in the row, since they are
text from the tool or from CloudTrail, never an identity STS checked (data model 2.5). A record
whose requester is its approver is `self_approved` and alerts as any self-approved grant does.

The record's row is `active` until its `ends_at`, so `BreakGlassActive` pages for it and the sweep
records its expiry in the tenants' logs; it never opens the database to `sft_breakglass`
(`sft.data.break_glass_records`). The after-action review is due 2 business days after the grant
starts (`review_due`): Saturdays and Sundays don't count; public holidays do.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final, Protocol
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from sft.core.errors import FieldError, Unprocessable, json_pointer
from sft.data import audit, break_glass_records, tenants
from sft.data.audit import Actor, Origin, Target
from sft.data.break_glass_records import RecordedGrant
from sft.data.database import Database
from sft.data.models import ActorType, BreakGlassGrant, BreakGlassState
from sft.data.scope import Scope
from sft.service.break_glass import TARGET, SweepJob, tenant_records
from sft.service.operator_auth import Operator
from sft.service.permissions import authorize

log = logging.getLogger(__name__)

ACTION: Final = "break_glass.recorded"
MAX_GRANT: Final = timedelta(hours=1)
REVIEW_BUSINESS_DAYS: Final = 2
LOOKBACK: Final = timedelta(days=1)
"""How far back each reconciliation reads CloudTrail: far more than its 15 minutes, so a run that
failed for hours still catches up."""
UNRECORDED_AFTER: Final = timedelta(hours=1)
"""An assignment unrecorded this long after it started alerts (authn and authz 8.3)."""
UNKNOWN_INCIDENT: Final = "unknown"
UNKNOWN_REASON: Final = (
    "Recorded from CloudTrail by the reconciliation job; the removal schedule gave no reason."
)


class RecordedBy(StrEnum):
    TOOL = "tool"
    RECONCILIATION = "reconciliation"


@dataclass(frozen=True, slots=True)
class NewRecord:
    """`BreakGlassGrantCreate`."""

    assignment_request_id: str
    requester: str
    approver: str
    incident_id: str
    reason: str
    tenant_ids: Sequence[UUID]
    starts_at: datetime
    ends_at: datetime


@dataclass(frozen=True, slots=True)
class Recorded:
    grant: BreakGlassGrant
    created: bool
    """False when the assignment was recorded before: the answer is then `200`."""
    tenant_records_missed: int = 0


@dataclass(frozen=True, slots=True)
class TrailAssignment:
    """A `BreakGlass` assignment as CloudTrail shows it, with what its removal schedule says."""

    assignment_request_id: str
    requester: str
    """The Identity Center user name of the operator given `BreakGlass`."""
    approver: str
    """The role session name of the `BreakGlassApprover` that made the assignment."""
    starts_at: datetime
    ends_at: datetime | None = None
    incident_id: str | None = None
    reason: str | None = None
    tenant_ids: Sequence[UUID] = ()


class AssignmentTrail(Protocol):
    """Reads `BreakGlass` assignments from CloudTrail (`sft.runtime.break_glass_trail`); a fake
    in tests. Raises on any failure: the run then fails, and its staleness alerts."""

    async def break_glass_assignments(self, *, since: datetime) -> Sequence[TrailAssignment]: ...


@dataclass(frozen=True, slots=True)
class ReconcileResult:
    seen: int = 0
    reconciled: int = 0
    failed: Sequence[str] = field(default_factory=tuple)
    """The assignment request IDs the job couldn't record."""
    unrecorded: int = 0
    """Failed ones that started at least `UNRECORDED_AFTER` ago: the alert's gauge."""
    tenant_records_missed: int = 0


def review_due(starts_at: datetime) -> datetime:
    """`REVIEW_BUSINESS_DAYS` business days after the grant starts, at the same time of day."""
    due = starts_at
    left = REVIEW_BUSINESS_DAYS
    while left:
        due += timedelta(days=1)
        if due.weekday() < 5:  # Monday to Friday
            left -= 1
    return due


async def record(
    database: Database, operator: Operator, new: NewRecord, *, origin: Origin
) -> Recorded:
    """`recordBreakGlassGrant`, by the break-glass tool."""
    now = datetime.now(UTC)
    authorize(operator.caller, "recordBreakGlassGrant", now=now)
    return await _record(
        database, new, RecordedBy.TOOL, operator=operator, origin=origin, now=now, strict=True
    )


async def reconcile(
    database: Database, trail: AssignmentTrail, *, now: datetime | None = None
) -> ReconcileResult:
    """Record every `BreakGlass` assignment of the last day that has no row yet."""
    now = now or datetime.now(UTC)
    found = await trail.break_glass_assignments(since=now - LOOKBACK)
    async with database.transaction(Scope.platform()) as session:
        have = await break_glass_records.recorded_assignments(
            session, {a.assignment_request_id for a in found}
        )
    reconciled, missed, failed, unrecorded = 0, 0, [], 0
    for assignment in found:
        if assignment.assignment_request_id in have:
            continue
        try:
            recorded = await _record(
                database,
                _from_trail(assignment),
                RecordedBy.RECONCILIATION,
                operator=None,
                origin=None,
                now=now,
                strict=False,
            )
        except (Unprocessable, SQLAlchemyError, OSError):
            log.exception(
                "a break-glass assignment couldn't be recorded",
                extra={"assignment_request_id": assignment.assignment_request_id},
            )
            failed.append(assignment.assignment_request_id)
            if now - assignment.starts_at >= UNRECORDED_AFTER:
                unrecorded += 1
            continue
        have.add(assignment.assignment_request_id)
        if recorded.created:
            reconciled += 1
            missed += recorded.tenant_records_missed
            log.warning(
                "a break-glass assignment was recorded by reconciliation, not by the tool",
                extra={"assignment_request_id": assignment.assignment_request_id},
            )
    return ReconcileResult(len(found), reconciled, tuple(failed), unrecorded, missed)


def _from_trail(assignment: TrailAssignment) -> NewRecord:
    """What CloudTrail and the removal schedule say, made to fit a record: the assignment is
    removed after an hour, so a later or missing end is the hour's end."""
    latest = assignment.starts_at + MAX_GRANT
    ends_at = assignment.ends_at
    if ends_at is None or ends_at > latest or ends_at <= assignment.starts_at:
        ends_at = latest
    return NewRecord(
        assignment_request_id=assignment.assignment_request_id,
        requester=assignment.requester,
        approver=assignment.approver,
        incident_id=(assignment.incident_id or UNKNOWN_INCIDENT)[:64],
        reason=(assignment.reason or UNKNOWN_REASON)[:1000],
        tenant_ids=tuple(dict.fromkeys(assignment.tenant_ids))[:100],
        starts_at=assignment.starts_at,
        ends_at=ends_at,
    )


def _checked(new: NewRecord) -> int:
    """The grant's length in whole minutes, or `422 validation_failed`."""
    errors = []
    for name in ("assignment_request_id", "requester", "approver", "incident_id"):
        if not getattr(new, name).strip():
            errors.append(_error(name, "Required."))
    if new.starts_at.tzinfo is None or new.ends_at.tzinfo is None:
        errors.append(_error("starts_at", "A time with its offset."))
    elif not new.starts_at < new.ends_at <= new.starts_at + MAX_GRANT:
        errors.append(_error("ends_at", "After starts_at, and at most 1 hour after it."))
    if errors:
        raise Unprocessable("validation_failed", errors[0].detail, errors=errors)
    return max(1, math.ceil((new.ends_at - new.starts_at).total_seconds() / 60))


async def _record(
    database: Database,
    new: NewRecord,
    recorded_by: RecordedBy,
    *,
    operator: Operator | None,
    origin: Origin | None,
    now: datetime,
    strict: bool,
) -> Recorded:
    minutes = _checked(new)
    actor = operator.actor if operator is not None else Actor(ActorType.SYSTEM)
    async with database.transaction(Scope.platform()) as session:
        existing = await break_glass_records.find_by_assignment(session, new.assignment_request_id)
        if existing is not None:
            return Recorded(existing, created=False)
        known: list[UUID] = []
        for index, tenant_id in enumerate(new.tenant_ids):
            if await tenants.directory_tenant(session, tenant_id) is not None:
                known.append(tenant_id)
            elif strict:
                raise Unprocessable(
                    "validation_failed",
                    "No tenant has this ID.",
                    errors=[_error(f"tenant_ids/{index}", "No tenant has this ID.")],
                )
        row = await break_glass_records.insert_recorded(
            session,
            RecordedGrant(
                assignment_request_id=new.assignment_request_id,
                requester=new.requester,
                approver=new.approver,
                incident_id=new.incident_id,
                reason=new.reason,
                tenant_ids=known,
                starts_at=new.starts_at,
                ends_at=new.ends_at,
                duration_minutes=minutes,
                recorded_by=recorded_by.value,
                review_due_at=review_due(new.starts_at),
                expired=new.ends_at <= now,
            ),
        )
        if row is None:  # recorded meanwhile by the tool or the job
            again = await break_glass_records.find_by_assignment(session, new.assignment_request_id)
            if again is None:  # pragma: no cover - the conflict was on this ID
                raise RuntimeError("the break-glass record vanished")
            return Recorded(again, created=False)
        extra: dict[str, audit.Detail] = {"recorded_by": recorded_by}
        if len(known) < len(new.tenant_ids):
            extra["tenants_dropped"] = len(new.tenant_ids) - len(known)
        details: dict[str, audit.Detail] = {
            "state": BreakGlassState(row.state),
            "duration_minutes": row.duration_minutes,
            "tenant_count": len(row.tenant_ids),
            "self_approved": row.self_approved,
            "ends_at": new.ends_at,
            **extra,
            **(operator.details() if operator is not None else {}),
        }
        if operator is None:
            details["job"] = SweepJob.BREAK_GLASS_RECONCILIATION
        await audit.record(
            session,
            action=ACTION,
            actor=actor,
            target=Target(TARGET, row.id),
            origin=origin,
            security_critical=True,
            details=details,
        )
    missed = await tenant_records(
        database,
        row,
        ACTION,
        actor,
        operator,
        job=SweepJob.BREAK_GLASS_RECONCILIATION,
        extra=extra,
    )
    return Recorded(row, created=True, tenant_records_missed=missed)


def _error(name: str, detail: str) -> FieldError:
    return FieldError(detail, pointer=json_pointer(*name.split("/")))


__all__ = [
    "AssignmentTrail",
    "NewRecord",
    "ReconcileResult",
    "Recorded",
    "RecordedBy",
    "TrailAssignment",
    "reconcile",
    "record",
    "review_due",
]
