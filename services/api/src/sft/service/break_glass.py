"""Break-glass in the service: two operators, a time box and a record of each step (#232; FR-35;
authn and authz 8.3; threat model R-08).

1. **Request** (`requestBreakGlass`): an operator names the incident, a reason, the tenants and
   at most 60 minutes. Nothing is reachable yet.
2. **Approval** (`approveBreakGlass`): another operator approves within an hour, and the grant is
   `active` from that moment for its duration. Self-approval is `403 self_approval_forbidden`,
   unless the environment allows it for a single maintainer (`BREAK_GLASS_SELF_APPROVAL`); it is
   then marked `self_approved` and alerts on its own (deploy/alerts/break-glass.rules.yaml).
3. **Use**: the operator logs in as `sft_breakglass` and sets `app.break_glass_grant`; the role
   reads the grant's tenants' rows of a few tables, read only, until `ends_at` (revision 0030).
4. **End**: at `ends_at` access ends by itself. The sweep (`sweep`, every 30 seconds in the
   operator API) records it as `expired`, and lapses requests nobody approved; an operator may end
   a grant early or withdraw a request (`endBreakGlass`).

**The record.** Each step is a security-critical platform audit event, and the approval, the end
and the expiry also go to each named tenant's audit log, where its admins see them (UC-4). Events
name the grant and the operators, never the incident or the reason, which are free text (data
model 2.5); the grant row keeps those. A tenant's record is written after the platform one, in the
tenant's scope; if it fails, the failure is logged and counted, and the platform record stands.

The Identity Center `BreakGlass` path of authn and authz 8.3 stays the way in when the API or the
database is down; `recordBreakGlassGrant` is its record, not this module.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from sft.core.errors import Conflict, FieldError, Forbidden, NotFound, Unprocessable, json_pointer
from sft.data import audit, break_glass, tenants
from sft.data.audit import Actor, Origin, Target
from sft.data.database import Database
from sft.data.models import ActorType, BreakGlassGrant, BreakGlassState
from sft.data.scope import Scope
from sft.service.operator_auth import Operator
from sft.service.permissions import authorize

log = logging.getLogger(__name__)

TARGET: Final = "break_glass_grant"
MAX_MINUTES: Final = 60


class SweepJob(StrEnum):
    """The system actor's name in the sweep's events."""

    BREAK_GLASS_SWEEP = "break_glass_sweep"


@dataclass(frozen=True, slots=True)
class NewRequest:
    incident_id: str
    reason: str
    tenant_ids: Sequence[UUID]
    duration_minutes: int


@dataclass(frozen=True, slots=True)
class SweepResult:
    expired: Sequence[BreakGlassGrant] = field(default_factory=tuple)
    lapsed: Sequence[BreakGlassGrant] = field(default_factory=tuple)
    active: dict[bool, int] = field(default_factory=dict)
    """Grants giving access now, by whether they were self-approved."""
    tenant_records_missed: int = 0


def _now() -> datetime:
    return datetime.now(UTC)


def _details(grant: BreakGlassGrant, operator: Operator | None = None) -> dict[str, audit.Detail]:
    details: dict[str, audit.Detail] = {
        "state": BreakGlassState(grant.state),
        "duration_minutes": grant.duration_minutes,
        "tenant_count": len(grant.tenant_ids),
        "self_approved": grant.self_approved,
    }
    if grant.ends_at is not None:
        details["ends_at"] = grant.ends_at
    if operator is not None:
        details.update(operator.details())
    return details


async def request(
    database: Database, operator: Operator, new: NewRequest, *, origin: Origin
) -> BreakGlassGrant:
    """`requestBreakGlass`."""
    authorize(operator.caller, "requestBreakGlass", now=_now())
    if not 1 <= new.duration_minutes <= MAX_MINUTES:
        raise _invalid("duration_minutes", f"At most {MAX_MINUTES} minutes.")
    async with database.transaction(Scope.platform()) as session:
        for index, tenant_id in enumerate(new.tenant_ids):
            if await tenants.directory_tenant(session, tenant_id) is None:
                raise _invalid(f"tenant_ids/{index}", "No tenant has this ID.")
        grant = await break_glass.insert_request(
            session,
            incident_id=new.incident_id,
            reason=new.reason,
            tenant_ids=new.tenant_ids,
            duration_minutes=new.duration_minutes,
            requester=str(operator.name),
        )
        await audit.record(
            session,
            action="break_glass.requested",
            actor=operator.actor,
            target=Target(TARGET, grant.id),
            origin=origin,
            security_critical=True,
            details=_details(grant, operator),
        )
    return grant


async def approve(
    database: Database,
    operator: Operator,
    grant_id: UUID,
    *,
    allow_self_approval: bool,
    origin: Origin,
) -> BreakGlassGrant:
    """`approveBreakGlass`: a second operator, within the hour; access starts now."""
    authorize(operator.caller, "approveBreakGlass", now=_now())
    async with database.transaction(Scope.platform()) as session:
        grant = await break_glass.get_grant(session, grant_id, for_update=True)
        if grant is None:
            raise NotFound()
        if grant.state != BreakGlassState.REQUESTED:
            raise Conflict("invalid_state", current_state=grant.state)
        if await break_glass.lapsed(session, grant):
            raise Conflict("invalid_state", "The request lapsed.", current_state="lapsed")
        own = grant.requester == str(operator.name)
        if own and not allow_self_approval:
            raise Forbidden("self_approval_forbidden", "A second operator approves.")
        grant = await break_glass.approve(
            session, grant_id, approver=str(operator.name), self_approved=own
        )
        await audit.record(
            session,
            action="break_glass.approved",
            actor=operator.actor,
            target=Target(TARGET, grant.id),
            origin=origin,
            security_critical=True,
            details=_details(grant, operator),
        )
    await _tenant_records(database, grant, "break_glass.approved", operator.actor, operator)
    return grant


async def end(
    database: Database, operator: Operator, grant_id: UUID, *, origin: Origin
) -> BreakGlassGrant:
    """`endBreakGlass`: end an active grant early, or withdraw a request; idempotent."""
    authorize(operator.caller, "endBreakGlass", now=_now())
    async with database.transaction(Scope.platform()) as session:
        grant = await break_glass.get_grant(session, grant_id, for_update=True)
        if grant is None:
            raise NotFound()
        if grant.state == BreakGlassState.ACTIVE:
            new_state = BreakGlassState.ENDED
        elif grant.state == BreakGlassState.REQUESTED:
            new_state = BreakGlassState.WITHDRAWN
        else:
            return grant
        was_active = grant.state == BreakGlassState.ACTIVE
        grant = await break_glass.end(session, grant_id, state=new_state, ended_by=operator.name)
        await audit.record(
            session,
            action="break_glass.ended",
            actor=operator.actor,
            target=Target(TARGET, grant.id),
            origin=origin,
            security_critical=True,
            details=_details(grant, operator),
        )
    if was_active:
        await _tenant_records(database, grant, "break_glass.ended", operator.actor, operator)
    return grant


async def list_requests(
    database: Database, operator: Operator, *, state: BreakGlassState | None, limit: int
) -> Sequence[BreakGlassGrant]:
    """`listBreakGlassRequests`."""
    authorize(operator.caller, "listBreakGlassRequests", now=_now())
    async with database.transaction(Scope.platform()) as session:
        return await break_glass.list_grants(session, state=state, limit=limit)


async def sweep(database: Database) -> SweepResult:
    """Record grants whose time is up and requests nobody approved, each with its events, and
    count the grants giving access now. Safe to run in several pods: each row changes once."""
    system = Actor(ActorType.SYSTEM)
    job: dict[str, audit.Detail] = {"job": SweepJob.BREAK_GLASS_SWEEP}
    async with database.transaction(Scope.platform()) as session:
        expired = await break_glass.expire_due(session)
        lapsed = await break_glass.lapse_due(session)
        for grant, action in [
            *((g, "break_glass.expired") for g in expired),
            *((g, "break_glass.lapsed") for g in lapsed),
        ]:
            await audit.record(
                session,
                action=action,
                actor=system,
                target=Target(TARGET, grant.id),
                security_critical=True,
                details={**_details(grant), **job},
            )
        active = await break_glass.active_counts(session)
    missed = 0
    for grant in expired:
        missed += await _tenant_records(database, grant, "break_glass.expired", system, None)
    return SweepResult(expired, lapsed, active, missed)


async def _tenant_records(
    database: Database,
    grant: BreakGlassGrant,
    action: str,
    actor: Actor,
    operator: Operator | None,
) -> int:
    """The step's record in each named tenant's log; how many couldn't be written."""
    missed = 0
    details = _details(grant, operator)
    if operator is None:
        details["job"] = SweepJob.BREAK_GLASS_SWEEP
    for tenant_id in grant.tenant_ids:
        try:
            async with database.transaction(Scope.tenant(tenant_id)) as session:
                await audit.record(
                    session,
                    action=action,
                    actor=actor,
                    target=Target(TARGET, grant.id),
                    security_critical=True,
                    details=details,
                )
        except (SQLAlchemyError, OSError):
            missed += 1
            log.exception(
                "a break-glass record wasn't written to a tenant's log",
                extra={"action": action, "tenant_id": str(tenant_id)},
            )
    return missed


def _invalid(field_name: str, detail: str) -> Unprocessable:
    return Unprocessable(
        "validation_failed", detail, errors=[FieldError(detail, pointer=json_pointer(field_name))]
    )


__all__ = [
    "NewRequest",
    "SweepResult",
    "approve",
    "end",
    "list_requests",
    "request",
    "sweep",
]
