"""Re-importing archived audit events and re-applying security-critical changes, after a
point-in-time restore or a regional failover (#253, #252; architecture 6 and 7, data model 2.3,
2.5 and 4.2, NFR-10, NFR-11, NFR-15).

A restore, or a failover that loses the replica's unreplicated tail, takes the database back in
time. The audit archive doesn't go back: it holds every security-critical record in both regions
before the API confirmed it (#177), and the archive job's copy of every event. The runbooks
(docs/runbooks/point-in-time-restore.md, regional-failover.md) run this module as `sft_recovery`,
in recovery scope, before any worker starts:

1. `start_generation`: the archive cursor's generation becomes one more than the highest in the
   archive, so reused transaction IDs never overwrite or hide an archived record (data model 2.5).
   The same statement rewinds the cursor to the oldest event written since a time the runbook
   names, so batches that never reached the surviving region are archived again under the new
   generation (#42: the archive cursor against untimed archive replication). Readers drop the
   duplicates by `id`. A range the archive job had claimed and not finished is dropped with it
   (`claimed_up_to_tx`, `sft.data.archive_cursor`): the job claims afresh from the rewound
   position, and a run still writing the old claim can no longer move the cursor.
2. `prepare_partitions`: the monthly partitions from the oldest record's month, so re-imported
   events land in their own month, never the default partition (data model 6).
3. `replay`: every record newer than the restore point, oldest first, each in a transaction of
   its own:
   - **Re-import.** The event is inserted with its own `id` and `occurred_at`, `ON CONFLICT DO
     NOTHING` on the primary key `(id, occurred_at)`. One row inserted means the database didn't
     have the event, so it didn't have the change either; nothing inserted means it did, and the
     record is done. Its `tx_id` is the re-import's, so the archive job copies it once more into
     the new generation.
   - **Re-apply.** For a security-critical record that was missing, its change is made again, as
     idempotent statements keyed by the record's target (`_REAPPLY`). Only changes that take
     access away are re-applied: revocations, lockouts, deactivations, demotions, forced sign-outs,
     sign-in resets, API key revocations, and the counts of download grants. A change that touched
     a row also writes `recovery.reapplied` in the same transaction, naming the record: the event
     the changed tables' fail-closed trigger needs (it wants one from this transaction, at its
     start), and the audit log's account of who changed the row and why. A record whose change is
     already in effect (its statements touch nothing) is only re-imported.
4. `republish_outbox`: every outbox message sent since a time the runbook names (24 hours before
   the failure) goes back to unsent, so the relay publishes it again once the workers scale up:
   the work that sat in the lost region's queues, or whose results the restore took back, is done
   again, and consumers skip what they already did (architecture 5.3, ADR-0013).

**What isn't re-applied, on purpose.**
- **Unlocks** (`recipient.unlocked`, `uploader.unlocked`). An unlock gives access back and issues
  a new link, whose email is an outbox message the recovery role can't write. Re-applying it
  would leave a recipient unlocked with no link. Left locked, the recipient is safe, and the
  member unlocks again, which sends the new link (decision of #253, in
  docs/operations/disaster-recovery.md).
- **The invitation of a sign-in reset.** The reset's sessions and pool identities go, which is
  what takes access away; the admin resets again to send the invitation.
- **Grant intents** (`download.grant_intent`) are neither re-imported nor applied: an intent with
  no committed record gave no access (data model 2.3). A **committed record**
  (`download.grant_committed`) whose grant has no row in the database adds the one download it
  counted to the recipient's counter. The grant row itself isn't rebuilt: its file version and
  session may not exist after the restore, and a recipient who still needs the file asks for a
  new grant. A member's grant of a received file counts nothing (data model 2.3).

**Grants this needs.** `sft_recovery` may insert audit events (revision 0002) and run
`audit_create_partitions`; it reads and moves `audit_archive_cursor`, the generation included
(revision 0034). The rest, the reads and updates of data model 4.2 plus `files (delete_after)`,
`idp_connections (id, tenant_id)` read, `audit_events (tx_id, occurred_at)` read for step 1, and
`outbox (published_at, attempts, next_attempt_at, last_error)` for step 4, are revision 0035's,
each in recovery scope only.

Everything here takes IDs, enums and times only; no record holds a name, address, token or code
(data model 2.5), and nothing is logged but counts.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy import TextClause, text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data import audit
from sft.data.database import Database
from sft.data.scope import Scope

log = logging.getLogger(__name__)

PEOPLE: Final = frozenset({"member", "admin"})
"""Actor types that are a user, so a record's actor can fill `revoked_by` or `unlocked_by`."""

GRANT_INTENT: Final = "download.grant_intent"
GRANT_COMMITTED: Final = "download.grant_committed"


class Outcome(StrEnum):
    """What `replay` did with one record."""

    PRESENT = "present"
    """The database already had the event, so it had the change too."""
    REIMPORTED = "reimported"
    """The event was missing and is back; nothing else needed changing."""
    REAPPLIED = "reapplied"
    """The event was missing; it is back and its change is made again, with `recovery.reapplied`."""
    NOT_REAPPLIED = "not_reapplied"
    """The event is back; its change is left out on purpose (an unlock, module docstring)."""
    IGNORED = "ignored"
    """A grant intent: neither re-imported nor applied."""


@dataclass(frozen=True, slots=True)
class Record:
    """One archived event, as a direct record (#177) or the archive job's copy holds it. Extra keys
    in the archive job's copy are ignored: what is re-applied needs none of them."""

    id: UUID
    tenant_id: UUID | None
    occurred_at: datetime
    action: str
    actor_type: str
    actor_id: UUID | None
    target_type: str | None
    target_id: UUID | None
    outcome: str
    security_critical: bool
    details: Mapping[str, object] = field(default_factory=dict)


def parse_record(body: bytes) -> Record:
    """A record from its archive object's JSON (`sft.service.audit_archive.record_body`).
    Raises `ValueError` for anything that isn't one."""
    raw = json.loads(body)
    if not isinstance(raw, dict):
        raise ValueError("an archive record is a JSON object")
    details = raw.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("a record's details are a JSON object")
    occurred_at = datetime.fromisoformat(str(raw["occurred_at"]))
    if occurred_at.tzinfo is None:
        raise ValueError("a record's occurred_at carries its offset")
    return Record(
        id=UUID(str(raw["id"])),
        tenant_id=_uuid(raw.get("tenant_id")),
        occurred_at=occurred_at,
        action=str(raw["action"]),
        actor_type=str(raw["actor_type"]),
        actor_id=_uuid(raw.get("actor_id")),
        target_type=None if raw.get("target_type") is None else str(raw["target_type"]),
        target_id=_uuid(raw.get("target_id")),
        outcome=str(raw["outcome"]),
        security_critical=bool(raw.get("security_critical", False)),
        details=details,
    )


def _uuid(value: object) -> UUID | None:
    return None if value is None else UUID(str(value))


def merge(records: Iterable[Record], *, since: datetime) -> list[Record]:
    """The records newer than `since`, each once, oldest first.

    The same event can be in the archive twice, as a direct record and as the archive job's copy,
    and under two generations after an earlier recovery; readers drop duplicates by `id` (data
    model 2.5). A security-critical copy wins, so its change isn't missed."""
    if since.tzinfo is None:
        raise ValueError("since must be an aware datetime")
    kept: dict[UUID, Record] = {}
    for record in records:
        if record.occurred_at <= since:
            continue
        held = kept.get(record.id)
        if held is None or (record.security_critical and not held.security_critical):
            kept[record.id] = record
    return sorted(kept.values(), key=lambda r: (r.occurred_at, r.id))


def day_prefixes(prefix: str, owner: str, first: date, last: date) -> list[str]:
    """The key prefixes of `owner`'s direct records from `first` to `last`, both included
    (`security-critical/v1/<tenant ID or "platform">/<yyyy>/<mm>/<dd>/`, #177). The entry point
    lists each in the surviving region's archive."""
    if last < first:
        return []
    days = (last - first).days
    return [
        f"{prefix}/{owner}/{date.fromordinal(first.toordinal() + n):%Y/%m/%d}/"
        for n in range(days + 1)
    ]


@dataclass
class ReplayReport:
    """What `replay` did, by action and outcome; and the changes it made again, by ID only."""

    counts: Counter[tuple[str, Outcome]] = field(default_factory=Counter)
    reapplied: list[tuple[str, UUID | None, UUID | None]] = field(default_factory=list)
    """(action, tenant, target) of each change made again, for the drill log."""

    def total(self, outcome: Outcome) -> int:
        return sum(n for (_, o), n in self.counts.items() if o is outcome)


# ---- 1. the archive generation and the cursor ----

_START_GENERATION = text(
    "UPDATE audit_archive_cursor "
    "SET generation = :generation, "
    "    archived_up_to_tx = COALESCE((SELECT e.tx_id FROM audit_events e "
    "        WHERE e.occurred_at >= :rewind_to "
    "          AND e.tx_id < audit_archive_cursor.archived_up_to_tx "
    "        ORDER BY e.tx_id LIMIT 1), archived_up_to_tx), "
    "    claimed_up_to_tx = NULL, "
    "    archived_at = now() "
    "WHERE generation < :generation"
)
_GENERATION = text("SELECT generation FROM audit_archive_cursor")


async def start_generation(
    database: Database, *, highest_in_archive: int, rewind_to: datetime
) -> int:
    """Start the archive generation after `highest_in_archive`, and rewind the cursor to the
    oldest event written since `rewind_to` (module docstring, step 1); the cursor's generation.

    Running it again with the same numbers changes nothing: a cursor already past
    `highest_in_archive` keeps its generation and position."""
    if rewind_to.tzinfo is None:
        raise ValueError("rewind_to must be an aware datetime")
    async with database.transaction(Scope.recovery()) as session:
        await session.execute(
            _START_GENERATION,
            {"generation": highest_in_archive + 1, "rewind_to": rewind_to},
        )
        generation = (await session.execute(_GENERATION)).scalar_one()
    return int(generation)


# ---- 2. partitions ----


async def prepare_partitions(database: Database, records: Sequence[Record]) -> dict[str, str]:
    """The audit partitions from the oldest record's month through three months ahead (data
    model 6), before anything is re-imported."""
    if not records:
        return {}
    oldest = min(r.occurred_at for r in records).astimezone(UTC).date().replace(day=1)
    async with database.transaction(Scope.recovery()) as session:
        return await audit.create_partitions(session, 3, oldest)


# ---- 3. re-import and re-apply ----

_REIMPORT = text(
    "INSERT INTO audit_events (id, tenant_id, occurred_at, actor_type, actor_id, action, "
    "target_type, target_id, outcome, security_critical, details) VALUES (:id, :tenant, "
    ":occurred_at, :actor_type, :actor_id, :action, :target_type, :target_id, :outcome, "
    ":security_critical, CAST(:details AS jsonb)) ON CONFLICT DO NOTHING"
)

# The recovery's own event for a change it made again: now, by the system, naming the record.
_REAPPLIED_EVENT = text(
    "INSERT INTO audit_events (id, tenant_id, actor_type, action, target_type, target_id, "
    "outcome, security_critical, details) VALUES (:id, :tenant, 'system', 'recovery.reapplied', "
    ":target_type, :target_id, 'success', false, CAST(:details AS jsonb))"
)

# Each change, made again as the original made it, by its target and the record's time, and only
# where the restored row doesn't have it yet. `:at` is the record's `occurred_at`, `:by` the
# acting user (null for an API key or the system), `:target` and `:tenant` the record's.
_TRANSFER_REVOKED = (
    text(
        "UPDATE transfers SET state = 'revoked', hold_reason = NULL, "
        "ended_at = COALESCE(ended_at, :at), revoked_by = COALESCE(revoked_by, :by), "
        "updated_at = now() WHERE tenant_id = :tenant AND id = :target AND state <> 'revoked'"
    ),
    text(
        "UPDATE link_sessions SET revoked_at = :at WHERE tenant_id = :tenant "
        "AND revoked_at IS NULL AND recipient_id IN (SELECT id FROM transfer_recipients "
        "WHERE tenant_id = :tenant AND transfer_id = :target)"
    ),
    # The files go to the deletion job, as revokeTransfer's `cancel_files` sends them (NFR-8).
    text(
        "UPDATE files SET delete_after = :at WHERE tenant_id = :tenant "
        "AND transfer_id = :target AND delete_after IS NULL"
    ),
)
_UPLOAD_REQUEST_REVOKED = (
    text(
        "UPDATE upload_requests SET state = 'revoked', ended_at = COALESCE(ended_at, :at), "
        "revoked_by = COALESCE(revoked_by, :by), updated_at = now() "
        "WHERE tenant_id = :tenant AND id = :target AND state <> 'revoked'"
    ),
    text(
        "UPDATE link_sessions SET revoked_at = :at WHERE tenant_id = :tenant "
        "AND revoked_at IS NULL AND upload_request_id = :target"
    ),
)
_RECIPIENT_LOCKED = (
    text(
        "UPDATE transfer_recipients SET locked_at = :at, "
        "failed_attempts = LEAST(20, GREATEST(failed_attempts, :attempts)), updated_at = now() "
        "WHERE tenant_id = :tenant AND id = :target AND locked_at IS NULL"
    ),
)
_UPLOADER_LOCKED = (
    text(
        "UPDATE upload_requests SET locked_at = :at, "
        "failed_attempts = LEAST(20, GREATEST(failed_attempts, :attempts)), updated_at = now() "
        "WHERE tenant_id = :tenant AND id = :target AND locked_at IS NULL"
    ),
)
_API_KEY_REVOKED = (
    text(
        "UPDATE api_keys SET revoked_at = :at, revoked_reason = :reason "
        "WHERE tenant_id = :tenant AND id = :target AND revoked_at IS NULL"
    ),
)


# A user's member sessions that began before the record end, for the action's reason
# (`_SESSION_REASONS`), as `member_sessions.revoke_user_sessions` ends them.
_END_SESSIONS = text(
    "UPDATE member_sessions SET revoked_at = :at, revoked_reason = :session_reason "
    "WHERE tenant_id = :tenant AND user_id = :target AND revoked_at IS NULL "
    "AND created_at <= :at"
)
_SESSION_REASONS: Final[Mapping[str, str]] = {
    "user.deactivated": "deactivated",
    "user.role_changed": "role_changed",
    "user.signed_out_by_admin": "signed_out_by_admin",
    "user.sign_in_reset": "sign_in_reset",
}

_USER_DEACTIVATED = (
    text(
        "UPDATE users SET status = 'deactivated', invitation_token_hash = NULL, "
        "invitation_expires_at = NULL, dlp_approver = false, sso_fallback = false, "
        "updated_at = now() WHERE tenant_id = :tenant AND id = :target "
        "AND status <> 'deactivated'"
    ),
    _END_SESSIONS,
)
_USER_DEMOTED = (
    text(
        "UPDATE users SET role = 'member', sso_fallback = false, updated_at = now() "
        "WHERE tenant_id = :tenant AND id = :target AND role <> 'member'"
    ),
    _END_SESSIONS,
)
_USER_SIGNED_OUT = (_END_SESSIONS,)
_USER_SIGN_IN_RESET = (
    _END_SESSIONS,
    # The user's identities in the user pools, never an SSO provider's (`resetUserSignIn`), that
    # existed when the reset was made.
    text(
        "DELETE FROM user_identities WHERE tenant_id = :tenant AND user_id = :target "
        "AND created_at <= :at AND idp_connection_id IN "
        "(SELECT id FROM idp_connections WHERE tenant_id IS NULL)"
    ),
)
_GRANT_COUNTED = (
    text(
        "UPDATE download_counters SET count = count + 1, "
        "first_downloaded_at = COALESCE(first_downloaded_at, :at), "
        "last_downloaded_at = GREATEST(last_downloaded_at, :at), updated_at = now() "
        "WHERE tenant_id = :tenant AND recipient_id = :by_recipient AND file_id = :target "
        "AND NOT EXISTS (SELECT 1 FROM download_grants WHERE id = :grant)"
    ),
)

_REAPPLY: Final[Mapping[str, tuple[TextClause, ...]]] = {
    "transfer.revoked": _TRANSFER_REVOKED,
    "upload_request.revoked": _UPLOAD_REQUEST_REVOKED,
    "recipient.locked": _RECIPIENT_LOCKED,
    "uploader.locked": _UPLOADER_LOCKED,
    "api_key.revoked": _API_KEY_REVOKED,
    "user.deactivated": _USER_DEACTIVATED,
    "user.signed_out_by_admin": _USER_SIGNED_OUT,
    "user.sign_in_reset": _USER_SIGN_IN_RESET,
    GRANT_COMMITTED: _GRANT_COUNTED,
}
"""Security-critical actions whose change is made again, and its statements."""

NOT_REAPPLIED: Final = frozenset({"recipient.unlocked", "uploader.unlocked"})
"""Security-critical actions that give access back: re-imported only (module docstring)."""


async def replay(database: Database, records: Iterable[Record], *, since: datetime) -> ReplayReport:
    """Re-import every record newer than `since` and re-apply the security-critical ones the
    database is missing, oldest first (module docstring, step 3). Safe to run again: a record
    already re-imported is `PRESENT` the second time and changes nothing."""
    report = ReplayReport()
    for record in merge(records, since=since):
        if record.action == GRANT_INTENT:
            report.counts[(record.action, Outcome.IGNORED)] += 1
            continue
        async with database.transaction(Scope.recovery()) as session:
            outcome = await _replay_one(session, record)
        report.counts[(record.action, outcome)] += 1
        if outcome is Outcome.REAPPLIED:
            report.reapplied.append((record.action, record.tenant_id, record.target_id))
    log.info(
        "recovery replay done",
        extra={
            "reimported": report.total(Outcome.REIMPORTED),
            "reapplied": report.total(Outcome.REAPPLIED),
            "not_reapplied": report.total(Outcome.NOT_REAPPLIED),
            "present": report.total(Outcome.PRESENT),
            "ignored": report.total(Outcome.IGNORED),
        },
    )
    return report


async def _replay_one(session: AsyncSession, record: Record) -> Outcome:
    inserted = await session.execute(
        _REIMPORT,
        {
            "id": record.id,
            "tenant": record.tenant_id,
            "occurred_at": record.occurred_at,
            "actor_type": record.actor_type,
            "actor_id": record.actor_id,
            "action": record.action,
            "target_type": record.target_type,
            "target_id": record.target_id,
            "outcome": record.outcome,
            "security_critical": record.security_critical,
            "details": json.dumps(dict(record.details), sort_keys=True),
        },
    )
    if not inserted.rowcount:  # type: ignore[attr-defined]
        return Outcome.PRESENT
    statements = _statements(record)
    if statements is None:
        if record.security_critical and record.action in NOT_REAPPLIED:
            return Outcome.NOT_REAPPLIED
        return Outcome.REIMPORTED
    parameters = _parameters(record)
    touched = 0
    for statement in statements:
        result = await session.execute(statement, parameters)
        touched += int(result.rowcount or 0)  # type: ignore[attr-defined]
    if not touched:
        return Outcome.REIMPORTED
    await session.execute(
        _REAPPLIED_EVENT,
        {
            "id": uuid7(),
            "tenant": record.tenant_id,
            "target_type": record.target_type,
            "target_id": record.target_id,
            "details": json.dumps(
                {"record_id": str(record.id), "record_action": record.action}, sort_keys=True
            ),
        },
    )
    return Outcome.REAPPLIED


def _statements(record: Record) -> tuple[TextClause, ...] | None:
    """The statements that make the record's change again, or None if it has none to make."""
    if not record.security_critical or record.tenant_id is None or record.target_id is None:
        return None
    if record.action == "user.role_changed":
        # Only a demotion is security-critical (`users.change_role`); a promotion is never
        # re-applied, it gives access.
        return _USER_DEMOTED if record.details.get("role") == "member" else None
    if record.action == GRANT_COMMITTED and record.actor_type != "recipient":
        return None  # a member's grant of a received file counts nothing (data model 2.3)
    return _REAPPLY.get(record.action)


def _parameters(record: Record) -> dict[str, object]:
    details = record.details
    attempts = details.get("failed_attempts")
    grant = details.get("grant_id")
    return {
        "tenant": record.tenant_id,
        "target": record.target_id,
        "at": record.occurred_at,
        "by": record.actor_id if record.actor_type in PEOPLE else None,
        "by_recipient": record.actor_id,
        "attempts": attempts if isinstance(attempts, int) else 20,
        "reason": details.get("reason", "admin"),
        "session_reason": _SESSION_REASONS.get(record.action),
        "grant": UUID(str(grant)) if grant is not None else record.id,
    }


# ---- 4. the outbox ----

_REPUBLISH = text(
    "UPDATE outbox SET published_at = NULL, attempts = 0, next_attempt_at = now(), "
    "last_error = NULL WHERE published_at >= :since"
)


async def republish_outbox(database: Database, *, since: datetime) -> int:
    """Mark every outbox message published since `since` unsent again (module docstring, step
    4); how many. Run it before the workers scale up, after `replay`, so no consumer acts before
    the security-critical changes are back (architecture 7)."""
    if since.tzinfo is None:
        raise ValueError("since must be an aware datetime")
    async with database.transaction(Scope.recovery()) as session:
        result = await session.execute(_REPUBLISH, {"since": since})
    count = int(result.rowcount or 0)  # type: ignore[attr-defined]
    log.info("outbox messages to publish again", extra={"count": count})
    return count
