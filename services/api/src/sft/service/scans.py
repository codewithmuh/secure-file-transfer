"""Recording a file's scan and inspection, and the scan sweep (FR-16 to FR-19, FR-36, FR-47; data
model 3.1, 3.5; ADR-0019, ADR-0022).

The scan worker (`sft.workers.scan`) and the scan sweep act as named system actors (authn and authz
6.1), each named in its audit events' details (`system_actor`).

**Recording** (`record`) writes, in the caller's transaction, the file's state, its scan columns,
its inspection and one `dlp_findings` row per detector that matched (its location hints and
masked previews sealed with the tenant's DLP data key, #233), with `file.scanned`, and only
while the file is still `scanning`: a result that arrives after another, or after the sweep, changes
nothing. `unscannable_allowed` is read from the tenant's policy now, at scan time, and never
changes after (data model 3.1). An infected or `scan_failed` file's inspection is `skipped` and its
findings are discarded. The audit event names detectors, counts and enums only, never a value
(FR-54, NFR-26).

**The sweep** (`fail_overdue_scans`) moves each file still `scanning` past its deadline to
`scan_failed` and runs the evaluation, which holds its transfer. It finds them across tenants in
system scope and acts on each in its own tenant's scope (data model 4.2): `scan_failed` with
`deadline_passed`, its inspection `failed` (both engines ran out of time). Files over 2 GB wait
for GuardDuty's result (#234, `sft.service.guardduty`), and the sweep is their fallback too, two
hours after completion (`sft.service.scan_timing`). The lifecycle jobs (#181) schedule it.

**Received files** (#213) follow the same pass. A result has no transfer to evaluate; instead, in
the transaction that records it, a file that would be shareable gets the DLP decision of the
tenant's rules for received files (FR-51, #221; `sft.service.dlp_decision.decide_received`): a
block in enforce mode sets `dlp_blocked`, and `dlp.decided` records it either way. Then the file
counts towards its upload request's next notice (`note_received`): shareable, the member is told it
arrived; blocked, both sides are told, the uploader without any finding, rule or scan detail
(FR-12).

**Patterns past their budget** (#164, detectors 5): the inspector names the tenant patterns it
stopped on the file, and the same transaction counts one more stop for each
(`dlp_pattern_stops`) and writes `dlp.pattern_budget_exceeded` with their IDs, never a match. The
file's state doesn't change. One notice per request per 5 minutes: the
result that makes it due writes one outbox message, delayed by that window, and the notification
worker sends the counts of every file that settled meanwhile (architecture 4.3).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from string import ascii_lowercase
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import audit, dlp_policy, files, findings, tenants, upload_requests
from sft.data.audit import Actor, Target
from sft.data.database import Database
from sft.data.findings import Counts
from sft.data.models import (
    ActorType,
    DlpAction,
    FileState,
    InspectionReason,
    InspectionState,
    ScanDetail,
    ScanEngine,
    UnscannablePolicy,
)
from sft.data.outbox import UPLOAD_REQUEST_FILES_SETTLED, enqueue
from sft.data.scope import Scope
from sft.service import dlp_decision, finding_details
from sft.service.dlp_decision import Decided
from sft.service.evaluation import DLP_RULE, evaluate, is_shareable

FILE: Final = "file"
CUSTOM_PREFIX: Final = "custom:"
"""How a tenant pattern is named in a result's `budget_exceeded` (detectors 5)."""
DLP_BLOCKED_TAG: Final = "dlp_blocked"
"""The `scan` tag of a received file a DLP rule blocked: the API's read condition refuses it."""
SYSTEM: Final = Actor(ActorType.SYSTEM)
SWEEP_BATCH: Final = 100
_AUDIT_KEY: Final = re.compile(r"[a-z][a-z_]{0,56}")
"""A built-in detector's ID that fits an audit details key with its `_medium` suffix."""


class SystemActor(StrEnum):
    """The named system actors of the scan pipeline (authn and authz 6.1)."""

    SCAN_WORKER = "scan_worker"
    SCAN_SWEEP = "scan_sweep"


@dataclass(frozen=True, slots=True)
class ScanResult:
    """What the malware scan found: the file's next state, and why if it isn't clean."""

    state: FileState
    detail: ScanDetail | None = None
    engine: ScanEngine | None = ScanEngine.CLAMAV


@dataclass(frozen=True, slots=True)
class InspectionResult:
    """What the DLP inspector answered, checked against its schema (`sft.dlp.protocol`)."""

    state: InspectionState
    reasons: tuple[InspectionReason, ...] = ()
    engine_version: str | None = None
    findings: tuple[Counts, ...] = field(default_factory=tuple)
    policy_version: int | None = None
    """The tenant's DLP policy version whose detectors the inspector ran with (#218); None when
    the inspector gave no result, or the tenant has no policy."""
    budget_exceeded: tuple[str, ...] = ()
    """The tenant patterns stopped on the file for spending their budget, `custom:<id>`
    (#164)."""


SKIPPED: Final = InspectionResult(InspectionState.SKIPPED)
"""The inspection of an infected file, or one whose scan failed: no findings are kept."""


def tag_value(
    state: FileState,
    unscannable_allowed: bool,
    inspection: InspectionState,
    dlp_blocked: bool = False,
) -> str:
    """The `scan` tag's value (ADR-0019). The API may read only `clean` and `unscannable_allowed`
    objects, so a file whose inspection failed gets neither, and nor does a received file a DLP
    rule blocked (FR-51)."""
    if dlp_blocked:
        return DLP_BLOCKED_TAG
    if is_shareable(state, unscannable_allowed, inspection):
        return "clean" if state is FileState.CLEAN else "unscannable_allowed"
    if inspection is InspectionState.FAILED and state in (FileState.CLEAN, FileState.UNSCANNABLE):
        return "inspection_failed"
    return state.value


def _audit_findings(found: Sequence[Counts]) -> dict[str, audit.Detail]:
    """Per detector, the distinct values counted at each confidence: IDs and counts only."""
    details: dict[str, audit.Detail] = {"findings": len(found)}
    for counts in found:
        if not _AUDIT_KEY.fullmatch(counts.detector):
            continue  # a tenant's own detector (`custom:…`): counted above, never named
        for level in ("low", "medium", "high"):
            value = getattr(counts, level)
            if value:
                details[f"{counts.detector}_{level}"] = value
    return details


async def note_received(session: AsyncSession, request_id: UUID, *, shareable: bool) -> None:
    """A received file of the request settled, shareable or blocked: it counts towards the
    request's next notice, and the result that makes that notice due writes its one message,
    delayed by the notice window (module docstring)."""
    if await upload_requests.note_settled(session, request_id, shareable=shareable):
        await enqueue(
            session,
            UPLOAD_REQUEST_FILES_SETTLED,
            {"upload_request_id": request_id},
            delay=upload_requests.NOTICE_WINDOW,
        )


async def record(
    session: AsyncSession,
    file_id: UUID,
    transfer_id: UUID | None,
    scan: ScanResult,
    inspection: InspectionResult,
    *,
    attempts: int,
    sha256: bytes | None = None,
    upload_request_id: UUID | None = None,
) -> bool:
    """Record the result if the file is still `scanning` (module docstring); False if it wasn't.
    `sha256` is the digest of the version the worker read in full, if it did (#180). A received
    file's result counts towards its request's next notice, in the same transaction (#213)."""
    if scan.state in (FileState.INFECTED, FileState.SCAN_FAILED):
        inspection = SKIPPED
    allowed = False
    if scan.state is FileState.UNSCANNABLE:
        policy = await tenants.unscannable_policy(session)
        allowed = policy is UnscannablePolicy.ALLOW_WITH_WARNING
    changed = await files.record_scan(
        session,
        file_id,
        state=scan.state,
        engine=scan.engine,
        detail=scan.detail,
        attempts=attempts,
        unscannable_allowed=allowed,
        inspection_state=inspection.state,
        inspection_reasons=inspection.reasons,
        inspection_engine_version=inspection.engine_version,
        inspection_policy_version=inspection.policy_version,
        sha256=sha256,
    )
    if not changed:
        return False
    # Location hints and previews sealed under the tenant's DLP data key first (#233).
    found = await finding_details.seal_findings(session, inspection.findings)
    await findings.insert_findings(session, file_id, found)
    reasons: dict[str, audit.Detail] = {f"reason_{r.value}": True for r in inspection.reasons}
    owner: dict[str, audit.Detail] = (
        {"transfer_id": transfer_id}
        if upload_request_id is None
        else {"upload_request_id": upload_request_id}
    )
    dlp_blocked = False
    if upload_request_id is not None:
        shareable = is_shareable(scan.state, allowed, inspection.state)
        if shareable:
            decided = await dlp_decision.decide_received(
                session,
                file_id,
                reasons=[r.value for r in inspection.reasons],
                found=inspection.findings,
            )
            if decided is not None:
                dlp_blocked = dlp_decision.blocks(decided)
                if dlp_blocked:
                    await files.block_received(session, file_id)
                await _record_received_decision(session, file_id, upload_request_id, decided)
        await note_received(session, upload_request_id, shareable=shareable and not dlp_blocked)
    if inspection.budget_exceeded:
        await _record_stops(session, file_id, inspection.budget_exceeded)
    await audit.record(
        session,
        action="file.scanned",
        actor=SYSTEM,
        target=Target(FILE, file_id),
        details={
            "system_actor": SystemActor.SCAN_WORKER,
            **owner,
            "state": scan.state,
            "scan_engine": scan.engine,
            "scan_detail": scan.detail,
            "attempts": attempts,
            "unscannable_allowed": allowed,
            "inspection_state": inspection.state,
            "inspection_policy_version": inspection.policy_version,
            **({"dlp_blocked": True} if dlp_blocked else {}),
            **reasons,
            **_audit_findings(inspection.findings),
        },
    )
    return True


async def _record_received_decision(
    session: AsyncSession, file_id: UUID, upload_request_id: UUID, decided: Decided
) -> None:
    """`dlp.decided` for a received file, and `dlp.rule_matched` per rule it matched: IDs, enums
    and counts only, as for a transfer (`sft.service.evaluation`)."""
    await audit.record(
        session,
        action="dlp.decided",
        actor=SYSTEM,
        target=Target(FILE, file_id),
        details={
            "system_actor": SystemActor.SCAN_WORKER,
            "upload_request_id": upload_request_id,
            "decision_id": decided.id,
            "outcome": decided.outcome,
            "mode": decided.mode,
            "enforced": decided.enforced,
            "policy_version": decided.policy_version,
            "matched_rules": len(decided.matches),
            "dlp_blocked": dlp_decision.blocks(decided),
        },
    )
    for match in decided.matches:
        await audit.record(
            session,
            action="dlp.rule_matched",
            actor=SYSTEM,
            target=Target(DLP_RULE, match.rule.id),
            details={
                "system_actor": SystemActor.SCAN_WORKER,
                "decision_id": decided.id,
                "file_id": file_id,
                "rule_revision": match.rule.revision,
                "action": DlpAction(match.rule.action),
                "matched_count": match.count,
            },
        )


MAX_STOPPED: Final = 20
"""A tenant has at most 20 patterns (detectors 5), so a result names at most 20."""


async def _record_stops(session: AsyncSession, file_id: UUID, stopped: Sequence[str]) -> None:
    """The patterns stopped on the file (#164): one more stop each, and one
    `dlp.pattern_budget_exceeded` with their IDs. A name that isn't `custom:<uuid>` is dropped:
    the protocol allows only tenant patterns there."""
    ids: list[UUID] = []
    for name in stopped[:MAX_STOPPED]:
        if not name.startswith(CUSTOM_PREFIX):
            continue
        try:
            detector_id = UUID(name.removeprefix(CUSTOM_PREFIX))
        except ValueError:
            continue
        if detector_id not in ids:
            ids.append(detector_id)
    if not ids:
        return
    await dlp_policy.record_pattern_stops(session, ids)
    await audit.record(
        session,
        action="dlp.pattern_budget_exceeded",
        actor=SYSTEM,
        target=Target(FILE, file_id),
        details={
            "system_actor": SystemActor.SCAN_WORKER,
            "patterns": len(ids),
            # Details keys are lower-case letters only: `detector_a` to `detector_t`.
            **{f"detector_{ascii_lowercase[i]}": detector_id for i, detector_id in enumerate(ids)},
        },
    )


@dataclass(frozen=True, slots=True)
class Swept:
    file_id: UUID
    detail: ScanDetail


async def fail_overdue_scans(
    database: Database, *, now: datetime, limit: int = SWEEP_BATCH
) -> list[Swept]:
    """The scan sweep, as `sft_jobs` (module docstring). Returns the files it failed."""
    async with database.transaction(Scope.system()) as session:
        overdue = await files.overdue_scans(session, limit=limit)
    swept = []
    for item in overdue:
        async with database.transaction(Scope.tenant(item.tenant_id)) as session:
            detail, inspection = ScanDetail.DEADLINE_PASSED, InspectionState.FAILED
            owner = await files.fail_overdue_scan(
                session, item.file_id, detail=detail, inspection_state=inspection
            )
            if owner is None:
                continue  # a result came first
            owned: dict[str, audit.Detail] = (
                {"transfer_id": owner.transfer_id}
                if owner.upload_request_id is None
                else {"upload_request_id": owner.upload_request_id}
            )
            await audit.record(
                session,
                action="file.scanned",
                actor=SYSTEM,
                target=Target(FILE, item.file_id),
                details={
                    "system_actor": SystemActor.SCAN_SWEEP,
                    **owned,
                    "state": FileState.SCAN_FAILED,
                    "scan_detail": detail,
                    "inspection_state": inspection,
                },
            )
            if owner.upload_request_id is not None:
                # A received file: blocked, so both sides hear of it (FR-12).
                await note_received(session, owner.upload_request_id, shareable=False)
            elif owner.transfer_id is not None:
                await evaluate(
                    session,
                    owner.transfer_id,
                    actor=SYSTEM,
                    now=now,
                    details={"system_actor": SystemActor.SCAN_SWEEP},
                )
        swept.append(Swept(item.file_id, detail))
    return swept
