"""A transfer's DLP decision for its sender: `getTransferDlp` and `confirmTransfer` (#219; FR-41,
FR-42, FR-45, FR-46, FR-53; architecture 4.6; data model 2.7, 3.2; authn and authz 5.3, 6.3).

**`getTransferDlp`** (`dlp_findings.read`) shows the transfer's current decision, `null` until
there is one: its outcome, mode and policy version, the rules it matched as their revisions were
(name, condition, action, the count that crossed the threshold; the threshold for a `content`
rule only), each recipient's trust and new-domain flags, each counted file's inspection and
findings (detectors in the caller's language, counts only), and the message's findings (none
until #221). The owner sees it, as do an admin acting as one and an API key with
`transfers:read` (another member gets 404, a key without that scope 404, as for
`getFileInspection`). An active approver reads it too for a transfer that has an approval request
(authn and authz 6.3: "an approver who isn't an admin reaches only transfers with an approval
request"; #220), so one who has decided still sees what they decided on. `approval_request` is the
transfer's latest request, in whatever state (`sft.service.approval_requests.summary`). Location
hints and masked previews arrive with DLP-8, so `details_visible` is false for everyone and no
response holds details to audit.

- A recipient's flags are worked out as they are read: trusted against the policy's trusted
  domains now, and new if the tenant hadn't first sent to the domain before the decision (or, with
  no decision yet, in the last 365 days). The decision's own counts are as it made them.

**`confirmTransfer`** (`transfer.confirm`) is the sender's answer to a warning (FR-42). In order
(authn and authz 6.4: 404, then 403, then 409):

1. Only a person, in a web session: an API key gets `403` (`DLP_PEOPLE_ONLY`). Only the owner:
   another member gets 404; an admin acting as one sees the transfer, so gets `403` (authn and
   authz 6.1, point 4), which is the issue's "an admin on another member's transfer `403`"; a
   local admin without a passkey acts as a member and gets 404.
2. Under the transfer's row lock: a transfer already `sent` or `pending_approval` under the named
   decision comes back as it is, so a retry is safe. `revoked`, `expired` and `cancelled` are
   their 409s. A transfer whose current decision isn't `decision_id` (a file was removed in
   another tab, say) is `409 dlp_decision_changed` and changes nothing; any other state is
   `409 invalid_state`.
3. A warning: the confirmation is recorded (`dlp_confirmations`, the justification sealed with
   `sft.service.fields`, never logged), then the transfer is sent as from the evaluation
   (`sft.service.evaluation.send`): counters, recipients queued, domains known, `transfer.sent`.
   `transfer.confirmed` records the decision and whether a justification was given, never the text.
4. A required approval (FR-43, #220): `sft.service.approval_requests.request_approval` checks the
   justification, the 3 requests and the eligible approvers, then records the confirmation and a
   pending request and moves the transfer to `pending_approval`. A refusal for want of an
   approver (`409 no_eligible_approver`) rolls the transaction back, and a second transaction
   tells the tenant's admins (`tell_admins`).

Rate limits (abuse 2.2, K): `getTransferDlp` 600 reads an hour, `confirmTransfer` 30 a minute,
per account, both with group H (`sft.api.dlp`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import Conflict, NotFound
from sft.core.ids import uuid7
from sft.data import audit, dlp_decisions, dlp_policy, files, findings, tenants, transfers
from sft.data.access import NotFoundError
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.dlp_decisions import Decision
from sft.data.models import (
    DlpCondition,
    DlpOutcome,
    FileState,
    InspectionReason,
    InspectionState,
    Transfer,
    TransferState,
)
from sft.service import fields
from sft.service.approval_requests import (
    ApprovalSummaryView,
    NoEligibleApprover,
    active_approver,
    summary,
    tell_admins,
)
from sft.service.approval_requests import request_approval as _request_approval
from sft.service.caller import Caller, CallerKind
from sft.service.dlp_decision import KNOWN_FOR, check_recipients, normalise_domain
from sft.service.evaluation import send
from sft.service.file_reads import TRANSFERS_READ, FindingView, detector_name
from sft.service.permissions import Reach, authorize
from sft.service.transfers import (
    TRANSFER,
    TransferView,
    audit_details,
    effective_state,
    require_reach,
    require_visible,
    tenant_scope,
    transfer_view,
)

CONFIRMED_ALREADY: Final = frozenset({TransferState.SENT, TransferState.PENDING_APPROVAL})
"""States a confirmation of the transfer's current decision leads to: a repeat returns them."""


# ---- getTransferDlp ----


@dataclass(frozen=True, slots=True)
class RecipientFlags:
    recipient_id: UUID
    email: str
    trusted: bool
    new_domain: bool


@dataclass(frozen=True, slots=True)
class FileFindings:
    file_id: UUID
    display_name: str
    inspection_state: InspectionState
    reasons: tuple[InspectionReason, ...]
    findings: tuple[FindingView, ...]


@dataclass(frozen=True, slots=True)
class TransferDlpView:
    transfer_id: UUID
    state: TransferState
    decision: Decision | None
    recipients: tuple[RecipientFlags, ...]
    files: tuple[FileFindings, ...]
    message_findings: tuple[FindingView, ...] = ()
    """The message's findings (FR-50): none until #221 inspects the message."""
    approval_request: ApprovalSummaryView | None = None
    """The transfer's latest approval request, in whatever state (#220)."""


def threshold_of(condition: str, threshold: int) -> int | None:
    """A matched rule's threshold as the contract shows it: only a `content` rule has one."""
    return threshold if condition == DlpCondition.CONTENT.value else None


async def get_transfer_dlp(
    database: Database,
    caller: Caller,
    transfer_id: UUID,
    *,
    language: str | None,
    now: datetime,
) -> TransferDlpView:
    """`getTransferDlp` (module docstring)."""
    reach = authorize(caller, "getTransferDlp", now=now)
    if caller.kind is CallerKind.API_KEY and TRANSFERS_READ not in caller.scopes:
        # A transfer needs `transfers:read`; `upload_requests:read` reaches received files only.
        raise NotFound
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        try:
            transfer = await transfers.get_transfer(session, transfer_id)
        except NotFoundError:
            raise NotFound from None
        approval = await summary(session, transfer.id, now)
        try:
            require_visible(caller, reach, transfer)
        except NotFound:
            # An approver reaches a transfer with an approval request (authn and authz 6.3).
            if caller.kind is not CallerKind.MEMBER or approval is None:
                raise
            if not await active_approver(session, caller.user_id):
                raise
        if language not in ("en", "ja"):
            language = (await tenants.get_policy(session)).default_locale
        decision = None
        if transfer.dlp_decision_id is not None:
            decision = await dlp_decisions.get_decision(session, transfer.dlp_decision_id)
        recipients = await recipient_flags(session, transfer.id, decision, now)
        counted = await _file_findings(session, tenant_id, transfer.id, language)
        return TransferDlpView(
            transfer_id=transfer.id,
            state=effective_state(TransferState(transfer.state), transfer.expires_at, now),
            decision=decision,
            recipients=recipients,
            files=counted,
            approval_request=approval,
        )


async def recipient_flags(
    session: AsyncSession, transfer_id: UUID, decision: Decision | None, now: datetime
) -> tuple[RecipientFlags, ...]:
    rows = await transfers.list_recipients(session, transfer_id)
    domains = sorted({normalise_domain(r.domain) for r in rows if r.domain})
    if decision is None:
        known = await dlp_decisions.known_since(session, domains, since=now - KNOWN_FOR)
    else:
        known = await dlp_decisions.known_before(session, domains, at=decision.decided_at)
    policy = await dlp_policy.get_policy(session)
    trusted = tuple(policy.trusted_domains) if policy is not None else ()
    checks = check_recipients([(r.id, r.domain) for r in rows], trusted, known)
    return tuple(
        RecipientFlags(row.id, row.email, check.trusted, check.new_domain)
        for row, check in zip(rows, checks, strict=True)
    )


async def _file_findings(
    session: AsyncSession, tenant_id: UUID, transfer_id: UUID, language: str
) -> tuple[FileFindings, ...]:
    """The counted files (not rejected, not removed), each with its findings, counts only."""
    counted = [
        f
        for f in await files.list_transfer_files(session, transfer_id)
        if f.state != FileState.REJECTED.value
    ]
    found = await findings.counts_by_file(session, [f.id for f in counted])
    own: set[UUID] = set()
    for counts in (c for f in counted for c in found.get(f.id, ())):
        if counts.detector.startswith(dlp_policy.CUSTOM_PREFIX):
            try:
                own.add(UUID(counts.detector.removeprefix(dlp_policy.CUSTOM_PREFIX)))
            except ValueError:
                continue
    names = {
        dlp_policy.detector_ref(i): name
        for i, name in (await dlp_policy.detector_names(session, sorted(own))).items()
    }
    return tuple(
        FileFindings(
            file_id=f.id,
            display_name=fields.open_sealed(tenant_id, f.display_name_ct),
            inspection_state=InspectionState(f.inspection_state),
            reasons=tuple(InspectionReason(r) for r in f.inspection_reasons),
            findings=_finding_views(found.get(f.id, ()), names, language),
        )
        for f in counted
    )


def _finding_views(
    found: Sequence[findings.Counts], names: dict[str, str], language: str
) -> tuple[FindingView, ...]:
    return tuple(
        FindingView(
            detector=c.detector,
            detector_name=names.get(c.detector) or detector_name(c.detector, language),
            count_low=c.low,
            count_medium=c.medium,
            count_high=c.high,
        )
        for c in found
    )


# ---- confirmTransfer ----


def _not_confirmable(transfer: Transfer, state: TransferState, decision_id: UUID) -> Conflict:
    """The 409 for a transfer that isn't awaiting confirmation of `decision_id` (step 2)."""
    if state is TransferState.REVOKED:
        return Conflict("transfer_revoked", current_state=state.value)
    if state is TransferState.EXPIRED:
        return Conflict("transfer_expired", current_state=state.value)
    if state is not TransferState.CANCELLED and transfer.dlp_decision_id not in (None, decision_id):
        return Conflict(
            "dlp_decision_changed",
            "The transfer has a newer DLP decision: review it again.",
            current_state=state.value,
        )
    return Conflict(
        "invalid_state",
        "Only a transfer awaiting confirmation can be confirmed.",
        current_state=state.value,
    )


async def confirm_transfer(
    database: Database,
    caller: Caller,
    transfer_id: UUID,
    *,
    decision_id: UUID,
    justification: str | None,
    origin: Origin,
    now: datetime,
) -> TransferView:
    """`confirmTransfer` (module docstring)."""
    reach = authorize(caller, "confirmTransfer", now=now)
    scope = tenant_scope(caller)
    tenant_id, user_id = scope.tenant_id, caller.user_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    assert user_id is not None  # noqa: S101 - checked by tenant_scope
    try:
        return await _confirm(
            database, caller, transfer_id, reach, decision_id, justification, origin, now
        )
    except NoEligibleApprover as refused:
        # The refusal changed nothing; the admins' notice commits on its own (step 4).
        await tell_admins(database, caller, refused, origin)
        raise


async def _confirm(
    database: Database,
    caller: Caller,
    transfer_id: UUID,
    reach: Reach,
    decision_id: UUID,
    justification: str | None,
    origin: Origin,
    now: datetime,
) -> TransferView:
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        try:
            transfer = await transfers.get_transfer(session, transfer_id, lock=True)
        except NotFoundError:
            raise NotFound from None
        require_reach(caller, reach, transfer, now)
        state = effective_state(TransferState(transfer.state), transfer.expires_at, now)
        if state in CONFIRMED_ALREADY and transfer.dlp_decision_id == decision_id:
            return await transfer_view(session, tenant_id, transfer, now)
        if state is not TransferState.AWAITING_CONFIRMATION or (
            transfer.dlp_decision_id != decision_id
        ):
            raise _not_confirmable(transfer, state, decision_id)
        decision = await dlp_decisions.get_decision(session, decision_id)
        if decision is None:  # pragma: no cover - the transfer's key names it
            raise RuntimeError("the transfer's decision is missing")
        if DlpOutcome(decision.outcome) is DlpOutcome.REQUIRE_APPROVAL:
            await _request_approval(session, caller, transfer, decision, justification, origin, now)
            pending = await transfers.get_transfer(session, transfer.id)
            return await transfer_view(session, tenant_id, pending, now)
        if DlpOutcome(decision.outcome) is not DlpOutcome.WARN:  # pragma: no cover
            raise RuntimeError("a transfer awaits confirmation only of a warning or an approval")
        await _confirm_warning(session, caller, transfer, decision, justification, origin, now)
        sent = await transfers.get_transfer(session, transfer.id)
        return await transfer_view(session, tenant_id, sent, now)


async def _confirm_warning(
    session: AsyncSession,
    caller: Caller,
    transfer: Transfer,
    decision: Decision,
    justification: str | None,
    origin: Origin,
    now: datetime,
) -> None:
    """Step 3: record the confirmation, then send the transfer as the evaluation would."""
    tenant_id, user_id = caller.tenant_id, caller.user_id
    assert tenant_id is not None  # noqa: S101 - checked by tenant_scope
    assert user_id is not None  # noqa: S101 - checked by tenant_scope
    confirmation_id = uuid7()
    await dlp_decisions.insert_confirmation(
        session,
        confirmation_id=confirmation_id,
        transfer_id=transfer.id,
        decision_id=decision.id,
        confirmed_by=user_id,
        justification_ct=None if justification is None else fields.seal(tenant_id, justification),
    )
    target = Target(TRANSFER, transfer.id)
    await audit.record(
        session,
        action="transfer.confirmed",
        actor=caller.actor(),
        target=target,
        origin=origin,
        details=audit_details(
            caller,
            decision_id=decision.id,
            confirmation_id=confirmation_id,
            outcome=DlpOutcome(decision.outcome),
            justification_given=justification is not None,
        ),
    )
    locked = await transfers.lock_for_evaluation(session, transfer.id)
    counted = await files.counted_states(session, transfer.id)
    await send(session, locked, [f.id for f in counted])
    await audit.record(
        session,
        action="transfer.sent",
        actor=caller.actor(),
        target=target,
        origin=origin,
        details=audit_details(
            caller,
            from_state=TransferState.AWAITING_CONFIRMATION,
            files=len(counted),
            decision_id=decision.id,
        ),
    )
