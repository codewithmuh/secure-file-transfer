"""The tenant's DLP policy, rules and own detectors, for tenant admins (#218, DLP-4; FR-38, FR-40,
FR-41, FR-45, FR-54; data model 2.7; detectors 5, 6; ADR-0022).

The operations of the contract's "Data loss prevention" tag that manage the policy:
`getDlpPolicy`, `updateDlpPolicy`, `listDlpRules`, `createDlpRule`, `getDlpRule`, `updateDlpRule`,
`deleteDlpRule`, `listDlpDetectors`, `createDlpDetector`, `getDlpDetector`, `updateDlpDetector` and
`deleteDlpDetector`.

**Who** (authn and authz 6.3, 5.3): tenant admins acting as one (a local admin needs a passkey
sign-in), never a member or an approver; every write needs a sign-in in the last 15 minutes. API
keys are refused with `403`: the policy needs a web session (`DLP_PEOPLE_ONLY`). Another tenant's
rule or detector is `404`, as is a deleted one.

**Every write** runs in one transaction of the caller's tenant that:

1. locks the policy row, so the tenant's policy changes run one at a time, and checks
   `expected_version` when sent (`409 dlp_policy_conflict`): two admins editing the same version
   can't both win;
2. makes the change: the policy's fields, or a rule's or detector's next revision with the old one
   retired, or a deletion that only retires (data model 2.7);
3. raises the policy version once (`dlp_policies.version`), so a decision names the policy it
   applied;
4. writes the audit event: `dlp_policy.updated` with the fields changed and counts of domains,
   `dlp_rule.created|changed|deleted`, `dlp_detector.created|changed|deleted`, each with the ID,
   the revision and the new policy version, never a keyword, a threshold or a domain (FR-54). A
   name is free text, which audit details never hold (`sft.data.audit.Detail`): the target's ID
   names it, and its revision row keeps it;
5. writes one outbox message per kind of change (`dlp_policy.changed.<kind>`), which the
   notification worker turns into `dlp_policy_changed` to every active admin (FR-54);
6. charges the tenant's 100 policy changes a day (abuse 2.2, K), last, so a refused change writes
   nothing and only a change that is made counts.

A write that changes nothing (the values sent are the ones there) returns the item as it is,
with no new revision, version, event, email or charge.

**What #218 accepts** (the Should parts are #221's, refused with `422 validation_failed` until
then rather than stored and ignored): only `enforce` mode, `sent` rules, one approver, no 24-hour
window, keyword lists but no patterns. `require_approval` is accepted with its rule: the tenant
needs more active approvers than the rule needs (`422 approvers_insufficient`) to create or enable
one; #220 makes it act. A tenant has at most 50 live rules and 50 detectors.

**Keyword lists** are checked by the detector library as the inspector will compile them
(`sft.dlp.detect.validate`), then together with the tenant's other live detectors, so a set the
inspector couldn't compile is refused when it is saved, not when a file is scanned. Their terms
are stored sealed (`sft.service.dlp_definitions`) and never logged.

**Built-in detectors** come from the inspection engine: `listDlpDetectors` lists them with names
and descriptions in the caller's language (`Accept-Language`, else the tenant's default language),
with the engine's version. They can't be changed or deleted (`409 invalid_state`).
"""

from __future__ import annotations

import functools
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import Conflict, FieldError, NotFound, Unprocessable, json_pointer
from sft.core.ids import uuid7
from sft.data import audit, dlp_policy, tenants
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.dlp_policy import CUSTOM_PREFIX, DetectorFields, RuleFields, detector_ref
from sft.data.models import (
    DlpAction,
    DlpCondition,
    DlpConfidence,
    DlpDetector,
    DlpDetectorKind,
    DlpDirection,
    DlpMode,
    DlpPolicy,
    DlpRecipientScope,
    DlpRule,
    InspectionReason,
)
from sft.data.outbox import DLP_POLICY_CHANGED, enqueue
from sft.dlp.detect import BUILTIN_DETECTORS, DetectorError, validate
from sft.dlp.detect.tenant import TenantDetectors
from sft.dlp.engine import load_engine
from sft.service.caller import Caller
from sft.service.dlp_definitions import (
    Definition,
    Keywords,
    detector_unit,
    open_definition,
    seal_definition,
)
from sft.service.email.catalog import PolicyChange
from sft.service.file_reads import DETECTOR_NAMES
from sft.service.idempotency import IdempotentRequest, Outcome, once
from sft.service.permissions import authorize
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import DLP_POLICY_CHANGE
from sft.service.transfers import tenant_scope

log = logging.getLogger(__name__)

POLICY_TARGET: Final = "dlp_policy"
RULE_TARGET: Final = "dlp_rule"
DETECTOR_TARGET: Final = "dlp_detector"

MAX_LIVE_RULES: Final = 50
MAX_DETECTORS: Final = 50
MAX_TRUSTED_DOMAINS: Final = 500
MIN_APPROVAL_TIMEOUT: Final = timedelta(hours=1)
MAX_APPROVAL_TIMEOUT: Final = timedelta(days=7)


# ---- built-in detectors (detectors 4) ----

DETECTOR_DESCRIPTIONS: Final[Mapping[str, tuple[str, str]]] = {
    "jp_my_number": (
        "12-digit Individual Numbers with a valid check digit; high confidence near a label "
        "such as マイナンバー.",
        "検査数字が正しい12桁の個人番号。「マイナンバー」などの見出しの近くでは確度が高くなります。",
    ),
    "jp_corporate_number": (
        "13-digit Corporate Numbers with a valid check digit; higher confidence near a label.",
        "検査数字が正しい13桁の法人番号。見出しの近くでは確度が高くなります。",
    ),
    "payment_card": (
        "Card numbers of known issuers that pass the Luhn check; high confidence near a label.",
        "主要ブランドの番号体系に合いLuhnチェックを通るカード番号。見出しの近くでは確度が高くなります。",
    ),
    "jp_bank_account": (
        "Japanese bank and branch codes with a 7-digit account number, near a banking label.",
        "金融機関コード・支店コードと7桁の口座番号。銀行関連の見出しの近くで検出します。",
    ),
    "iban": (
        "International Bank Account Numbers that pass the ISO 13616 check.",
        "ISO 13616の検査を通る国際銀行口座番号(IBAN)。",
    ),
    "phone_number": (
        "Japanese and international phone numbers; higher confidence near a label.",
        "国内・国際の電話番号。見出しの近くでは確度が高くなります。",
    ),
    "email_address": (
        "Email addresses with a known top-level domain.",
        "既知のトップレベルドメインを持つメールアドレス。",
    ),
    "jp_passport": (
        "Japanese passport numbers near a passport label.",
        "旅券の見出しの近くにある日本の旅券番号。",
    ),
    "passport_mrz": (
        "Machine-readable zones of passports, with valid check digits.",
        "検査数字が正しい旅券の機械読取領域(MRZ)。",
    ),
    "jp_drivers_licence": (
        "12-digit Japanese driver's licence numbers with a valid check digit, near a label.",
        "見出しの近くにある、検査数字が正しい12桁の運転免許証番号。",
    ),
    "cloud_credential": (
        "Access keys and tokens of cloud providers and developer services.",
        "クラウドや開発者向けサービスのアクセスキーとトークン。",
    ),
    "private_key": (
        "PEM and OpenSSH private keys.",
        "PEM形式とOpenSSH形式の秘密鍵。",
    ),
    "confidentiality_label": (
        "Confidentiality labels such as Confidential or 社外秘.",
        "「Confidential」や「社外秘」などの機密表示。",
    ),
}
"""What each built-in detector finds and how its confidence is set, in English and Japanese."""


@functools.cache
def engine_version() -> str:
    """The inspection engine version whose built-in detectors are listed ([DLP] 9)."""
    return load_engine().version


def builtin_ids() -> list[str]:
    """The engine's built-in detectors, in the order of detectors 4 where named there."""
    named = [d for d in DETECTOR_NAMES if d in BUILTIN_DETECTORS]
    return named + sorted(BUILTIN_DETECTORS - set(named))


def _language(language: str | None, fallback: str) -> str:
    return language if language in ("en", "ja") else fallback


# ---- views ----


@dataclass(frozen=True, slots=True)
class PolicyView:
    mode: DlpMode
    version: int
    trusted_domains: tuple[str, ...]
    approval_timeout: timedelta
    active_approvers: int
    updated_at: datetime
    updated_by: UUID | None


@dataclass(frozen=True, slots=True)
class RuleList:
    policy_version: int
    items: tuple[DlpRule, ...]


@dataclass(frozen=True, slots=True)
class DetectorView:
    """A built-in detector, or one of the tenant's own with its definition."""

    id: str
    kind: str
    name: str
    enabled: bool
    description: str | None = None
    revision: int | None = None
    definition: Definition | None = None
    created_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class DetectorList:
    engine_version: str
    items: tuple[DetectorView, ...]


# ---- requests ----


@dataclass(frozen=True, slots=True)
class PolicyUpdate:
    """The fields of `DlpPolicyUpdate` that were sent; None leaves a field as it is."""

    expected_version: int | None = None
    mode: DlpMode | None = None
    trusted_domains: Sequence[str] | None = None
    approval_timeout: timedelta | None = None


@dataclass(frozen=True, slots=True)
class RuleCreate:
    """`DlpRuleCreate`, its defaults applied."""

    name: str
    direction: DlpDirection
    condition: DlpCondition
    action: DlpAction
    expected_version: int | None = None
    enabled: bool = True
    detectors: Sequence[str] = ()
    min_confidence: DlpConfidence = DlpConfidence.MEDIUM
    threshold: int = 1
    reasons: Sequence[InspectionReason] = ()
    include_sender_24h: bool = False
    recipient_scope: DlpRecipientScope = DlpRecipientScope.ANY
    approvals_required: int = 1


@dataclass(frozen=True, slots=True)
class RuleUpdate:
    """The fields of `DlpRuleUpdate` that were sent; None leaves a field as it is."""

    expected_version: int | None = None
    name: str | None = None
    enabled: bool | None = None
    condition: DlpCondition | None = None
    detectors: Sequence[str] | None = None
    min_confidence: DlpConfidence | None = None
    threshold: int | None = None
    reasons: Sequence[InspectionReason] | None = None
    include_sender_24h: bool | None = None
    recipient_scope: DlpRecipientScope | None = None
    action: DlpAction | None = None
    approvals_required: int | None = None


@dataclass(frozen=True, slots=True)
class DetectorCreate:
    """`DlpDetectorCreate`. The pattern fields are #221's: sent with `kind: keywords` or at all
    before then, they are refused."""

    name: str
    kind: DlpDetectorKind
    expected_version: int | None = None
    enabled: bool = True
    keywords: Sequence[str] | None = None
    pattern: str | None = None
    context_keywords: Sequence[str] | None = None
    min_length: int | None = None


@dataclass(frozen=True, slots=True)
class DetectorUpdate:
    """The fields of `DlpDetectorUpdate` that were sent; None leaves a field as it is."""

    expected_version: int | None = None
    name: str | None = None
    enabled: bool | None = None
    keywords: Sequence[str] | None = None
    pattern: str | None = None
    context_keywords: Sequence[str] | None = None
    case_insensitive: bool | None = None
    min_length: int | None = None


# ---- errors ----


def _invalid(detail: str, *fields: str | int) -> Unprocessable:
    """`422 validation_failed`, pointing at the body field that breaks the rule, if one does."""
    pointer = json_pointer(*fields) if fields else None
    return Unprocessable("validation_failed", detail, errors=[FieldError(detail, pointer=pointer)])


def _not_yet(field: str, what: str) -> Unprocessable:
    return _invalid(f"{what} arrives with #221; it can't be set yet.", field)


def _stale() -> Conflict:
    return Conflict("dlp_policy_conflict", "The policy changed since it was read: load it again.")


# ---- reads ----


async def get_dlp_policy(database: Database, caller: Caller, *, now: datetime) -> PolicyView:
    """`getDlpPolicy`."""
    authorize(caller, "getDlpPolicy", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        policy = await _policy(session)
        return await _policy_view(session, policy)


async def list_dlp_rules(database: Database, caller: Caller, *, now: datetime) -> RuleList:
    """`listDlpRules`: the live rules, with the policy version they belong to."""
    authorize(caller, "listDlpRules", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        policy = await _policy(session)
        rules = await dlp_policy.list_live_rules(session)
    return RuleList(policy.version, tuple(rules))


async def get_dlp_rule(
    database: Database, caller: Caller, rule_id: UUID, *, now: datetime
) -> DlpRule:
    """`getDlpRule`: the rule's live revision, or `404`."""
    authorize(caller, "getDlpRule", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        rule = await dlp_policy.get_live_rule(session, rule_id)
    if rule is None:
        raise NotFound
    return rule


async def list_dlp_detectors(
    database: Database, caller: Caller, *, language: str | None, now: datetime
) -> DetectorList:
    """`listDlpDetectors`: the engine's built-in detectors, then the tenant's own."""
    authorize(caller, "listDlpDetectors", now=now)
    scope = tenant_scope(caller)
    assert scope.tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        language = _language(language, (await tenants.get_policy(session)).default_locale)
        own = await dlp_policy.list_live_detectors(session)
    items = [_builtin(d, language) for d in builtin_ids()]
    items += [_own(scope.tenant_id, d) for d in own]
    return DetectorList(engine_version(), tuple(items))


async def get_dlp_detector(
    database: Database, caller: Caller, detector_id: str, *, language: str | None, now: datetime
) -> DetectorView:
    """`getDlpDetector`: a built-in detector by its ID, or one of the tenant's own by `custom:`
    and its ID; `404` otherwise."""
    authorize(caller, "getDlpDetector", now=now)
    scope = tenant_scope(caller)
    assert scope.tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    own_id = _own_id(detector_id)
    async with database.transaction(scope) as session:
        if own_id is None:
            language = _language(language, (await tenants.get_policy(session)).default_locale)
            return _builtin(detector_id, language)
        detector = await dlp_policy.get_live_detector(session, own_id)
    if detector is None:
        raise NotFound
    return _own(scope.tenant_id, detector)


def _own_id(detector_id: str) -> UUID | None:
    """The tenant detector's ID in `custom:<id>`; None for a built-in one; `404` for an ID that
    is neither."""
    if detector_id.startswith(CUSTOM_PREFIX):
        try:
            return UUID(detector_id.removeprefix(CUSTOM_PREFIX))
        except ValueError:
            raise NotFound from None
    if detector_id not in BUILTIN_DETECTORS:
        raise NotFound
    return None


def _builtin(detector_id: str, language: str) -> DetectorView:
    index = 1 if language == "ja" else 0
    names = DETECTOR_NAMES.get(detector_id)
    description = DETECTOR_DESCRIPTIONS.get(detector_id)
    return DetectorView(
        id=detector_id,
        kind="built_in",
        name=names[index] if names else detector_id,
        description=description[index] if description else None,
        enabled=True,
    )


def _own(tenant_id: UUID, detector: DlpDetector) -> DetectorView:
    return DetectorView(
        id=detector_ref(detector.id),
        kind=detector.kind,
        name=detector.name,
        enabled=detector.enabled,
        revision=detector.revision,
        definition=open_definition(tenant_id, detector.definition_ct),
        created_at=detector.created_at,
    )


async def _policy(session: AsyncSession, *, lock: bool = False) -> DlpPolicy:
    policy = await dlp_policy.get_policy(session, lock=lock)
    if policy is None:
        # Revision 0024 and createTenant give every tenant one; a tenant without is a bug.
        log.error("a tenant has no DLP policy")
        raise NotFound
    return policy


async def _policy_view(session: AsyncSession, policy: DlpPolicy) -> PolicyView:
    return PolicyView(
        mode=DlpMode(policy.mode),
        version=policy.version,
        trusted_domains=tuple(policy.trusted_domains),
        approval_timeout=policy.approval_timeout,
        active_approvers=await dlp_policy.count_active_approvers(session),
        updated_at=policy.updated_at,
        updated_by=policy.updated_by,
    )


# ---- the write every change makes ----


@dataclass(frozen=True, slots=True)
class _Write:
    caller: Caller
    limiter: RateLimiter
    origin: Origin
    tenant_id: UUID


async def _locked(session: AsyncSession, expected_version: int | None) -> DlpPolicy:
    """The policy, locked for this change, if `expected_version` is the current one."""
    policy = await _policy(session, lock=True)
    if expected_version is not None and expected_version != policy.version:
        raise _stale()
    return policy


async def _record(
    session: AsyncSession,
    write: _Write,
    *,
    action: str,
    target: Target,
    changes: Sequence[PolicyChange],
    details: Mapping[str, audit.Detail],
    mode: DlpMode | None = None,
    trusted_domains: Sequence[str] | None = None,
    approval_timeout: timedelta | None = None,
) -> DlpPolicy:
    """Steps 3 to 6 of the module docstring: the version (with the policy's own fields that
    changed), the event, the notices, the charge."""
    policy = await dlp_policy.raise_version(
        session,
        updated_by=write.caller.user_id,
        mode=mode,
        trusted_domains=trusted_domains,
        approval_timeout=approval_timeout,
    )
    await audit.record(
        session,
        action=action,
        actor=write.caller.actor(),
        target=target,
        origin=write.origin,
        details={**details, "policy_version": policy.version},
    )
    for change in changes:
        await enqueue(session, DLP_POLICY_CHANGED[change.value], {})
    await write.limiter.check(DLP_POLICY_CHANGE, write.caller.rate_limit_keys())
    return policy


def _write(caller: Caller, limiter: RateLimiter, origin: Origin) -> _Write:
    scope = tenant_scope(caller)
    assert scope.tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    return _Write(caller, limiter, origin, scope.tenant_id)


# ---- the policy's settings ----


def normalise_domain(value: str, index: int) -> str:
    """A trusted domain, lowercase and IDNA-normalised, with at least two labels: a top-level
    domain alone would trust everyone under it."""
    domain = value.strip().rstrip(".").lower()
    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise _invalid("Not a domain name.", "trusted_domains", index) from None
    labels = ascii_domain.split(".")
    if (
        len(ascii_domain) > 253
        or len(labels) < 2
        or not all(
            0 < len(label) <= 63
            and label[0] != "-"
            and label[-1] != "-"
            and all(c.isascii() and (c.isalnum() or c == "-") for c in label)
            for label in labels
        )
    ):
        raise _invalid("Not a domain name with at least two labels.", "trusted_domains", index)
    return ascii_domain


async def update_dlp_policy(
    database: Database,
    caller: Caller,
    change: PolicyUpdate,
    *,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
) -> PolicyView:
    """`updateDlpPolicy`: change the fields sent (module docstring)."""
    authorize(caller, "updateDlpPolicy", now=now)
    if change.mode is DlpMode.MONITOR:
        raise _not_yet("mode", "Monitor mode (FR-52)")
    timeout = change.approval_timeout
    if timeout is not None and not MIN_APPROVAL_TIMEOUT <= timeout <= MAX_APPROVAL_TIMEOUT:
        raise _invalid("approval_timeout is between PT1H and P7D.", "approval_timeout")
    domains: list[str] | None = None
    if change.trusted_domains is not None:
        domains = []
        for index, value in enumerate(change.trusted_domains):
            domain = normalise_domain(value, index)
            if domain not in domains:
                domains.append(domain)
        if len(domains) > MAX_TRUSTED_DOMAINS:
            raise _invalid("At most 500 trusted domains.", "trusted_domains")
    write = _write(caller, limiter, origin)
    async with database.transaction(tenant_scope(caller)) as session:
        policy = await _locked(session, change.expected_version)
        mode = change.mode if change.mode is not None and change.mode != policy.mode else None
        if domains == list(policy.trusted_domains):
            domains = None
        if timeout == policy.approval_timeout:
            timeout = None
        changes: list[PolicyChange] = []
        details: dict[str, audit.Detail] = {}
        if mode is not None:
            details["mode"] = mode
            changes.append(PolicyChange.MODE_CHANGED)
        if domains is not None:
            before = set(policy.trusted_domains)
            details["trusted_domains_changed"] = True
            details["trusted_domains"] = len(domains)
            details["trusted_domains_added"] = len(set(domains) - before)
            details["trusted_domains_removed"] = len(before - set(domains))
            changes.append(PolicyChange.TRUSTED_DOMAINS_CHANGED)
        if timeout is not None:
            details["approval_timeout_seconds"] = int(timeout.total_seconds())
            changes.append(PolicyChange.APPROVAL_TIMEOUT_CHANGED)
        if changes:
            policy = await _record(
                session,
                write,
                action="dlp_policy.updated",
                target=Target(POLICY_TARGET, write.tenant_id),
                changes=changes,
                details=details,
                mode=mode,
                trusted_domains=domains,
                approval_timeout=timeout,
            )
        return await _policy_view(session, policy)


# ---- rules ----


def _rule_fields(rule: DlpRule) -> RuleFields:
    return RuleFields(
        name=rule.name,
        direction=rule.direction,
        condition=rule.condition,
        detectors=tuple(rule.detectors),
        min_confidence=rule.min_confidence,
        threshold=rule.threshold,
        reasons=tuple(rule.reasons),
        include_sender_24h=rule.include_sender_24h,
        recipient_scope=rule.recipient_scope,
        action=rule.action,
        approvals_required=rule.approvals_required,
        enabled=rule.enabled,
    )


def _requires_approval(fields: RuleFields) -> bool:
    return fields.enabled and fields.action == DlpAction.REQUIRE_APPROVAL.value


async def _check_rule(
    session: AsyncSession,
    fields: RuleFields,
    *,
    sent: frozenset[str],
    before: RuleFields | None = None,
) -> RuleFields:
    """The rule's checks (module docstring), on its fields as they would be stored; the fields
    with those that don't apply to its condition cleared. `sent` names the fields the request
    sent, for the pointer of an error."""
    if fields.direction != DlpDirection.SENT.value:
        raise _not_yet("direction", "Rules for received files (FR-51)")
    if fields.include_sender_24h:
        raise _not_yet("include_sender_24h", "The sender's 24-hour window (FR-49)")
    if fields.approvals_required != 1:
        raise _not_yet("approvals_required", "Two approvers (FR-44)")
    condition = DlpCondition(fields.condition)
    if condition is DlpCondition.CONTENT:
        if not fields.detectors:
            raise _invalid("A content rule names at least one detector.", "detectors")
        if fields.reasons and "reasons" in sent:
            raise _invalid("Reasons are for a not_inspected rule.", "reasons")
        live = {detector_ref(d.id) for d in await dlp_policy.list_live_detectors(session)}
        for index, detector in enumerate(fields.detectors):
            if detector not in BUILTIN_DETECTORS and detector not in live:
                raise _invalid("No such detector.", "detectors", index)
        fields = replace(fields, reasons=())
    elif condition is DlpCondition.NOT_INSPECTED:
        if not fields.reasons:
            raise _invalid("A not_inspected rule names at least one reason.", "reasons")
        if fields.detectors and "detectors" in sent:
            raise _invalid("Detectors are for a content rule.", "detectors")
        fields = replace(fields, detectors=())
    else:
        for name in ("detectors", "reasons"):
            if getattr(fields, name) and name in sent:
                raise _invalid("A new_domain rule names no detectors or reasons.", name)
        fields = replace(fields, detectors=(), reasons=())
    newly_requires = _requires_approval(fields) and (
        before is None
        or not _requires_approval(before)
        or before.approvals_required != fields.approvals_required
    )
    if newly_requires:
        approvers = await dlp_policy.count_active_approvers(session)
        if approvers <= fields.approvals_required:
            raise Unprocessable(
                "approvers_insufficient",
                "The tenant needs more active approvers than the rule requires.",
            )
    return fields


def _rule_details(rule: DlpRule, **more: audit.Detail) -> dict[str, audit.Detail]:
    """The rule's enums, flags and revision: never its name, detectors' terms or threshold."""
    return {
        "revision": rule.revision,
        "direction": DlpDirection(rule.direction),
        "condition": DlpCondition(rule.condition),
        "action": DlpAction(rule.action),
        "recipient_scope": DlpRecipientScope(rule.recipient_scope),
        "enabled": rule.enabled,
        **more,
    }


async def create_dlp_rule(
    database: Database,
    caller: Caller,
    new: RuleCreate,
    *,
    sent: frozenset[str],
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[DlpRule]:
    """`createDlpRule`: a new rule at revision 1. With an `Idempotency-Key`, a retry gets the
    first answer and the rule as it is now (`sft.service.idempotency`)."""
    authorize(caller, "createDlpRule", now=now)
    write = _write(caller, limiter, origin)
    fields = RuleFields(
        name=new.name,
        direction=new.direction.value,
        condition=new.condition.value,
        detectors=tuple(new.detectors),
        min_confidence=new.min_confidence.value,
        threshold=new.threshold,
        reasons=tuple(r.value for r in new.reasons),
        include_sender_24h=new.include_sender_24h,
        recipient_scope=new.recipient_scope.value,
        action=new.action.value,
        approvals_required=new.approvals_required,
        enabled=new.enabled,
    )
    async with database.transaction(tenant_scope(caller)) as session:

        async def create() -> DlpRule:
            await _locked(session, new.expected_version)
            checked = await _check_rule(session, fields, sent=sent)
            if await dlp_policy.count_live_rules(session) >= MAX_LIVE_RULES:
                raise _invalid("A tenant has at most 50 rules.")
            rule = await dlp_policy.insert_rule(
                session, uuid7(), 1, checked, created_by=caller.user_id
            )
            await _record(
                session,
                write,
                action="dlp_rule.created",
                target=Target(RULE_TARGET, rule.id),
                changes=[PolicyChange.RULE_ADDED],
                details=_rule_details(rule),
            )
            return rule

        async def rebuild(rule_id: UUID) -> DlpRule | None:
            return await dlp_policy.get_live_rule(session, rule_id)

        return await once(
            session,
            caller,
            idempotency,
            status=201,
            resource_type=RULE_TARGET,
            create=create,
            rebuild=rebuild,
            resource_id=lambda rule: rule.id,
        )


async def update_dlp_rule(
    database: Database,
    caller: Caller,
    rule_id: UUID,
    change: RuleUpdate,
    *,
    sent: frozenset[str],
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
) -> DlpRule:
    """`updateDlpRule`: the rule's next revision, the old one retired; the rule as it is if
    nothing changes."""
    authorize(caller, "updateDlpRule", now=now)
    write = _write(caller, limiter, origin)
    async with database.transaction(tenant_scope(caller)) as session:
        await _locked(session, change.expected_version)
        rule = await dlp_policy.get_live_rule(session, rule_id)
        if rule is None:
            raise NotFound
        before = _rule_fields(rule)
        updates: dict[str, Any] = {
            f.name: _stored(getattr(change, f.name))
            for f in fields(RuleFields)
            if getattr(change, f.name, None) is not None
        }
        wanted = replace(before, **updates)
        if wanted == before:
            return rule
        checked = await _check_rule(session, wanted, sent=sent, before=before)
        if checked == before:
            return rule
        if not await dlp_policy.retire_rule(session, rule.id, rule.revision):  # pragma: no cover
            raise _stale()  # the lock rules this out
        changed = [
            f.name
            for f in fields(RuleFields)
            if getattr(checked, f.name) != getattr(before, f.name)
        ]
        new = await dlp_policy.insert_rule(
            session, rule.id, rule.revision + 1, checked, created_by=caller.user_id
        )
        await _record(
            session,
            write,
            action="dlp_rule.changed",
            target=Target(RULE_TARGET, rule.id),
            changes=[PolicyChange.RULE_CHANGED],
            details=_rule_details(new, **{f"changed_{name}": True for name in changed}),
        )
        return new


def _stored(value: object) -> object:
    """A request value as a rule revision stores it: enums as their values, lists as tuples."""
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, list | tuple):
        return tuple(_stored(v) for v in value)
    return value


async def delete_dlp_rule(
    database: Database,
    caller: Caller,
    rule_id: UUID,
    *,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
) -> None:
    """`deleteDlpRule`: retire the live revision; `404` if there is none."""
    authorize(caller, "deleteDlpRule", now=now)
    write = _write(caller, limiter, origin)
    async with database.transaction(tenant_scope(caller)) as session:
        await _locked(session, None)
        rule = await dlp_policy.get_live_rule(session, rule_id)
        if rule is None or not await dlp_policy.retire_rule(session, rule.id, rule.revision):
            raise NotFound
        await _record(
            session,
            write,
            action="dlp_rule.deleted",
            target=Target(RULE_TARGET, rule.id),
            changes=[PolicyChange.RULE_REMOVED],
            details={"revision": rule.revision},
        )


# ---- the tenant's own detectors ----


def _definition_error(error: DetectorError) -> Unprocessable:
    # The reason names the rule broken, never a term (sft.dlp.detect.tenant).
    if error.reason == "keywords_too_large":
        return _invalid("The tenant's keyword lists are too large together to inspect.", "keywords")
    return _invalid(f"The keyword list breaks a rule: {error.reason}.", "keywords")


async def _check_definitions(
    session: AsyncSession, tenant_id: UUID, detector_id: UUID, definition: Definition
) -> None:
    """The library's save-time checks of one detector, then of the tenant's live detectors with
    it, as the inspector will compile them for every file."""
    unit = detector_unit(detector_id, definition)
    others = [
        detector_unit(d.id, open_definition(tenant_id, d.definition_ct))
        for d in await dlp_policy.list_live_detectors(session)
        if d.id != detector_id and d.enabled
    ]
    try:
        validate(unit)
        TenantDetectors([*others, unit])
    except DetectorError as error:
        raise _definition_error(error) from None


def _keywords(terms: Sequence[str]) -> Keywords:
    if not 1 <= len(terms) <= 1000:
        raise _invalid("A keyword list has 1 to 1,000 terms.", "keywords")
    for index, term in enumerate(terms):
        if not term.strip() or len(term) > 100:
            raise _invalid("A term has 1 to 100 characters.", "keywords", index)
    return Keywords(tuple(terms))


def _detector_details(detector: DlpDetector, **more: audit.Detail) -> dict[str, audit.Detail]:
    """The detector's kind, flag and revision: never its name or its terms."""
    return {
        "revision": detector.revision,
        "kind": DlpDetectorKind(detector.kind),
        "enabled": detector.enabled,
        **more,
    }


async def create_dlp_detector(
    database: Database,
    caller: Caller,
    new: DetectorCreate,
    *,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
    idempotency: IdempotentRequest | None = None,
) -> Outcome[DetectorView]:
    """`createDlpDetector`: a keyword list at revision 1 (patterns are #221's)."""
    authorize(caller, "createDlpDetector", now=now)
    if new.kind is DlpDetectorKind.PATTERN:
        raise _not_yet("kind", "Patterns (FR-39)")
    for name in ("pattern", "context_keywords", "min_length"):
        if getattr(new, name) is not None:
            raise _invalid("Only a pattern has this field.", name)
    if new.keywords is None:
        raise _invalid("A keyword list needs its keywords.", "keywords")
    definition = _keywords(new.keywords)
    write = _write(caller, limiter, origin)
    if caller.user_id is None:  # pragma: no cover - authorize admits only members here
        raise NotFound
    created_by = caller.user_id
    async with database.transaction(tenant_scope(caller)) as session:

        async def create() -> DlpDetector:
            await _locked(session, new.expected_version)
            live = await dlp_policy.list_live_detectors(session)
            if len(live) >= MAX_DETECTORS:
                raise _invalid("A tenant has at most 50 detectors.")
            detector_id = uuid7()
            await _check_definitions(session, write.tenant_id, detector_id, definition)
            detector = await dlp_policy.insert_detector(
                session,
                detector_id,
                1,
                DetectorFields(
                    name=new.name,
                    kind=DlpDetectorKind.KEYWORDS.value,
                    definition_ct=seal_definition(write.tenant_id, definition),
                    enabled=new.enabled,
                ),
                created_by=created_by,
            )
            await _record(
                session,
                write,
                action="dlp_detector.created",
                target=Target(DETECTOR_TARGET, detector.id),
                changes=[PolicyChange.DETECTOR_ADDED],
                details=_detector_details(detector),
            )
            return detector

        async def rebuild(detector_id: UUID) -> DlpDetector | None:
            return await dlp_policy.get_live_detector(session, detector_id)

        outcome = await once(
            session,
            caller,
            idempotency,
            status=201,
            resource_type=DETECTOR_TARGET,
            create=create,
            rebuild=rebuild,
            resource_id=lambda detector: detector.id,
        )
    return Outcome(_own(write.tenant_id, outcome.value), outcome.status, outcome.replayed)


async def update_dlp_detector(
    database: Database,
    caller: Caller,
    detector_id: str,
    change: DetectorUpdate,
    *,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
) -> DetectorView:
    """`updateDlpDetector`: the detector's next revision; a built-in one is `409 invalid_state`."""
    authorize(caller, "updateDlpDetector", now=now)
    own_id = _own_id(detector_id)
    if own_id is None:
        raise Conflict("invalid_state", "A built-in detector can't be changed.")
    for name in ("pattern", "context_keywords", "case_insensitive", "min_length"):
        if getattr(change, name) is not None:
            raise _invalid("Only a pattern has this field.", name)
    definition = None if change.keywords is None else _keywords(change.keywords)
    write = _write(caller, limiter, origin)
    if caller.user_id is None:  # pragma: no cover - authorize admits only members here
        raise NotFound
    created_by = caller.user_id
    async with database.transaction(tenant_scope(caller)) as session:
        await _locked(session, change.expected_version)
        detector = await dlp_policy.get_live_detector(session, own_id)
        if detector is None:
            raise NotFound
        old = open_definition(write.tenant_id, detector.definition_ct)
        name = detector.name if change.name is None else change.name
        enabled = detector.enabled if change.enabled is None else change.enabled
        wanted = old if definition is None else definition
        if (name, enabled, wanted) == (detector.name, detector.enabled, old):
            return _own(write.tenant_id, detector)
        if wanted != old or (enabled and not detector.enabled):
            await _check_definitions(session, write.tenant_id, detector.id, wanted)
        if not await dlp_policy.retire_detector(session, detector.id, detector.revision):
            raise _stale()  # pragma: no cover - the lock rules this out
        new = await dlp_policy.insert_detector(
            session,
            detector.id,
            detector.revision + 1,
            DetectorFields(
                name=name,
                kind=detector.kind,
                definition_ct=seal_definition(write.tenant_id, wanted),
                enabled=enabled,
            ),
            created_by=created_by,
        )
        changed: dict[str, audit.Detail] = {}
        if name != detector.name:
            changed["changed_name"] = True
        if enabled != detector.enabled:
            changed["changed_enabled"] = True
        if wanted != old:
            changed["changed_definition"] = True
        await _record(
            session,
            write,
            action="dlp_detector.changed",
            target=Target(DETECTOR_TARGET, detector.id),
            changes=[PolicyChange.DETECTOR_CHANGED],
            details=_detector_details(new, **changed),
        )
        return _own(write.tenant_id, new)


async def delete_dlp_detector(
    database: Database,
    caller: Caller,
    detector_id: str,
    *,
    limiter: RateLimiter,
    origin: Origin,
    now: datetime,
) -> None:
    """`deleteDlpDetector`: retire it, unless a live rule uses it (`409 detector_in_use`)."""
    authorize(caller, "deleteDlpDetector", now=now)
    own_id = _own_id(detector_id)
    if own_id is None:
        raise Conflict("invalid_state", "A built-in detector can't be deleted.")
    write = _write(caller, limiter, origin)
    async with database.transaction(tenant_scope(caller)) as session:
        await _locked(session, None)
        detector = await dlp_policy.get_live_detector(session, own_id)
        if detector is None:
            raise NotFound
        if await dlp_policy.live_rules_using(session, detector_ref(detector.id)):
            raise Conflict("detector_in_use", "A rule uses this detector: change it first.")
        if not await dlp_policy.retire_detector(session, detector.id, detector.revision):
            raise NotFound  # pragma: no cover - the lock rules this out
        await _record(
            session,
            write,
            action="dlp_detector.deleted",
            target=Target(DETECTOR_TARGET, detector.id),
            changes=[PolicyChange.DETECTOR_REMOVED],
            details={"revision": detector.revision, "kind": DlpDetectorKind(detector.kind)},
        )
