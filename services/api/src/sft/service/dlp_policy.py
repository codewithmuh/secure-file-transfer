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

**What is accepted** (#218, and #221's Should parts): `enforce` and `monitor` mode (FR-52);
rules for sent files, and for received files (FR-51), which only allow and record or block, test
`content` or `not_inspected` and apply to any recipient; one or two approvers (FR-44), two only
with `require_approval`; the sender's 24-hour window (FR-49) on a `content` rule for sent files;
keyword lists and patterns (FR-38, FR-39). `require_approval` needs more active approvers than
the rule needs (`422 approvers_insufficient`) to create or enable one. A tenant has at most 50
live rules, 50 detectors and 20 patterns.

**Keyword lists and patterns** are checked by the detector library as the inspector will compile
them (`sft.dlp.detect.validate`), then together with the tenant's other live detectors, so a set
the inspector couldn't compile is refused when it is saved, not when a file is scanned. A pattern
is refused, with a pointer to `pattern`, if it doesn't compile in RE2, is longer than 512
characters, compiles to more than 1,000 instructions forward or reverse, or matches the empty
string (detectors 5). Definitions are stored sealed (`sft.service.dlp_definitions`) and never
logged. `getDlpDetector` shows how many files stopped a pattern for its scan-time budget, and
when last (#164).

**`testDlpDetectors`** (FR-56) runs detectors on up to 16,384 characters of sample text, in
memory, and returns each match masked as findings are: the IDs asked for, a `draft` that isn't
saved, or every detector when neither is sent. The text is never stored or logged; the audit
event names the detectors and counts only (`dlp.detector_tested`). 30 a minute per account
(abuse 2.2, K).

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
from string import ascii_lowercase
from typing import Any, Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import Conflict, FieldError, NotFound, TooLarge, Unprocessable, json_pointer
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
from sft.dlp.detect import BUILTIN_DETECTORS, DetectorError, try_detectors, validate
from sft.dlp.detect.tenant import TenantDetectors
from sft.dlp.engine import load_engine
from sft.service.caller import Caller
from sft.service.dlp_definitions import (
    Definition,
    Keywords,
    PatternDefinition,
    detector_unit,
    open_definition,
    seal_definition,
)
from sft.service.email.catalog import PolicyChange
from sft.service.fields import KeyPurpose, TenantKeys, tenant_keys
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
MAX_PATTERNS: Final = 20
MAX_TEST_TEXT: Final = 16_384
"""Characters of sample text `testDlpDetectors` takes (abuse 2.2, K): more is `413`."""
MAX_TEST_MATCHES: Final = 100
DRAFT: Final = "draft"
"""How `testDlpDetectors` names the draft's matches."""
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
    budget_stops: int | None = None
    """For a pattern in `getDlpDetector`: the files that stopped it for its budget (#164)."""
    last_budget_stop_at: datetime | None = None


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
    """`DlpDetectorCreate`. The pattern fields, sent with `kind: keywords`, are refused."""

    name: str
    kind: DlpDetectorKind
    expected_version: int | None = None
    enabled: bool = True
    keywords: Sequence[str] | None = None
    pattern: str | None = None
    context_keywords: Sequence[str] | None = None
    min_length: int | None = None
    case_insensitive: bool = True


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
        keys = await _dlp_keys(session, scope.tenant_id)
    items = [_builtin(d, language) for d in builtin_ids()]
    items += [_own(keys, d) for d in own]
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
        keys = await _dlp_keys(session, scope.tenant_id)
        if detector is None:
            raise NotFound
        stops = None
        if detector.kind == DlpDetectorKind.PATTERN.value:
            stops = await dlp_policy.pattern_stops(session, detector.id)
    view = _own(keys, detector)
    if detector.kind != DlpDetectorKind.PATTERN.value:
        return view
    return replace(
        view,
        budget_stops=0 if stops is None else stops.files,
        last_budget_stop_at=None if stops is None else stops.last_at,
    )


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


async def _dlp_keys(session: AsyncSession, tenant_id: UUID, *, write: bool = False) -> TenantKeys:
    """The tenant's DLP data keys, which seal its detectors' definitions (#233)."""
    return await tenant_keys(session, tenant_id, KeyPurpose.DLP, write=write)


def _own(keys: TenantKeys, detector: DlpDetector) -> DetectorView:
    return DetectorView(
        id=detector_ref(detector.id),
        kind=detector.kind,
        name=detector.name,
        enabled=detector.enabled,
        revision=detector.revision,
        definition=open_definition(keys, detector.id, detector.definition_ct),
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
    condition = DlpCondition(fields.condition)
    if fields.direction == DlpDirection.RECEIVED.value:
        # FR-51: a received file's rule allows and records or blocks; nobody confirms it.
        if fields.action not in (DlpAction.ALLOW_AND_RECORD.value, DlpAction.BLOCK.value):
            raise _invalid("A rule for received files allows and records, or blocks.", "action")
        if condition is DlpCondition.NEW_DOMAIN:
            raise _invalid("A rule for received files tests content or inspection.", "condition")
        if fields.recipient_scope != DlpRecipientScope.ANY.value:
            raise _invalid("A rule for received files has no recipients.", "recipient_scope")
        if fields.include_sender_24h:
            raise _invalid("A rule for received files has no sender.", "include_sender_24h")
    if fields.include_sender_24h and condition is not DlpCondition.CONTENT:
        raise _invalid(
            "The sender's 24 hours add up a content rule's matches.", "include_sender_24h"
        )
    if fields.approvals_required not in (1, 2):
        raise _invalid("A rule needs one or two approvers.", "approvals_required")
    if fields.approvals_required == 2 and fields.action != DlpAction.REQUIRE_APPROVAL.value:
        if "approvals_required" in sent:
            raise _invalid("Two approvers apply only to require_approval.", "approvals_required")
        fields = replace(fields, approvals_required=1)  # the action changed away from approval
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
            details=_rule_details(
                new, **{f"changed_{_audit_name(name)}": True for name in changed}
            ),
        )
        return new


def _audit_name(field: str) -> str:
    """A rule field as an audit details key, which holds lower-case letters only."""
    return "sender_window" if field == "include_sender_24h" else field


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

_PATTERN_FIELDS: Final = ("pattern", "context_keywords", "case_insensitive", "min_length")
_FIELD_OF_REASON: Final[Mapping[str, str]] = {
    "expression_too_long": "pattern",
    "does_not_compile": "pattern",
    "too_complex": "pattern",
    "matches_empty_string": "pattern",
    "invalid_context_keywords": "context_keywords",
    "invalid_min_length": "min_length",
}
_DETAIL_OF_REASON: Final[Mapping[str, str]] = {
    "expression_too_long": "A pattern has at most 512 characters.",
    "does_not_compile": "The pattern doesn't compile in RE2.",
    "too_complex": "The pattern compiles to more than 1,000 RE2 instructions.",
    "matches_empty_string": "The pattern matches the empty string.",
    "invalid_context_keywords": "A context keyword has 1 to 100 characters.",
    "invalid_min_length": "min_length is at most 512.",
    "too_many_patterns": "A tenant has at most 20 patterns.",
    "keywords_too_large": "The tenant's keyword lists are too large together to inspect.",
}


def _definition_error(error: DetectorError, *prefix: str) -> Unprocessable:
    """A save-time refusal of the detector library, pointing at the field it concerns (under
    `prefix`, the draft of `testDlpDetectors`). The reason names the rule broken, never a term or
    the expression (sft.dlp.detect.tenant)."""
    detail = _DETAIL_OF_REASON.get(error.reason, f"The keyword list breaks a rule: {error.reason}.")
    if error.reason == "too_many_patterns":
        return _invalid(detail)
    return _invalid(detail, *prefix, _FIELD_OF_REASON.get(error.reason, "keywords"))


async def _check_definitions(
    session: AsyncSession, tenant_id: UUID, detector_id: UUID, definition: Definition
) -> None:
    """The library's save-time checks of one detector, then of the tenant's live detectors with
    it, as the inspector will compile them for every file."""
    unit = detector_unit(detector_id, definition)
    keys = await _dlp_keys(session, tenant_id)
    others = [
        detector_unit(d.id, open_definition(keys, d.id, d.definition_ct))
        for d in await dlp_policy.list_live_detectors(session)
        if d.id != detector_id and d.enabled
    ]
    try:
        validate(unit)
        TenantDetectors([*others, unit])
    except DetectorError as error:
        raise _definition_error(error) from None


def _keywords(terms: Sequence[str], *prefix: str) -> Keywords:
    if not 1 <= len(terms) <= 1000:
        raise _invalid("A keyword list has 1 to 1,000 terms.", *prefix, "keywords")
    for index, term in enumerate(terms):
        if not term.strip() or len(term) > 100:
            raise _invalid("A term has 1 to 100 characters.", *prefix, "keywords", index)
    return Keywords(tuple(terms))


def _pattern(
    pattern: str | None,
    context_keywords: Sequence[str] | None,
    case_insensitive: bool,
    min_length: int | None,
    *prefix: str,
) -> PatternDefinition:
    """A pattern's fields as the contract takes them (FR-39); the library checks the rest."""
    if pattern is None:
        raise _invalid("A pattern needs its pattern.", *prefix, "pattern")
    if not 1 <= len(pattern) <= 512:
        raise _invalid("A pattern has 1 to 512 characters.", *prefix, "pattern")
    context = tuple(context_keywords or ())
    if len(context) > 50:
        raise _invalid("A pattern has at most 50 context keywords.", *prefix, "context_keywords")
    for index, term in enumerate(context):
        if not term.strip() or len(term) > 100:
            raise _invalid(
                "A context keyword has 1 to 100 characters.", *prefix, "context_keywords", index
            )
    return PatternDefinition(
        pattern=pattern,
        context_keywords=context,
        case_insensitive=case_insensitive,
        min_length=min_length,
    )


def _new_definition(new: DetectorCreate, *prefix: str) -> Definition:
    """The definition of a `DlpDetectorCreate`: a keyword list or a pattern, with only its own
    kind's fields."""
    if new.kind is DlpDetectorKind.PATTERN:
        if new.keywords is not None:
            raise _invalid("Only a keyword list has this field.", *prefix, "keywords")
        return _pattern(
            new.pattern, new.context_keywords, new.case_insensitive, new.min_length, *prefix
        )
    for name in ("pattern", "context_keywords", "min_length"):
        if getattr(new, name) is not None:
            raise _invalid("Only a pattern has this field.", *prefix, name)
    if new.keywords is None:
        raise _invalid("A keyword list needs its keywords.", *prefix, "keywords")
    return _keywords(new.keywords, *prefix)


def _changed_definition(old: Definition, change: DetectorUpdate) -> Definition:
    """The definition with the fields of a `DlpDetectorUpdate` applied; another kind's fields
    are refused."""
    if isinstance(old, Keywords):
        for name in _PATTERN_FIELDS:
            if getattr(change, name) is not None:
                raise _invalid("Only a pattern has this field.", name)
        return old if change.keywords is None else _keywords(change.keywords)
    if change.keywords is not None:
        raise _invalid("Only a keyword list has this field.", "keywords")
    return _pattern(
        old.pattern if change.pattern is None else change.pattern,
        old.context_keywords if change.context_keywords is None else change.context_keywords,
        old.case_insensitive if change.case_insensitive is None else change.case_insensitive,
        old.min_length if change.min_length is None else change.min_length,
    )


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
    """`createDlpDetector`: a keyword list or a pattern at revision 1."""
    authorize(caller, "createDlpDetector", now=now)
    definition = _new_definition(new)
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
            patterns = sum(1 for d in live if d.kind == DlpDetectorKind.PATTERN.value)
            if isinstance(definition, PatternDefinition) and patterns >= MAX_PATTERNS:
                raise _invalid("A tenant has at most 20 patterns.")
            detector_id = uuid7()
            await _check_definitions(session, write.tenant_id, detector_id, definition)
            detector = await dlp_policy.insert_detector(
                session,
                detector_id,
                1,
                DetectorFields(
                    name=new.name,
                    kind=definition.kind.value,
                    definition_ct=seal_definition(
                        await _dlp_keys(session, write.tenant_id, write=True),
                        detector_id,
                        definition,
                    ),
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
        keys = await _dlp_keys(session, write.tenant_id)
    return Outcome(_own(keys, outcome.value), outcome.status, outcome.replayed)


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
    write = _write(caller, limiter, origin)
    if caller.user_id is None:  # pragma: no cover - authorize admits only members here
        raise NotFound
    created_by = caller.user_id
    async with database.transaction(tenant_scope(caller)) as session:
        await _locked(session, change.expected_version)
        detector = await dlp_policy.get_live_detector(session, own_id)
        if detector is None:
            raise NotFound
        keys = await _dlp_keys(session, write.tenant_id, write=True)
        old = open_definition(keys, detector.id, detector.definition_ct)
        name = detector.name if change.name is None else change.name
        enabled = detector.enabled if change.enabled is None else change.enabled
        wanted = _changed_definition(old, change)
        if (name, enabled, wanted) == (detector.name, detector.enabled, old):
            return _own(keys, detector)
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
                definition_ct=seal_definition(keys, detector.id, wanted),
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
        return _own(keys, new)


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


# ---- testDlpDetectors (FR-56) ----


@dataclass(frozen=True, slots=True)
class DetectorTest:
    """`DlpDetectorTest`: the text, the detectors asked for and a draft, as sent."""

    text: str
    detectors: Sequence[str] | None = None
    draft: DetectorCreate | None = None


@dataclass(frozen=True, slots=True)
class TestMatch:
    detector: str
    confidence: str
    line: int
    preview: str


@dataclass(frozen=True, slots=True)
class TestResult:
    matches: tuple[TestMatch, ...]
    truncated: bool


def _letters(index: int) -> str:
    """`a` to `z`, then `aa`, `ab`…: audit details keys hold lower-case letters, not digits."""
    first, second = divmod(index, 26)
    return ("" if first == 0 else ascii_lowercase[first - 1]) + ascii_lowercase[second]


async def test_dlp_detectors(
    database: Database,
    caller: Caller,
    test: DetectorTest,
    *,
    origin: Origin,
    now: datetime,
) -> TestResult:
    """`testDlpDetectors` (module docstring). The route applies the 30 a minute per account."""
    authorize(caller, "testDlpDetectors", now=now)
    if len(test.text) > MAX_TEST_TEXT:
        raise TooLarge("request_too_large", "The sample text has at most 16,384 characters.")
    draft = None if test.draft is None else _new_definition(test.draft, "draft")
    scope = tenant_scope(caller)
    tenant_id = scope.tenant_id
    assert tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
    async with database.transaction(scope) as session:
        live = {d.id: d for d in await dlp_policy.list_live_detectors(session)}
        builtin: set[str] = set()
        own: list[DlpDetector] = []
        for index, name in enumerate(test.detectors or ()):
            if name in BUILTIN_DETECTORS:
                builtin.add(name)
                continue
            try:
                found = live.get(UUID(name.removeprefix(CUSTOM_PREFIX)))
            except ValueError:
                found = None
            if not name.startswith(CUSTOM_PREFIX) or found is None:
                raise _invalid("No such detector.", "detectors", index)
            if found not in own:
                own.append(found)
        everything = not test.detectors and draft is None
        if everything:
            builtin = set(BUILTIN_DETECTORS)
            own = [d for d in live.values() if d.enabled]
        keys = await _dlp_keys(session, tenant_id)
        units = [detector_unit(d.id, open_definition(keys, d.id, d.definition_ct)) for d in own]
        if draft is not None:
            unit = detector_unit(UUID(int=0), draft)
            units.append(replace(unit, id=DRAFT))
        try:
            if draft is not None:
                validate(units[-1])
            matches = try_detectors(test.text, units)
        except DetectorError as error:
            if draft is not None and error.detector_id == DRAFT:
                raise _definition_error(error, "draft") from None
            raise _definition_error(error) from None
        wanted = builtin | {detector_ref(d.id) for d in own} | {CUSTOM_PREFIX + DRAFT}
        kept = [
            TestMatch(
                DRAFT if m.detector == CUSTOM_PREFIX + DRAFT else m.detector,
                m.confidence,
                m.line,
                m.preview,
            )
            for m in matches
            if m.detector in wanted
        ]
        details: dict[str, audit.Detail] = {
            "detectors": len(builtin) + len(own),
            "draft_kind": None if draft is None else draft.kind,
            "all_detectors": everything,
            "matches": min(len(kept), MAX_TEST_MATCHES),
            "truncated": len(kept) > MAX_TEST_MATCHES,
        }
        # The detectors by ID, never the text or a match (FR-56).
        details |= {f"builtin_{name}": True for name in sorted(builtin) if not everything}
        details |= {
            f"detector_{_letters(index)}": d.id for index, d in enumerate(own) if not everything
        }
        await audit.record(
            session,
            action="dlp.detector_tested",
            actor=caller.actor(),
            target=Target(POLICY_TARGET, tenant_id),
            origin=origin,
            details=details,
        )
    return TestResult(tuple(kept[:MAX_TEST_MATCHES]), len(kept) > MAX_TEST_MATCHES)
