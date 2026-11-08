"""The DLP decision of a transfer (#219; architecture 4.6, steps 1 to 4; data model 2.7, 3.2;
FR-41, FR-45, FR-46, FR-48).

The evaluation (`sft.service.evaluation`) calls `decide` under the transfer's row lock, once every
counted file is shareable. It runs as the caller of a send or a file removal (`sft_api`), as the
scan worker (`sft_scan`) or as a job (`sft_jobs`), so it reads only what those roles may: the
policy and its rules, the recipients' domains (never an address), the files' inspection reasons
and their findings' counts (never their details).

1. **Recipients.** A recipient's domain is compared lowercase and IDNA-normalised (`xn--` labels),
   as the policy stores its trusted domains. It is **trusted** when it is, or is a subdomain of,
   one of them (FR-45). The tenant's SSO domains would count too, but `sso_domains` doesn't exist
   yet: M6 brings it. A domain is **new** when the tenant hasn't sent to it in the 365 days
   before the decision (`dlp_known_domains`, FR-46).
2. **Rules.** Every live, enabled rule for sent files is tested:
   - `content`: the matches of its detectors at or above its confidence, added up over the
     counted files (FR-48), against its threshold; the count is that sum. The message's findings
     (FR-50) and the sender's last 24 hours (FR-49) join with #221.
   - `not_inspected`: any counted file whose inspection reasons include one the rule lists; the
     count is the files.
   - `new_domain`: any new recipient domain; the count is the new domains.
   A rule scoped to `untrusted` recipients is tested only if one is, and its `new_domain` count
   is of untrusted recipients' domains.
3. **Outcome.** The strictest action of the matched rules (`none` < `allow_and_record` < `warn` <
   `require_approval` < `block`), or `none`. One `dlp_decisions` row records it with the policy
   version, the mode and the numbers of untrusted recipients and new domains, never which, and
   one `dlp_decision_rules` row each matched rule, at the revision it applied.
4. **Enforcement.** In enforce mode the outcome acts (`Decided.sends`); in monitor mode (#221,
   refused by the policy API until then) everything is sent and `enforced` is false.

A tenant always has a policy (revision 0024, `createTenant`). One without is a fault, and the
evaluation fails closed: nothing is sent without a decision (FR-41).
"""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data import dlp_decisions, findings, transfers
from sft.data.dlp_decisions import MatchedRule, PolicyRule
from sft.data.files import CountedFile
from sft.data.findings import Counts
from sft.data.models import (
    DlpAction,
    DlpCondition,
    DlpConfidence,
    DlpMode,
    DlpOutcome,
    DlpRecipientScope,
)

KNOWN_FOR: Final = timedelta(days=365)
"""A recipient domain the tenant has sent to within this is not new (FR-46); the daily cleanup
deletes a known domain this long after `last_sent_at` (data model 6)."""

STRICTNESS: Final[Mapping[DlpOutcome, int]] = {
    outcome: rank for rank, outcome in enumerate(DlpOutcome)
}
"""`none` < `allow_and_record` < `warn` < `require_approval` < `block` (FR-41)."""

SENDS: Final = frozenset({DlpOutcome.NONE, DlpOutcome.ALLOW_AND_RECORD})
"""Outcomes that let a transfer be sent in enforce mode."""


class MissingPolicyError(RuntimeError):
    """The tenant has no DLP policy, which revision 0024 and `createTenant` never allow."""


# ---- recipients (step 1) ----


def normalise_domain(domain: str) -> str:
    """A recipient domain as the policy stores trusted domains: lowercase, without a trailing
    dot, IDNA (`xn--`) labels. A domain IDNA can't encode stays as it is, lowercase, so it never
    equals a trusted domain."""
    plain = domain.strip().rstrip(".").lower()
    try:
        return plain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return plain


def is_trusted(domain: str, trusted_domains: Collection[str]) -> bool:
    """The domain is a trusted domain or a subdomain of one (FR-45)."""
    return any(domain == t or domain.endswith(f".{t}") for t in trusted_domains)


@dataclass(frozen=True, slots=True)
class RecipientCheck:
    recipient_id: UUID
    domain: str
    trusted: bool
    new_domain: bool


def check_recipients(
    recipients: Sequence[tuple[UUID, str | None]],
    trusted_domains: Collection[str],
    known: Collection[str],
) -> list[RecipientCheck]:
    """Each recipient's trust and newness, from its domain."""
    checks = []
    for recipient_id, raw in recipients:
        domain = normalise_domain(raw or "")
        checks.append(
            RecipientCheck(
                recipient_id,
                domain,
                trusted=bool(domain) and is_trusted(domain, trusted_domains),
                new_domain=domain not in known,
            )
        )
    return checks


async def recipient_domains(session: AsyncSession, transfer_id: UUID) -> list[str]:
    """The transfer's distinct recipient domains, normalised, sorted."""
    rows = await transfers.recipient_domains(session, transfer_id)
    return sorted({normalise_domain(d) for _, d in rows if d})


# ---- rules (step 2) and the outcome (step 3) ----


@dataclass(frozen=True, slots=True)
class FileEvidence:
    """What a rule tests on one counted file: its inspection reasons and its findings."""

    file_id: UUID
    reasons: tuple[str, ...]
    findings: tuple[Counts, ...]


def at_or_above(counts: Counts, confidence: str) -> int:
    """Distinct matches at `confidence` or higher (detectors 3): `medium` counts medium and high."""
    level = DlpConfidence(confidence)
    total = counts.high
    if level is not DlpConfidence.HIGH:
        total += counts.medium
    if level is DlpConfidence.LOW:
        total += counts.low
    return total


@dataclass(frozen=True, slots=True)
class Match:
    rule: PolicyRule
    count: int


def match_rule(
    rule: PolicyRule, recipients: Sequence[RecipientCheck], files: Sequence[FileEvidence]
) -> Match | None:
    """The rule's match and its count, or None (module docstring, step 2)."""
    in_scope = list(recipients)
    if rule.recipient_scope == DlpRecipientScope.UNTRUSTED.value:
        in_scope = [r for r in recipients if not r.trusted]
        if not in_scope:
            return None
    condition = DlpCondition(rule.condition)
    if condition is DlpCondition.CONTENT:
        detectors = set(rule.detectors)
        total = sum(
            at_or_above(counts, rule.min_confidence)
            for file in files
            for counts in file.findings
            if counts.detector in detectors
        )
        return Match(rule, total) if total >= rule.threshold else None
    if condition is DlpCondition.NOT_INSPECTED:
        reasons = set(rule.reasons)
        files_hit = sum(1 for file in files if reasons & set(file.reasons))
        return Match(rule, files_hit) if files_hit else None
    new = {r.domain for r in in_scope if r.new_domain}
    return Match(rule, len(new)) if new else None


def outcome_of(matches: Sequence[Match]) -> DlpOutcome:
    """The strictest action of the matched rules, or `none`."""
    return max(
        (DlpOutcome(m.rule.action) for m in matches),
        key=STRICTNESS.__getitem__,
        default=DlpOutcome.NONE,
    )


# ---- the decision ----


@dataclass(frozen=True, slots=True)
class Decided:
    """A decision as written: its ID, what it found and what it does."""

    id: UUID
    outcome: DlpOutcome
    mode: DlpMode
    policy_version: int
    matches: tuple[Match, ...]
    untrusted_recipients: int
    new_domains: int

    @property
    def enforced(self) -> bool:
        return self.mode is DlpMode.ENFORCE

    @property
    def sends(self) -> bool:
        """Whether the transfer goes out now (step 4)."""
        return not self.enforced or self.outcome in SENDS


async def decide(
    session: AsyncSession, transfer_id: UUID, counted: Sequence[CountedFile], *, now: datetime
) -> Decided:
    """Decide on the transfer's counted files, all shareable, and write the decision. The caller
    holds the transfer's row lock, applies the outcome and writes the audit events."""
    policy = await dlp_decisions.decision_policy(session)
    if policy is None:
        raise MissingPolicyError("the tenant has no DLP policy: nothing is sent undecided")
    recipient_rows = await transfers.recipient_domains(session, transfer_id)
    domains = sorted({normalise_domain(d) for _, d in recipient_rows if d})
    known = await dlp_decisions.known_since(session, domains, since=now - KNOWN_FOR)
    recipients = check_recipients(recipient_rows, policy.trusted_domains, known)
    found = await findings.counts_by_file(session, [f.id for f in counted])
    files = [
        FileEvidence(f.id, tuple(r.value for r in f.inspection_reasons), tuple(found.get(f.id, ())))
        for f in counted
    ]
    matches = tuple(
        m for m in (match_rule(rule, recipients, files) for rule in policy.rules) if m is not None
    )
    decided = Decided(
        id=uuid7(),
        outcome=outcome_of(matches),
        mode=DlpMode(policy.mode),
        policy_version=policy.version,
        matches=matches,
        untrusted_recipients=sum(1 for r in recipients if not r.trusted),
        new_domains=len({r.domain for r in recipients if r.new_domain}),
    )
    await dlp_decisions.insert_decision(
        session,
        decision_id=decided.id,
        transfer_id=transfer_id,
        policy_version=decided.policy_version,
        mode=decided.mode.value,
        outcome=decided.outcome.value,
        enforced=decided.enforced,
        untrusted_recipients=decided.untrusted_recipients,
        new_domains=decided.new_domains,
        rules=[
            MatchedRule(m.rule.id, m.rule.revision, DlpAction(m.rule.action).value, m.count)
            for m in matches
        ],
    )
    return decided
