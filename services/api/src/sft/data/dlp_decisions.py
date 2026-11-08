"""Data access for the DLP decision: `dlp_decisions`, `dlp_decision_rules`, `dlp_confirmations`
and `dlp_known_domains` (#219; data model 2.7, 3.2, 5, 6; revision 0025).

- **The evaluation** (`sft.service.evaluation`) reads the policy and its live, enabled rules for
  sent files in one statement (`decision_policy`), so the version it records names exactly the
  rules it applied, writes one decision with the rules it matched (`insert_decision`), and records
  the recipient domains of a transfer it sends (`record_known_domains`). It runs as `sft_api`,
  `sft_scan` and `sft_jobs`, so these functions name their columns.
- **The API** reads a decision with its rules as they were (`get_decision`, joined to the rule
  revisions the decision applied) and the summary `Transfer.dlp` shows, and records confirmations.
- **The daily cleanup** (`sft_jobs`) finds tenants with known domains 365 days past
  `last_sent_at` across tenants, in system scope, then deletes them in each tenant's scope.

Every function filters with `in_scope`, and every write takes its tenant from the scope. A
decision is never updated; nothing here changes one.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from uuid import UUID

from sqlalchemy import and_, delete, func, insert, select, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.sealed import key_version
from sft.data import sso
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import (
    DlpConfirmation,
    DlpDecision,
    DlpDecisionRule,
    DlpDirection,
    DlpKnownDomain,
    DlpPolicy,
    DlpRule,
)
from sft.data.scope import ScopeKind

_TENANT = (ScopeKind.TENANT,)

KNOWN_DOMAIN_BATCH: Final = 1000
"""The most known domains one upsert writes: more than a transfer's 50 recipients ever have."""


# ---- the evaluation's read of the policy ----


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """What the decision needs of one live, enabled rule for sent files (data model 2.7)."""

    id: UUID
    revision: int
    condition: str
    detectors: tuple[str, ...]
    min_confidence: str
    threshold: int
    reasons: tuple[str, ...]
    recipient_scope: str
    action: str
    include_sender_24h: bool = False


@dataclass(frozen=True, slots=True)
class DecisionPolicy:
    """The tenant's policy as one decision applies it."""

    version: int
    mode: str
    trusted_domains: tuple[str, ...]
    rules: tuple[PolicyRule, ...]


async def decision_policy(
    session: AsyncSession, direction: DlpDirection = DlpDirection.SENT
) -> DecisionPolicy | None:
    """The scope's tenant's policy and its live, enabled rules for `direction` (sent files, or
    received files, #221), in the order they were made, read in one statement so they belong to
    one version, with the tenant's proven SSO domains among the trusted domains (#231). None for
    a tenant without a policy."""
    require_scope(session, *_TENANT)
    rule_join = and_(
        DlpRule.tenant_id == DlpPolicy.tenant_id,
        DlpRule.retired_at.is_(None),
        DlpRule.enabled.is_(True),
        DlpRule.direction == direction.value,
        in_scope(DlpRule, session),
    )
    rows = (
        await session.execute(
            select(
                DlpPolicy.version,
                DlpPolicy.mode,
                DlpPolicy.trusted_domains,
                DlpRule.id,
                DlpRule.revision,
                DlpRule.condition,
                DlpRule.detectors,
                DlpRule.min_confidence,
                DlpRule.threshold,
                DlpRule.reasons,
                DlpRule.recipient_scope,
                DlpRule.action,
                DlpRule.include_sender_24h,
            )
            .select_from(DlpPolicy)
            .outerjoin(DlpRule, rule_join)
            .where(in_scope(DlpPolicy, session))
            .order_by(DlpRule.id)
        )
    ).all()
    if not rows:
        return None
    first = rows[0]
    rules = tuple(
        PolicyRule(
            id=row.id,
            revision=row.revision,
            condition=row.condition,
            detectors=tuple(row.detectors),
            min_confidence=row.min_confidence,
            threshold=row.threshold,
            reasons=tuple(row.reasons),
            recipient_scope=row.recipient_scope,
            action=row.action,
            include_sender_24h=row.include_sender_24h,
        )
        for row in rows
        if row.id is not None
    )
    # The tenant's proven SSO domains are trusted too (FR-45, #231).
    trusted = tuple(sorted({*first.trusted_domains, *await sso.verified_domains(session)}))
    return DecisionPolicy(first.version, first.mode, trusted, rules)


# ---- decisions ----


@dataclass(frozen=True, slots=True)
class MatchedRule:
    """A rule a decision matched, at the revision it applied."""

    rule_id: UUID
    revision: int
    action: str
    matched_count: int


async def insert_decision(
    session: AsyncSession,
    *,
    decision_id: UUID,
    transfer_id: UUID | None,
    policy_version: int,
    mode: str,
    outcome: str,
    enforced: bool,
    untrusted_recipients: int,
    new_domains: int,
    rules: Sequence[MatchedRule],
    file_id: UUID | None = None,
) -> None:
    """A transfer's decision of the scope's tenant, or a received file's (`file_id`, #221), and
    the rules it matched. Commits only with an
    audit event in the same transaction (`audit_required`). No `RETURNING`: the system roles may
    insert decisions but not read them."""
    require_scope(session, *_TENANT)
    tenant_id = tenant_of(session)
    await session.execute(
        insert(DlpDecision).values(
            id=decision_id,
            tenant_id=tenant_id,
            transfer_id=transfer_id,
            file_id=file_id,
            policy_version=policy_version,
            mode=mode,
            outcome=outcome,
            enforced=enforced,
            untrusted_recipients=untrusted_recipients,
            new_domains=new_domains,
        )
    )
    if rules:
        await session.execute(
            insert(DlpDecisionRule),
            [
                {
                    "decision_id": decision_id,
                    "tenant_id": tenant_id,
                    "rule_id": rule.rule_id,
                    "rule_revision": rule.revision,
                    "action": rule.action,
                    "matched_count": rule.matched_count,
                }
                for rule in rules
            ],
        )


@dataclass(frozen=True, slots=True)
class DecisionRule:
    """A matched rule as the decision applied it: its revision's name, condition and threshold."""

    rule_id: UUID
    revision: int
    name: str
    condition: str
    action: str
    matched_count: int
    threshold: int


@dataclass(frozen=True, slots=True)
class Decision:
    id: UUID
    transfer_id: UUID | None
    file_id: UUID | None
    policy_version: int
    mode: str
    outcome: str
    enforced: bool
    untrusted_recipients: int
    new_domains: int
    decided_at: datetime
    rules: tuple[DecisionRule, ...]


async def get_decision(session: AsyncSession, decision_id: UUID) -> Decision | None:
    """The decision, with the rules it matched as their revisions were; None if the scope
    doesn't reach it."""
    require_scope(session, *_TENANT)
    found: DlpDecision | None = await session.scalar(
        select(DlpDecision).where(DlpDecision.id == decision_id, in_scope(DlpDecision, session))
    )
    if found is None:
        return None
    rows = await session.execute(
        select(
            DlpDecisionRule.rule_id,
            DlpDecisionRule.rule_revision,
            DlpRule.name,
            DlpRule.condition,
            DlpDecisionRule.action,
            DlpDecisionRule.matched_count,
            DlpRule.threshold,
        )
        .join(
            DlpRule,
            and_(
                DlpRule.tenant_id == DlpDecisionRule.tenant_id,
                DlpRule.id == DlpDecisionRule.rule_id,
                DlpRule.revision == DlpDecisionRule.rule_revision,
                in_scope(DlpRule, session),
            ),
        )
        .where(DlpDecisionRule.decision_id == found.id, in_scope(DlpDecisionRule, session))
        .order_by(DlpDecisionRule.rule_id)
    )
    return Decision(
        id=found.id,
        transfer_id=found.transfer_id,
        file_id=found.file_id,
        policy_version=found.policy_version,
        mode=found.mode,
        outcome=found.outcome,
        enforced=found.enforced,
        untrusted_recipients=found.untrusted_recipients,
        new_domains=found.new_domains,
        decided_at=found.decided_at,
        rules=tuple(DecisionRule(*row) for row in rows.tuples()),
    )


@dataclass(frozen=True, slots=True)
class Summary:
    """A decision in brief, for `Transfer.dlp` (the contract's `TransferDlpSummary`)."""

    outcome: str
    mode: str
    enforced: bool


async def decision_summary(session: AsyncSession, decision_id: UUID) -> Summary | None:
    require_scope(session, *_TENANT)
    row = (
        await session.execute(
            select(DlpDecision.outcome, DlpDecision.mode, DlpDecision.enforced).where(
                DlpDecision.id == decision_id, in_scope(DlpDecision, session)
            )
        )
    ).first()
    return None if row is None else Summary(row.outcome, row.mode, row.enforced)


# ---- confirmations ----


async def insert_confirmation(
    session: AsyncSession,
    *,
    confirmation_id: UUID,
    transfer_id: UUID,
    decision_id: UUID,
    confirmed_by: UUID,
    justification_ct: bytes | None,
) -> None:
    """The sender's confirmation of a decision of the scope's tenant (FR-42). The justification
    arrives sealed (`sft.service.fields`), and the row names its key version (#236)."""
    require_scope(session, *_TENANT)
    await session.execute(
        insert(DlpConfirmation).values(
            id=confirmation_id,
            tenant_id=tenant_of(session),
            transfer_id=transfer_id,
            decision_id=decision_id,
            confirmed_by=confirmed_by,
            justification_ct=justification_ct,
            data_key_version=key_version(justification_ct),
        )
    )


# ---- known recipient domains (FR-46) ----


async def known_since(
    session: AsyncSession, domains: Sequence[str], *, since: datetime
) -> set[str]:
    """Which of `domains` the tenant has sent to since `since`: the evaluation's "not new"."""
    require_scope(session, *_TENANT)
    if not domains:
        return set()
    rows = await session.scalars(
        select(DlpKnownDomain.domain).where(
            DlpKnownDomain.domain.in_(list(domains)),
            DlpKnownDomain.last_sent_at >= since,
            in_scope(DlpKnownDomain, session),
        )
    )
    return set(rows)


async def known_before(session: AsyncSession, domains: Sequence[str], *, at: datetime) -> set[str]:
    """Which of `domains` the tenant had first sent to before `at`: a past decision's "not new",
    which a later send to the domain doesn't change."""
    require_scope(session, *_TENANT)
    if not domains:
        return set()
    rows = await session.scalars(
        select(DlpKnownDomain.domain).where(
            DlpKnownDomain.domain.in_(list(domains)),
            DlpKnownDomain.first_sent_at < at,
            in_scope(DlpKnownDomain, session),
        )
    )
    return set(rows)


async def record_known_domains(session: AsyncSession, domains: Sequence[str]) -> int:
    """Record that the scope's tenant sent to each of `domains` now: a new row, or
    `last_sent_at` moved on. In sorted order, so two sends that share domains lock their rows in
    the same order and never deadlock."""
    require_scope(session, *_TENANT)
    wanted = sorted(set(domains))[:KNOWN_DOMAIN_BATCH]
    if not wanted:
        return 0
    tenant_id = tenant_of(session)
    statement = pg_insert(DlpKnownDomain).values(
        [{"tenant_id": tenant_id, "domain": domain} for domain in wanted]
    )
    await session.execute(
        statement.on_conflict_do_update(
            index_elements=[DlpKnownDomain.tenant_id, DlpKnownDomain.domain],
            set_={"last_sent_at": func.now()},
            where=in_scope(DlpKnownDomain, session),
        )
    )
    return len(wanted)


async def tenants_with_stale_domains(
    session: AsyncSession, *, before: datetime, limit: int
) -> list[UUID]:
    """Tenants with a known domain last sent to before `before`, across tenants, in system
    scope (data model 6)."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.scalars(
        select(DlpKnownDomain.tenant_id)
        .where(DlpKnownDomain.last_sent_at < before, in_scope(DlpKnownDomain, session))
        .group_by(DlpKnownDomain.tenant_id)
        .limit(limit)
    )
    return list(rows)


async def delete_stale_domains(session: AsyncSession, *, before: datetime, limit: int) -> int:
    """Delete up to `limit` of the scope's tenant's known domains last sent to before `before`;
    the caller audits the batch."""
    require_scope(session, *_TENANT)
    found = (
        select(DlpKnownDomain.tenant_id, DlpKnownDomain.domain)
        .where(DlpKnownDomain.last_sent_at < before, in_scope(DlpKnownDomain, session))
        .limit(limit)
        .correlate(None)
    )
    result = await session.execute(
        delete(DlpKnownDomain)
        .where(
            tuple_(DlpKnownDomain.tenant_id, DlpKnownDomain.domain).in_(found),
            in_scope(DlpKnownDomain, session),
        )
        .returning(DlpKnownDomain.domain)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())
