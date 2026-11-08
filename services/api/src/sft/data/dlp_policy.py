"""Data access for the DLP policy: `dlp_policies`, `dlp_rules` and `dlp_detectors` (#218; data
model 2.7, 5, 6; revision 0024).

- **The policy row**, one per tenant, in its scope. Every write locks it first (`get_policy(...,
  lock=True)`), so the changes of one tenant's policy, its rules and its detectors run one after
  the other: `expected_version`, the 50-rule and 50-detector limits and "a live rule uses this
  detector" are checked under that lock. `raise_version` then changes the fields asked and raises
  `version` by one, in the same transaction as the rule or detector change.
- **Rules and detectors are revisions** (`(id, revision)`), never changed in place: an update
  retires the live revision (`retired_at`) and inserts the next; a deletion only retires. The API's
  role may change no column but `retired_at` (revision 0024).
- **The default policy** is the database's `dlp_default_policy` function (revision 0024), which
  `createTenant` calls as `sft_operator` (`insert_default_policy`).
- **The scan worker** reads the tenant's live, enabled detectors with the policy version
  (`scan_detectors`), as `sft_scan`, which may read and never write these tables.
- **The daily cleanup** (`sft_jobs`) finds tenants with retired revisions nothing needs any more
  across tenants in system scope, then deletes them in each tenant's scope, in batches (data
  model 6). The caller writes the audit event each batch's trigger asks for.

Every function filters with `in_scope`, and every write takes its tenant from the scope.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    Text,
    and_,
    cast,
    delete,
    func,
    insert,
    literal,
    select,
    text,
    tuple_,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import (
    DlpDecisionRule,
    DlpDetector,
    DlpFinding,
    DlpMode,
    DlpPatternStop,
    DlpPolicy,
    DlpRule,
    Role,
    User,
    UserStatus,
)
from sft.data.scope import ScopeKind

CUSTOM_PREFIX: Final = "custom:"
"""How a rule and a finding name a tenant's own detector: `custom:` and its ID (data model 2.7).
The same prefix as the detector library's (`sft.dlp.units.CUSTOM_PREFIX`), which the data layer
doesn't import."""

_TENANT = (ScopeKind.TENANT,)


def detector_ref(detector_id: UUID) -> str:
    """`custom:<id>`, as rules and findings name a tenant's own detector."""
    return f"{CUSTOM_PREFIX}{detector_id}"


# ---- the policy row ----


async def get_policy(session: AsyncSession, *, lock: bool = False) -> DlpPolicy | None:
    """The scope's tenant's policy; with `lock`, locked until the transaction ends."""
    require_scope(session, *_TENANT)
    statement = select(DlpPolicy).where(in_scope(DlpPolicy, session))
    if lock:
        statement = statement.with_for_update()
    policy: DlpPolicy | None = await session.scalar(
        statement.execution_options(populate_existing=True)
    )
    return policy


async def raise_version(
    session: AsyncSession,
    *,
    updated_by: UUID | None,
    mode: DlpMode | None = None,
    trusted_domains: Sequence[str] | None = None,
    approval_timeout: timedelta | None = None,
) -> DlpPolicy:
    """Change the fields given, and raise `version` by one; the policy as it is now.

    Call it once per change, after `get_policy(..., lock=True)`. Commits only with an audit event
    in the same transaction (`audit_required`).
    """
    require_scope(session, *_TENANT)
    values: dict[str, object] = {
        "version": DlpPolicy.version + 1,
        "updated_by": updated_by,
        "updated_at": func.now(),
    }
    if mode is not None:
        values["mode"] = DlpMode(mode).value
    if trusted_domains is not None:
        values["trusted_domains"] = list(trusted_domains)
    if approval_timeout is not None:
        values["approval_timeout"] = approval_timeout
    policy: DlpPolicy | None = await session.scalar(
        update(DlpPolicy)
        .where(in_scope(DlpPolicy, session))
        .values(values)
        .returning(DlpPolicy)
        .execution_options(synchronize_session=False, populate_existing=True)
    )
    if policy is None:
        raise LookupError("the tenant has no DLP policy")
    return policy


async def insert_default_policy(session: AsyncSession, *, created_by: UUID, locale: str) -> None:
    """The default policy of detectors 6 for the scope's tenant, at version 1, its rules named in
    `locale` (`createTenant`, as `sft_operator`; revision 0024's `dlp_default_policy`)."""
    require_scope(session, *_TENANT)
    await session.execute(
        text("SELECT dlp_default_policy(:tenant, :created_by, :locale)"),
        {"tenant": tenant_of(session), "created_by": created_by, "locale": locale},
    )


async def count_active_approvers(session: AsyncSession) -> int:
    """Active users of the tenant with the DLP approver designation (FR-43)."""
    require_scope(session, *_TENANT)
    count = await session.scalar(
        select(func.count())
        .select_from(User)
        .where(
            User.dlp_approver.is_(True),
            User.status == UserStatus.ACTIVE.value,
            in_scope(User, session),
        )
    )
    return int(count or 0)


async def active_admin_ids(session: AsyncSession) -> list[UUID]:
    """The tenant's active admins, oldest first: who a policy change is emailed to (FR-54)."""
    require_scope(session, *_TENANT)
    rows = await session.scalars(
        select(User.id)
        .where(
            User.role == Role.ADMIN.value,
            User.status == UserStatus.ACTIVE.value,
            in_scope(User, session),
        )
        .order_by(User.id)
    )
    return list(rows)


# ---- rules ----


def _live(model: type[DlpRule] | type[DlpDetector]) -> ColumnElement[bool]:
    return model.retired_at.is_(None)


async def list_live_rules(session: AsyncSession) -> list[DlpRule]:
    """The tenant's live rules, in the order they were made (UUIDv7 IDs)."""
    require_scope(session, *_TENANT)
    rows = await session.scalars(
        select(DlpRule).where(_live(DlpRule), in_scope(DlpRule, session)).order_by(DlpRule.id)
    )
    return list(rows)


async def count_live_rules(session: AsyncSession) -> int:
    require_scope(session, *_TENANT)
    count = await session.scalar(
        select(func.count()).select_from(DlpRule).where(_live(DlpRule), in_scope(DlpRule, session))
    )
    return int(count or 0)


async def get_live_rule(session: AsyncSession, rule_id: UUID) -> DlpRule | None:
    """The rule's live revision; None if it was deleted or isn't the tenant's."""
    require_scope(session, *_TENANT)
    rule: DlpRule | None = await session.scalar(
        select(DlpRule)
        .where(DlpRule.id == rule_id, _live(DlpRule), in_scope(DlpRule, session))
        .execution_options(populate_existing=True)
    )
    return rule


@dataclass(frozen=True, slots=True)
class RuleFields:
    """Every field of a rule revision but its identity and its times."""

    name: str
    direction: str
    condition: str
    detectors: Sequence[str]
    min_confidence: str
    threshold: int
    reasons: Sequence[str]
    include_sender_24h: bool
    recipient_scope: str
    action: str
    approvals_required: int
    enabled: bool


async def insert_rule(
    session: AsyncSession,
    rule_id: UUID,
    revision: int,
    fields: RuleFields,
    *,
    created_by: UUID | None,
) -> DlpRule:
    """A rule revision of the scope's tenant: a new rule at revision 1, or the next revision of
    one whose live revision `retire_rule` has just retired."""
    require_scope(session, *_TENANT)
    rule: DlpRule | None = await session.scalar(
        insert(DlpRule)
        .values(
            id=rule_id,
            revision=revision,
            tenant_id=tenant_of(session),
            name=fields.name,
            direction=fields.direction,
            condition=fields.condition,
            detectors=list(fields.detectors),
            min_confidence=fields.min_confidence,
            threshold=fields.threshold,
            reasons=list(fields.reasons),
            include_sender_24h=fields.include_sender_24h,
            recipient_scope=fields.recipient_scope,
            action=fields.action,
            approvals_required=fields.approvals_required,
            enabled=fields.enabled,
            created_by=created_by,
        )
        .returning(DlpRule)
    )
    if rule is None:  # pragma: no cover - an insert returns its row
        raise RuntimeError("the rule revision wasn't written")
    return rule


async def retire_rule(session: AsyncSession, rule_id: UUID, revision: int) -> bool:
    """Retire the rule's live revision `revision`; False if it isn't live or the tenant's."""
    require_scope(session, *_TENANT)
    result = await session.execute(
        update(DlpRule)
        .where(
            DlpRule.id == rule_id,
            DlpRule.revision == revision,
            _live(DlpRule),
            in_scope(DlpRule, session),
        )
        .values(retired_at=func.now())
        .returning(DlpRule.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def live_rules_using(session: AsyncSession, detector: str) -> int:
    """How many live rules name `detector` (`custom:<id>`): such a detector can't be deleted."""
    require_scope(session, *_TENANT)
    count = await session.scalar(
        select(func.count())
        .select_from(DlpRule)
        .where(
            DlpRule.detectors.any(detector),  # type: ignore[arg-type]
            _live(DlpRule),
            in_scope(DlpRule, session),
        )
    )
    return int(count or 0)


# ---- detectors ----


async def list_live_detectors(session: AsyncSession) -> list[DlpDetector]:
    """The tenant's live detectors, in the order they were made."""
    require_scope(session, *_TENANT)
    rows = await session.scalars(
        select(DlpDetector)
        .where(_live(DlpDetector), in_scope(DlpDetector, session))
        .order_by(DlpDetector.id)
    )
    return list(rows)


async def get_live_detector(session: AsyncSession, detector_id: UUID) -> DlpDetector | None:
    """The detector's live revision; None if it was deleted or isn't the tenant's."""
    require_scope(session, *_TENANT)
    detector: DlpDetector | None = await session.scalar(
        select(DlpDetector)
        .where(DlpDetector.id == detector_id, _live(DlpDetector), in_scope(DlpDetector, session))
        .execution_options(populate_existing=True)
    )
    return detector


@dataclass(frozen=True, slots=True)
class DetectorFields:
    name: str
    kind: str
    definition_ct: bytes
    enabled: bool


async def insert_detector(
    session: AsyncSession,
    detector_id: UUID,
    revision: int,
    fields: DetectorFields,
    *,
    created_by: UUID,
) -> DlpDetector:
    """A detector revision of the scope's tenant, as `insert_rule` for rules."""
    require_scope(session, *_TENANT)
    detector: DlpDetector | None = await session.scalar(
        insert(DlpDetector)
        .values(
            id=detector_id,
            revision=revision,
            tenant_id=tenant_of(session),
            name=fields.name,
            kind=fields.kind,
            definition_ct=fields.definition_ct,
            enabled=fields.enabled,
            created_by=created_by,
        )
        .returning(DlpDetector)
    )
    if detector is None:  # pragma: no cover - an insert returns its row
        raise RuntimeError("the detector revision wasn't written")
    return detector


async def retire_detector(session: AsyncSession, detector_id: UUID, revision: int) -> bool:
    """Retire the detector's live revision `revision`; False if it isn't live."""
    require_scope(session, *_TENANT)
    result = await session.execute(
        update(DlpDetector)
        .where(
            DlpDetector.id == detector_id,
            DlpDetector.revision == revision,
            _live(DlpDetector),
            in_scope(DlpDetector, session),
        )
        .values(retired_at=func.now())
        .returning(DlpDetector.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def detector_names(session: AsyncSession, detector_ids: Sequence[UUID]) -> dict[UUID, str]:
    """The name of each of these detectors of the tenant, from its latest revision, live or
    retired: findings keep naming a deleted detector (the cleanup keeps that revision)."""
    require_scope(session, *_TENANT)
    if not detector_ids:
        return {}
    rows = await session.execute(
        select(DlpDetector.id, DlpDetector.name)
        .where(DlpDetector.id.in_(detector_ids), in_scope(DlpDetector, session))
        .order_by(DlpDetector.id, DlpDetector.revision.desc())
        .distinct(DlpDetector.id)
    )
    return {row.id: row.name for row in rows}


# ---- the scan worker's read (architecture 4.6) ----


@dataclass(frozen=True, slots=True)
class ScanDetector:
    id: UUID
    kind: str
    definition_ct: bytes


@dataclass(frozen=True, slots=True)
class ScanDetectors:
    """What the inspector gets with a file: the policy version, and the tenant's live, enabled
    detectors. A tenant without a policy row has version None and no detectors."""

    policy_version: int | None
    detectors: tuple[ScanDetector, ...]


async def scan_detectors(session: AsyncSession) -> ScanDetectors:
    """The tenant's live, enabled detectors and the policy version they belong to, in one
    transaction, so the version recorded on the file names the detectors that ran."""
    require_scope(session, *_TENANT)
    version = await session.scalar(select(DlpPolicy.version).where(in_scope(DlpPolicy, session)))
    rows = await session.execute(
        select(DlpDetector.id, DlpDetector.kind, DlpDetector.definition_ct)
        .where(
            _live(DlpDetector),
            DlpDetector.enabled.is_(True),
            in_scope(DlpDetector, session),
        )
        .order_by(DlpDetector.id)
    )
    found = tuple(ScanDetector(r.id, r.kind, r.definition_ct) for r in rows)
    return ScanDetectors(version, found if version is not None else ())


# ---- patterns stopped by their scan-time budget (#164, #221, revision 0027) ----


@dataclass(frozen=True, slots=True)
class PatternStops:
    files: int
    last_at: datetime


async def record_pattern_stops(session: AsyncSession, detector_ids: Sequence[UUID]) -> int:
    """One more file stopped each of these patterns, now: as the scan worker (`sft_scan`), in the
    transaction that records the file's result. Only the scope's tenant's own detectors count (no
    foreign key can say so: a detector's key has its revision), so a stop never names another
    tenant's. In detector order, so two results that share patterns lock their rows in the same
    order."""
    require_scope(session, *_TENANT)
    wanted = sorted(set(detector_ids))
    if not wanted:
        return 0
    own = (
        select(
            DlpDetector.tenant_id,
            DlpDetector.id,
            literal(1),
            func.now(),
        )
        .where(DlpDetector.id.in_(wanted), in_scope(DlpDetector, session))
        .distinct()
        .order_by(DlpDetector.tenant_id, DlpDetector.id)
    )
    statement = pg_insert(DlpPatternStop).from_select(
        ["tenant_id", "detector_id", "files_stopped", "last_stopped_at"], own
    )
    result = await session.execute(
        statement.on_conflict_do_update(
            index_elements=[DlpPatternStop.tenant_id, DlpPatternStop.detector_id],
            set_={
                "files_stopped": DlpPatternStop.files_stopped + 1,
                "last_stopped_at": func.now(),
            },
            where=in_scope(DlpPatternStop, session),
        ).returning(DlpPatternStop.detector_id)
    )
    return len(result.all())


async def pattern_stops(session: AsyncSession, detector_id: UUID) -> PatternStops | None:
    """How many files stopped the pattern, and when last; None if none ever did."""
    require_scope(session, *_TENANT)
    row = (
        await session.execute(
            select(DlpPatternStop.files_stopped, DlpPatternStop.last_stopped_at).where(
                DlpPatternStop.detector_id == detector_id, in_scope(DlpPatternStop, session)
            )
        )
    ).first()
    return None if row is None else PatternStops(row.files_stopped, row.last_stopped_at)


# ---- the daily cleanup (data model 6) ----


def _rule_unreferenced(retired: type[DlpRule]) -> list[ColumnElement[bool]]:
    """What keeps a retired rule revision: a decision that applied it (#219). Its foreign key
    refuses the delete anyway; this keeps the cleanup from trying. `sft_jobs` reads
    `dlp_decision_rules (tenant_id, rule_id, rule_revision)` for it, in system scope too
    (`jobs_find`, revision 0025)."""
    applied = (
        select(literal(1))
        .where(
            DlpDecisionRule.tenant_id == retired.tenant_id,
            DlpDecisionRule.rule_id == retired.id,
            DlpDecisionRule.rule_revision == retired.revision,
        )
        .exists()
    )
    return [~applied]


def _deletable_rules() -> ColumnElement[bool]:
    return and_(DlpRule.retired_at.is_not(None), *_rule_unreferenced(DlpRule))


def _deletable_detectors() -> ColumnElement[bool]:
    """A retired detector revision nothing needs: a later revision of the same detector carries
    its name on, or, for the last revision of a deleted detector, no live rule and no finding
    names it (`custom:<id>`)."""
    later = aliased(DlpDetector)
    ref = literal(CUSTOM_PREFIX, Text) + cast(DlpDetector.id, Text)
    # `SELECT 1`, not `SELECT *`: the jobs' role reads only two columns of `dlp_findings`.
    superseded = (
        select(literal(1))
        .where(
            later.tenant_id == DlpDetector.tenant_id,
            later.id == DlpDetector.id,
            later.revision > DlpDetector.revision,
        )
        .exists()
    )
    named_by_rule = (
        select(literal(1))
        .where(
            DlpRule.tenant_id == DlpDetector.tenant_id,
            DlpRule.retired_at.is_(None),
            DlpRule.detectors.any(ref),
        )
        .exists()
    )
    named_by_finding = (
        select(literal(1))
        .where(DlpFinding.tenant_id == DlpDetector.tenant_id, DlpFinding.detector == ref)
        .exists()
    )
    return and_(
        DlpDetector.retired_at.is_not(None), superseded | ~(named_by_rule | named_by_finding)
    )


async def tenants_with_retired_rules(
    session: AsyncSession, *, before: datetime, limit: int
) -> list[UUID]:
    """Tenants with rule revisions retired before `before` that nothing needs, across tenants,
    in system scope."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.scalars(
        select(DlpRule.tenant_id)
        .where(DlpRule.retired_at < before, _deletable_rules(), in_scope(DlpRule, session))
        .group_by(DlpRule.tenant_id)
        .limit(limit)
    )
    return list(rows)


async def delete_retired_rules(session: AsyncSession, *, before: datetime, limit: int) -> int:
    """Delete up to `limit` of the scope's tenant's rule revisions retired before `before` that
    nothing needs. The caller writes the audit event the table's trigger asks for."""
    require_scope(session, *_TENANT)
    found = (
        select(DlpRule.id, DlpRule.revision)
        .where(DlpRule.retired_at < before, _deletable_rules(), in_scope(DlpRule, session))
        .limit(limit)
        .correlate(None)
    )
    result = await session.execute(
        delete(DlpRule)
        .where(
            tuple_(DlpRule.id, DlpRule.revision).in_(found),
            in_scope(DlpRule, session),
        )
        .returning(DlpRule.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())


async def tenants_with_retired_detectors(
    session: AsyncSession, *, before: datetime, limit: int
) -> list[UUID]:
    """Tenants with detector revisions retired before `before` that nothing needs, across
    tenants, in system scope."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.scalars(
        select(DlpDetector.tenant_id)
        .where(
            DlpDetector.retired_at < before,
            _deletable_detectors(),
            in_scope(DlpDetector, session),
        )
        .group_by(DlpDetector.tenant_id)
        .limit(limit)
    )
    return list(rows)


async def delete_retired_detectors(session: AsyncSession, *, before: datetime, limit: int) -> int:
    """Delete up to `limit` of the scope's tenant's detector revisions retired before `before`
    that nothing needs; the caller audits the batch."""
    require_scope(session, *_TENANT)
    found = (
        select(DlpDetector.id, DlpDetector.revision)
        .where(
            DlpDetector.retired_at < before,
            _deletable_detectors(),
            in_scope(DlpDetector, session),
        )
        .limit(limit)
        .correlate(None)
    )
    result = await session.execute(
        delete(DlpDetector)
        .where(
            tuple_(DlpDetector.id, DlpDetector.revision).in_(found),
            in_scope(DlpDetector, session),
        )
        .returning(DlpDetector.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())
