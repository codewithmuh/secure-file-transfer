"""The daily check that each tenant's SSO provider is in both user pools as recorded (#239; FR-26;
authn and authz 2.5, 2.6).

An operator creates a tenant's provider in both pools with the CLI (`sft.runtime.sso_providers`)
and records it with `configureTenantSso`. Nothing stops someone with the `Operator` permission set
changing a provider afterwards, or a pool losing one, and a provider missing from the standby pool
only shows at a failover. So once a day the operator API compares the recorded configuration
(`sft.data.sso_drift`) with each pool (`ProviderDirectory`, an adapter: Cognito in AWS, a fake in
tests) and reports, per pool:

- **missing**: an active connection's provider isn't in the pool;
- **changed**: it is, but its type, its OIDC issuer, its attribute mapping (email, subject and
  groups only, as the CLI writes it) or its identifiers (none: our sign-in page picks the provider)
  differ, or the app client doesn't offer it;
- **unrecorded**: the pool has a provider no tenant has recorded, such as one a tenant's
  connection no longer names, or one made by hand.

An inactive connection is checked for nothing but counts as recorded: its provider may stay in the
pools or go. Each finding is a platform audit event, `sso_provider.drift_found`, naming the pool,
the problem and the connection, and each run writes `sso_provider.drift_checked` with its counts.
The operator API exports the counts (`sft_sso_provider_drift{pool,problem}`), which alert
(deploy/alerts/sso.rules.yaml). The check never changes a pool: an operator fixes the provider
with the CLI (docs/runbooks/sso-provider-drift.md). A failure to read a pool fails the run; the
stale-check alert covers it.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol
from uuid import UUID

from sft.data import audit, sso_drift
from sft.data.audit import Actor, Target
from sft.data.database import Database
from sft.data.models import ActorType
from sft.data.scope import Scope
from sft.data.sso_drift import RecordedProvider

log = logging.getLogger(__name__)

OIDC_ATTRIBUTES: Final = {"email": "email", "username": "sub", "custom:sso_groups": "groups"}
SAML_ATTRIBUTES: Final = {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "custom:sso_groups": "http://schemas.xmlsoap.org/claims/Group",
}
"""What the CLI maps, and all it maps (authn and authz 2.5). Cognito may add `username` itself."""
_ADDED_BY_THE_POOL: Final = frozenset({"username"})
TARGET: Final = "idp_connection"


class Problem(StrEnum):
    MISSING = "missing"
    CHANGED = "changed"
    UNRECORDED = "unrecorded"


class Aspect(StrEnum):
    """What differs in a changed provider."""

    TYPE = "type"
    ISSUER = "issuer"
    ATTRIBUTE_MAPPING = "attribute_mapping"
    IDENTIFIERS = "identifiers"
    NOT_ENABLED = "not_enabled"


class PoolRegion(StrEnum):
    """Which user pool: Tokyo's or Osaka's (authn and authz 2.6)."""

    TOKYO = "ap-northeast-1"
    OSAKA = "ap-northeast-3"


class DriftJob(StrEnum):
    SSO_DRIFT_CHECK = "sso_drift_check"


@dataclass(frozen=True, slots=True)
class PoolProvider:
    """A provider as a pool describes it."""

    name: str
    type: str
    """`OIDC` or `SAML`."""
    issuer: str | None = None
    attribute_mapping: Mapping[str, str] = field(default_factory=dict)
    identifiers: Sequence[str] = ()


@dataclass(frozen=True, slots=True)
class PoolSnapshot:
    providers: Mapping[str, PoolProvider]
    enabled: frozenset[str]
    """The providers the app client offers."""


class ProviderDirectory(Protocol):
    """Reads the providers of each user pool (`sft.runtime.sso_directory`); a fake in tests."""

    @property
    def pools(self) -> Sequence[PoolRegion]: ...

    async def snapshot(self, pool: PoolRegion) -> PoolSnapshot:
        """The pool's providers and its app client's; raises if the pool can't be read."""
        ...


@dataclass(frozen=True, slots=True)
class Drift:
    pool: PoolRegion
    problem: Problem
    provider_name: str
    aspects: tuple[Aspect, ...] = ()
    connection_id: UUID | None = None
    tenant_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class DriftResult:
    pools: Sequence[PoolRegion]
    checked: int
    findings: Sequence[Drift]

    def counts(self) -> dict[tuple[PoolRegion, Problem], int]:
        """Findings by pool and problem, every pair present."""
        found = Counter((d.pool, d.problem) for d in self.findings)
        return {
            (pool, problem): found[(pool, problem)] for pool in self.pools for problem in Problem
        }


def _differences(recorded: RecordedProvider, found: PoolProvider, enabled: bool) -> list[Aspect]:
    aspects = []
    if found.type.upper() != recorded.kind.upper():
        aspects.append(Aspect.TYPE)
    if recorded.kind == "oidc" and (found.issuer or "").rstrip("/") != recorded.issuer.rstrip("/"):
        aspects.append(Aspect.ISSUER)
    expected = OIDC_ATTRIBUTES if recorded.kind == "oidc" else SAML_ATTRIBUTES
    mapping = dict(found.attribute_mapping)
    if any(mapping.get(k) != v for k, v in expected.items()) or (
        set(mapping) - set(expected) - _ADDED_BY_THE_POOL
    ):
        aspects.append(Aspect.ATTRIBUTE_MAPPING)
    if list(found.identifiers):
        aspects.append(Aspect.IDENTIFIERS)
    if not enabled:
        aspects.append(Aspect.NOT_ENABLED)
    return aspects


def compare(
    pool: PoolRegion, recorded: Sequence[RecordedProvider], snapshot: PoolSnapshot
) -> list[Drift]:
    """One pool's findings against the recorded configuration."""
    findings = []
    names = {r.provider_name for r in recorded}
    for r in recorded:
        if r.status != "active":
            continue
        found = snapshot.providers.get(r.provider_name)
        if found is None:
            findings.append(
                Drift(pool, Problem.MISSING, r.provider_name, (), r.connection_id, r.tenant_id)
            )
            continue
        aspects = _differences(r, found, r.provider_name in snapshot.enabled)
        if aspects:
            findings.append(
                Drift(
                    pool,
                    Problem.CHANGED,
                    r.provider_name,
                    tuple(aspects),
                    r.connection_id,
                    r.tenant_id,
                )
            )
    for name in sorted(set(snapshot.providers) - names):
        findings.append(Drift(pool, Problem.UNRECORDED, name, (), None, _tenant_of(name)))
    return findings


def _tenant_of(provider_name: str) -> UUID | None:
    """The tenant a provider is named after (`provider_name_for`), if it is one's name at all."""
    try:
        tenant_id = UUID(hex=provider_name)
    except ValueError:
        return None
    return tenant_id if tenant_id.hex == provider_name else None


async def check(database: Database, directory: ProviderDirectory) -> DriftResult:
    """Compare every pool with the recorded configuration, and audit what differs."""
    async with database.transaction(Scope.platform()) as session:
        recorded = await sso_drift.recorded_providers(session)
    findings: list[Drift] = []
    for pool in directory.pools:
        findings += compare(pool, recorded, await directory.snapshot(pool))
    system = Actor(ActorType.SYSTEM)
    job: dict[str, audit.Detail] = {"job": DriftJob.SSO_DRIFT_CHECK}
    async with database.transaction(Scope.platform()) as session:
        for drift in findings:
            details: dict[str, audit.Detail] = {
                **job,
                "pool": drift.pool,
                "problem": drift.problem,
                "tenant_id": drift.tenant_id,
            }
            for aspect in drift.aspects:
                details[aspect.value] = True
            await audit.record(
                session,
                action="sso_provider.drift_found",
                actor=system,
                target=None if drift.connection_id is None else Target(TARGET, drift.connection_id),
                details=details,
            )
        await audit.record(
            session,
            action="sso_provider.drift_checked",
            actor=system,
            details={
                **job,
                "pools": len(directory.pools),
                "providers_checked": len(recorded),
                "findings": len(findings),
            },
        )
    if findings:
        log.warning(
            "SSO providers differ from the recorded configuration",
            extra={"findings": len(findings)},
        )
    return DriftResult(tuple(directory.pools), len(recorded), tuple(findings))


__all__ = [
    "OIDC_ATTRIBUTES",
    "SAML_ATTRIBUTES",
    "Aspect",
    "Drift",
    "DriftResult",
    "PoolProvider",
    "PoolRegion",
    "PoolSnapshot",
    "Problem",
    "ProviderDirectory",
    "check",
    "compare",
]
