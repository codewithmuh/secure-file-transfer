"""The operator API's scheduled work beyond the break-glass sweep (#239): the break-glass
reconciliation every 15 minutes and the daily SSO drift check.

Both run in the operator API's process, like the sweep, rather than as CronJobs: they need what
only the operator API has, platform scope as `sft_operator` (`break_glass_grants`, the tenants'
recorded SSO connections) and its IAM role, and they report through its /metrics, which Prometheus
already scrapes (authn and authz 2.5, 8.3). Each starts only where the environment configures it:
the reconciliation with `BREAK_GLASS_TRAIL_ROLE_ARN`, the drift check with `SSO_DRIFT_POOLS`. A
failed run is logged and tried again at the next interval; the stale-run alerts fire if none
succeeds for too long (deploy/alerts/break-glass-records.rules.yaml, sso.rules.yaml). Running in
more than one replica is safe: a grant is recorded once (its assignment ID is unique), and a drift
finding repeated is only repeated.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Gauge

from sft.core.settings import OperatorSettings
from sft.data.database import Database
from sft.runtime.break_glass_trail import CloudTrailAssignments
from sft.runtime.sso_directory import CognitoProviderDirectory
from sft.service import break_glass_records, sso_drift
from sft.service.break_glass_records import AssignmentTrail, ReconcileResult
from sft.service.sso_drift import DriftResult, PoolRegion, Problem, ProviderDirectory

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RecordMetrics:
    """What deploy/alerts/break-glass-records.rules.yaml reads."""

    last_success: Gauge
    reconciled: Counter
    unrecorded: Gauge
    tenant_records_missed: Counter
    """The sweep's counter: a record missing in a tenant's log alerts the same way."""

    @classmethod
    def create(cls, registry: CollectorRegistry, tenant_records_missed: Counter) -> RecordMetrics:
        unrecorded = Gauge(
            "sft_break_glass_unrecorded_assignments",
            "BreakGlass assignments in CloudTrail that the reconciliation couldn't record, an "
            "hour or more after they started (authn and authz 8.3); any pages.",
            registry=registry,
        )
        unrecorded.set(0)
        return cls(
            last_success=Gauge(
                "sft_break_glass_reconciliation_last_success_timestamp_seconds",
                "When the break-glass reconciliation last ran to the end, as a Unix time.",
                registry=registry,
            ),
            reconciled=Counter(
                "sft_break_glass_records_reconciled_total",
                "Break-glass grants the reconciliation recorded because the tool didn't.",
                registry=registry,
            ),
            unrecorded=unrecorded,
            tenant_records_missed=tenant_records_missed,
        )

    def observe(self, result: ReconcileResult) -> None:
        if result.reconciled:
            self.reconciled.inc(result.reconciled)
        if result.tenant_records_missed:
            self.tenant_records_missed.inc(result.tenant_records_missed)
        self.unrecorded.set(result.unrecorded)
        self.last_success.set_to_current_time()


@dataclass(frozen=True, slots=True)
class DriftMetrics:
    """What deploy/alerts/sso.rules.yaml reads."""

    findings: Gauge
    last_success: Gauge

    @classmethod
    def create(cls, registry: CollectorRegistry, pools: tuple[PoolRegion, ...]) -> DriftMetrics:
        findings = Gauge(
            "sft_sso_provider_drift",
            "Tenant SSO providers that differ from the recorded configuration in a user pool, "
            "at the last check, by pool and problem (authn and authz 2.5).",
            ["pool", "problem"],
            registry=registry,
        )
        for pool in pools:
            for problem in Problem:
                findings.labels(pool=pool.value, problem=problem.value).set(0)
        return cls(
            findings=findings,
            last_success=Gauge(
                "sft_sso_drift_check_last_success_timestamp_seconds",
                "When the SSO drift check last ran to the end, as a Unix time.",
                registry=registry,
            ),
        )

    def observe(self, result: DriftResult) -> None:
        for (pool, problem), count in result.counts().items():
            self.findings.labels(pool=pool.value, problem=problem.value).set(count)
        self.last_success.set_to_current_time()


async def every[T](
    run: Callable[[], Awaitable[T]], observe: Callable[[T], None], interval: float, name: str
) -> None:
    """Run `run` now and then every `interval` seconds until cancelled; a failure is logged."""
    while True:
        try:
            observe(await run())
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("a scheduled operator job failed", extra={"job": name})
        await asyncio.sleep(interval)


def start(
    settings: OperatorSettings,
    database: Database,
    registry: CollectorRegistry,
    tenant_records_missed: Counter,
    *,
    trail: AssignmentTrail | None = None,
    directory: ProviderDirectory | None = None,
) -> list[asyncio.Task[None]]:
    """The jobs this environment configures, started; the caller cancels them at shutdown."""
    tasks = []
    if trail is None and settings.break_glass_trail_role_arn:
        assert settings.break_glass_permission_set_arn  # noqa: S101 - the settings' validator
        assert settings.identity_store_id  # noqa: S101
        trail = CloudTrailAssignments(
            role_arn=settings.break_glass_trail_role_arn,
            region=settings.identity_center_region,
            account_id=settings.operator_aws_account_id,
            permission_set_arn=settings.break_glass_permission_set_arn,
            identity_store_id=settings.identity_store_id,
        )
    if trail is not None:
        found = trail
        records = RecordMetrics.create(registry, tenant_records_missed)
        tasks.append(
            asyncio.create_task(
                every(
                    lambda: break_glass_records.reconcile(database, found),
                    records.observe,
                    settings.break_glass_reconcile_seconds,
                    "break_glass_reconciliation",
                )
            )
        )
    if directory is None and settings.sso_drift_pools:
        directory = CognitoProviderDirectory(settings.sso_drift_pools)
    if directory is not None:
        pools = directory
        drift = DriftMetrics.create(registry, tuple(pools.pools))
        tasks.append(
            asyncio.create_task(
                every(
                    lambda: sso_drift.check(database, pools),
                    drift.observe,
                    settings.sso_drift_check_seconds,
                    "sso_drift_check",
                )
            )
        )
    return tasks


__all__ = ["DriftMetrics", "RecordMetrics", "every", "start"]
