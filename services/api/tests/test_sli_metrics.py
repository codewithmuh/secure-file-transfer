"""The SLI metrics and their catalogue (#242; architecture 5.5; NFR-5, NFR-23, NFR-26).

Every metric the code defines is in docs/operations/metrics.md, and every application metric the
catalogue lists is defined in the code. Every label is one of a closed list that can't hold a
tenant ID, an address, a file name or a detected value, and the label values made at start are
bounded codes. The series the SLOs and alerts read exist at zero on start, and move on the right
events: a transfer the evaluation sends, and a received file found clean.
"""

from __future__ import annotations

import dataclasses
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry
from prometheus_client.metrics import MetricWrapperBase

import sft
from member_fixtures import seed_tenant
from pg import ScratchDatabase
from sft.api.observability import HttpMetrics
from sft.api.operator.app import BreakGlassMetrics
from sft.data.audit import Actor
from sft.data.counters import CounterMetrics
from sft.data.database import Database
from sft.data.models import ActorType
from sft.data.roles import SCAN
from sft.data.scope import Scope
from sft.probe import report
from sft.probe.journey import STEPS
from sft.runtime.secrets import KeyringMetrics
from sft.service import evaluation, sli
from sft.service.archive_job import ArchiveJobMetrics
from sft.service.audit_partitions import AuditPartitionMetrics
from sft.service.downloads import DownloadMetrics
from sft.service.evaluation import Outcome
from sft.service.fields import FieldMetrics
from sft.service.lifecycle import JobMetrics, PurgeMetrics
from sft.service.links import LinkMetrics
from sft.service.notifications import NotifyMetrics
from sft.workers.consumer import ConsumerMetrics
from sft.workers.relay import RelayMetrics
from sft.workers.scan import GuardDutyMetrics, ScanMetrics
from transfer_fixtures import seed_file, seed_transfer

pytestmark = pytest.mark.anyio

CATALOGUE = Path(sft.__file__).parents[4] / "docs" / "operations" / "metrics.md"
SOURCE = Path(sft.__file__).parent

# Every label any metric of ours may have: codes from closed lists, a route template, an HTTP
# status, a region, a job's name. None of them can carry a tenant, a person, a file or a value
# (NFR-26, architecture 5.5); a new label joins this list only after that review.
ALLOWED_LABELS = frozenset(
    {
        "action",
        "cap",
        "column",
        "consumer",
        "group",
        "job",
        "key_type",
        "keyring",
        "kind",
        "method",
        "outcome",
        "pool",
        "purpose",
        "queue",
        "reason",
        "region",
        "result",
        "route",
        "self_approved",
        "size_class",
        "state",
        "status",
        "step",
        "type",
    }
)
_DEFINED = re.compile(r"(Counter|Gauge|Histogram)\(\s*\"([a-z][a-z0-9_]*)\"")
_CATALOGUED = re.compile(
    r"^\| `([a-z][a-z0-9_]*)` \| (?:counter|gauge|histogram|gauge or histogram) \|(.*)$",
    re.MULTILINE,
)


def every_metric(registry: CollectorRegistry) -> list[object]:
    """Every metrics object of the service, each made once, as the processes make them."""
    return [
        HttpMetrics.create(),
        BreakGlassMetrics.create(registry),
        CounterMetrics.create(registry),
        KeyringMetrics.create(registry),
        ArchiveJobMetrics.create(registry),
        AuditPartitionMetrics.create(registry),
        DownloadMetrics.create(registry),
        FieldMetrics.create(registry),
        JobMetrics.create(registry),
        PurgeMetrics.create(registry),
        LinkMetrics.create(registry),
        NotifyMetrics.create(registry),
        ConsumerMetrics.create(registry),
        RelayMetrics.create(registry),
        ScanMetrics.create(registry),
        GuardDutyMetrics.create(registry),
        sli.SliMetrics.create(registry),
    ]


def wrappers(metrics: object) -> list[MetricWrapperBase]:
    found: list[MetricWrapperBase] = []
    for f in dataclasses.fields(metrics):  # type: ignore[arg-type]
        value = getattr(metrics, f.name)
        if isinstance(value, MetricWrapperBase):
            found.append(value)
        elif dataclasses.is_dataclass(value):
            found.extend(wrappers(value))
    return found


def defined_names() -> set[str]:
    """Every metric the code defines, by the name Prometheus exposes: a counter's ends in
    `_total`, which the client adds when the code's name leaves it out."""
    return {
        name if kind != "Counter" or name.endswith("_total") else f"{name}_total"
        for path in SOURCE.rglob("*.py")
        for kind, name in _DEFINED.findall(path.read_text())
    }


def catalogued() -> dict[str, str]:
    return dict(_CATALOGUED.findall(CATALOGUE.read_text()))


def test_every_label_is_a_bounded_code_never_tenant_data() -> None:
    registry = CollectorRegistry()
    seen = 0
    for metrics in every_metric(registry):
        for metric in wrappers(metrics):
            seen += 1
            labels = set(metric._labelnames)
            assert labels <= ALLOWED_LABELS, (metric._name, labels - ALLOWED_LABELS)
    assert seen > 30
    # The values made at start are codes: no UUID, address or free text.
    for family in registry.collect():
        for sample in family.samples:
            for name, value in sample.labels.items():
                if name == "le":
                    continue  # a histogram's bucket edge
                assert re.fullmatch(r"[a-z0-9_.:-]{1,64}", value), (sample.name, value)
                with pytest.raises(ValueError, match="badly formed"):
                    uuid.UUID(value)


def test_the_probe_labels_only_its_steps() -> None:
    """The synthetic probe (#248) pushes a registry of its own each run: its labels are the closed
    list's too, and `step` is one of its fixed steps."""
    registry = report.registry_for(
        passed=False,
        failed_step="verify",
        steps=STEPS,
        seconds=1.0,
        step_seconds=dict.fromkeys(STEPS, 0.1),
        first_byte_seconds=0.2,
        finished_at=0.0,
    )
    for family in registry.collect():
        for sample in family.samples:
            assert set(sample.labels) <= ALLOWED_LABELS, (sample.name, sample.labels)
            if "step" in sample.labels:
                assert sample.labels["step"] in STEPS


def test_every_metric_is_catalogued_and_every_catalogued_app_metric_exists() -> None:
    defined = defined_names()
    listed = catalogued()
    assert defined - set(listed) == set(), "add these to docs/operations/metrics.md"
    # Rows whose source is our code name a module of sft; the others come from exporters and the
    # probe (OBS, PERF).
    ours = {name for name, rest in listed.items() if "`sft." in rest}
    assert ours - defined == set(), "the catalogue lists metrics the code no longer defines"


def test_the_sli_series_exist_at_zero_on_start() -> None:
    registry = CollectorRegistry()
    sli.SliMetrics.create(registry)
    ScanMetrics.create(registry)
    ArchiveJobMetrics.create(registry)
    for kind in ("transfer", "request_file"):
        for size in ("small", "large"):
            labels = {"kind": kind, "size_class": size}
            assert registry.get_sample_value("time_to_shareable_seconds_count", labels) == 0
    for pool in ("small", "large"):
        assert registry.get_sample_value("scan_pass_duration_seconds_count", {"pool": pool}) == 0
    for region in ("ap-northeast-1", "ap-northeast-3"):
        labels = {"region": region}
        assert registry.get_sample_value("audit_archive_events_total", labels) == 0
        assert registry.get_sample_value("audit_archive_write_failures_total", labels) == 0
    assert registry.get_sample_value("audit_archive_lag_seconds") == 0


def test_observing_needs_the_processs_metrics_and_picks_the_size_class() -> None:
    now = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
    previous = sli.install(None)
    try:
        assert (
            sli.observe_shareable(sli.ShareableKind.TRANSFER, started_at=now, now=now, largest=1)
            is None
        )
        registry = CollectorRegistry()
        sli.install(sli.SliMetrics.create(registry))
        seconds = sli.observe_shareable(
            sli.ShareableKind.REQUEST_FILE,
            started_at=now - timedelta(seconds=90),
            now=now,
            largest=sli.SMALL_MAX_BYTES + 1,
        )
        assert seconds == 90
        large = {"kind": "request_file", "size_class": "large"}
        assert registry.get_sample_value("time_to_shareable_seconds_count", large) == 1
        assert (
            registry.get_sample_value("time_to_shareable_seconds_bucket", {**large, "le": "120.0"})
            == 1
        )
        # A start the database put in the future counts as 0, never negative.
        assert (
            sli.observe_shareable(
                sli.ShareableKind.TRANSFER,
                started_at=now + timedelta(seconds=5),
                now=now,
                largest=None,
            )
            == 0
        )
    finally:
        sli.install(previous)
    assert sli.size_class(sli.SMALL_MAX_BYTES) is sli.SizeClass.SMALL
    assert sli.size_class(None) is sli.SizeClass.SMALL


async def test_a_transfer_the_evaluation_sends_moves_time_to_shareable(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    transfer_id, _ = seed_transfer(migrated_db, tenant.id, tenant.member, state="submitted")
    file_id = seed_file(migrated_db, tenant.id, transfer_id, state="clean")
    # Submitted a minute ago, its last upload completed 45 seconds ago: the clock starts then.
    migrated_db.sql(
        "UPDATE transfers SET submitted_at = now() - interval '60 seconds' WHERE id = :id",
        id=transfer_id,
    )
    migrated_db.sql(
        "UPDATE files SET completion_started_at = now() - interval '45 seconds' WHERE id = :id",
        id=file_id,
    )
    registry = CollectorRegistry()
    previous = sli.install(sli.SliMetrics.create(registry))
    database = Database.connect(migrated_db.url(SCAN), pool_size=1)
    try:
        async with database.transaction(Scope.tenant(tenant.id)) as session:
            outcome = await evaluation.evaluate(
                session, transfer_id, actor=Actor(ActorType.SYSTEM), now=datetime.now(UTC)
            )
    finally:
        await database.dispose()
        sli.install(previous)
    assert outcome is Outcome.SENT
    small = {"kind": "transfer", "size_class": "small"}
    assert registry.get_sample_value("time_to_shareable_seconds_count", small) == 1
    observed = registry.get_sample_value("time_to_shareable_seconds_sum", small)
    assert observed is not None
    assert 40 <= observed < 120
