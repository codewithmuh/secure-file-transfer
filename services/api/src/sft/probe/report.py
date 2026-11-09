"""Where a probe run's result goes: Prometheus through the Pushgateway, and CloudWatch.

**Prometheus** (the shared names of M7; ALERTS' rules and OBS's dashboards read them):

- `synthetic_probe_success`: 1 when the last run passed, 0 when it failed.
- `synthetic_probe_step_failures_total{step}`: 1 on the step that failed, 0 on every other, each
  run. The Pushgateway keeps the last push, so `increase()` over a window counts failed runs.
- `synthetic_probe_duration_seconds`: the last run, end to end.
- `synthetic_probe_last_success_timestamp_seconds`: pushed only by a run that passed, with
  `pushadd` (POST), which replaces only the metrics in the push, so a failed run leaves it as it
  was: its age is how long the journey has been broken.
- `synthetic_probe_step_duration_seconds{step}` and `synthetic_probe_download_first_byte_seconds`:
  where the time went, NFR-4's synthetic measure among them.

**CloudWatch** (ADR-0005, M7 shared names): namespace `SecureFileTransfer/Probe`, metric
`ProbeSuccess` (1 or 0) with the dimension `Environment`, which the watchdog alarm reads, and the
same value with `Environment` and `ImageDigest`, which `promotion-gate` reads for the digest it
promotes. The CloudWatch alarm treats missing data as breaching, so a probe that stops running
alarms too.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final, Protocol

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from prometheus_client import CollectorRegistry, Counter, Gauge, pushadd_to_gateway

log = logging.getLogger(__name__)

NAMESPACE: Final = "SecureFileTransfer/Probe"
METRIC: Final = "ProbeSuccess"
PUSH_JOB: Final = "sft-synthetic-probe"


def registry_for(
    *,
    passed: bool,
    failed_step: str | None,
    steps: Sequence[str],
    seconds: float,
    step_seconds: Mapping[str, float],
    first_byte_seconds: float | None,
    finished_at: float,
) -> CollectorRegistry:
    """One run's metrics, in a registry of their own for the push."""
    registry = CollectorRegistry()
    Gauge(
        "synthetic_probe_success", "1 if the last probe run passed, else 0", registry=registry
    ).set(1 if passed else 0)
    failures = Counter(
        "synthetic_probe_step_failures",
        "Probe runs that failed at this step (the last run: 1 on its failing step)",
        ["step"],
        registry=registry,
    )
    for step in steps:
        failures.labels(step).inc(1 if step == failed_step else 0)
    Gauge(
        "synthetic_probe_duration_seconds", "The last probe run, end to end", registry=registry
    ).set(seconds)
    durations = Gauge(
        "synthetic_probe_step_duration_seconds",
        "Each step of the last probe run",
        ["step"],
        registry=registry,
    )
    for step, value in step_seconds.items():
        durations.labels(step).set(value)
    if first_byte_seconds is not None:
        Gauge(
            "synthetic_probe_download_first_byte_seconds",
            "From the download request to its first byte, in the last run (NFR-4)",
            registry=registry,
        ).set(first_byte_seconds)
    if passed:
        Gauge(
            "synthetic_probe_last_success_timestamp_seconds",
            "When a probe run last passed",
            registry=registry,
        ).set(finished_at)
    return registry


def push(gateway: str, registry: CollectorRegistry) -> None:
    """POST, not PUT: keep the last success's timestamp when this run failed."""
    try:
        pushadd_to_gateway(gateway, job=PUSH_JOB, registry=registry, timeout=10)
    except OSError as exc:
        log.warning("metrics push failed", extra={"error": type(exc).__name__})


class _CloudWatchClient(Protocol):
    def put_metric_data(self, **kwargs: Any) -> Mapping[str, Any]: ...


def cloudwatch_client(region: str) -> _CloudWatchClient:
    client: _CloudWatchClient = boto3.client(
        "cloudwatch",
        region_name=region,
        config=Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5),
    )
    return client


def metric_data(
    *, environment: str, passed: bool, image_digest: str | None, at: datetime
) -> list[dict[str, Any]]:
    """`ProbeSuccess` by environment, and by environment and digest when the digest is known."""
    dimension_sets = [[{"Name": "Environment", "Value": environment}]]
    if image_digest:
        dimension_sets.append(
            [
                {"Name": "Environment", "Value": environment},
                {"Name": "ImageDigest", "Value": image_digest},
            ]
        )
    return [
        {
            "MetricName": METRIC,
            "Dimensions": dimensions,
            "Timestamp": at,
            "Value": 1.0 if passed else 0.0,
            "Unit": "Count",
        }
        for dimensions in dimension_sets
    ]


def publish(
    client: _CloudWatchClient,
    *,
    environment: str,
    passed: bool,
    image_digest: str | None,
    at: datetime | None = None,
) -> bool:
    """Put the result; False (and a warning) if CloudWatch refused it. Never raises: the missing
    datapoint is what the alarm sees then."""
    try:
        client.put_metric_data(
            Namespace=NAMESPACE,
            MetricData=metric_data(
                environment=environment,
                passed=passed,
                image_digest=image_digest,
                at=at or datetime.now(UTC),
            ),
        )
    except (BotoCoreError, ClientError) as exc:
        log.warning("CloudWatch put failed", extra={"error": type(exc).__name__})
        return False
    return True
