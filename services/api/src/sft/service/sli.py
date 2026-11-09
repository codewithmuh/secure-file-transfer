"""Time to shareable, the SLI of NFR-5 (#242; architecture 5.5; docs/operations/metrics.md).

`time_to_shareable_seconds{kind, size_class}`, a histogram:

- `kind="transfer"`: from the transfer's last upload completing, or its submission if that came
  later, to the transfer `sent`, with every file shareable and the recipient emails queued in the
  same transaction (`sft.service.evaluation.send`). Observed only when the evaluation itself
  sends it, from `submitted`: a transfer sent by its sender's confirmation or an approver's
  decision restarts NFR-5's clock at that act, and what follows is the email hand-off alone, which
  the outbox age, the notification worker's metrics and the synthetic probe watch.
- `kind="request_file"`: from a received file's upload completing to its scan result recorded
  `clean`, which makes it available to the member (FR-13).
- `size_class`: `small` when the largest counted file (for a transfer) or the file is at most
  100 MB, the split NFR-5's two targets use (p95 at most 2 minutes, and 15 minutes up to 20 GB);
  `large` otherwise. The bucket edges include 120 s and 900 s, so both targets are exact.

Labels carry no tenant, file, name or value (NFR-26); every label set exists at zero from the
start. The process that runs the evaluation installs its metrics once at startup (`install`): the
API, the scan worker and the reconciliation job. Elsewhere, and in tests that don't install them,
observing does nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Final

from prometheus_client import CollectorRegistry, Histogram

SMALL_MAX_BYTES: Final = 100_000_000
"""NFR-5's split: a transfer whose largest file is up to 100 MB has the 2-minute target."""
BUCKETS: Final = (5.0, 10.0, 20.0, 30.0, 60.0, 90.0, 120.0, 180.0, 300.0, 600.0, 900.0, 1800.0)


class ShareableKind(StrEnum):
    TRANSFER = "transfer"
    REQUEST_FILE = "request_file"


class SizeClass(StrEnum):
    SMALL = "small"
    LARGE = "large"


def size_class(largest: int | None) -> SizeClass:
    """`small` up to 100 MB; a size not known yet counts as small."""
    return SizeClass.LARGE if (largest or 0) > SMALL_MAX_BYTES else SizeClass.SMALL


@dataclass(frozen=True)
class SliMetrics:
    time_to_shareable: Histogram

    @classmethod
    def create(cls, registry: CollectorRegistry) -> SliMetrics:
        histogram = Histogram(
            "time_to_shareable_seconds",
            "NFR-5: from the last upload completing to a transfer sent, or a received file "
            "clean, by kind and size class (largest file up to 100 MB, or more).",
            ["kind", "size_class"],
            buckets=BUCKETS,
            registry=registry,
        )
        for kind in ShareableKind:
            for size in SizeClass:
                histogram.labels(kind.value, size.value)
        return cls(histogram)


_installed: SliMetrics | None = None


def install(metrics: SliMetrics | None) -> SliMetrics | None:
    """Make `metrics` this process's; the ones it replaces. The entry point calls it once at
    startup, and again with what it got back at shutdown."""
    global _installed
    previous, _installed = _installed, metrics
    return previous


def observe_shareable(
    kind: ShareableKind, *, started_at: datetime | None, now: datetime, largest: int | None
) -> float | None:
    """Observe one time to shareable, if this process has the metrics and the start is known;
    the seconds observed. A start in the future (clocks of two hosts) counts as 0."""
    if _installed is None or started_at is None:
        return None
    seconds = max(0.0, (now - started_at).total_seconds())
    _installed.time_to_shareable.labels(kind.value, size_class(largest).value).observe(seconds)
    return seconds
