"""Where a file is scanned, and how long its scan may take (ADR-0019, ADR-0022; data model 3.1;
abuse and rate limits 6.4, 6.5).

**Routing, by the real size** (`actual_size`, checked against the declared size at completion):

- up to 100 MB: `file.scan` on `Queue.SCAN_SMALL`, the small pool;
- over 100 MB, up to 2,000,000,000 bytes: `file.scan_large` on `Queue.SCAN_LARGE`, ClamAV's large
  pool, so large files never delay small ones;
- over 2,000,000,000 bytes: no message. Only GuardDuty scans these (M6); `storage_class` already
  put them in the large-files bucket pair. `LARGE_FILE_THRESHOLD` stays the bucket choice only.

**Timeouts grow with the size.** A ClamAV scan takes about 1 s plus 0.058 s per MB (abuse 6.4); a
clamd attempt gets 30 s plus 0.2 s per MB, about three times that with room for the S3 read. The
DLP inspector runs beside it on the same bytes and may take 15 minutes of wall clock (abuse 6.5),
plus the time to receive the bytes. An attempt lasts as long as the slower of the two.

**The deadline** (`scan_deadline`) covers every attempt: the queue wait before the first (fair
queues and the per-tenant caps defer scans, abuse 6.4), the 5 attempts SQS hands out before the
dead-letter queue, and the visibility timeout between two of them. Past it, the scan sweep records
`scan_failed`, so no file stays `scanning` for good.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Final

from sft.data.outbox import FILE_SCAN, FILE_SCAN_LARGE, Queue, Topic

SMALL_POOL_MAX_BYTES: Final = 100_000_000
"""The 100 MB split between the two ClamAV pools (ADR-0019); the API's setting may change it."""
CLAMAV_MAX_BYTES: Final = 2_000_000_000
"""ClamAV's side of the boundary; above it only GuardDuty scans (ADR-0019)."""

ATTEMPTS: Final = 5
"""Receives before the redrive policy moves a message to its dead-letter queue (ADR-0013)."""
VISIBILITY: Final = {
    Queue.SCAN_SMALL: timedelta(seconds=60),
    Queue.SCAN_LARGE: timedelta(seconds=180),
}
"""Each scan queue's visibility timeout (infra/modules/queues, local/elasticmq): how long a message
stays hidden after a worker that held it died, before another attempt."""
QUEUE_ALLOWANCE: Final = timedelta(hours=1)
"""Time a file may wait for its first attempt: the relay, the queue and deferrals over its
tenant's cap. Staging measures it (NFR-5)."""

CLAMD_BASE: Final = timedelta(seconds=30)
CLAMD_PER_MB: Final = 0.2
INSPECTOR_WALL_CLOCK: Final = timedelta(minutes=15)
"""The inspector's wall-clock limit per file (abuse 6.5, `sft.dlp.limits`)."""
INSPECTOR_BASE: Final = timedelta(seconds=30)
INSPECTOR_PER_MB: Final = 0.05
"""Receiving the bytes: the node volume writes about 125 MB/s, shared with clamd (ADR-0022)."""

_MB: Final = 1_000_000


def scan_topic(size: int, *, small_pool_max: int = SMALL_POOL_MAX_BYTES) -> Topic | None:
    """The scan message's topic for a file of `size` bytes, or None for GuardDuty's files."""
    if size > CLAMAV_MAX_BYTES:
        return None
    return FILE_SCAN if size <= small_pool_max else FILE_SCAN_LARGE


def clamd_timeout(size: int) -> timedelta:
    """How long one clamd scan of `size` bytes may take, the stream included."""
    return CLAMD_BASE + timedelta(seconds=CLAMD_PER_MB * size / _MB)


def inspector_timeout(size: int) -> timedelta:
    """How long the inspector may take to answer for `size` bytes."""
    return INSPECTOR_BASE + INSPECTOR_WALL_CLOCK + timedelta(seconds=INSPECTOR_PER_MB * size / _MB)


def attempt_timeout(size: int) -> timedelta:
    """One attempt: both engines at once, so the slower of the two."""
    return max(clamd_timeout(size), inspector_timeout(size))


def scan_deadline(
    size: int, now: datetime, *, small_pool_max: int = SMALL_POOL_MAX_BYTES
) -> datetime:
    """When the scan sweep gives up on a file of `size` bytes that entered `scanning` at `now`."""
    topic = scan_topic(size, small_pool_max=small_pool_max)
    queue = Queue.SCAN_LARGE if topic is None else topic.queue
    return (
        now
        + QUEUE_ALLOWANCE
        + ATTEMPTS * attempt_timeout(size)
        + (ATTEMPTS - 1) * VISIBILITY[queue]
    )
