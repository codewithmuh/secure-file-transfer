"""The download limits that aren't rates (abuse and rate limits 2.2, D and E; #180).

- **Byte caps** (group D): each counted grant adds its file's size to the recipient's total for the
  UTC day, at most 25 GB, and to the tenant's, at most 500 GB. A transfer with no download limit is
  capped this way too. They are `Budget` limits in megabytes, charged with the limiter's
  all-or-nothing `check_all`, which refunds a budget it charged when another refuses, so both are
  spent together or not at all; over a cap is `429` with `Retry-After` until the day ends. A fixed
  day, not a sliding one: the worst case is twice a cap across midnight, which still bounds a
  recipient to 2 % of what a tenant may be granted.
- **Concurrent streams** (group E): at most 6 per link session, 20 per IP address and 200 per
  tenant, as leases in the counter store that a running stream renews at every re-check and gives
  up when it ends, so a pod that dies frees its streams within a lease. Over a cap is `429`. A pod
  serves at most 100 streams at once, counted in the process; the next is `503` with
  `Retry-After: 10` (abuse 5.7).

Both fail open (abuse 4.5): while the counter store is unavailable each cap is counted in this pod,
at a third of its value, as the per-pod limiter does for the rates (the byte caps through the
limiter's own per-pod counters). Rejections are counted in
`rate_limit_rejections_total{group,key_type}` like every other limit's.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final
from uuid import UUID

from sft.core.errors import RateLimited, ServiceUnavailable
from sft.data.counters import CounterMetrics, CounterStore, CounterStoreUnavailableError
from sft.service.rate_limits.limiter import Charge
from sft.service.rate_limits.limits import (
    D_TENANT,
    DAY,
    Budget,
    Group,
    KeyType,
    KeyValue,
    Limit,
)
from sft.service.rate_limits.local import FALLBACK_DIVISOR

log = logging.getLogger(__name__)

BYTE_UNIT: Final = 1_000_000
"""Byte caps count megabytes (10^6), as the caps are written: 25 GB is 25,000 of them."""
STREAM_LEASE_MS: Final = 90_000
"""A stream's lease in the counter store: three re-checks, so one late re-check keeps it."""
POD_FULL_RETRY_AFTER: Final = 10
STREAM_CAP_RETRY_AFTER: Final = 30

# Group D's byte caps (abuse 2.2): budgets per UTC day, in megabytes, charged with the limiter's
# all-or-nothing `check_all` once a grant is certain (`sft.service.downloads`). Not in
# `limits.ALL`, whose table-driven tests count requests one at a time.
D_SUBJECT_BYTES = Limit(
    Group.DOWNLOAD_GRANTS, "subject_bytes", (KeyType.SUBJECT,), Budget(25_000, DAY)
)
D_TENANT_BYTES = Limit(
    Group.DOWNLOAD_GRANTS, "tenant_bytes", (KeyType.TENANT,), Budget(500_000, DAY)
)
BYTE_CAPS: Final = (D_SUBJECT_BYTES, D_TENANT_BYTES)


@dataclass(frozen=True)
class StreamCap:
    name: str
    key: KeyType
    cap: int

    def store_key(self, value: str) -> str:
        return f"sc:{Group.DOWNLOAD_CONTENT.value}.{self.name}:{self.key.value}:{value}"


E_SESSION = StreamCap("session_streams", KeyType.LINK_SESSION, 6)
E_IP = StreamCap("ip_streams", KeyType.IP, 20)
E_TENANT = StreamCap("tenant_streams", KeyType.TENANT, 200)
STREAM_CAPS: Final = (E_SESSION, E_IP, E_TENANT)


def units(size: int) -> int:
    """A file's size in the byte caps' units, rounded up: every grant costs at least one."""
    return max(1, math.ceil(size / BYTE_UNIT))


def grant_charges(keys: Mapping[KeyType, KeyValue], size: int) -> list[Charge]:
    """What a new grant costs (abuse 2.2, D): one of the tenant's grants an hour, and the file's
    size against the recipient's and the tenant's bytes of the day. Peek them before the intent
    record; charge them, all or none, in the grant's transaction."""
    cost = units(size)
    return [
        Charge(D_TENANT, keys),
        Charge(D_SUBJECT_BYTES, keys, cost),
        Charge(D_TENANT_BYTES, keys, cost),
    ]


@dataclass
class _Local:
    """The per-pod count of an outage: the streams held."""

    streams: dict[str, set[UUID]] = field(default_factory=dict)


class PodFull(ServiceUnavailable):
    """This pod serves its maximum of streams: `503`, `Retry-After: 10`."""

    def __init__(self) -> None:
        super().__init__(POD_FULL_RETRY_AFTER, "This server is busy. The download will resume.")


@dataclass
class StreamSlot:
    """One stream's place under every cap; renewed at each re-check, released at its end."""

    limits: DownloadLimits
    stream_id: UUID
    keys: tuple[str, ...]
    released: bool = False

    async def renew(self) -> None:
        await self.limits._renew(self)

    async def release(self) -> None:
        if not self.released:
            self.released = True
            await self.limits._release(self)


class DownloadLimits:
    """Group D's byte caps and group E's stream caps, over the counter store."""

    def __init__(
        self,
        store: CounterStore,
        metrics: CounterMetrics,
        *,
        pod_streams: int = 100,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._metrics = metrics
        self._clock = clock
        self._local = _Local()
        self.pod_streams = pod_streams
        self.active = 0
        """Streams this pod serves now."""

    def _refuse(self, group: Group, key_type: KeyType) -> None:
        self._metrics.rejections.labels(group.value, key_type.value).inc()

    # ---- concurrent streams ----

    async def open_stream(self, keys: Mapping[KeyType, str], stream_id: UUID) -> StreamSlot:
        """A place for one stream under the pod's cap and every stream cap, or `503` or `429`."""
        if self.active >= self.pod_streams:
            raise PodFull()
        slot = StreamSlot(
            self, stream_id, tuple(cap.store_key(keys[cap.key]) for cap in STREAM_CAPS)
        )
        held: list[str] = []
        now_ms = int(self._clock() * 1000)
        try:
            for cap, key in zip(STREAM_CAPS, slot.keys, strict=True):
                taken = await self._store.acquire_lease(
                    key, str(stream_id), now_ms=now_ms, ttl_ms=STREAM_LEASE_MS, cap=cap.cap
                )
                if not taken:
                    for done in held:
                        await self._store.release_lease(done, str(stream_id))
                    self._stream_refused(cap)
                held.append(key)
        except CounterStoreUnavailableError:
            log.warning("counter store unavailable: stream caps count per pod")
            for cap, key in zip(STREAM_CAPS, slot.keys, strict=True):
                if len(self._local.streams.get(key, set())) >= max(1, cap.cap // FALLBACK_DIVISOR):
                    self._stream_refused(cap)
            for key in slot.keys:
                self._local.streams.setdefault(key, set()).add(stream_id)
        self.active += 1
        return slot

    def _stream_refused(self, cap: StreamCap) -> None:
        self._refuse(Group.DOWNLOAD_CONTENT, cap.key)
        log.info("rate limited", extra={"limits": [f"{Group.DOWNLOAD_CONTENT.value}.{cap.name}"]})
        raise RateLimited(retry_after=STREAM_CAP_RETRY_AFTER)

    async def _renew(self, slot: StreamSlot) -> None:
        now_ms = int(self._clock() * 1000)
        try:
            for cap, key in zip(STREAM_CAPS, slot.keys, strict=True):
                # A renewal is never refused: the stream holds its place already, and a renewal
                # past an expired lease puts it back, even over the cap for a moment.
                await self._store.acquire_lease(
                    key,
                    str(slot.stream_id),
                    now_ms=now_ms,
                    ttl_ms=STREAM_LEASE_MS,
                    cap=cap.cap + 1,
                )
        except CounterStoreUnavailableError:
            pass

    async def _release(self, slot: StreamSlot) -> None:
        self.active = max(0, self.active - 1)
        for key in slot.keys:
            self._local.streams.get(key, set()).discard(slot.stream_id)
            try:
                await self._store.release_lease(key, str(slot.stream_id))
            except CounterStoreUnavailableError:
                continue  # its lease ends by itself
