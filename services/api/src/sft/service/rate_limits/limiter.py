"""The limiter: applies an operation's limits in order and decides what a refusal says.

- **Order.** Limits run in the order given, narrowest first (`limits.py`). Each one that admits the
  request counts it. After the first refusal the rest are only read, never counted, so a request
  refused per IP or per caller never uses up a tenant's budget or an address's cap (abuse design
  4.4); they are still read so that `Retry-After` is the largest wait among the limits exceeded
  (2.4).
- **Refusal.** `RateLimited`: `429 rate_limited` with `Retry-After` in whole seconds, at least 1.
  Each refused limit is counted in `rate_limit_rejections_total{group,key_type}` and logged by its
  ID only, never its key value: the log line carries the request ID, not an address or a token.
- **Store outage** (4.5). A limit of group A or B refuses with `503 service_unavailable` and
  `Retry-After: 5`; every other limit counts in this pod at a third of its value.
- **Addresses.** A per-address limit given `EmailPseudonyms` counts under the active pseudonym and
  adds the entries of each older one still in the 25-hour overlap (encryption and keys 6.5).
"""

from __future__ import annotations

import logging
import math
import secrets
import time
from collections.abc import Callable, Mapping, Sequence

from sft.core.errors import RateLimited, ServiceUnavailable
from sft.core.pseudonyms import EmailPseudonyms
from sft.data.counters import (
    CounterMetrics,
    CounterStore,
    CounterStoreUnavailableError,
    LogMode,
    Verdict,
)
from sft.service.rate_limits.limits import (
    FailureMode,
    KeyType,
    KeyValue,
    Limit,
    Quota,
    Rate,
)
from sft.service.rate_limits.local import LocalCounters, fallback_limit

log = logging.getLogger(__name__)

STORE_UNAVAILABLE_RETRY_AFTER = 5


class RateLimitStoreUnavailable(ServiceUnavailable):
    """A fail-closed limit couldn't reach the counter store: `503`, `Retry-After: 5`."""

    def __init__(self) -> None:
        super().__init__(retry_after=STORE_UNAVAILABLE_RETRY_AFTER)


class RateLimiter:
    def __init__(
        self,
        store: CounterStore,
        metrics: CounterMetrics,
        *,
        local: LocalCounters | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._store = store
        self._metrics = metrics
        self._local = local or LocalCounters()
        self._clock = clock

    async def check(
        self,
        limits: Sequence[Limit],
        keys: Mapping[KeyType, KeyValue],
        *,
        cost: int = 1,
    ) -> None:
        """Count one request (or `cost` units of a rate) against each limit, or raise.

        Raises `RateLimited`, or `RateLimitStoreUnavailable` for a fail-closed limit during an
        outage. A key value a limit needs but `keys` lacks is a programming error (`LookupError`).
        """
        if cost < 1:
            raise ValueError("cost is at least 1")
        now_ms = int(self._clock() * 1000)
        refused: list[tuple[Limit, KeyType, Verdict]] = []
        for limit in limits:
            key_type = limit.key_type(keys)
            verdict = await self._apply(
                limit, key_type, keys[key_type], now_ms, cost, bool(refused)
            )
            if not verdict.allowed:
                refused.append((limit, key_type, verdict))
        if refused:
            for limit, key_type, _ in refused:
                self._metrics.rejections.labels(limit.group.value, key_type.value).inc()
            wait_ms = max(verdict.wait_ms for _, _, verdict in refused)
            log.info("rate limited", extra={"limits": [limit.id for limit, _, _ in refused]})
            raise RateLimited(retry_after=max(1, math.ceil(wait_ms / 1000)))

    async def record(self, limit: Limit, value: str) -> None:
        """Record one failure against a quota of failures, such as a `401` for an IP.

        Never raises for an outage: the failure is then counted in this pod, which a fail-open
        limit reads during the outage, and a fail-closed one doesn't need.
        """
        rule = limit.rule
        if not limit.counts_failures or not isinstance(rule, Quota):
            raise ValueError(f"limit {limit.id} doesn't count failures")
        key = limit.store_key(limit.keys[0], value)
        now_ms = int(self._clock() * 1000)
        member = f"{now_ms}-{secrets.token_hex(4)}"
        window_ms, block_ms = rule.window_seconds * 1000, rule.block_seconds * 1000
        try:
            await self._store.log(
                key,
                now_ms=now_ms,
                limit=rule.limit,
                window_ms=window_ms,
                mode="record",
                member=member,
                block_ms=block_ms,
            )
        except CounterStoreUnavailableError:
            self._local.log(
                key,
                now_ms=now_ms,
                limit=fallback_limit(rule.limit),
                window_ms=window_ms,
                mode="record",
                block_ms=block_ms,
            )

    async def _apply(
        self,
        limit: Limit,
        key_type: KeyType,
        value: KeyValue,
        now_ms: int,
        cost: int,
        peek: bool,
    ) -> Verdict:
        try:
            return await self._counted(limit, key_type, value, now_ms, cost, peek, local=False)
        except CounterStoreUnavailableError:
            if limit.group.failure_mode is FailureMode.CLOSED:
                log.warning("counter store unavailable: refusing", extra={"limit": limit.id})
                raise RateLimitStoreUnavailable() from None
            return await self._counted(limit, key_type, value, now_ms, cost, peek, local=True)

    async def _counted(
        self,
        limit: Limit,
        key_type: KeyType,
        value: KeyValue,
        now_ms: int,
        cost: int,
        peek: bool,
        *,
        local: bool,
    ) -> Verdict:
        active, older = (
            (value.active, value.overlap) if isinstance(value, EmailPseudonyms) else (value, ())
        )
        key = limit.store_key(key_type, active)
        rule = limit.rule
        if isinstance(rule, Rate):
            if older:
                raise ValueError(f"limit {limit.id}: only quotas add an older pseudonym's count")
            limit_value = fallback_limit(rule.limit) if local else rule.limit
            period_ms = rule.period_seconds * 1000
            if local:
                return self._local.rate(
                    key, now_ms=now_ms, limit=limit_value, period_ms=period_ms, cost=cost, peek=peek
                )
            return await self._store.rate(
                key, now_ms=now_ms, limit=limit_value, period_ms=period_ms, cost=cost, peek=peek
            )
        if cost != 1:
            raise ValueError(f"limit {limit.id}: a quota counts one event at a time")
        window_ms, block_ms = rule.window_seconds * 1000, rule.block_seconds * 1000
        mode: LogMode = "peek" if peek or limit.counts_failures else "hit"
        limit_value = fallback_limit(rule.limit) if local else rule.limit
        if local:
            others = [
                s
                for old in older
                for s in self._local.scores(
                    limit.store_key(key_type, old), now_ms=now_ms, window_ms=window_ms
                )
            ]
            return self._local.log(
                key,
                now_ms=now_ms,
                limit=limit_value,
                window_ms=window_ms,
                mode=mode,
                block_ms=block_ms,
                others=others,
            )
        others = [
            s
            for old in older
            for s in await self._store.scores(
                limit.store_key(key_type, old), now_ms=now_ms, window_ms=window_ms
            )
        ]
        return await self._store.log(
            key,
            now_ms=now_ms,
            limit=limit_value,
            window_ms=window_ms,
            mode=mode,
            member=f"{now_ms}-{secrets.token_hex(4)}",
            block_ms=block_ms,
            others=others,
        )
