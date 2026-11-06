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
- **All or nothing** (`check_all`, `peek_all`). A request charged against many limits at once, as
  `sendTransfer` charges each recipient's address, first reads every limit in one pipelined call
  and charges only if all of them admit it, in a second. A refusal charges nothing. Two requests
  racing between the two calls can still leave one partly charged; both answers stay right.
"""

from __future__ import annotations

import logging
import math
import secrets
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from sft.core.errors import RateLimited, ServiceUnavailable
from sft.core.pseudonyms import EmailPseudonyms
from sft.data.counters import (
    Call,
    CounterMetrics,
    CounterStore,
    CounterStoreUnavailableError,
    LogCall,
    LogMode,
    RateCall,
    ScoresCall,
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


@dataclass(frozen=True)
class Charge:
    """One limit, the keys it counts under and what this request costs it (`check_all`)."""

    limit: Limit
    keys: Mapping[KeyType, KeyValue]
    cost: int = 1


@dataclass(frozen=True)
class _Planned:
    charge: Charge
    key_type: KeyType
    key: str
    older: tuple[str, ...]
    limit_value: int
    local_value: int


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

    async def peek_all(self, charges: Sequence[Charge]) -> None:
        """Raise as `check_all` would, and charge nothing: one pipelined call."""
        await self._all(charges, charge=False)

    async def check_all(self, charges: Sequence[Charge]) -> None:
        """Charge every one of `charges`, or none (module docstring): one pipelined call to read
        them all, and one more to charge if every limit admits the request."""
        await self._all(charges, charge=True)

    def _plan(self, charge: Charge) -> _Planned:
        if charge.cost < 1:
            raise ValueError("cost is at least 1")
        limit = charge.limit
        key_type = limit.key_type(charge.keys)
        value = charge.keys[key_type]
        active, older = (
            (value.active, value.overlap) if isinstance(value, EmailPseudonyms) else (value, ())
        )
        rule = limit.rule
        if isinstance(rule, Rate):
            if older:
                raise ValueError(f"limit {limit.id}: only quotas add an older pseudonym's count")
            local = fallback_limit(rule.limit, rule.max_cost)
        else:
            if charge.cost != 1:
                raise ValueError(f"limit {limit.id}: a quota counts one event at a time")
            if limit.counts_failures:
                raise ValueError(f"limit {limit.id} counts failures, not requests")
            local = fallback_limit(rule.limit)
        return _Planned(
            charge,
            key_type,
            limit.store_key(key_type, active),
            tuple(limit.store_key(key_type, old) for old in older),
            rule.limit,
            local,
        )

    async def _all(self, charges: Sequence[Charge], *, charge: bool) -> None:
        plans = [self._plan(c) for c in charges]
        if not plans:
            return
        now_ms = int(self._clock() * 1000)
        try:
            await self._all_in_store(plans, now_ms, charge=charge)
        except CounterStoreUnavailableError:
            if any(p.charge.limit.group.failure_mode is FailureMode.CLOSED for p in plans):
                log.warning("counter store unavailable: refusing")
                raise RateLimitStoreUnavailable() from None
            self._all_locally(plans, now_ms, charge=charge)

    def _calls(
        self,
        plans: Sequence[_Planned],
        now_ms: int,
        others: Mapping[str, list[float]],
        *,
        peek: bool,
    ) -> list[Call]:
        calls: list[Call] = []
        for plan in plans:
            rule = plan.charge.limit.rule
            if isinstance(rule, Rate):
                calls.append(
                    RateCall(
                        plan.key,
                        plan.limit_value,
                        rule.period_seconds * 1000,
                        plan.charge.cost,
                        peek,
                    )
                )
            else:
                calls.append(
                    LogCall(
                        plan.key,
                        plan.limit_value,
                        rule.window_seconds * 1000,
                        "peek" if peek else "hit",
                        f"{now_ms}-{secrets.token_hex(4)}",
                        rule.block_seconds * 1000,
                        tuple(s for old in plan.older for s in others.get(old, [])),
                    )
                )
        return calls

    async def _all_in_store(self, plans: Sequence[_Planned], now_ms: int, *, charge: bool) -> None:
        others: dict[str, list[float]] = {}
        older = [
            (old, plan.charge.limit.rule)
            for plan in plans
            for old in plan.older
            if isinstance(plan.charge.limit.rule, Quota)
        ]
        if older:
            found = await self._store.run(
                [ScoresCall(old, rule.window_seconds * 1000) for old, rule in older],
                now_ms=now_ms,
            )
            others = {
                old: list(times)
                for (old, _), times in zip(older, found, strict=True)
                if isinstance(times, list)
            }
        peeked = await self._store.run(self._calls(plans, now_ms, others, peek=True), now_ms=now_ms)
        self._refuse_if_any(plans, peeked)
        if charge:
            charged = await self._store.run(
                self._calls(plans, now_ms, others, peek=False), now_ms=now_ms
            )
            self._refuse_if_any(plans, charged)

    def _all_locally(self, plans: Sequence[_Planned], now_ms: int, *, charge: bool) -> None:
        # One pod, no await in between: the peek and the charge can't be interleaved.
        for peek in (True, False) if charge else (True,):
            verdicts: list[Verdict | list[float]] = []
            for plan in plans:
                rule = plan.charge.limit.rule
                if isinstance(rule, Rate):
                    verdicts.append(
                        self._local.rate(
                            plan.key,
                            now_ms=now_ms,
                            limit=plan.local_value,
                            period_ms=rule.period_seconds * 1000,
                            cost=plan.charge.cost,
                            peek=peek,
                        )
                    )
                else:
                    window_ms = rule.window_seconds * 1000
                    others = [
                        s
                        for old in plan.older
                        for s in self._local.scores(old, now_ms=now_ms, window_ms=window_ms)
                    ]
                    verdicts.append(
                        self._local.log(
                            plan.key,
                            now_ms=now_ms,
                            limit=plan.local_value,
                            window_ms=window_ms,
                            mode="peek" if peek else "hit",
                            block_ms=rule.block_seconds * 1000,
                            others=others,
                        )
                    )
            self._refuse_if_any(plans, verdicts)

    def _refuse_if_any(
        self, plans: Sequence[_Planned], verdicts: Sequence[Verdict | list[float]]
    ) -> None:
        refused = [
            (plan, verdict)
            for plan, verdict in zip(plans, verdicts, strict=True)
            if isinstance(verdict, Verdict) and not verdict.allowed
        ]
        if not refused:
            return
        for plan, _ in refused:
            self._metrics.rejections.labels(
                plan.charge.limit.group.value, plan.key_type.value
            ).inc()
        wait_ms = max(verdict.wait_ms for _, verdict in refused)
        log.info("rate limited", extra={"limits": sorted({p.charge.limit.id for p, _ in refused})})
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
            limit_value = fallback_limit(rule.limit, rule.max_cost) if local else rule.limit
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
