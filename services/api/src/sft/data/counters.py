"""The rate-limit counter store: Valkey, ElastiCache Serverless for Valkey in AWS (ADR-0014).

It runs the two counting algorithms of the abuse design (4.4), each as one Lua script over one key,
so a check and its increment are one atomic step and every script works in cluster mode, where a
script can't reach keys in different hash slots:

- `rate`: GCRA, the generic cell rate algorithm, for request rates. The key holds the theoretical
  arrival time; `limit` requests fit in `period`, and the answer gives the exact wait.
- `log`: a sliding log in a sorted set, for small event quotas (codes per address or link, failures
  per IP). Exact over the window. A `record` can also start a block for a fixed time.

Each takes the time from the caller in milliseconds (pods keep their clocks within a millisecond
with the Amazon Time Sync Service), so tests drive time instead of sleeping. A refused request
changes nothing.

Every call has 50 ms. After 5 failures in a row the store stops calling Valkey for 10 seconds and
fails at once (ADR-0014), so a sick cache doesn't add latency to every request; the caller then
applies each limit's failure mode. Any failure surfaces as `CounterStoreUnavailableError`.

Locally the URL holds the ACL user and its fake password. In AWS it is `rediss://` with the
workload's user, and M4 adds a credential provider that signs a 15-minute IAM token, plus the
cluster client for ElastiCache Serverless; neither changes this interface.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import valkey.asyncio as valkey
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram
from valkey.exceptions import ValkeyError

CALL_TIMEOUT_SECONDS = 0.05
BREAKER_ERRORS = 5
BREAKER_SECONDS = 10.0

# KEYS[1] the key; ARGV now (ms), interval (ms per request: period / limit), period (ms), cost,
# peek ("1": answer without counting). Returns {allowed, wait in ms}. The arrival time is kept to
# a microsecond.
_RATE = """
local now = tonumber(ARGV[1])
local interval = tonumber(ARGV[2])
local period = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local tat = tonumber(redis.call('GET', KEYS[1])) or now
if tat < now then tat = now end
local new_tat = tat + interval * cost
local allow_at = new_tat - period
-- Within a millisecond counts as on time: `interval` is rarely exact in binary floating point.
if allow_at - now >= 1 then
  return {0, math.ceil(allow_at - now)}
end
if ARGV[5] ~= '1' then
  local ttl = math.max(1, math.ceil(new_tat - now))
  redis.call('SET', KEYS[1], string.format('%.3f', new_tat), 'PX', ttl)
end
return {1, 0}
"""

# KEYS[1] the key; ARGV now (ms), window (ms), limit, mode, member, block (ms, 0 for none), then
# the scores of entries counted under other keys (an address's previous pseudonym). Modes:
#   hit: count the request if the window has room;
#   peek: answer without counting;
#   record: count an event (a failure) whatever the window holds, and block at the limit.
# The block is a member '!block' scored with its end. Returns {allowed, wait in ms}.
_LOG = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local mode = ARGV[4]
local block = tonumber(ARGV[6])
local blocked = tonumber(redis.call('ZSCORE', key, '!block'))
if blocked and blocked <= now then
  redis.call('ZREM', key, '!block')
  blocked = nil
end
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
local scores = {}
local own = redis.call('ZRANGE', key, '-inf', '+inf', 'BYSCORE', 'WITHSCORES')
for i = 1, #own, 2 do
  if own[i] ~= '!block' then table.insert(scores, tonumber(own[i + 1])) end
end
for i = 7, #ARGV do
  local score = tonumber(ARGV[i])
  if score > now - window then table.insert(scores, score) end
end
if mode == 'record' then
  redis.call('ZADD', key, now, ARGV[5])
  -- Keep the newest `limit` entries: enough to decide, and an attack can't grow the set.
  local own_count = redis.call('ZCARD', key) - (blocked and 1 or 0)
  if own_count > limit then
    redis.call('ZREMRANGEBYRANK', key, 0, own_count - limit - 1)
  end
  if block > 0 and #scores + 1 >= limit then
    redis.call('ZADD', key, now + block, '!block')
  end
  redis.call('PEXPIRE', key, math.max(window, block))
  return {1, 0}
end
if blocked then
  return {0, math.ceil(blocked - now)}
end
if #scores >= limit then
  table.sort(scores)
  return {0, math.max(1, math.ceil(scores[#scores - limit + 1] + window - now))}
end
if mode == 'hit' then
  redis.call('ZADD', key, now, ARGV[5])
  redis.call('PEXPIRE', key, math.max(window, block))
end
return {1, 0}
"""


class CounterStoreUnavailableError(Exception):
    """The store didn't answer in time, failed, or is resting after repeated failures."""


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    wait_ms: int
    """When the key next admits the request; 0 when allowed."""


LogMode = Literal["hit", "peek", "record"]


@dataclass(frozen=True)
class CounterMetrics:
    """The rate-limit metrics of the abuse design (8.1); the limiter counts the rejections."""

    errors: Counter
    latency: Histogram
    fallback_active: Gauge
    rejections: Counter

    @classmethod
    def create(cls, registry: CollectorRegistry) -> CounterMetrics:
        return cls(
            errors=Counter(
                "rate_limit_store_errors_total",
                "Counter store calls that failed or timed out, and calls skipped while it rests.",
                registry=registry,
            ),
            latency=Histogram(
                "rate_limit_store_latency_seconds",
                "Time per counter store call (ADR-0014 targets a p99 of 5 ms).",
                buckets=(0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1),
                registry=registry,
            ),
            fallback_active=Gauge(
                "rate_limit_fallback_active",
                "1 while the store rests after repeated failures and the failure modes apply.",
                registry=registry,
            ),
            rejections=Counter(
                "rate_limit_rejections_total",
                "Requests refused with 429, by the limit's group and key type.",
                ["group", "key_type"],
                registry=registry,
            ),
        )


def _verdict(result: Any) -> Verdict:
    if not (isinstance(result, list) and len(result) == 2):
        raise CounterStoreUnavailableError("unexpected answer from the counter store")
    return Verdict(allowed=result[0] == 1, wait_ms=int(result[1]))


class CounterStore:
    def __init__(
        self,
        client: valkey.Valkey,
        metrics: CounterMetrics,
        *,
        timeout: float = CALL_TIMEOUT_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._metrics = metrics
        self._timeout = timeout
        self._clock = clock
        self._rate = client.register_script(_RATE)
        self._log = client.register_script(_LOG)
        self._failures = 0
        self._resting_until = 0.0

    @classmethod
    def connect(cls, url: str, metrics: CounterMetrics) -> CounterStore:
        """A store for `url`. It opens no connection until the first call needs one."""
        client = valkey.from_url(  # type: ignore[no-untyped-call]
            url,
            socket_timeout=CALL_TIMEOUT_SECONDS,
            socket_connect_timeout=CALL_TIMEOUT_SECONDS,
            # A refused call is answered by the failure mode, never retried into the latency budget.
            retry_on_timeout=False,
        )
        return cls(client, metrics)

    async def rate(
        self, key: str, *, now_ms: int, limit: int, period_ms: int, cost: int, peek: bool
    ) -> Verdict:
        args: list[str | int] = [
            now_ms,
            repr(period_ms / limit),
            period_ms,
            cost,
            "1" if peek else "0",
        ]
        return _verdict(await self._call(lambda: self._rate(keys=[key], args=args)))

    async def log(
        self,
        key: str,
        *,
        now_ms: int,
        limit: int,
        window_ms: int,
        mode: LogMode,
        member: str,
        block_ms: int = 0,
        others: Sequence[float] = (),
    ) -> Verdict:
        args: list[str | int] = [now_ms, window_ms, limit, mode, member, block_ms]
        args += [repr(score) for score in others]
        return _verdict(await self._call(lambda: self._log(keys=[key], args=args)))

    async def scores(self, key: str, *, now_ms: int, window_ms: int) -> list[float]:
        """The entry times in a log's window, to count them under another key (`others`)."""
        result = await self._call(
            lambda: self._client.zrangebyscore(
                key, f"({now_ms - window_ms}", "+inf", withscores=True
            )
        )
        if not isinstance(result, list):
            raise CounterStoreUnavailableError("unexpected answer from the counter store")
        return [float(score) for member, score in result if member != b"!block"]

    async def close(self) -> None:
        await self._client.aclose()

    async def _call(self, operation: Callable[[], Awaitable[Any]]) -> Any:
        if self._failures >= BREAKER_ERRORS and self._clock() < self._resting_until:
            self._metrics.errors.inc()
            raise CounterStoreUnavailableError(
                "the counter store is resting after repeated failures"
            )
        start = time.perf_counter()
        try:
            async with asyncio.timeout(self._timeout):
                result = await operation()
        except (ValkeyError, OSError, TimeoutError) as exc:
            self._failed()
            raise CounterStoreUnavailableError(type(exc).__name__) from exc
        finally:
            self._metrics.latency.observe(time.perf_counter() - start)
        if self._failures:
            self._failures = 0
            self._metrics.fallback_active.set(0)
        return result

    def _failed(self) -> None:
        self._metrics.errors.inc()
        self._failures += 1
        if self._failures >= BREAKER_ERRORS:
            self._resting_until = self._clock() + BREAKER_SECONDS
            self._metrics.fallback_active.set(1)
