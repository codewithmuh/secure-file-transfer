"""The rate-limit counter store: Valkey, ElastiCache Serverless for Valkey in AWS (ADR-0014).

It runs the two counting algorithms of the abuse design (4.4), each as one Lua script over one key,
so a check and its increment are one atomic step and every script works in cluster mode, where a
script can't reach keys in different hash slots:

- `rate`: GCRA, the generic cell rate algorithm, for request rates. The key holds the theoretical
  arrival time, and the answer gives the exact wait. It is sized so that any window
  (t - period, t] admits at most `limit` requests (`gcra_split`): a burst of about half the limit,
  then the rest evenly spaced.
- `log`: a sliding log in a sorted set, for small event quotas (codes per address or link, failures
  per IP). Exact over the window. A `record` can also start a block for a fixed time.

- `lease`: a capped set of leases in a sorted set, each with its own expiry, for work that runs a
  while, such as the scans a tenant has running at once (ADR-0019) or a session's download streams
  (abuse 2.2, E). A lease that isn't released, because its worker died, ends at its expiry.
- `budget`: a total of units per fixed window, such as the bytes granted to a recipient in a UTC
  day (abuse 2.2, D). A request spends its cost only if the total stays within the limit; a
  negative cost refunds (`BudgetCall`, batched in `run`).

Each takes the time from the caller in milliseconds (pods keep their clocks within a millisecond
with the Amazon Time Sync Service), so tests drive time instead of sleeping. A refused request
changes nothing.

Every call has 50 ms. After 5 failures in a row the store stops calling Valkey for 10 seconds and
fails at once (ADR-0014), so a sick cache doesn't add latency to every request; the caller then
applies each limit's failure mode. Any failure surfaces as `CounterStoreUnavailableError`.

Locally the URL holds the ACL user and its fake password. In AWS it is `rediss://` with the
workload's user: with `iam` (VALKEY_IAM_CACHE), a credential provider signs a 15-minute IAM token
for each new connection (`sft.data.iam_auth`, #184). The cluster client for ElastiCache Serverless
is still to come; neither changes this interface.
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

from sft.data.iam_auth import valkey_iam

CALL_TIMEOUT_SECONDS = 0.05
BREAKER_ERRORS = 5
BREAKER_SECONDS = 10.0

# KEYS[1] the key; ARGV now (ms), interval (µs per request at the sustained rate), burst (µs: the
# burst's size times the interval), cost, peek ("1": answer without counting). Returns {allowed,
# wait in ms}. Times are whole microseconds, which Lua's doubles hold exactly, so a key admits at
# most what `gcra_split` promises, never one more through rounding.
_RATE = """
local now = tonumber(ARGV[1]) * 1000
local interval = tonumber(ARGV[2])
local burst = tonumber(ARGV[3])
local cost = tonumber(ARGV[4])
local tat = tonumber(redis.call('GET', KEYS[1])) or now
if tat < now then tat = now end
local new_tat = tat + interval * cost
local allow_at = new_tat - burst
if allow_at > now then
  return {0, math.ceil((allow_at - now) / 1000)}
end
if ARGV[5] ~= '1' then
  local ttl = math.ceil((new_tat - now) / 1000)
  redis.call('SET', KEYS[1], string.format('%.0f', new_tat), 'PX', ttl)
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

# KEYS[1] the lease set; ARGV now (ms), ttl (ms), cap, member. Expired leases are dropped first. A
# member that holds a lease already renews it. Returns 1 if the member holds a lease now, 0 if the
# set is at its cap.
_LEASE = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local cap = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
if not redis.call('ZSCORE', key, ARGV[4]) and redis.call('ZCARD', key) >= cap then
  return 0
end
redis.call('ZADD', key, now + ttl, ARGV[4])
if redis.call('PTTL', key) < ttl then
  redis.call('PEXPIRE', key, ttl)
end
return 1
"""


def gcra_split(limit: int) -> tuple[int, int]:
    """GCRA's burst and its sustained rate per period, for at most `limit` in any period.

    A fresh key admits `burst` requests at once, then `rate` per period, one each period / rate.
    A window (t - period, t], the sliding log's window, then holds at most burst + rate - 1 =
    `limit` requests, and a client that sends as fast as it is let gets exactly that many. Sizing
    both as `limit` would let 2 x limit - 1 through. A cost above the burst is never admitted.
    """
    return limit // 2 + 1, (limit + 1) // 2


def gcra_shape(limit: int, period_ms: int) -> tuple[int, int]:
    """GCRA's interval and burst for `limit` per period, in whole microseconds.

    The interval is rounded up, so a key is never faster than its rate.
    """
    burst, rate = gcra_split(limit)
    interval = -(-period_ms * 1000 // rate)
    return interval, burst * interval


# KEYS[1] the window's total; ARGV cost, limit, ttl (ms), peek ("1": answer without spending).
# Returns 1 if the cost fits (and, unless peeking, is spent), 0 if it doesn't. A negative cost, a
# refund, always fits.
_BUDGET = """
local used = tonumber(redis.call('GET', KEYS[1])) or 0
local cost = tonumber(ARGV[1])
if used + cost > tonumber(ARGV[2]) then
  return 0
end
if ARGV[4] ~= '1' then
  redis.call('INCRBY', KEYS[1], cost)
  if redis.call('PTTL', KEYS[1]) < 0 then
    redis.call('PEXPIRE', KEYS[1], ARGV[3])
  end
end
return 1
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
class RateCall:
    """One `rate` script call in a batch (`CounterStore.run`)."""

    key: str
    limit: int
    period_ms: int
    cost: int
    peek: bool


@dataclass(frozen=True)
class LogCall:
    """One `log` script call in a batch."""

    key: str
    limit: int
    window_ms: int
    mode: LogMode
    member: str
    block_ms: int = 0
    others: tuple[float, ...] = ()


@dataclass(frozen=True)
class ScoresCall:
    """The entry times in one log's window, in a batch."""

    key: str
    window_ms: int


@dataclass(frozen=True)
class BudgetCall:
    """One `budget` script call in a batch: spend `cost` (or refund, when negative) of `limit` in
    the window `key` names. `wait_ms` is what a refusal answers: the window's end."""

    key: str
    limit: int
    ttl_ms: int
    cost: int
    peek: bool
    wait_ms: int


Call = RateCall | LogCall | ScoresCall | BudgetCall


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


@dataclass(frozen=True, slots=True)
class ValkeyIam:
    """Where IAM tokens for Valkey are signed: the serverless cache's name and its region."""

    cache_name: str
    region: str

    @classmethod
    def of(cls, cache_name: str | None, region: str) -> ValkeyIam | None:
        """From VALKEY_IAM_CACHE and AWS_REGION: None where the cache isn't named (locally)."""
        return None if cache_name is None else cls(cache_name, region)


def iam_url(url: str, iam: ValkeyIam | None) -> tuple[str, dict[str, Any]]:
    """`valkey.from_url`'s URL and extra arguments: with `iam`, the URL without its user and a
    credential provider that signs in as that user."""
    if iam is None:
        return url, {}
    bare, credentials = valkey_iam(url, iam.cache_name, region=iam.region)
    return bare, {"credential_provider": credentials}


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
        self._lease = client.register_script(_LEASE)
        self._budget = client.register_script(_BUDGET)
        self._failures = 0
        self._resting_until = 0.0

    @classmethod
    def connect(
        cls, url: str, metrics: CounterMetrics, *, iam: ValkeyIam | None = None
    ) -> CounterStore:
        """A store for `url`. It opens no connection until the first call needs one. With `iam`
        (VALKEY_IAM_CACHE, in AWS), each new connection signs in with an IAM token as the URL's
        user (`sft.data.iam_auth`)."""
        address, extra = iam_url(url, iam)
        client = valkey.from_url(  # type: ignore[no-untyped-call]
            address,
            **extra,
            socket_timeout=CALL_TIMEOUT_SECONDS,
            socket_connect_timeout=CALL_TIMEOUT_SECONDS,
            # A refused call is answered by the failure mode, never retried into the latency budget.
            retry_on_timeout=False,
        )
        return cls(client, metrics)

    async def rate(
        self, key: str, *, now_ms: int, limit: int, period_ms: int, cost: int, peek: bool
    ) -> Verdict:
        interval, burst = gcra_shape(limit, period_ms)
        args: list[str | int] = [now_ms, interval, burst, cost, "1" if peek else "0"]
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

    async def acquire_lease(
        self, key: str, member: str, *, now_ms: int, ttl_ms: int, cap: int
    ) -> bool:
        """Take (or renew) `member`'s lease in the set `key`, if fewer than `cap` are live."""
        args: list[str | int] = [now_ms, ttl_ms, cap, member]
        result = await self._call(lambda: self._lease(keys=[key], args=args))
        return bool(result == 1)

    async def release_lease(self, key: str, member: str) -> None:
        await self._call(lambda: self._client.zrem(key, member))

    async def run(self, calls: Sequence[Call], *, now_ms: int) -> list[Verdict | list[float]]:
        """Many calls in one round trip: a pipeline, not a transaction, so each script still
        touches one key, as cluster mode needs. One answer per call, in order: a `Verdict`, or
        for `ScoresCall` the times. The whole batch fails as one `CounterStoreUnavailableError`."""
        if not calls:
            return []

        async def execute() -> Any:
            pipe = self._client.pipeline(transaction=False)
            for call in calls:
                if isinstance(call, RateCall):
                    interval, burst = gcra_shape(call.limit, call.period_ms)
                    args: list[str | int] = [
                        now_ms,
                        interval,
                        burst,
                        call.cost,
                        "1" if call.peek else "0",
                    ]
                    await self._rate(keys=[call.key], args=args, client=pipe)
                elif isinstance(call, LogCall):
                    args = [now_ms, call.window_ms, call.limit, call.mode, call.member]
                    args += [call.block_ms, *(repr(score) for score in call.others)]
                    await self._log(keys=[call.key], args=args, client=pipe)
                elif isinstance(call, BudgetCall):
                    args = [call.cost, call.limit, call.ttl_ms, "1" if call.peek else "0"]
                    await self._budget(keys=[call.key], args=args, client=pipe)
                else:
                    pipe.zrangebyscore(
                        call.key, f"({now_ms - call.window_ms}", "+inf", withscores=True
                    )
            return await pipe.execute()

        results = await self._call(execute)
        if not isinstance(results, list) or len(results) != len(calls):
            raise CounterStoreUnavailableError("unexpected answer from the counter store")
        out: list[Verdict | list[float]] = []
        for call, result in zip(calls, results, strict=True):
            if isinstance(call, ScoresCall):
                if not isinstance(result, list):
                    raise CounterStoreUnavailableError("unexpected answer from the counter store")
                out.append([float(score) for member, score in result if member != b"!block"])
            elif isinstance(call, BudgetCall):
                fits = result == 1
                out.append(Verdict(allowed=fits, wait_ms=0 if fits else call.wait_ms))
            else:
                out.append(_verdict(result))
        return out

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
