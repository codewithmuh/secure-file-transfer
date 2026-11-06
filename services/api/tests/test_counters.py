"""The counter store's scripts against a real Valkey, and its timeout and rest after failures."""

import asyncio
import random
from collections.abc import AsyncIterator

import pytest
from prometheus_client import CollectorRegistry

from sft.data.counters import (
    BREAKER_ERRORS,
    BREAKER_SECONDS,
    CounterMetrics,
    CounterStore,
    CounterStoreUnavailableError,
    Verdict,
    gcra_split,
)
from sft.service.rate_limits.limits import ALL, Rate
from sft.service.rate_limits.local import LocalCounters, fallback_limit

pytestmark = pytest.mark.anyio

T0 = 1_800_000_000_000  # a fixed time in ms; the scripts take the time from the caller


async def rate(store: CounterStore, now: int, *, cost: int = 1, peek: bool = False) -> Verdict:
    # 3 in 3 s: a burst of 2, then one every 1.5 s.
    return await store.rate(
        "rl:T.rate:ip:192.0.2.1", now_ms=now, limit=3, period_ms=3000, cost=cost, peek=peek
    )


def test_gcra_split() -> None:
    # Burst plus rate is one more than the limit: a window (t - period, t] holds burst + rate - 1.
    assert [gcra_split(limit) for limit in (1, 2, 3, 60, 61)] == [
        (1, 1),
        (2, 1),
        (2, 2),
        (31, 30),
        (31, 31),
    ]


async def test_rate_admits_its_burst_then_gives_the_exact_wait(counter_store: CounterStore) -> None:
    assert [(await rate(counter_store, T0)).allowed for _ in range(2)] == [True] * 2
    assert await rate(counter_store, T0) == Verdict(False, 1500)
    # One interval later, one more fits: the third in [T0, T0 + 3000).
    assert await rate(counter_store, T0 + 1499) == Verdict(False, 1)
    assert (await rate(counter_store, T0 + 1500)).allowed
    assert await rate(counter_store, T0 + 1500) == Verdict(False, 1500)


async def test_rate_rolls_over_and_expires(counter_store: CounterStore) -> None:
    for _ in range(2):
        await rate(counter_store, T0)
    # Once the burst has drained, the whole burst again.
    assert [(await rate(counter_store, T0 + 3000)).allowed for _ in range(3)] == [True] * 2 + [
        False
    ]
    ttl = await counter_store._client.pttl("rl:T.rate:ip:192.0.2.1")
    assert 0 < ttl <= 3000


async def test_a_refused_or_peeked_request_counts_nothing(counter_store: CounterStore) -> None:
    for _ in range(3):
        assert (await rate(counter_store, T0, peek=True)).allowed
    for _ in range(2):
        await rate(counter_store, T0)
    for _ in range(5):
        await rate(counter_store, T0)  # refused
    assert (await rate(counter_store, T0 + 1500)).allowed


async def test_rate_cost(counter_store: CounterStore) -> None:
    assert (await rate(counter_store, T0, cost=2)).allowed  # the whole burst at once
    assert await rate(counter_store, T0, cost=1) == Verdict(False, 1500)
    assert await rate(counter_store, T0, cost=2) == Verdict(False, 3000)
    assert (await rate(counter_store, T0 + 1500, cost=1)).allowed
    # More than the burst at once is never admitted, even on a fresh key.
    assert not (await rate(counter_store, T0 + 100_000, cost=3)).allowed


def most_in_any_window(times: list[int], window_ms: int) -> int:
    """The most of `times`, in order, that any window (t - window, t] holds."""
    most = first = 0
    for last, at in enumerate(times):
        while times[first] <= at - window_ms:
            first += 1
        most = max(most, last - first + 1)
    return most


STEADY = range(T0, T0 + 150_000, 50)
"""A request every 50 ms for two and a half minutes."""


async def test_a_steady_stream_gets_the_burst_then_at_most_the_limit_per_period(
    counter_store: CounterStore,
) -> None:
    # 60 a minute (NFR-14's link steps): a burst of 31, then one every 2 s.
    admitted = []
    for now in STEADY:
        verdict = await counter_store.rate(
            "rl:T.steady:ip:x", now_ms=now, limit=60, period_ms=60_000, cost=1, peek=False
        )
        if verdict.allowed:
            admitted.append(now)
    assert admitted[:32] == [T0 + 50 * i for i in range(31)] + [T0 + 2000]
    assert most_in_any_window(admitted, 60_000) == 60


def test_the_per_pod_limiter_holds_a_steady_stream_to_the_limit_too() -> None:
    local = LocalCounters()
    admitted = [
        now
        for now in STEADY
        if local.rate("k", now_ms=now, limit=60, period_ms=60_000, cost=1, peek=False).allowed
    ]
    assert admitted[:31] == [T0 + 50 * i for i in range(31)]
    assert most_in_any_window(admitted, 60_000) == 60


@pytest.mark.parametrize(
    "limit",
    sorted(
        {x.rule.limit for x in ALL if isinstance(x.rule, Rate)}
        | {fallback_limit(x.rule.limit) for x in ALL if isinstance(x.rule, Rate)}
        | {1, 2, 3, 7}
    ),
)
def test_every_rate_admits_exactly_its_limit_in_any_period(limit: int) -> None:
    # A client that asks again the moment it may, for three periods, gets the limit in every
    # window of one period and never more. Each table value, its per-pod third, and a few odd ones.
    local = LocalCounters()
    period = 60_000
    admitted, now = [], T0
    while now < T0 + 3 * period:
        verdict = local.rate("k", now_ms=now, limit=limit, period_ms=period, cost=1, peek=False)
        if verdict.allowed:
            admitted.append(now)
        else:
            now += verdict.wait_ms
    assert admitted[: gcra_split(limit)[0]] == [T0] * gcra_split(limit)[0]
    assert most_in_any_window(admitted, period) == limit


async def log(
    store: CounterStore,
    now: int,
    mode: str = "hit",
    *,
    key: str = "rl:T.log:subject:s1",
    block: int = 0,
    others: tuple[float, ...] = (),
) -> Verdict:
    return await store.log(
        key,
        now_ms=now,
        limit=3,
        window_ms=10_000,
        mode=mode,  # type: ignore[arg-type]
        member=f"{now}-{random.random()}",  # noqa: S311 - not a secret
        block_ms=block,
        others=others,
    )


async def test_log_counts_in_a_sliding_window(counter_store: CounterStore) -> None:
    for at in (0, 1000, 2000):
        assert (await log(counter_store, T0 + at)).allowed
    # Full until the oldest entry leaves the window.
    assert await log(counter_store, T0 + 2500) == Verdict(False, 7500)
    assert await log(counter_store, T0 + 9999) == Verdict(False, 1)
    assert (await log(counter_store, T0 + 10_000)).allowed
    assert not (await log(counter_store, T0 + 10_000)).allowed
    assert 0 < await counter_store._client.pttl("rl:T.log:subject:s1") <= 10_000


async def test_peek_doesnt_count(counter_store: CounterStore) -> None:
    for _ in range(5):
        assert (await log(counter_store, T0, "peek")).allowed
    assert await counter_store._client.exists("rl:T.log:subject:s1") == 0


async def test_record_counts_failures_and_blocks(counter_store: CounterStore) -> None:
    key = "rl:T.fail:ip:192.0.2.1"
    for _ in range(2):
        await log(counter_store, T0, "record", key=key, block=60_000)
    assert (await log(counter_store, T0, "peek", key=key)).allowed
    await log(counter_store, T0 + 100, "record", key=key, block=60_000)
    # The third failure starts a block of 60 s, longer than the window.
    assert await log(counter_store, T0 + 100, "peek", key=key) == Verdict(False, 60_000)
    assert await log(counter_store, T0 + 30_000, "peek", key=key) == Verdict(False, 30_100)
    assert 0 < await counter_store._client.pttl(key) <= 60_000
    assert (await log(counter_store, T0 + 60_100, "peek", key=key)).allowed
    assert await counter_store._client.exists(key) == 0  # nothing left once the block ends


async def test_record_keeps_only_the_newest_entries(counter_store: CounterStore) -> None:
    key = "rl:T.fail:ip:192.0.2.2"
    for i in range(50):
        await log(counter_store, T0 + i, "record", key=key)
    assert await counter_store._client.zcard(key) == 3
    # Full until the third newest leaves the window.
    assert await log(counter_store, T0 + 100, "peek", key=key) == Verdict(False, 9947)


async def test_log_adds_other_keys_entries(counter_store: CounterStore) -> None:
    old = "rl:T.log:email:eold:abc"
    for at in (0, 1000):
        await log(counter_store, T0 + at, key=old)
    scores = await counter_store.scores(old, now_ms=T0 + 2000, window_ms=10_000)
    assert scores == [T0, T0 + 1000]
    assert (
        await log(counter_store, T0 + 2000, key="rl:T.log:email:enew:abc", others=tuple(scores))
    ).allowed
    refused = await log(
        counter_store, T0 + 2000, key="rl:T.log:email:enew:abc", others=tuple(scores)
    )
    assert refused == Verdict(False, 8000)
    # Entries older than the window don't count.
    assert (
        await log(counter_store, T0 + 10_500, key="rl:T.log:email:enew:abc", others=tuple(scores))
    ).allowed


async def test_the_scripts_match_the_per_pod_limiter(counter_store: CounterStore) -> None:
    # The fallback must behave like the store: the same random sequence, the same answers.
    rng = random.Random(97)  # noqa: S311 - not a secret
    local = LocalCounters()
    now = T0
    for step in range(400):
        now += rng.choice((0, 0, 1, 50, 400, 1500, 4000))
        kind = rng.choice(("rate", "hit", "peek", "record"))
        if kind == "rate":
            # 5 in 2 s has an interval of 666,667 µs: not a whole millisecond.
            limit = rng.choice((1, 4, 5))
            args = {
                "now_ms": now,
                "limit": limit,
                "period_ms": 2000,
                "cost": rng.choice((1, 2)),
                "peek": rng.random() < 0.2,
            }
            key = f"rl:T.r{limit}:ip:x"
            got = await counter_store.rate(key, **args)  # type: ignore[arg-type]
            want = local.rate(key, **args)  # type: ignore[arg-type]
        else:
            # A limit always has the same block, so each key keeps its own.
            key, block = rng.choice((("rl:T.l:ip:x", 0), ("rl:T.b:ip:x", 7000)))
            args = {"now_ms": now, "limit": 3, "window_ms": 5000, "mode": kind, "block_ms": block}
            got = await counter_store.log(key, member=f"m{step}", **args)  # type: ignore[arg-type]
            want = local.log(key, **args)  # type: ignore[arg-type]
        assert got == want, (step, kind)


# ---- failures ----


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
async def silent_server() -> AsyncIterator[int]:
    """A TCP server that accepts connections and never answers."""
    held: list[asyncio.StreamWriter] = []

    async def accept(_: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        held.append(writer)

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    yield server.sockets[0].getsockname()[1]
    for writer in held:
        writer.close()
    server.close()


def errors(metrics: CounterMetrics) -> float:
    return metrics.errors._value.get()  # type: ignore[attr-defined, no-any-return]


async def test_a_call_gives_up_after_50_ms(silent_server: int) -> None:
    metrics = CounterMetrics.create(CollectorRegistry())
    store = CounterStore.connect(f"redis://u:p@127.0.0.1:{silent_server}/0", metrics)
    loop = asyncio.get_running_loop()
    start = loop.time()
    with pytest.raises(CounterStoreUnavailableError):
        await rate(store, T0)
    assert loop.time() - start < 0.5
    assert errors(metrics) == 1
    await store.close()


async def test_the_store_rests_after_repeated_failures(valkey_url: str) -> None:
    metrics = CounterMetrics.create(CollectorRegistry())
    clock = Clock()
    store = CounterStore.connect("redis://u:p@127.0.0.1:1/0", metrics)
    store._clock = clock
    for _ in range(BREAKER_ERRORS):
        with pytest.raises(CounterStoreUnavailableError):
            await rate(store, T0)
    assert metrics.fallback_active._value.get() == 1  # type: ignore[attr-defined]
    # Resting: no call is made, so nothing waits for a timeout.
    calls = 0
    real = store._rate

    async def counting(**kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return await real(**kwargs)  # type: ignore[arg-type]

    store._rate = counting  # type: ignore[assignment]
    with pytest.raises(CounterStoreUnavailableError, match="resting"):
        await rate(store, T0)
    assert calls == 0
    assert errors(metrics) == BREAKER_ERRORS + 1
    # After the rest, one call tries again; it fails, and the store rests again at once.
    clock.now += BREAKER_SECONDS
    with pytest.raises(CounterStoreUnavailableError):
        await rate(store, T0)
    assert calls == 1
    with pytest.raises(CounterStoreUnavailableError, match="resting"):
        await rate(store, T0)
    await store.close()
    # A healthy store closes the circuit and the gauge drops.
    healthy = CounterStore.connect(valkey_url, metrics)
    healthy._failures = BREAKER_ERRORS
    healthy._clock = clock
    assert (await rate(healthy, T0)).allowed
    assert healthy._failures == 0
    assert metrics.fallback_active._value.get() == 0  # type: ignore[attr-defined]
    await healthy.close()


async def test_wrong_credentials_are_an_outage(valkey_url: str) -> None:
    store = CounterStore.connect(
        valkey_url.replace(valkey_url.split("@")[0].split("//")[1], "sft-test:wrong"),
        CounterMetrics.create(CollectorRegistry()),
    )
    with pytest.raises(CounterStoreUnavailableError):
        await rate(store, T0)
    await store.close()


async def test_an_unexpected_answer_is_an_outage(counter_store: CounterStore) -> None:
    async def odd(*_: object, **__: object) -> object:
        return "nonsense"

    counter_store._rate = odd  # type: ignore[assignment]
    with pytest.raises(CounterStoreUnavailableError, match="unexpected"):
        await rate(counter_store, T0)
    counter_store._client.zrangebyscore = odd  # type: ignore[method-assign, assignment]
    with pytest.raises(CounterStoreUnavailableError, match="unexpected"):
        await counter_store.scores("k", now_ms=T0, window_ms=1)


async def test_leases_are_capped_renewed_and_expire(counter_store: CounterStore) -> None:
    # The scan worker's per-tenant caps (ADR-0019, #175).
    key = "scan:scan-small:tenant"
    for n in range(4):
        assert await counter_store.acquire_lease(key, f"s{n}", now_ms=0, ttl_ms=1000, cap=4)
    assert not await counter_store.acquire_lease(key, "s4", now_ms=10, ttl_ms=1000, cap=4)
    # A scan that holds a lease renews it, even at the cap.
    assert await counter_store.acquire_lease(key, "s0", now_ms=20, ttl_ms=5000, cap=4)
    await counter_store.release_lease(key, "s1")
    assert await counter_store.acquire_lease(key, "s4", now_ms=30, ttl_ms=1000, cap=4)
    # A worker that died leaves its lease to expire.
    assert await counter_store.acquire_lease(key, "s5", now_ms=1500, ttl_ms=1000, cap=4)
