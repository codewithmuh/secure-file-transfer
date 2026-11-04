"""The limits as data, and the limiter against a real Valkey (abuse and rate limits 9.2)."""

import math
from collections.abc import AsyncIterator

import pytest
from prometheus_client import CollectorRegistry

from sft.core.errors import RateLimited, ServiceUnavailable
from sft.core.pseudonyms import EmailPseudonyms
from sft.data.counters import CounterMetrics, CounterStore
from sft.service.rate_limits import RateLimiter, RateLimitStoreUnavailable, limits
from sft.service.rate_limits.limits import (
    ALL,
    MAX_TTL_SECONDS,
    FailureMode,
    Group,
    KeyType,
    Limit,
    Quota,
    Rate,
)
from sft.service.rate_limits.local import LocalCounters, fallback_limit

pytestmark = pytest.mark.anyio

IP = "203.0.113.7"
TENANT = "11111111-1111-4111-8111-111111111111"
ACCOUNT = "22222222-2222-4222-8222-222222222222"


class Clock:
    def __init__(self) -> None:
        self.now = 1_800_000_000.0

    def __call__(self) -> float:
        return self.now


def keys_for(limit: Limit) -> dict[KeyType, str | EmailPseudonyms]:
    values: dict[KeyType, str | EmailPseudonyms] = {
        KeyType.IP: IP,
        KeyType.ACCOUNT: ACCOUNT,
        KeyType.API_KEY: "44444444-4444-4444-8444-444444444444",
        KeyType.OPERATOR: "55555555-5555-4555-8555-555555555555",
        KeyType.TENANT: TENANT,
        KeyType.EMAIL: EmailPseudonyms("e1:AAAAAAAAAAAAAAAAAAAAAA"),
        KeyType.TENANT_EMAIL: EmailPseudonyms("e1:AAAAAAAAAAAAAAAAAAAAAA").within(TENANT),
        KeyType.SUBJECT: "66666666-6666-4666-8666-666666666666:1800000000",
        KeyType.LINK_SESSION: "77777777-7777-4777-8777-777777777777",
    }
    return {k: values[k] for k in limit.keys}


def period(limit: Limit) -> int:
    rule = limit.rule
    return rule.period_seconds if isinstance(rule, Rate) else rule.window_seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def metrics() -> CounterMetrics:
    return CounterMetrics.create(CollectorRegistry())


@pytest.fixture
def limiter(counter_store: CounterStore, metrics: CounterMetrics, clock: Clock) -> RateLimiter:
    return RateLimiter(counter_store, metrics, clock=clock)


@pytest.fixture
async def down(metrics: CounterMetrics, clock: Clock) -> AsyncIterator[RateLimiter]:
    """A limiter whose store is unreachable: nothing listens on port 1."""
    store = CounterStore.connect("redis://u:p@127.0.0.1:1/0", metrics)
    yield RateLimiter(store, metrics, clock=clock)
    await store.close()


# ---- the table ----


def test_ids_are_unique_and_every_limit_is_listed() -> None:
    assert len({limit.id for limit in ALL}) == len(ALL)
    defined = {v for v in vars(limits).values() if isinstance(v, Limit)}
    assert defined == set(ALL)


@pytest.mark.parametrize("limit", ALL, ids=lambda limit: limit.id)
def test_every_key_lives_at_most_25_hours(limit: Limit) -> None:
    rule = limit.rule
    longest = period(limit) + (rule.block_seconds if isinstance(rule, Quota) else 0)
    assert 0 < longest <= MAX_TTL_SECONDS
    assert rule.limit >= 1


def test_link_steps_and_sign_in_fail_closed_and_the_rest_fail_open() -> None:
    closed = {g for g in Group if g.failure_mode is FailureMode.CLOSED}
    assert closed == {Group.LINK_STEPS, Group.SIGN_IN}


def test_the_nfr_14_values() -> None:
    assert limits.A_IP.rule == Rate(60, 60)
    assert limits.A_EMAIL_HOUR.rule == Quota(5, 3600)
    assert limits.H_TENANT.rule == Rate(1000, 60)
    assert limits.H_FAILED_AUTH.rule == Quota(100, 300, "failures", 900)


def test_bundles_run_narrowest_first() -> None:
    # The caller's own keys, then IP, then the address, then the tenant (abuse design 4.4).
    rank = {
        KeyType.ACCOUNT: 0,
        KeyType.SUBJECT: 0,
        KeyType.OPERATOR: 0,
        KeyType.IP: 1,
        KeyType.EMAIL: 2,
        KeyType.TENANT_EMAIL: 2,
        KeyType.TENANT: 3,
    }
    for bundle in (
        limits.REQUEST_CODE,
        limits.TENANT_OPERATION,
        limits.SAFETY_ACTION,
        limits.INVITE_USER,
    ):
        ranks = [rank[limit.keys[0]] for limit in bundle]
        assert ranks == sorted(ranks)
    assert limits.H_TENANT not in limits.SAFETY_ACTION


def test_store_keys() -> None:
    assert limits.A_IP.store_key(KeyType.IP, IP) == f"rl:A.ip_requests:ip:{IP}"
    key = limits.A_EMAIL_DAY.store_key(KeyType.EMAIL, "e1:AAAAAAAAAAAAAAAAAAAAAA")
    # No braces: no hash tag, so one key per script works in cluster mode (local development 4).
    assert "{" not in key
    assert "}" not in key
    for value in ("", "a b", "{tag}", "x\r\nFLUSHALL", "dev.member@example.com", "a" * 201):
        with pytest.raises(ValueError, match="key value"):
            limits.A_IP.store_key(KeyType.IP, value)


def test_a_missing_key_is_a_programming_error() -> None:
    with pytest.raises(LookupError, match=r"H\.caller_requests"):
        limits.H_CALLER.key_type({KeyType.TENANT: TENANT})
    assert limits.H_CALLER.key_type({KeyType.API_KEY: "k"}) is KeyType.API_KEY


# ---- every limit against Valkey ----


@pytest.mark.parametrize(
    "limit", [limit for limit in ALL if not limit.counts_failures], ids=lambda limit: limit.id
)
async def test_each_limit_admits_its_value_then_refuses_then_rolls_over(
    limiter: RateLimiter, clock: Clock, metrics: CounterMetrics, limit: Limit
) -> None:
    keys = keys_for(limit)
    for _ in range(limit.rule.limit):
        await limiter.check([limit], keys)
    with pytest.raises(RateLimited) as refused:
        await limiter.check([limit], keys)
    wait = refused.value.retry_after
    if isinstance(limit.rule, Rate):
        assert wait == math.ceil(limit.rule.period_seconds / limit.rule.limit)
    else:
        assert wait == period(limit)  # every entry came at the same instant
    key_type = limit.keys[0].value
    assert metrics.rejections.labels(limit.group.value, key_type)._value.get() == 1  # type: ignore[attr-defined]
    clock.now += wait - 1
    with pytest.raises(RateLimited):
        await limiter.check([limit], keys)
    clock.now += 1
    await limiter.check([limit], keys)
    clock.now += period(limit)  # the whole window later, the full limit again
    for _ in range(limit.rule.limit):
        await limiter.check([limit], keys)


@pytest.mark.parametrize(
    "limit", [limit for limit in ALL if limit.counts_failures], ids=lambda limit: limit.id
)
async def test_each_failure_quota_refuses_once_full(
    limiter: RateLimiter, clock: Clock, limit: Limit
) -> None:
    rule = limit.rule
    assert isinstance(rule, Quota)
    keys = keys_for(limit)
    for _ in range(rule.limit - 1):
        await limiter.record(limit, IP)
        await limiter.check([limit], keys)  # a check alone never counts
    await limiter.record(limit, IP)
    with pytest.raises(RateLimited) as refused:
        await limiter.check([limit], keys)
    assert refused.value.retry_after == max(rule.window_seconds, rule.block_seconds)
    clock.now += max(rule.window_seconds, rule.block_seconds)
    await limiter.check([limit], keys)


async def test_401s_block_an_ip_for_15_minutes(limiter: RateLimiter, clock: Clock) -> None:
    keys = {KeyType.IP: IP, KeyType.ACCOUNT: ACCOUNT, KeyType.TENANT: TENANT}
    for _ in range(100):
        await limiter.record(limits.H_FAILED_AUTH, IP)
    clock.now += 299  # failures still in the window, and the block runs from the 100th
    with pytest.raises(RateLimited) as refused:
        await limiter.check(limits.TENANT_OPERATION, keys)
    assert refused.value.retry_after == 900 - 299
    clock.now += 301  # the window is empty, the block still holds
    with pytest.raises(RateLimited):
        await limiter.check(limits.TENANT_OPERATION, keys)
    clock.now += 300
    await limiter.check(limits.TENANT_OPERATION, keys)


async def test_rate_cost_counts_recipient_emails(limiter: RateLimiter) -> None:
    keys = {KeyType.ACCOUNT: ACCOUNT, KeyType.TENANT: TENANT}
    await limiter.check([limits.G_CALLER_EMAILS], keys, cost=150)
    await limiter.check([limits.G_CALLER_EMAILS], keys, cost=50)
    with pytest.raises(RateLimited):
        await limiter.check([limits.G_CALLER_EMAILS], keys, cost=1)
    with pytest.raises(ValueError, match="one event"):
        await limiter.check([limits.J_TENANTS], keys_for(limits.J_TENANTS), cost=2)
    with pytest.raises(ValueError, match="at least 1"):
        await limiter.check([limits.H_CALLER], keys, cost=0)


# ---- order and Retry-After ----


async def test_a_refused_request_leaves_wider_limits_unchanged(
    limiter: RateLimiter, counter_store: CounterStore
) -> None:
    keys = {KeyType.IP: IP, KeyType.ACCOUNT: ACCOUNT, KeyType.TENANT: TENANT}
    for _ in range(300):
        await limiter.check(limits.TENANT_OPERATION, keys)
    tenant_key = limits.H_TENANT.store_key(KeyType.TENANT, TENANT)
    before = await counter_store._client.get(tenant_key)
    for _ in range(20):
        with pytest.raises(RateLimited):
            await limiter.check(limits.TENANT_OPERATION, keys)
    assert await counter_store._client.get(tenant_key) == before


async def test_a_refused_code_request_doesnt_use_up_the_address(
    limiter: RateLimiter, counter_store: CounterStore
) -> None:
    keys = (
        keys_for(limits.A_SUBJECT_GAP) | keys_for(limits.A_EMAIL_HOUR) | keys_for(limits.A_TENANT)
    )
    await limiter.check(limits.REQUEST_CODE, keys)
    for _ in range(10):
        with pytest.raises(RateLimited):  # 1 code every 30 s per link
            await limiter.check(limits.REQUEST_CODE, keys)
    address_key = limits.A_EMAIL_HOUR.store_key(KeyType.EMAIL, "e1:AAAAAAAAAAAAAAAAAAAAAA")
    assert await counter_store._client.zcard(address_key) == 1


async def test_retry_after_is_the_largest_wait(limiter: RateLimiter, clock: Clock) -> None:
    keys = (
        keys_for(limits.A_SUBJECT_GAP) | keys_for(limits.A_EMAIL_HOUR) | keys_for(limits.A_TENANT)
    )
    other_link = dict(keys, **{KeyType.SUBJECT: "88888888-8888-4888-8888-888888888888:1"})
    for i in range(5):  # five links to one address use up its hour
        await limiter.check(limits.REQUEST_CODE, dict(keys, **{KeyType.SUBJECT: f"s{i}:1"}))
        clock.now += 60
    # The link's 30 s gap and the address's hour are both exceeded: the hour wins.
    await limiter.check([limits.A_SUBJECT_GAP], other_link)
    with pytest.raises(RateLimited) as refused:
        await limiter.check(limits.REQUEST_CODE, other_link)
    assert refused.value.retry_after == 3600 - 5 * 60


async def test_an_address_keeps_its_count_across_a_key_rotation(limiter: RateLimiter) -> None:
    old = EmailPseudonyms("eold:AAAAAAAAAAAAAAAAAAAAAA")
    new = EmailPseudonyms("enew:BBBBBBBBBBBBBBBBBBBBBB", overlap=(old.active,))
    for _ in range(3):
        await limiter.check([limits.A_EMAIL_HOUR], {KeyType.EMAIL: old})
    for _ in range(2):
        await limiter.check([limits.A_EMAIL_HOUR], {KeyType.EMAIL: new})
    with pytest.raises(RateLimited):
        await limiter.check([limits.A_EMAIL_HOUR], {KeyType.EMAIL: new})
    with pytest.raises(ValueError, match="only quotas"):
        await limiter.check([limits.H_TENANT], {KeyType.TENANT: new})


# ---- outages (abuse design 4.5) ----


@pytest.mark.parametrize(
    "limit",
    [limit for limit in ALL if limit.group.failure_mode is FailureMode.CLOSED],
    ids=lambda limit: limit.id,
)
async def test_fail_closed_limits_refuse_with_503(down: RateLimiter, limit: Limit) -> None:
    with pytest.raises(RateLimitStoreUnavailable) as refused:
        await down.check([limit], keys_for(limit))
    assert isinstance(refused.value, ServiceUnavailable)
    assert refused.value.retry_after == 5


@pytest.mark.parametrize(
    "limit",
    [x for x in ALL if x.group.failure_mode is FailureMode.LOCAL and not x.counts_failures],
    ids=lambda limit: limit.id,
)
async def test_fail_open_limits_count_per_pod_at_a_third(
    down: RateLimiter, clock: Clock, limit: Limit
) -> None:
    keys = keys_for(limit)
    for _ in range(fallback_limit(limit.rule.limit)):
        await down.check([limit], keys)
    with pytest.raises(RateLimited):
        await down.check([limit], keys)
    clock.now += period(limit)
    await down.check([limit], keys)


async def test_failures_are_recorded_per_pod_during_an_outage(
    down: RateLimiter, clock: Clock
) -> None:
    keys = {KeyType.IP: IP, KeyType.ACCOUNT: ACCOUNT, KeyType.TENANT: TENANT}
    for _ in range(fallback_limit(100)):
        await down.record(limits.H_FAILED_AUTH, IP)
    with pytest.raises(RateLimited) as refused:
        await down.check(limits.TENANT_OPERATION, keys)
    assert refused.value.retry_after == 900
    with pytest.raises(ValueError, match="doesn't count failures"):
        await down.record(limits.H_TENANT, TENANT)


async def test_a_fail_open_bundle_with_a_fail_closed_limit_still_refuses(
    down: RateLimiter,
) -> None:
    keys = {KeyType.IP: IP, KeyType.ACCOUNT: ACCOUNT, KeyType.TENANT: TENANT}
    await down.check(limits.TENANT_OPERATION, keys)
    with pytest.raises(RateLimitStoreUnavailable):
        await down.check([*limits.TENANT_OPERATION, limits.B_START], keys)


def test_the_per_pod_limiter_bounds_its_memory() -> None:
    local = LocalCounters(max_keys=10)
    for i in range(25):
        local.rate(f"k{i}", now_ms=0, limit=1, period_ms=1000, cost=1, peek=False)
    assert len(local) <= 10
    assert local.scores("missing", now_ms=0, window_ms=1000) == []
    assert fallback_limit(2) == 1
    assert fallback_limit(300) == 100
