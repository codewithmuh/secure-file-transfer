"""Rate limits (NFR-14, ADR-0014, abuse and rate limits section 2).

- `limits`: every limit as data, and the bundle each operation applies.
- `limiter`: `RateLimiter.check(limits, keys)` and `RateLimiter.record(limit, value)`, over the
  counter store (`sft.data.counters`), with each group's failure mode.
- `local`: the per-pod fallback for the groups that fail open.
"""

from sft.service.rate_limits.limiter import RateLimiter, RateLimitStoreUnavailable

__all__ = ["RateLimitStoreUnavailable", "RateLimiter"]
