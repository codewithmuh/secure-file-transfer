"""Rate limits (NFR-14, ADR-0014, abuse and rate limits section 2).

- `limits`: every limit as data, and the bundle each operation applies.
- `limiter`: `RateLimiter.check(limits, keys)`, `RateLimiter.check_all(charges)` (all or nothing,
  batched) and `RateLimiter.record(limit, value)`, over the counter store (`sft.data.counters`),
  with each group's failure mode.
- `local`: the per-pod fallback for the groups that fail open.
"""

from sft.service.rate_limits.limiter import Charge, RateLimiter, RateLimitStoreUnavailable

__all__ = ["Charge", "RateLimitStoreUnavailable", "RateLimiter"]
