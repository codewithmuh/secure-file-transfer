"""The per-pod limiter: the same two algorithms as the counter store's scripts, in this process.

It counts only while the store is unavailable, for the groups that fail open (abuse design 4.5),
and each limit is a third of its value, because 3 is the minimum pod count: the service as a whole
then allows at most (pods / 3) times each limit. Its state starts empty and is never shared.

Memory is bounded: past `max_keys` keys, expired ones are dropped, then the oldest, down to 90 %.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field

from sft.data.counters import LogMode, Verdict, gcra_shape

FALLBACK_DIVISOR = 3


def fallback_limit(limit: int, max_cost: int = 1) -> int:
    """A third of `limit`, but never so low that one request of `max_cost` exceeds the burst:
    GCRA admits `limit // 2 + 1` at once (`gcra_split`), so the floor is `2 * (max_cost - 1)`."""
    return max(1, limit // FALLBACK_DIVISOR, 2 * (max_cost - 1))


@dataclass
class _Entry:
    expires_ms: float
    tat_us: int = 0
    scores: list[float] = field(default_factory=list)
    blocked_until: float = 0.0


class LocalCounters:
    def __init__(self, max_keys: int = 100_000) -> None:
        self._entries: dict[str, _Entry] = {}
        self._max_keys = max_keys

    def __len__(self) -> int:
        return len(self._entries)

    def rate(
        self, key: str, *, now_ms: int, limit: int, period_ms: int, cost: int, peek: bool
    ) -> Verdict:
        # In whole microseconds, as the script counts.
        interval, burst = gcra_shape(limit, period_ms)
        now = now_ms * 1000
        entry = self._live(key, now_ms)
        tat = max(entry.tat_us if entry else now, now)
        new_tat = tat + interval * cost
        allow_at = new_tat - burst
        if allow_at > now:
            return Verdict(False, math.ceil((allow_at - now) / 1000))
        if not peek:
            expires_ms = now_ms + math.ceil((new_tat - now) / 1000)
            self._put(key, _Entry(expires_ms=expires_ms, tat_us=new_tat), now_ms)
        return Verdict(True, 0)

    def log(
        self,
        key: str,
        *,
        now_ms: int,
        limit: int,
        window_ms: int,
        mode: LogMode,
        block_ms: int = 0,
        others: Sequence[float] = (),
    ) -> Verdict:
        entry = self._live(key, now_ms) or _Entry(expires_ms=now_ms + max(window_ms, block_ms))
        entry.scores = [s for s in entry.scores if s > now_ms - window_ms]
        if entry.blocked_until <= now_ms:
            entry.blocked_until = 0.0
        scores = entry.scores + [s for s in others if s > now_ms - window_ms]
        if mode == "record":
            entry.scores = [*entry.scores, now_ms][-limit:]
            if block_ms and len(scores) + 1 >= limit:
                entry.blocked_until = now_ms + block_ms
            entry.expires_ms = now_ms + max(window_ms, block_ms)
            self._put(key, entry, now_ms)
            return Verdict(True, 0)
        if entry.blocked_until:
            return Verdict(False, math.ceil(entry.blocked_until - now_ms))
        if len(scores) >= limit:
            oldest = sorted(scores)[len(scores) - limit]
            return Verdict(False, max(1, math.ceil(oldest + window_ms - now_ms)))
        if mode == "hit":
            entry.scores.append(now_ms)
            entry.expires_ms = now_ms + max(window_ms, block_ms)
            self._put(key, entry, now_ms)
        return Verdict(True, 0)

    def scores(self, key: str, *, now_ms: int, window_ms: int) -> list[float]:
        entry = self._live(key, now_ms)
        return [s for s in entry.scores if s > now_ms - window_ms] if entry else []

    def _live(self, key: str, now_ms: int) -> _Entry | None:
        entry = self._entries.get(key)
        if entry is not None and entry.expires_ms <= now_ms:
            del self._entries[key]
            return None
        return entry

    def _put(self, key: str, entry: _Entry, now_ms: int) -> None:
        self._entries.pop(key, None)  # re-inserted last, so the oldest come first
        self._entries[key] = entry
        if len(self._entries) > self._max_keys:
            self._entries = {k: e for k, e in self._entries.items() if e.expires_ms > now_ms}
            # Down to 90 %, so a pod full of live keys doesn't sweep on every request.
            while len(self._entries) > self._max_keys * 9 // 10:
                del self._entries[next(iter(self._entries))]
