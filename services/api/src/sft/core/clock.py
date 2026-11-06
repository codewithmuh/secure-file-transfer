"""The time the service and the lifecycle jobs read as "now" (#182).

`Clock` is the wall clock in UTC plus an offset. The offset is a test hook: the M2 journey test
moves the jobs' clock past a transfer's expiry to show that expiry deletes every copy (delivery
plan 3), without waiting a day. It comes from `CLOCK_OFFSET_SECONDS`, which the settings refuse
outside `ENVIRONMENT=local` or `test` (`sft.core.settings.ClockSettings`), so it is never active
in dev, staging or prod.

Only times the service compares in Python move with it: a transfer's expiry on every call
(architecture 4.2) and every "due" a lifecycle job finds. What PostgreSQL stamps with its own
`now()` (an audit event's `occurred_at`, a session's idle time) doesn't, and needn't: nothing the
journey test checks depends on it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


@dataclass(frozen=True, slots=True)
class Clock:
    offset: timedelta = timedelta(0)

    def now(self) -> datetime:
        return datetime.now(UTC) + self.offset

    @classmethod
    def offset_by(cls, seconds: int) -> Clock:
        return cls(timedelta(seconds=seconds))


SYSTEM_CLOCK = Clock()
"""The wall clock, with no offset: what every environment but local and test runs."""
