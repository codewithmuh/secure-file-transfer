"""Row IDs: UUIDv7, made by the application (data model 1).

They sort by creation time, which keeps indexes compact and lets the outbox be read in the order its
rows were written. Python's `uuid.uuid7` arrives only in 3.14, so this is RFC 9562's layout: a
48-bit Unix time in milliseconds, then 74 random bits around the version and variant bits.

IDs made by this process also sort in the order they were made, even within one millisecond: a new
ID that would not sort after the last one is the last one plus one (RFC 9562 6.2, method 2). So a
list ordered by ID shows the newest row first.
"""

from __future__ import annotations

import secrets
import threading
import time
import uuid

_VERSION = 0x7
_VARIANT = 0b10
_RAND_B_MAX = (1 << 62) - 1

_lock = threading.Lock()
_last = 0


def uuid7(now_ms: int | None = None) -> uuid.UUID:
    """A new UUIDv7. `now_ms` is for tests; by default it is the current time."""
    ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if not 0 <= ms < 1 << 48:
        raise ValueError("the time must fit in 48 bits of milliseconds")
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    value = (ms << 80) | (_VERSION << 76) | (rand_a << 64) | (_VARIANT << 62) | rand_b
    if now_ms is not None:
        return uuid.UUID(int=value)
    global _last
    with _lock:
        # Plus one in rand_b. If rand_b is full (one chance in 2^62), the random ID is kept, since
        # a carry would overwrite the variant bits.
        if value <= _last and _last & _RAND_B_MAX != _RAND_B_MAX:
            value = _last + 1
        _last = max(value, _last)
    return uuid.UUID(int=value)
