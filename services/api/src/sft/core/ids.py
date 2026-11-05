"""Row IDs: UUIDv7, made by the application (data model 1).

They sort by creation time, which keeps indexes compact and lets the outbox be read in the order its
rows were written. Python's `uuid.uuid7` arrives only in 3.14, so this is RFC 9562's layout: a
48-bit Unix time in milliseconds, then 74 random bits around the version and variant bits.
"""

from __future__ import annotations

import secrets
import time
import uuid

_VERSION = 0x7
_VARIANT = 0b10


def uuid7(now_ms: int | None = None) -> uuid.UUID:
    """A new UUIDv7. `now_ms` is for tests; by default it is the current time."""
    ms = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if not 0 <= ms < 1 << 48:
        raise ValueError("the time must fit in 48 bits of milliseconds")
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    value = (ms << 80) | (_VERSION << 76) | (rand_a << 64) | (_VARIANT << 62) | rand_b
    return uuid.UUID(int=value)
