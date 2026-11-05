import time
import uuid

import pytest

from sft.core.ids import uuid7


def test_a_uuid7_has_version_7_and_the_rfc_variant() -> None:
    value = uuid7()
    assert value.version == 7
    assert value.variant == uuid.RFC_4122


def test_it_starts_with_the_time_in_milliseconds() -> None:
    before = time.time_ns() // 1_000_000
    value = uuid7()
    after = time.time_ns() // 1_000_000
    assert before <= value.int >> 80 <= after


def test_later_ids_sort_after_earlier_ones() -> None:
    ids = [uuid7(now_ms=ms) for ms in (1_000, 1_001, 2_000)]
    assert ids == sorted(ids)


def test_ids_made_in_the_same_millisecond_differ() -> None:
    assert len({uuid7(now_ms=5) for _ in range(1_000)}) == 1_000


@pytest.mark.parametrize("ms", [-1, 1 << 48])
def test_the_time_must_fit(ms: int) -> None:
    with pytest.raises(ValueError, match="48 bits"):
        uuid7(now_ms=ms)
