"""The scan-time budget of tenant patterns ([DLP] 5, #147).

A pattern past its budget stops for the rest of the file and is reported by ID, with no match in
the outcome; the file's other detectors carry on.
"""

from __future__ import annotations

import random
import string
from collections.abc import Iterator

import pytest
from pydantic import ValidationError

from sft.dlp.detect.scanner import _Scanner
from sft.dlp.detect.tenant import DEFAULT_BUDGET, PatternBudget, TenantDetectors
from sft.dlp.protocol import Result, result
from sft.dlp.units import KeywordList, Pattern, TextUnit

SLOW = r"(?:.{0,30}\d){1,2}q"  # 548 RE2 instructions: it passes the save-time checks
MIB = 1024 * 1024


@pytest.fixture(scope="module")
def random_text() -> str:
    rng = random.Random(147)  # noqa: S311 - reproducible test data
    alphabet = string.ascii_letters + string.digits + " .,"
    return "".join(rng.choice(alphabet) for _ in range(MIB))


def scan(
    units: list[TextUnit], tenant: list[Pattern | KeywordList], budget: PatternBudget
) -> tuple[dict[str, dict[str, int]], list[str], _Scanner]:
    scanner = _Scanner(tenant, budget=budget)
    for unit in units:
        scanner.feed(unit)
    findings = {f.detector: dict(f.counts) for f in scanner.findings()}
    return findings, scanner.budget_exceeded(), scanner


def spent(scanner: _Scanner, detector: str) -> tuple[float, int]:
    """The CPU seconds and characters a tenant pattern spent on the file."""
    [pattern] = [p for p in scanner._tenant._patterns if p.detector == detector]
    return pattern.spent, pattern.scanned


def test_the_example_pattern_is_stopped_on_1_mib_of_random_text(random_text: str) -> None:
    # The default budget: 0.5 s plus 50 ms per MiB scanned. Unchecked, the pattern takes about
    # 1.5 to 2.5 s on this text.
    units = [TextUnit("line 1", f"mihon.taro@example.com {random_text}")]
    tenant = [Pattern("slow", SLOW), KeywordList("words", ("zzzunusedzzz",))]
    findings, stopped, scanner = scan(units, tenant, DEFAULT_BUDGET)
    assert stopped == ["custom:slow"]
    seconds, scanned = spent(scanner, "custom:slow")
    # Stopped within its budget, plus at most one 64 KiB chunk, before the end of the text.
    assert DEFAULT_BUDGET.allowed(scanned) < seconds < DEFAULT_BUDGET.allowed(scanned) + 0.5
    assert scanned < MIB
    # The other detectors still ran over the whole unit.
    assert findings["email_address"]["high"] == 1


def test_a_stopped_pattern_stays_stopped_for_the_rest_of_the_file(random_text: str) -> None:
    budget = PatternBudget(base_seconds=0.02, seconds_per_mib=0.0)
    units = [TextUnit(f"page {n}", random_text[: 256 * 1024]) for n in range(1, 5)]
    tenant = [Pattern("slow", SLOW), Pattern("fast", "ORD-[0-9]{6}")]
    _, stopped, scanner = scan(units, tenant, budget)
    assert stopped == ["custom:slow"]
    assert spent(scanner, "custom:slow")[1] < 256 * 1024  # stopped in the first page
    assert spent(scanner, "custom:fast")[1] > 0.99 * MIB  # the other one read every page


def test_an_ordinary_pattern_keeps_within_the_default_budget(random_text: str) -> None:
    units = [TextUnit("page 1", random_text + " ORD-123456")]
    findings, stopped, _ = scan(units, [Pattern("orders", "ORD-[0-9]{6}")], DEFAULT_BUDGET)
    assert stopped == []
    assert findings["custom:orders"]["high"] == 1


class Clock:
    """A clock that moves one second per call, so the time budget is deterministic."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 0.5
        return self.now


def test_the_budget_is_checked_after_each_chunk() -> None:
    # Each chunk "costs" 0.5 s on this clock; 1.2 s allowed means the third chunk is the last.
    budget = PatternBudget(base_seconds=1.2, seconds_per_mib=0.0, chunk_chars=10, clock=Clock())
    text = " ".join(["x1"] * 50)  # a match in every chunk
    detectors = TenantDetectors([Pattern("x", "x[0-9]")], budget)
    hits = list(detectors.detect(prepared(text)))
    assert len(hits) <= 3 * 4  # at most 4 matches in a chunk of 10 characters
    assert detectors.budget_exceeded() == ["custom:x"]


def test_the_match_budget_stops_a_pattern_that_matches_everything() -> None:
    budget = PatternBudget(max_matches=100)
    detectors = TenantDetectors([Pattern("any", "[a-z]")], budget)
    hits = list(detectors.detect(prepared("abcdefghij" * 1000)))
    assert len(hits) <= 101
    assert detectors.budget_exceeded() == ["custom:any"]


@pytest.mark.parametrize("chunk", [1, 3, 7, 64])
def test_chunks_lose_no_match_and_keep_anchors(chunk: int) -> None:
    text = "abc-123 de-45 ab-6789 x-1"
    expected = whole(text, r"[a-z]+-[0-9]+")
    assert chunked(text, r"[a-z]+-[0-9]+", chunk) == expected
    # `^` and `$` still mean the ends of the unit, not of a chunk.
    assert chunked(text, r"^[a-z]+", chunk) == ["abc"]
    assert chunked(text, r"[0-9]$", chunk) == ["1"]


def test_a_match_runs_at_most_its_reach_past_its_chunk() -> None:
    text = "q" + "a" * 100
    budget = PatternBudget(chunk_chars=10, match_reach_chars=20)
    hits = list(TenantDetectors([Pattern("q", "qa+")], budget).detect(prepared(text)))
    assert [len(hit.value) for hit in hits] == [30]


def test_the_outcome_carries_ids_only() -> None:
    answer = result(
        engine_version="2", state="inspected", reasons=[], budget_exceeded=["custom:slow"]
    )
    assert Result.model_validate_json(answer.model_dump_json()).budget_exceeded == ["custom:slow"]
    assert result(engine_version="2", state="inspected", reasons=[]).budget_exceeded == []
    for bad in (["jp_my_number"], ["custom:slow", "custom:slow"], ["custom:a b"]):
        with pytest.raises(ValidationError):
            result(engine_version="2", state="inspected", reasons=[], budget_exceeded=bad)


# ---- helpers ----


def prepared(text: str) -> object:
    from sft.dlp.detect.prepared import Prepared

    return Prepared(TextUnit("line 1", text))


def whole(text: str, expression: str) -> list[str]:
    big = PatternBudget(chunk_chars=MIB)
    return values(TenantDetectors([Pattern("p", expression)], big).detect(prepared(text)))


def chunked(text: str, expression: str, chunk: int) -> list[str]:
    budget = PatternBudget(chunk_chars=chunk)
    return values(TenantDetectors([Pattern("p", expression)], budget).detect(prepared(text)))


def values(hits: Iterator[object]) -> list[str]:
    return [hit.value for hit in hits]  # type: ignore[attr-defined]
