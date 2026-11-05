"""A tenant's own detectors: keyword lists (FR-38) and RE2 patterns (FR-39), as [DLP] section 5
specifies.

Keyword terms are matched on the keyword view (section 3). A term with a CJK character matches as a
substring; any other term matches as a whole word, with no ASCII letter or digit right before or
after it. All of a tenant's terms go into one RE2 set, so a unit is read once whatever the number of
terms.

Patterns are RE2 expressions of at most 512 characters with an 8 MiB memory budget, matched on the
normalised text with every group non-capturing (only a match's span is used), and with an RE2
program of at most 1,000 instructions. `validate` adds the save-time check of FR-56: no empty match
anywhere in the 1 MiB test text. Every check is deterministic: none times anything, so a pattern is
accepted or refused the same way on any machine.

Errors name the rule that failed, never the term or the expression: both are the tenant's
confidential data.
"""

from __future__ import annotations

import functools
import re
from collections.abc import Iterator, Sequence

from sft.dlp.detect.normalise import has_cjk, keyword_term, scrub_surrogates
from sft.dlp.detect.prepared import HIGH, LOW, Hit, Keywords, Prepared
from sft.dlp.detect.regex import Regex, RegexError, RegexSet
from sft.dlp.units import CUSTOM_PREFIX, KeywordList, Pattern, TenantDetector

MAX_DETECTORS = 50
MAX_PATTERNS = 20
MAX_TERMS = 1000
MAX_TERM_LENGTH = 100
MAX_EXPRESSION_LENGTH = 512
MAX_CONTEXT_KEYWORDS = 100
MAX_PROGRAM_SIZE = 1000
"""RE2 instructions a pattern may compile to, forward or reverse ([DLP] 5). RE2's work per character
grows with it; our own largest pattern (email addresses) has about 530."""

# The keyword set holds up to 50,000 terms of up to 100 characters.
_KEYWORD_SET_MAX_MEM = 64 << 20
_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


class DetectorError(ValueError):
    """A tenant detector that breaks a rule of [DLP] 5. `reason` says which; nothing of the
    definition.
    """

    def __init__(self, reason: str, detector_id: str | None = None) -> None:
        self.reason = reason
        self.detector_id = (
            detector_id if detector_id is not None and _ID.fullmatch(detector_id) else None
        )
        super().__init__(f"{reason} (detector {self.detector_id or 'unknown'})")


def _term_expression(term: str) -> str:
    escaped = re.escape(term)
    if has_cjk(term):
        return escaped
    return f"(?:^|[^a-z0-9]){escaped}(?:[^a-z0-9]|$)"


class _CompiledPattern:
    __slots__ = ("context", "detector", "min_length", "regex")

    def __init__(self, pattern: Pattern) -> None:
        if len(pattern.expression) > MAX_EXPRESSION_LENGTH:
            raise DetectorError("expression_too_long", pattern.id)
        if len(pattern.context_keywords) > MAX_CONTEXT_KEYWORDS or any(
            not 0 < len(k.strip()) <= MAX_TERM_LENGTH for k in pattern.context_keywords
        ):
            raise DetectorError("invalid_context_keywords", pattern.id)
        if not 0 <= pattern.min_length <= MAX_EXPRESSION_LENGTH:
            raise DetectorError("invalid_min_length", pattern.id)
        try:
            self.regex = Regex(
                pattern.expression, case_insensitive=pattern.case_insensitive, never_capture=True
            )
        except RegexError:
            raise DetectorError("does_not_compile", pattern.id) from None
        if self.regex.program_size > MAX_PROGRAM_SIZE:
            raise DetectorError("too_complex", pattern.id)
        if self.regex.fullmatch(""):
            raise DetectorError("matches_empty_string", pattern.id)
        self.detector = CUSTOM_PREFIX + pattern.id
        self.context = Keywords(pattern.context_keywords) if pattern.context_keywords else None
        self.min_length = max(1, pattern.min_length)

    def detect(self, unit: Prepared) -> Iterator[Hit]:
        for span in self.regex.finditer(unit.text):
            if span.end - span.start < self.min_length:
                continue
            value = unit.text[span.start : span.end]
            if self.context is None:
                confidence = HIGH
            else:
                confidence = HIGH if unit.has_context(span.start, span.end, self.context) else LOW
            yield Hit(
                self.detector, confidence, value, "****" + (value[-4:] if len(value) > 4 else "")
            )


class TenantDetectors:
    """A tenant's keyword lists and patterns, compiled once per file."""

    def __init__(self, detectors: Sequence[TenantDetector]) -> None:
        if len(detectors) > MAX_DETECTORS:
            raise DetectorError("too_many_detectors")
        patterns = [d for d in detectors if isinstance(d, Pattern)]
        if len(patterns) > MAX_PATTERNS:
            raise DetectorError("too_many_patterns")
        seen: set[str] = set()
        expressions: list[str] = []
        # For each expression in the set: the detector it belongs to, its term's form and the term
        # as listed.
        self._terms: list[tuple[str, str, str]] = []
        self._patterns: list[_CompiledPattern] = []
        for detector in detectors:
            if not isinstance(detector, KeywordList | Pattern):
                raise DetectorError("unknown_kind")
            if not _ID.fullmatch(detector.id) or detector.id in seen:
                raise DetectorError("invalid_id", detector.id)
            seen.add(detector.id)
            if isinstance(detector, Pattern):
                self._patterns.append(_CompiledPattern(detector))
                continue
            if not 0 < len(detector.terms) <= MAX_TERMS:
                raise DetectorError("invalid_term_count", detector.id)
            for listed in detector.terms:
                term = keyword_term(listed)
                if not 0 < len(listed.strip()) <= MAX_TERM_LENGTH or not term:
                    raise DetectorError("invalid_term", detector.id)
                expressions.append(_term_expression(term))
                preview = scrub_surrogates(listed.strip()[:64])
                self._terms.append((CUSTOM_PREFIX + detector.id, term, preview))
        try:
            self._set = RegexSet(expressions, max_mem=_KEYWORD_SET_MAX_MEM) if expressions else None
        except RegexError:
            raise DetectorError("keywords_too_large") from None

    def detect(self, unit: Prepared) -> Iterator[Hit]:
        if self._set is not None:
            for index in self._set.matching(unit.view):
                detector, term, listed = self._terms[index]
                yield Hit(detector, HIGH, term, listed)
        for pattern in self._patterns:
            yield from pattern.detect(unit)


@functools.cache
def _test_text() -> str:
    """The 1 MiB test text a pattern must not match empty anywhere in: mixed Japanese, English,
    digits and marks.
    """
    sample = (
        "顧客一覧 株式会社サンプル 電話 03-0000-0000 Order ORD-2026-000123 version 1.2.3 "
        "メモ: 来週の打ち合わせ。 The quick brown fox jumps over the lazy dog 0123456789 "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa <<<<>>>> ____ ---- .... \t\n"
    )
    return (sample * (1024 * 1024 // len(sample) + 1))[: 1024 * 1024]


def validate(detector: TenantDetector) -> None:
    """The save-time checks of a tenant detector (FR-56): raises DetectorError, or returns.

    The pattern is compiled once, by TenantDetectors, and its compiled form reused here.
    """
    for compiled in TenantDetectors([detector])._patterns:
        # An expression that can match empty somewhere, such as `\b`, though not on its own.
        if any(span.start == span.end for span in compiled.regex.finditer(_test_text())):
            raise DetectorError("matches_empty_string", detector.id)
