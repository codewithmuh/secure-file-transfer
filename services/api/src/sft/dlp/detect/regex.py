"""A typed wrapper over the few RE2 calls the detectors make (ADR-0022, google-re2, which has no
type hints).

RE2 runs in time linear in its input, and has no backreferences or lookaround, so no pattern, ours
or a tenant's, can make an inspection slow without bound (threat model T-103). `log_errors` is off:
RE2 would otherwise write a pattern that fails to compile to standard error, and a tenant's pattern
is confidential.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import re2

DEFAULT_MAX_MEM = 8 << 20
"""Each compiled expression's memory budget: 8 MiB ([DLP] 5)."""


class RegexError(ValueError):
    """An expression that RE2 can't compile, or that is past its memory budget."""


@dataclass(frozen=True, slots=True)
class Span:
    start: int
    end: int
    groups: tuple[str | None, ...]


class Regex:
    """A compiled RE2 expression, matched on `str` with offsets in characters."""

    __slots__ = ("_compiled",)

    def __init__(
        self,
        expression: str,
        *,
        case_insensitive: bool = False,
        never_capture: bool = False,
        max_mem: int = DEFAULT_MAX_MEM,
    ) -> None:
        options = re2.Options()
        options.max_mem = max_mem
        options.log_errors = False
        options.case_sensitive = not case_insensitive
        # Every group non-capturing: RE2 then finds a match's span with its DFAs alone, and never
        # runs the slower submatch engines.
        options.never_capture = never_capture
        try:
            self._compiled: Any = re2.compile(expression, options)
        except (re2.error, UnicodeEncodeError):
            # The error's message quotes the expression, which may be a tenant's: drop it. A lone
            # surrogate can't be encoded for RE2 at all.
            raise RegexError("the expression doesn't compile in RE2") from None

    @property
    def program_size(self) -> int:
        """The larger of RE2's forward and reverse program sizes: what each character of input
        costs it, at worst.
        """
        return max(int(self._compiled.programsize), int(self._compiled.reverseprogramsize))

    def finditer(self, text: str) -> Iterator[Span]:
        for match in self._compiled.finditer(text):
            start, end = match.span()
            yield Span(start, end, tuple(match.groups()))

    def search(self, text: str) -> Span | None:
        match = self._compiled.search(text)
        if match is None:
            return None
        start, end = match.span()
        return Span(start, end, tuple(match.groups()))

    def fullmatch(self, text: str) -> bool:
        return self._compiled.fullmatch(text) is not None


class RegexSet:
    """Many expressions matched in one pass; says which of them match anywhere in a text."""

    __slots__ = ("_set",)

    def __init__(self, expressions: list[str], *, max_mem: int) -> None:
        options = re2.Options()
        options.max_mem = max_mem
        options.log_errors = False
        self._set: Any = re2.Set.SearchSet(options)
        try:
            for expression in expressions:
                self._set.Add(expression)
            self._set.Compile()
        except (re2.error, UnicodeEncodeError):
            # The error's message quotes the expression, a tenant's confidential term: drop it.
            raise RegexError(
                "the expressions don't compile in RE2, or are past their budget"
            ) from None

    def matching(self, text: str) -> list[int]:
        """The indices of the expressions that match somewhere in `text`."""
        found = self._set.Match(text)
        return list(found) if found else []
