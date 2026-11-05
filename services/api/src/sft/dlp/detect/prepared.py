"""A text unit made ready for the detectors: normalised text, its cells and their headers, and
context checks.

A `Hit` is one match inside the scanner. It holds the matched value's canonical form only so the
scanner can count distinct values with its keyed hash; the value never leaves the scanner, and
`repr` leaves it out so no log line or error report can show it (FR-53, NFR-26).
"""

from __future__ import annotations

import bisect
from collections.abc import Iterable
from dataclasses import dataclass, field

from sft.dlp.detect.normalise import keyword_term, keyword_view, normalise, scrub_surrogates
from sft.dlp.units import TextUnit

LOW, MEDIUM, HIGH = 0, 1, 2
CONTEXT_WINDOW = 40
"""Context keywords count within this many characters before or after a match ([DLP] 3)."""

MAX_LOCATION = 256


@dataclass(frozen=True, slots=True)
class Hit:
    detector: str
    confidence: int
    value: str = field(repr=False)
    preview: str


_ASCII_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyz")


def _whole_word(view: str, term: str) -> bool:
    """`term` in `view` with no ASCII letter right before it, and after it none but a plural "s".

    A digit may follow: "TEL03-..." and "TEL:03-..." both have the keyword. The view is case-folded,
    so lower case is enough.
    """
    position = view.find(term)
    while position >= 0:
        end = position + len(term)
        if end < len(view) and view[end] == "s":
            end += 1
        if (position == 0 or view[position - 1] not in _ASCII_LETTERS) and (
            end == len(view) or view[end] not in _ASCII_LETTERS
        ):
            return True
        position = view.find(term, position + 1)
    return False


class Keywords:
    """A set of context keywords, matched on the keyword view.

    A keyword in ASCII counts only as a whole word, so "tel" isn't in "hotel", "cell" in
    "excellent" or "phone" in "headphones". Japanese has no word boundaries: any other keyword
    counts wherever it appears ([DLP] 3). `whole_words=False` makes ASCII keywords substrings too,
    for long keywords that sit inside identifiers ("awsSecretAccessKey").
    """

    __slots__ = ("terms", "whole_words")

    def __init__(self, terms: Iterable[str], *, whole_words: bool = True) -> None:
        self.terms = tuple(sorted({t for t in (keyword_term(term) for term in terms) if t}))
        self.whole_words = whole_words

    def found_in(self, view: str) -> bool:
        return any(
            _whole_word(view, term) if self.whole_words and term.isascii() else term in view
            for term in self.terms
        )


class Prepared:
    """One unit's normalised text, with its cells' spans in that text and their headers' keyword
    views.
    """

    __slots__ = ("_cell_starts", "_cells", "_view", "location", "text")

    def __init__(self, unit: TextUnit) -> None:
        self.location = scrub_surrogates(unit.location[:MAX_LOCATION])
        cells: list[tuple[int, int, str]] = []
        if unit.cells:
            parts: list[str] = []
            offset = 0
            for cell in unit.cells:
                part = normalise(unit.text[cell.start : cell.end])
                cells.append((offset, offset + len(part), keyword_view(normalise(cell.header))))
                parts.append(part)
                offset += len(part) + 1
            self.text = "\t".join(parts)
        else:
            self.text = normalise(unit.text)
        self._cells = cells
        self._cell_starts = [start for start, _, _ in cells]
        self._view: str | None = None

    @property
    def view(self) -> str:
        """The keyword view of the whole unit, made on first use."""
        if self._view is None:
            self._view = keyword_view(self.text)
        return self._view

    def cell_at(self, position: int) -> tuple[int, int, str] | None:
        """The cell that holds this position of the normalised text: its span and its header."""
        index = bisect.bisect_right(self._cell_starts, position) - 1
        if index < 0:
            return None
        start, end, header = self._cells[index]
        return (start, end, header) if position <= end else None

    @property
    def cells(self) -> list[tuple[int, int, str]]:
        return self._cells

    def has_context(self, start: int, end: int, keywords: Keywords) -> bool:
        """A keyword within 40 characters of the match, in this unit, or in the match's column
        header.
        """
        window = self.text[max(0, start - CONTEXT_WINDOW) : end + CONTEXT_WINDOW]
        if keywords.found_in(keyword_view(window)):
            return True
        cell = self.cell_at(start)
        return cell is not None and keywords.found_in(cell[2])

    def window(self, start: int, end: int, width: int = CONTEXT_WINDOW) -> str:
        return self.text[max(0, start - width) : end + width]
