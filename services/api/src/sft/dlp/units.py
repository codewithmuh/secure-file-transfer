"""The data types sft.dlp.extract and sft.dlp.detect share (ADR-0022). No I/O, no logic."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

Confidence = Literal["low", "medium", "high"]

CUSTOM_PREFIX = "custom:"
"""A tenant detector's findings are named CUSTOM_PREFIX + its id (data model 2.7)."""


@dataclass(frozen=True, slots=True)
class Cell:
    """One cell of a table row: offsets into the row unit's raw text, and its column header."""

    start: int
    end: int
    header: str


@dataclass(frozen=True, slots=True)
class TextUnit:
    """Raw extracted text with its location hint; cells only for a table row."""

    location: str
    text: str
    cells: tuple[Cell, ...] = ()


@dataclass(frozen=True, slots=True)
class Finding:
    """One detector's result for one file: distinct-value counts, never a value."""

    detector: str
    counts: Mapping[Confidence, int]
    locations: tuple[str, ...]
    previews: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class KeywordList:
    """A tenant keyword list (FR-38)."""

    id: str
    terms: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Pattern:
    """A tenant pattern (FR-39)."""

    id: str
    expression: str
    context_keywords: tuple[str, ...] = ()
    min_length: int = 0
    case_insensitive: bool = False


type TenantDetector = KeywordList | Pattern
