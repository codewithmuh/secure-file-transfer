"""Normalisation of extracted text before the detectors run ([DLP] section 3).

Two views of a unit's text:

- `normalise`: Unicode NFKC, then the dashes and spaces between digits made uniform. Case is kept,
  because some formats are case-sensitive (access key IDs, tokens, base64 bodies, machine-readable
  zones). Full-width digits and letters become ASCII and half-width katakana becomes full-width, so
  a My Number typed in full-width digits matches like any other.
- `keyword_view`: the normalised text, case-folded, with spaces and line breaks between two CJK
  characters removed, because PDF text layers break Japanese words across lines. Keywords and
  context match on this view.

The fixed expressions here use Python's `re`: each is a character class with fixed-width
lookarounds, so it runs in linear time. RE2 compiles the detectors' own patterns (ADR-0022).
"""

from __future__ import annotations

import re
import unicodedata

# What IMEs produce for a dash between digits, after NFKC: hyphen (and non-breaking hyphen, which
# NFKC maps to it), figure dash, en dash, em dash, horizontal bar, hyphen bullet, minus sign and the
# katakana prolonged sound mark (half-width too, which NFKC maps to it). NFKC already maps the
# full-width and small hyphen-minus to "-".
_DASHES = "\u2010\u2012\u2013\u2014\u2015\u2043\u2212\u30fc"
_DASH_BETWEEN_DIGITS = re.compile(f"(?<=[0-9])[{_DASHES}](?=[0-9])")
# Any run of spaces between digits counts as one space. NFKC maps the ideographic and no-break
# spaces to " ".
_SPACES_BETWEEN_DIGITS = re.compile(r"(?<=[0-9]) {2,}(?=[0-9])")

# CJK characters for the line-break rule: CJK punctuation marks 々〆〇, hiragana, katakana, CJK
# unified ideographs and extension A, and the compatibility ideographs.
CJK = "\u3005-\u3007\u3040-\u309f\u30a0-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff"
_CJK_CHAR = re.compile(f"[{CJK}]")
# Tabs stay: they separate a table row's cells.
_SPACE_BETWEEN_CJK = re.compile(f"(?<=[{CJK}])[^\\S\t]+(?=[{CJK}])")


def normalise(text: str) -> str:
    """NFKC, with dashes and runs of spaces between digits made uniform. Keeps case."""
    text = unicodedata.normalize("NFKC", text)
    text = _DASH_BETWEEN_DIGITS.sub("-", text)
    return _SPACES_BETWEEN_DIGITS.sub(" ", text)


# A typographic apostrophe (U+2019) as "'", so "driver's licence" matches however it was typed.
_APOSTROPHE = str.maketrans({0x2019: "'"})


def keyword_view(normalised: str) -> str:
    """Case-folded, with whitespace between two CJK characters removed. Takes normalised text."""
    return _SPACE_BETWEEN_CJK.sub("", normalised.casefold().translate(_APOSTROPHE))


def keyword_term(term: str) -> str:
    """A keyword or context term in the form it is matched in: normalised, then its keyword view."""
    return keyword_view(normalise(term).strip())


def has_cjk(text: str) -> bool:
    return _CJK_CHAR.search(text) is not None
