"""The Japanese bank and branch code list behind `jp_bank_account`'s high confidence ([DLP] 4.4).

A valid pair, a 4-digit bank code and a 3-digit branch code, within 80 characters of an account
number, or in the same spreadsheet or CSV row, raises the match from medium to high. The list is
data, bundled in `bank_codes.txt` beside this module and loaded once per process:

    # source: <who publishes it, and where>
    # licence: <the terms that allow bundling it>
    # retrieved: <YYYY-MM-DD>
    NNNNNNN
    ...

Header lines start with `#`; `source`, `licence` and `retrieved` are required, `none` when nothing
is bundled. Every other line is one 7-digit code, the bank code then the branch code, in ascending
order, each once. `tools/bank_codes.py` writes the file from a licensed CSV, and the refresh steps
are in the service README ("DLP bank and branch codes").

**Nothing is bundled yet** (#146): no source whose licence allows redistribution could be
confirmed, so the file holds the header with `none` and no codes, and `jp_bank_account` stays at
medium. Tests and the accuracy corpus use a synthetic list instead (`tests/bank_codes_fixture.txt`).

The list is a frozen set of 7-character strings: about 2 MB of memory for the 30,000 or so branches
of Japan, parsed in tens of milliseconds, well inside the inspector's start-up and memory budgets.
"""

from __future__ import annotations

import functools
import importlib.resources
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final

DATA_FILE: Final = "bank_codes.txt"
REQUIRED: Final = ("source", "licence", "retrieved")
NONE: Final = "none"
MAX_CODES: Final = 100_000
"""Far more branches than Japan has: a bigger file is a mistake, not a list."""

_CODE = re.compile(r"[0-9]{7}")
_HEADER = re.compile(r"#\s*([a-z]+):\s*(.*?)\s*")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class BankCodeError(ValueError):
    """The bank code data is malformed. The message names the line, never a code."""


@dataclass(frozen=True, slots=True)
class BankCodes:
    """A set of valid bank and branch code pairs, with where it came from."""

    codes: frozenset[str] = field(repr=False)
    source: str = NONE
    licence: str = NONE
    retrieved: str = NONE

    def __len__(self) -> int:
        return len(self.codes)

    def valid(self, bank: str, branch: str) -> bool:
        """Whether `bank` (4 digits) and `branch` (3 digits) are a pair on the list."""
        return len(bank) == 4 and len(branch) == 3 and bank + branch in self.codes

    @property
    def version(self) -> str:
        """The list's part of the detectors' version: its retrieval date, or `none`."""
        return self.retrieved.replace("-", "") if self.codes else NONE


EMPTY: Final = BankCodes(frozenset())


def parse(text: str) -> BankCodes:
    """The codes and header of a bank code file. Raises `BankCodeError` naming the bad line."""
    header: dict[str, str] = {}
    codes: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if line.startswith("#"):
            match = _HEADER.fullmatch(line)
            if match is not None and match.group(1) in REQUIRED:
                header[match.group(1)] = match.group(2)
            continue
        if not _CODE.fullmatch(line):
            raise BankCodeError(f"line {number}: not a 7-digit bank and branch code")
        if codes and line <= codes[-1]:
            raise BankCodeError(f"line {number}: codes must be in ascending order, each once")
        codes.append(line)
        if len(codes) > MAX_CODES:
            raise BankCodeError(f"more than {MAX_CODES} codes")
    missing = [name for name in REQUIRED if not header.get(name)]
    if missing:
        raise BankCodeError(f"the header names no {', '.join(missing)}")
    if codes and (NONE in (header["source"], header["licence"])):
        raise BankCodeError("codes need a source and a licence")
    if codes and not _DATE.fullmatch(header["retrieved"]):
        raise BankCodeError("retrieved is a date, YYYY-MM-DD")
    return BankCodes(frozenset(codes), header["source"], header["licence"], header["retrieved"])


def render(codes: Iterable[str], *, source: str, licence: str, retrieved: str) -> str:
    """A bank code file for `codes`, as `parse` reads it: sorted, each once, with its header."""
    for name, value in (("source", source), ("licence", licence), ("retrieved", retrieved)):
        if not value.strip() or "\n" in value:
            raise BankCodeError(f"{name} is one line of text")
    unique = sorted(set(codes))
    for code in unique:
        if not _CODE.fullmatch(code):
            raise BankCodeError("a code is 7 digits: the bank code, then the branch code")
    lines = [
        "# Japanese bank and branch codes for jp_bank_account (docs/design/dlp-detectors.md 4.4).",
        "# One 7-digit code per line: the 4-digit bank code, then the 3-digit branch code.",
        "# Written by tools/bank_codes.py; refresh steps in services/api/README.md.",
        f"# source: {source}",
        f"# licence: {licence}",
        f"# retrieved: {retrieved}",
        *unique,
    ]
    text = "\n".join(lines) + "\n"
    parse(text)  # the same checks a load makes
    return text


@functools.cache
def load() -> BankCodes:
    """The bundled list, read once per process."""
    data = importlib.resources.files(__package__).joinpath(DATA_FILE).read_text("utf-8")
    return parse(data)
