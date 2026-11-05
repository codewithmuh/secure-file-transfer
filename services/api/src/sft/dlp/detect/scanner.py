"""The scanner: one per file, fed its text units as extraction streams them ([DLP] sections 1, 3 and
7).

It counts distinct values per detector at each confidence, keeps at most 10 location hints and 3
masked previews, and returns findings that hold no value. Distinct values are counted by a keyed
hash whose key is random per scanner and lives only in this process, so nothing that could be
matched back to a value exists outside it. A value counts once, at the highest confidence it
reached.

The scanner keeps no text: per detector a set of 16-byte digests, and the little state the
cross-line detectors need. Past 1,000,000 distinct values for one detector it stops remembering new
ones and counts each further match, which overcounts and so errs on the side of the rule.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Sequence
from typing import Protocol

from sft.dlp.detect import builtin
from sft.dlp.detect.blocks import BlockDetector
from sft.dlp.detect.credentials import CredentialDetector
from sft.dlp.detect.prepared import Hit, Prepared
from sft.dlp.detect.tenant import TenantDetectors
from sft.dlp.units import Confidence, Finding, TenantDetector, TextUnit

MAX_LOCATIONS = 10
MAX_PREVIEWS = 3
MAX_PREVIEW_LENGTH = 64
MAX_DISTINCT = 1_000_000

_LEVELS: tuple[Confidence, Confidence, Confidence] = ("low", "medium", "high")


class Scanner(Protocol):
    def feed(self, unit: TextUnit) -> None: ...

    def findings(self) -> list[Finding]: ...


class _Tally:
    __slots__ = ("locations", "overflow", "previews", "values")

    def __init__(self) -> None:
        self.values: dict[bytes, int] = {}
        self.overflow = [0, 0, 0]
        self.locations: list[str] = []
        self.previews: list[str] = []

    def add(self, digest: bytes, confidence: int, preview: str, location: str) -> None:
        known = self.values.get(digest)
        if known is not None:
            if confidence > known:
                self.values[digest] = confidence
        elif len(self.values) < MAX_DISTINCT:
            self.values[digest] = confidence
        else:
            self.overflow[confidence] += 1
        if len(self.locations) < MAX_LOCATIONS and location not in self.locations:
            self.locations.append(location)
        # One preview per distinct value: the first form it was seen in.
        preview = preview[:MAX_PREVIEW_LENGTH]
        if known is None and len(self.previews) < MAX_PREVIEWS and preview not in self.previews:
            self.previews.append(preview)

    def finding(self, detector: str) -> Finding:
        counts = list(self.overflow)
        for confidence in self.values.values():
            counts[confidence] += 1
        return Finding(
            detector=detector,
            counts={level: counts[index] for index, level in enumerate(_LEVELS)},
            locations=tuple(self.locations),
            previews=tuple(self.previews),
        )


class _Scanner:
    def __init__(self, tenant: Sequence[TenantDetector]) -> None:
        self._tenant = TenantDetectors(tenant)
        self._key = secrets.token_bytes(32)
        self._tallies: dict[str, _Tally] = {}
        self._credentials = CredentialDetector()
        self._blocks = BlockDetector()
        self._units = 0

    def __repr__(self) -> str:
        return f"<Scanner units={self._units} detectors={len(self._tallies)}>"

    def _digest(self, value: str) -> bytes:
        return hmac.new(self._key, value.encode(), hashlib.sha256).digest()[:16]

    def _record(self, hit: Hit, location: str) -> None:
        digest = self._digest(hit.value)
        tally = self._tallies.get(hit.detector)
        if tally is None:
            tally = self._tallies[hit.detector] = _Tally()
        tally.add(digest, hit.confidence, hit.preview, location)

    def feed(self, unit: TextUnit) -> None:
        self._units += 1
        prepared = Prepared(unit)
        for hit in builtin.detect(prepared):
            self._record(hit, prepared.location)
        for hit, location in self._credentials.feed(prepared, self._units):
            self._record(hit, location)
        for hit, location in self._blocks.feed(prepared):
            self._record(hit, location)
        for hit in self._tenant.detect(prepared):
            self._record(hit, prepared.location)

    def findings(self) -> list[Finding]:
        return [self._tallies[name].finding(name) for name in sorted(self._tallies)]


def new_scanner(tenant: Sequence[TenantDetector] = ()) -> Scanner:
    """A scanner for one file, with the tenant's own detectors. Raises DetectorError if one is
    invalid.
    """
    return _Scanner(tenant)


def inspect_text(text: str, tenant: Sequence[TenantDetector] = ()) -> list[Finding]:
    """The findings in one piece of text, such as a transfer's message (FR-50)."""
    scanner = _Scanner(tenant)
    scanner.feed(TextUnit(location="message", text=text))
    return scanner.findings()
