"""A stub of the detector library (sft.dlp.detect, DLP-1) for the inspector's tests.

It finds `TOKEN-<digits>` and nothing else, counts distinct tokens at high confidence, and keeps
the first 10 locations, as the real library does. Run as a script, it is the inspector's child
process with this stub as its engine (`python -I tests/dlp_stub.py INPUT SCRATCH`), so a test can
run the whole sandbox without the real detectors. Self-contained: under `-I` the tests directory
isn't on the path.
"""

from __future__ import annotations

import re
import sys
from collections.abc import Sequence

from sft.dlp.engine import Engine
from sft.dlp.units import CUSTOM_PREFIX, Finding, KeywordList, TenantDetector, TextUnit

TOKEN = re.compile(r"TOKEN-\d+")
BUILTIN = frozenset({"stub_token"})


class StubScanner:
    def __init__(self, tenant: Sequence[TenantDetector] = ()) -> None:
        self.units: list[TextUnit] = []
        self._values: dict[str, set[str]] = {}
        self._locations: dict[str, list[str]] = {}
        self._keywords = [d for d in tenant if isinstance(d, KeywordList)]
        for detector in tenant:
            if detector.id == "invalid":
                raise ValueError("invalid tenant detector")

    def _hit(self, detector: str, value: str, location: str) -> None:
        self._values.setdefault(detector, set()).add(value)
        locations = self._locations.setdefault(detector, [])
        if len(locations) < 10 and location not in locations:
            locations.append(location)

    def feed(self, unit: TextUnit) -> None:
        if "RAISE-IN-DETECTOR" in unit.text:
            raise RuntimeError("detector bug")
        if "SPIN-IN-DETECTOR" in unit.text:
            while True:
                pass
        self.units.append(unit)
        for match in TOKEN.finditer(unit.text):
            self._hit("stub_token", match.group(0), unit.location)
        for keywords in self._keywords:
            for term in keywords.terms:
                if term in unit.text:
                    self._hit(CUSTOM_PREFIX + keywords.id, term, unit.location)

    def budget_exceeded(self) -> list[str]:
        return []

    def findings(self) -> list[Finding]:
        return [
            Finding(
                detector=detector,
                counts={"low": 0, "medium": 0, "high": len(values)},
                locations=tuple(self._locations[detector]),
                previews=("masked",),
            )
            for detector, values in sorted(self._values.items())
        ]


ENGINE = Engine(new_scanner=StubScanner, builtin_detectors=BUILTIN, detectors_version="stub.1")

if __name__ == "__main__":
    from sft.dlp import child

    sys.exit(child.main(engine=ENGINE))
