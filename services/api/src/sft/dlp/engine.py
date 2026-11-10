"""The detector library as the inspector uses it: a pluggable call (ADR-0022).

`sft.dlp.detect` (DLP-1) provides `new_scanner`, `BUILTIN_DETECTORS` and `DETECTORS_VERSION`. The
inspector loads it by name, so the sandbox and the extraction code don't depend on the detectors'
internals, and tests run the whole inspector with a stub.
"""

from __future__ import annotations

import importlib
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final, Protocol, cast

from sft.dlp.extract import EXTRACT_VERSION
from sft.dlp.units import Finding, TenantDetector, TextUnit

DETECTORS_MODULE: Final = "sft.dlp.detect"

_VERSION_CHARS: Final = re.compile(r"[^A-Za-z0-9._-]")


class Scanner(Protocol):
    """One file's detectors: fed unit by unit, asked for findings once."""

    def feed(self, unit: TextUnit) -> None: ...

    def findings(self) -> list[Finding]: ...

    def budget_exceeded(self) -> list[str]:
        """The tenant patterns stopped on this file for spending their scan-time budget."""
        ...


NewScanner = Callable[[Sequence[TenantDetector]], Scanner]


@dataclass(frozen=True, slots=True)
class Engine:
    new_scanner: NewScanner
    builtin_detectors: frozenset[str]
    detectors_version: str

    @property
    def version(self) -> str:
        """The inspection engine version recorded on each file ([detectors] 9)."""
        detectors = _VERSION_CHARS.sub("-", self.detectors_version)[:40] or "0"
        return f"x{EXTRACT_VERSION}+d{detectors}"


class EngineUnavailableError(Exception):
    """The detector library can't be loaded: the inspector can't inspect."""


def load_engine(module: str = DETECTORS_MODULE) -> Engine:
    try:
        detect = importlib.import_module(module)
        new_scanner = cast(NewScanner, detect.new_scanner)
        builtin = frozenset(cast(frozenset[str], detect.BUILTIN_DETECTORS))
        version = str(detect.DETECTORS_VERSION)
    except (ImportError, AttributeError, ValueError) as exc:
        # ValueError: data the detectors load at import is malformed, such as a damaged bank and
        # branch code list (BankCodeError). The inspector stops at start rather than inspect
        # without it.
        raise EngineUnavailableError(f"{module}: {type(exc).__name__}") from None
    return Engine(new_scanner=new_scanner, builtin_detectors=builtin, detectors_version=version)
