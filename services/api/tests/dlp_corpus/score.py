"""Precision and recall on the synthetic corpus, per detector and layout ([DLP] section 8, NFR-25).

Matching is by distinct value per document, exactly: the scorer gives each document its own scanner
and compares the scanner's keyed digests with the digests of the labelled values. Output holds
detectors, layouts, documents and counts, never a value.

- Precision at a confidence: reported values at or above it that are labelled values of that
  detector, over all reported values at or above it.
- Recall at a confidence: labelled values at or above it that were reported at or above it, over the
  labelled values at or above it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from sft.dlp.detect.scanner import _Scanner
from sft.dlp.units import Confidence, TenantDetector

from .generate import BANK_CODES, KEYWORD_LIST_ID, Document

LEVEL: dict[Confidence, int] = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True, slots=True)
class Target:
    confidence: Confidence
    precision: float
    recall: float
    low_recall: float | None = None  # check-digit identifiers: recall at low, too


# NFR-25 and [DLP] section 8, at the confidence the default rules use.
TARGETS: dict[str, Target] = {
    "jp_my_number": Target("high", 0.99, 0.99, 0.99),
    "jp_corporate_number": Target("high", 0.99, 0.99, 0.99),
    "payment_card": Target("high", 0.99, 0.99, 0.99),
    "iban": Target("medium", 0.99, 0.99, 0.99),
    "passport_mrz": Target("high", 0.99, 0.99, 0.99),
    "cloud_credential": Target("medium", 0.99, 0.99),
    "private_key": Target("high", 0.99, 0.99),
    "phone_number": Target("medium", 0.97, 0.95),
    "email_address": Target("high", 0.97, 0.95),
    "jp_bank_account": Target("medium", 0.90, 0.90),
    "jp_passport": Target("medium", 0.90, 0.90),
    "jp_drivers_licence": Target("medium", 0.90, 0.90),
    "confidentiality_label": Target("medium", 1.0, 1.0),
    "custom:" + KEYWORD_LIST_ID: Target("medium", 1.0, 1.0),
}


@dataclass(slots=True)
class Score:
    reported: int = 0  # values reported at or above the target confidence
    reported_true: int = 0  # ... that are labelled values
    labelled: int = 0  # labelled values at or above the target confidence
    found: int = 0  # ... reported at or above it
    labelled_any: int = 0  # every labelled value
    found_low: int = 0  # ... reported at any confidence
    misses: list[str] = field(default_factory=list)  # document names
    false_positives: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.reported_true / self.reported if self.reported else 1.0

    @property
    def recall(self) -> float:
        return self.found / self.labelled if self.labelled else 1.0

    @property
    def low_recall(self) -> float:
        return self.found_low / self.labelled_any if self.labelled_any else 1.0


# Their previews are the term that matched, by design ([DLP] 7): the tenant's own list, or a mark.
_PREVIEW_IS_THE_TERM = frozenset({"confidentiality_label", "custom:" + KEYWORD_LIST_ID})


def score(
    corpus: Sequence[Document],
    tenant: Sequence[TenantDetector],
    leaks: list[str] | None = None,
) -> dict[tuple[str, str], Score]:
    """Scores keyed by (detector, layout). Every document counts for every detector's precision.

    If `leaks` is given, it gets the name of every document whose findings show a labelled value.
    """
    scores: dict[tuple[str, str], Score] = {}
    for document in corpus:
        scanner = _Scanner(tenant, BANK_CODES)
        for unit in document.units:
            scanner.feed(unit)
        # Ends the file as every caller does: the findings also count what was still waiting.
        findings = scanner.findings()
        if leaks is not None:
            shown = repr(findings)
            if any(
                e.value in shown
                for e in document.expected
                if e.detector not in _PREVIEW_IS_THE_TERM
            ):
                leaks.append(document.name)
        tallies = scanner._tallies
        for detector, target in TARGETS.items():
            threshold = LEVEL[target.confidence]
            labelled = {
                scanner._digest(e.value): LEVEL[e.confidence]
                for e in document.expected
                if e.detector == detector
            }
            tally = tallies.get(detector)
            reported = tally.values if tally is not None else {}
            if not labelled and not reported:
                continue
            entry = scores.setdefault((detector, document.layout), Score())
            for digest, confidence in reported.items():
                if confidence >= threshold:
                    entry.reported += 1
                    if digest in labelled:
                        entry.reported_true += 1
                    elif len(entry.false_positives) < 10:
                        entry.false_positives.append(document.name)
            for digest, confidence in labelled.items():
                entry.labelled_any += 1
                if digest in reported:
                    entry.found_low += 1
                if confidence >= threshold:
                    entry.labelled += 1
                    if reported.get(digest, -1) >= threshold:
                        entry.found += 1
                    elif len(entry.misses) < 10:
                        entry.misses.append(document.name)
    return scores


def failures(scores: dict[tuple[str, str], Score]) -> list[str]:
    """One line per detector and layout below its target."""
    out = []
    for (detector, layout), entry in sorted(scores.items()):
        target = TARGETS[detector]
        problems = []
        if entry.precision < target.precision:
            problems.append(f"precision {entry.precision:.4f} < {target.precision}")
        if entry.recall < target.recall:
            problems.append(f"recall {entry.recall:.4f} < {target.recall}")
        if target.low_recall is not None and entry.low_recall < target.low_recall:
            problems.append(f"recall at low {entry.low_recall:.4f} < {target.low_recall}")
        if problems:
            out.append(
                f"{detector} ({layout}): {', '.join(problems)}; "
                f"missed in {entry.misses[:5]}, false positives in {entry.false_positives[:5]}"
            )
    return out


def table(scores: dict[tuple[str, str], Score]) -> str:
    """The per-detector table a release publishes: counts and ratios only."""
    lines = [
        f"{'detector':32} {'layout':6} {'at':6} {'reported':>8} {'precision':>9} "
        f"{'labelled':>8} {'recall':>7} {'recall@low':>10}"
    ]
    for (detector, layout), entry in sorted(scores.items()):
        target = TARGETS[detector]
        lines.append(
            f"{detector:32} {layout:6} {target.confidence:6} {entry.reported:8} "
            f"{entry.precision:9.4f} {entry.labelled:8} {entry.recall:7.4f} "
            f"{entry.low_recall:10.4f}"
        )
    return "\n".join(lines)
