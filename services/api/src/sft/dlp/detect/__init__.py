"""DLP detectors (ADR-0022, [DLP] = docs/design/dlp-detectors.md): pure code, no I/O.

The inspector's child process makes one scanner per file and feeds it the text units extraction
yields; the API calls `inspect_text` on a transfer's message (FR-50). Findings hold the detector,
distinct-value counts at each confidence, at most 10 location hints and at most 3 masked previews:
never a matched value (FR-53, NFR-26).

    scanner = new_scanner(tenant_detectors)
    for unit in units:
        scanner.feed(unit)
    findings = scanner.findings()

`DETECTORS_VERSION` changes with any change to a built-in detector or its data (issuer ranges, TLDs,
credential patterns, the bank and branch code list); it is part of the inspection engine version
each file records ([DLP] 9). The code list's part is its retrieval date, `banks-none` while none is
bundled (`bank_codes`).
"""

from sft.dlp.detect import bank_codes
from sft.dlp.detect.blocks import PASSPORT_MRZ, PRIVATE_KEY
from sft.dlp.detect.builtin import (
    BANK_ACCOUNT,
    CONFIDENTIALITY_LABEL,
    CORPORATE_NUMBER,
    DRIVERS_LICENCE,
    EMAIL_ADDRESS,
    IBAN,
    MY_NUMBER,
    PASSPORT,
    PAYMENT_CARD,
    PHONE_NUMBER,
)
from sft.dlp.detect.credentials import CLOUD_CREDENTIAL
from sft.dlp.detect.scanner import Scanner, TrialMatch, inspect_text, new_scanner, try_detectors
from sft.dlp.detect.tenant import DetectorError, validate
from sft.dlp.units import (
    CUSTOM_PREFIX,
    Cell,
    Confidence,
    Finding,
    KeywordList,
    Pattern,
    TenantDetector,
    TextUnit,
)

DETECTORS_VERSION = f"2.banks-{bank_codes.load().version}"

BUILTIN_DETECTORS = frozenset(
    {
        MY_NUMBER,
        CORPORATE_NUMBER,
        PAYMENT_CARD,
        BANK_ACCOUNT,
        IBAN,
        PHONE_NUMBER,
        EMAIL_ADDRESS,
        PASSPORT,
        PASSPORT_MRZ,
        DRIVERS_LICENCE,
        CLOUD_CREDENTIAL,
        PRIVATE_KEY,
        CONFIDENTIALITY_LABEL,
    }
)

__all__ = [
    "BUILTIN_DETECTORS",
    "CUSTOM_PREFIX",
    "DETECTORS_VERSION",
    "Cell",
    "Confidence",
    "DetectorError",
    "Finding",
    "KeywordList",
    "Pattern",
    "Scanner",
    "TenantDetector",
    "TextUnit",
    "TrialMatch",
    "inspect_text",
    "new_scanner",
    "try_detectors",
    "validate",
]
