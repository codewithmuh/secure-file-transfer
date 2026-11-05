"""The built-in detectors that look at one unit at a time ([DLP] section 4).

Numbers first: digit runs with their separators, checked against each detector's format, check digit
and context. Then phone numbers, emails, IBANs, Japanese passports and confidentiality labels. The
detectors that span lines or units (credentials, private keys, machine-readable zones) are in
`credentials` and `blocks`.

Every preview is masked here, as section 7 says, before the hit reaches the scanner.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

import phonenumbers

from sft.dlp.detect import checks
from sft.dlp.detect.normalise import keyword_term
from sft.dlp.detect.prepared import HIGH, LOW, MEDIUM, Hit, Keywords, Prepared
from sft.dlp.detect.regex import Regex
from sft.dlp.detect.tlds import TLDS

MY_NUMBER = "jp_my_number"
CORPORATE_NUMBER = "jp_corporate_number"
PAYMENT_CARD = "payment_card"
BANK_ACCOUNT = "jp_bank_account"
IBAN = "iban"
PHONE_NUMBER = "phone_number"
EMAIL_ADDRESS = "email_address"
PASSPORT = "jp_passport"
DRIVERS_LICENCE = "jp_drivers_licence"
CONFIDENTIALITY_LABEL = "confidentiality_label"

# Context keywords, in English and Japanese ([DLP] 4).
MY_NUMBER_CONTEXT = Keywords(
    ("マイナンバー", "個人番号", "番号カード", "My Number", "MyNumber", "Individual Number")
)
CORPORATE_CONTEXT = Keywords(("法人番号", "会社法人等番号", "Corporate Number"))
CARD_CONTEXT = Keywords(
    (
        *("カード番号", "クレジット", "有効期限", "セキュリティコード"),
        *("card number", "credit card", "expiry", "expiration", "exp date", "CVV", "CVC"),
    )
)
BANK_CONTEXT = Keywords(
    (
        *("口座番号", "口座", "普通", "当座", "預金", "支店", "ゆうちょ", "記号"),
        *("account number", "account no", "bank account"),
    )
)
JAPAN_POST_CONTEXT = Keywords(("ゆうちょ", "郵便貯金", "記号", "Japan Post Bank"))
IBAN_CONTEXT = Keywords(("IBAN", "口座", "account"))
PHONE_CONTEXT = Keywords(
    ("電話", "TEL", "携帯", "連絡先", "FAX", "phone", "mobile", "cell", "telephone")
)
PASSPORT_CONTEXT = Keywords(("旅券", "旅券番号", "パスポート", "passport"))
# The keyword view turns a typographic apostrophe into "'", so "driver's" covers both.
LICENCE_CONTEXT = Keywords(
    (
        *("運転免許", "免許証番号", "免許番号", "driver's licence", "driver's license"),
        *("drivers licence", "drivers license", "driving licence"),
    )
)

CONFIDENTIALITY_LABELS = (
    "社外秘", "部外秘", "関係者外秘", "極秘", "機密", "秘密", "取扱注意",
    "Confidential", "Strictly Confidential", "Internal Use Only", "Do Not Distribute",
)  # fmt: skip

_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

# A digit run: digits, with single hyphens, dots or spaces between groups.
_DIGIT_RUN = Regex(r"[0-9]+(?:[-. ][0-9]+)*")
_PHONE_MAX_PARTS = 7  # "+33 6 12 34 56 78" has six; bounds the work on a long run of spaced numbers
_PHONE = Regex(r"[+(]?[0-9][0-9() .-]*[0-9]\)?")
_EXPIRY = Regex(r"(?:^|[^0-9/])(?:0[1-9]|1[0-2]) ?/ ?(?:20[0-9]{2}|[0-9]{2})(?:[^0-9/]|$)")
_JAPAN_POST_KEYWORDS = Regex(r"記号[ :]*(1[0-9]{4})[ ,、]*番号[ :]*([0-9]{1,8})")
_EMAIL = Regex(
    r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
)
_EMAIL_LOCAL = frozenset("!#$%&'*+/=?^_`{|}~-.") | _ALNUM
_IBAN = Regex(r"[A-Z]{2}[0-9]{2}(?:(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,4})?|[A-Z0-9]{11,30})")
_PASSPORT = Regex(r"[A-Za-z]{2}[0-9]{7}")

_CARD_GROUPINGS = frozenset({(4, 4, 4, 4), (4, 6, 5), (4, 6, 4), (4, 4, 4, 4, 3)})


def _boundary_ok(text: str, start: int, end: int) -> bool:
    """A number doesn't run on into an ASCII letter or digit, directly or through a separator."""
    if start > 0:
        before = text[start - 1]
        if before in _ALNUM or (before in "-." and start > 1 and text[start - 2] in _ALNUM):
            return False
    if end < len(text):
        after = text[end]
        if after in _ALNUM or (after in "-." and end + 1 < len(text) and text[end + 1] in _ALNUM):
            return False
    return True


@dataclass(frozen=True, slots=True)
class _Number:
    """A candidate number: its span, its digit groups and the one separator between them."""

    start: int
    end: int
    groups: tuple[str, ...]
    separator: str | None  # "" when there is one group; None when the separators are mixed

    @property
    def digits(self) -> str:
        return "".join(self.groups)

    @property
    def grouping(self) -> tuple[int, ...]:
        return tuple(len(group) for group in self.groups)

    @property
    def plain(self) -> bool:
        return len(self.groups) == 1


def _number(text: str, start: int, end: int) -> _Number:
    groups: list[str] = []
    separators: set[str] = set()
    current = ""
    for char in text[start:end]:
        if char.isdigit():
            current += char
        else:
            separators.add(char)
            groups.append(current)
            current = ""
    groups.append(current)
    separator = "" if not separators else (separators.pop() if len(separators) == 1 else None)
    return _Number(start, end, tuple(groups), separator)


def _candidates(text: str, start: int, end: int) -> list[_Number]:
    """Readings of a digit run, longest first.

    A run with spaces can hold a number beside another, or a year after it ("4111 ... 1111 12/29").
    So after the whole run come the runs with up to two space-separated parts dropped at either end,
    then each part alone.
    """
    whole = _number(text, start, end)
    if " " not in text[start:end]:
        return [whole]
    spans: list[tuple[int, int]] = []
    offset = start
    for chunk in text[start:end].split(" "):
        spans.append((offset, offset + len(chunk)))
        offset += len(chunk) + 1
    count = len(spans)
    readings = {(spans[0][0], spans[-1][1])}
    for head in range(3):
        for tail in range(3):
            if head + tail < count:
                readings.add((spans[head][0], spans[count - 1 - tail][1]))
    readings.update(spans)
    ordered = sorted(readings, key=lambda span: (span[0] - span[1], span[0]))
    return [_number(text, a, b) for a, b in ordered]


def _uniform(number: _Number, separators: str = "- ") -> bool:
    return number.separator is not None and number.separator in separators


def _my_number(unit: Prepared, number: _Number) -> Hit | None:
    if number.grouping not in {(12,), (4, 4, 4)} or not _uniform(number):
        return None
    if not checks.is_my_number(number.digits):
        return None
    if unit.has_context(number.start, number.end, MY_NUMBER_CONTEXT):
        confidence = HIGH
    else:
        confidence = MEDIUM if number.grouping == (4, 4, 4) else LOW
    return Hit(MY_NUMBER, confidence, number.digits, "12 digits, check digit valid")


def _corporate_number(unit: Prepared, number: _Number) -> Hit | None:
    if number.grouping not in {(13,), (1, 4, 4, 4)} or not _uniform(number):
        return None
    if not checks.is_corporate_number(number.digits):
        return None
    context = unit.has_context(number.start, number.end, CORPORATE_CONTEXT)
    return Hit(
        CORPORATE_NUMBER, HIGH if context else LOW, number.digits, "*" * 9 + number.digits[-4:]
    )


def _payment_card(unit: Prepared, number: _Number) -> Hit | None:
    digits = number.digits
    if not 13 <= len(digits) <= 19 or not _uniform(number):
        return None
    if not number.plain and number.grouping not in _CARD_GROUPINGS:
        return None
    network = checks.card_network(digits)
    if network is None or not checks.luhn_ok(digits):
        return None
    if unit.has_context(number.start, number.end, CARD_CONTEXT) or (
        _EXPIRY.search(unit.window(number.start, number.end)) is not None
    ):
        confidence = HIGH
    else:
        confidence = LOW if number.plain else MEDIUM
    return Hit(PAYMENT_CARD, confidence, digits, f"{network} ****{digits[-4:]}")


def _bank_account(unit: Prepared, number: _Number) -> Hit | None:
    if number.grouping == (7,):
        if unit.has_context(number.start, number.end, BANK_CONTEXT):
            return Hit(BANK_ACCOUNT, MEDIUM, number.digits, "****" + number.digits[-3:])
        return None
    grouping = number.grouping
    if (
        len(grouping) == 2
        and grouping[0] == 5
        and grouping[1] <= 8
        and number.groups[0][0] == "1"
        and _uniform(number)
        and unit.has_context(number.start, number.end, JAPAN_POST_CONTEXT)
    ):
        return Hit(BANK_ACCOUNT, MEDIUM, number.digits, "***" + number.digits[-3:])
    return None


def _drivers_licence(unit: Prepared, number: _Number) -> Hit | None:
    if number.grouping not in {(12,), (4, 4, 4)} or not _uniform(number):
        return None
    digits = number.digits
    if int(digits[:2]) not in checks.LICENCE_COMMISSIONS:
        return None
    if not unit.has_context(number.start, number.end, LICENCE_CONTEXT):
        return None
    confidence = HIGH if checks.licence_check_ok(digits) else MEDIUM
    return Hit(DRIVERS_LICENCE, confidence, digits, "*" * 9 + digits[-3:])


_NUMBER_DETECTORS = (_my_number, _corporate_number, _payment_card, _bank_account, _drivers_licence)


def _numbers(unit: Prepared) -> Iterator[Hit]:
    text = unit.text
    # Japan Post Bank accounts written with their keywords: 記号 NNNNN 番号 NNNNNNNN.
    taken: list[tuple[int, int]] = []
    for span in _JAPAN_POST_KEYWORDS.finditer(text):
        symbol, account = span.groups
        if symbol is not None and account is not None:
            taken.append((span.start, span.end))
            value = symbol + account
            yield Hit(BANK_ACCOUNT, MEDIUM, value, "***" + value[-3:])
    for span in _DIGIT_RUN.finditer(text):
        if any(start <= span.start < end for start, end in taken):
            continue
        # Each part of a run belongs to one reading: the longest that some detector accepts.
        accepted: list[tuple[int, int]] = []
        for candidate in _candidates(text, span.start, span.end):
            if any(a < candidate.end and candidate.start < b for a, b in accepted):
                continue
            if not _boundary_ok(text, candidate.start, candidate.end):
                continue
            hits = [hit for detector in _NUMBER_DETECTORS if (hit := detector(unit, candidate))]
            if hits:
                accepted.append((candidate.start, candidate.end))
                yield from hits


def _phone_candidate(unit: Prepared, start: int, end: int) -> Hit | None:
    raw = unit.text[start:end]
    digits = "".join(char for char in raw if char.isdigit())
    if raw.startswith("+"):
        if not 8 <= len(digits) <= 15:
            return None
        region = None
    elif digits.startswith("0") and len(digits) in (10, 11):
        region = "JP"
    else:
        return None
    try:
        parsed = phonenumbers.parse(raw, region)
    except phonenumbers.NumberParseException:
        return None
    if not phonenumbers.is_valid_number(parsed):
        return None
    if unit.has_context(start, end, PHONE_CONTEXT):
        confidence = HIGH
    elif any(char in raw for char in "-(+"):
        confidence = MEDIUM
    else:
        confidence = LOW
    value = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    return Hit(PHONE_NUMBER, confidence, value, f"+{parsed.country_code} ****{digits[-4:]}")


def _phones(unit: Prepared) -> Iterator[Hit]:
    text = unit.text
    for span in _PHONE.finditer(text):
        start, end = span.start, span.end
        if not _boundary_ok(text, start, end) or (start > 0 and text[start - 1] == "+"):
            continue
        # Try the whole candidate, then the longest run of its space-separated parts that validates.
        chunks = text[start:end].split(" ")
        index = 0
        offset = start
        while index < len(chunks):
            for stop in range(min(len(chunks), index + _PHONE_MAX_PARTS), index, -1):
                length = len(" ".join(chunks[index:stop]))
                hit = _phone_candidate(unit, offset, offset + length)
                if hit is not None:
                    yield hit
                    offset += length + 1
                    index = stop
                    break
            else:
                offset += len(chunks[index]) + 1
                index += 1


def _emails(unit: Prepared) -> Iterator[Hit]:
    text = unit.text
    for span in _EMAIL.finditer(text):
        if span.start > 0 and text[span.start - 1] in _EMAIL_LOCAL:
            continue
        local, domain = text[span.start : span.end].split("@", 1)
        labels = domain.split(".")
        # The domain runs on into the next sentence ("example.com.Next"): drop labels until a TLD
        # ends it.
        while len(labels) >= 2 and labels[-1].lower() not in TLDS:
            labels.pop()
        if len(labels) < 2 or len(".".join(labels)) > 253:
            continue
        domain = ".".join(labels).lower()
        yield Hit(EMAIL_ADDRESS, HIGH, f"{local}@{domain}".lower(), f"{local[0]}***@{domain}"[:64])


def _ibans(unit: Prepared) -> Iterator[Hit]:
    text = unit.text
    for span in _IBAN.finditer(text):
        raw = text[span.start : span.end]
        groups = raw.split(" ")
        expected = checks.IBAN_LENGTHS.get(raw[:2])
        if expected is None:
            continue
        # Grouped in fours, the last group may be followed by an unrelated word: take the groups
        # that add up to the country's length.
        compact = ""
        taken = 0
        for group in groups:
            compact += group
            taken += 1
            if len(compact) >= expected:
                break
        end = span.start + len(" ".join(groups[:taken]))
        if len(compact) != expected or not _boundary_ok(text, span.start, end):
            continue
        if not checks.iban_ok(compact):
            continue
        grouped = len(groups) > 1
        context = grouped or unit.has_context(span.start, end, IBAN_CONTEXT)
        preview = compact[:2] + "*" * (len(compact) - 6) + compact[-4:]
        yield Hit(IBAN, HIGH if context else MEDIUM, compact, preview)


def _passports(unit: Prepared) -> Iterator[Hit]:
    text = unit.text
    for span in _PASSPORT.finditer(text):
        if not _boundary_ok(text, span.start, span.end):
            continue
        if unit.has_context(span.start, span.end, PASSPORT_CONTEXT):
            value = text[span.start : span.end].upper()
            yield Hit(PASSPORT, MEDIUM, value, "******" + value[-3:])


_LABEL_TERMS = tuple(
    sorted(
        ((keyword_term(label), label) for label in CONFIDENTIALITY_LABELS), key=lambda t: -len(t[0])
    )
)
# What may sit around a label that stands alone: spaces, brackets, dashes and other marks.
_DECORATION = frozenset(
    " \t\r\u3000[](){}<>\u3010\u3011\u3014\u3015\u300c\u300d\u300e\u300f\u300a\u300b\u3008\u3009"
    "-\u2013\u2014_*#=~|/\\:;.,\u30fb\u2605\u2606\u25a0\u25a1\u25c6\u25c7\u25cf\u25cb\u203b'\"!"
)


def _ascii_word_at(view: str, start: int, end: int) -> bool:
    return (start == 0 or view[start - 1] not in _ALNUM) and (
        end == len(view) or view[end] not in _ALNUM
    )


def _labels(unit: Prepared) -> Iterator[Hit]:
    """Confidentiality marks: medium when the line or cell holds only marks, low inside running
    text.
    """
    for line in unit.view.replace("\t", "\n").split("\n"):
        if not line:
            continue
        rest = line
        found: list[str] = []
        for term, label in _LABEL_TERMS:
            position = rest.find(term)
            while position >= 0:
                end = position + len(term)
                if term.isascii() and not _ascii_word_at(rest, position, end):
                    position = rest.find(term, position + 1)
                    continue
                found.append(label)
                rest = rest[:position] + "\0" * len(term) + rest[end:]
                position = rest.find(term, end)
        if not found:
            continue
        alone = all(char in _DECORATION or char == "\0" for char in rest)
        for label in found:
            yield Hit(CONFIDENTIALITY_LABEL, MEDIUM if alone else LOW, keyword_term(label), label)


def detect(unit: Prepared) -> Iterator[Hit]:
    """Every single-unit built-in detector over one unit."""
    yield from _numbers(unit)
    yield from _phones(unit)
    yield from _emails(unit)
    yield from _ibans(unit)
    yield from _passports(unit)
    yield from _labels(unit)
