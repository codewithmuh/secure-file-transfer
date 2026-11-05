"""Check digits and other validators of the built-in detectors ([DLP] section 4). Pure functions on
digits.

Each takes the value with its separators removed, and says whether the value passes its check. None
of them raises on a value of the wrong shape: it just fails.
"""

from __future__ import annotations

import base64
import binascii
import zlib

# My Number ([DLP] 4.1): P(n) is the n-th of the first 11 digits counting from the right, Q(n) = n +
# 1 for n from 1 to 6 and n - 5 for n from 7 to 11.
_MY_NUMBER_WEIGHTS = tuple(n + 1 if n <= 6 else n - 5 for n in range(1, 12))


def my_number_check_digit(first_11: str) -> int:
    remainder = sum(int(first_11[-n]) * _MY_NUMBER_WEIGHTS[n - 1] for n in range(1, 12)) % 11
    return 0 if remainder <= 1 else 11 - remainder


def is_my_number(digits: str) -> bool:
    return (
        len(digits) == 12
        and digits.isascii()
        and digits.isdigit()
        and (my_number_check_digit(digits[:11]) == int(digits[11]))
    )


def corporate_number_check_digit(base_12: str) -> int:
    """The National Tax Agency's method ([DLP] 4.2): base digits numbered from the right, n = 1 to
    12.
    """
    odd = sum(int(base_12[-n]) for n in range(1, 13, 2))
    even = sum(int(base_12[-n]) for n in range(2, 13, 2))
    return 9 - (even * 2 + odd) % 9


def is_corporate_number(digits: str) -> bool:
    """13 digits whose first is the check digit of the other 12."""
    return (
        len(digits) == 13
        and digits.isascii()
        and digits.isdigit()
        and (corporate_number_check_digit(digits[1:]) == int(digits[0]))
    )


def luhn_ok(digits: str) -> bool:
    if not (digits.isascii() and digits.isdigit()) or len(digits) < 2:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


# Issuer ranges and the lengths each uses ([DLP] 4.3): (first, last) prefixes of the same length, a
# network name, and the allowed lengths. Data, reviewed at each release; a change raises
# DETECTORS_VERSION.
_CARD_RANGES: tuple[tuple[str, str, str, frozenset[int]], ...] = (
    ("4", "4", "Visa", frozenset({13, 16, 19})),
    ("51", "55", "Mastercard", frozenset({16})),
    ("2221", "2720", "Mastercard", frozenset({16})),
    ("34", "34", "American Express", frozenset({15})),
    ("37", "37", "American Express", frozenset({15})),
    ("3528", "3589", "JCB", frozenset(range(16, 20))),
    ("36", "36", "Diners Club", frozenset(range(14, 20))),
    ("300", "305", "Diners Club", frozenset(range(14, 20))),
    ("38", "39", "Diners Club", frozenset(range(14, 20))),
    ("6011", "6011", "Discover", frozenset(range(16, 20))),
    ("644", "649", "Discover", frozenset(range(16, 20))),
    ("65", "65", "Discover", frozenset(range(16, 20))),
    ("62", "62", "UnionPay", frozenset(range(16, 20))),
)


def card_network(digits: str) -> str | None:
    """The network whose issuer range and lengths the number fits, or None."""
    for first, last, network, lengths in _CARD_RANGES:
        prefix = digits[: len(first)]
        if first <= prefix <= last and len(digits) in lengths:
            return network
    return None


# IBAN lengths by country, from the SWIFT IBAN registry (ISO 13616). Data, reviewed at each release.
IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22,
    "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HN": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28,
    "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22,
    "MK": 19, "MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
    "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
    "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}  # fmt: skip


def iban_ok(compact: str) -> bool:
    """ISO 13616: the country's length, and mod 97 = 1 with the first four characters moved to the
    end.
    """
    if (
        not compact.isascii()
        or not compact.isalnum()
        or IBAN_LENGTHS.get(compact[:2]) != len(compact)
    ):
        return False
    if not compact[2:4].isdigit():
        return False
    rearranged = compact[4:] + compact[:4]
    number = "".join(str(int(char, 36)) for char in rearranged)
    return int(number) % 97 == 1


def mrz_check_digit(field: str) -> int:
    """ICAO 9303 ([DLP] 4.6): weights 7, 3, 1; 0-9 as themselves, A-Z as 10-35, '<' as 0."""
    total = 0
    for index, char in enumerate(field):
        value = 0 if char == "<" else int(char, 36)
        total += value * (7, 3, 1)[index % 3]
    return total % 10


def _mrz_digit_ok(field: str, check: str) -> bool:
    return check.isdigit() and mrz_check_digit(field) == int(check)


def mrz_line_2_ok(line: str) -> bool:
    """The TD3 second line's document number, birth date, expiry date and composite check digits
    hold.
    """
    if len(line) != 44:
        return False
    return (
        _mrz_digit_ok(line[0:9], line[9])
        and _mrz_digit_ok(line[13:19], line[19])
        and _mrz_digit_ok(line[21:27], line[27])
        and _mrz_digit_ok(line[0:10] + line[13:20] + line[21:43], line[43])
    )


# Prefectural public safety commission codes, the first two digits of a driver's licence number
# ([DLP] 4.7).
LICENCE_COMMISSIONS = frozenset(
    {
        10,
        11,
        12,
        13,
        14,
        20,
        21,
        22,
        23,
        24,
        25,
        30,
        40,
        41,
        42,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        51,
        52,
    }
    | {
        53,
        54,
        55,
        60,
        61,
        62,
        63,
        64,
        65,
        70,
        71,
        72,
        73,
        74,
        80,
        81,
        82,
        83,
        90,
        91,
        92,
        93,
        94,
        95,
    }
    | {96, 97}
)
_LICENCE_WEIGHTS = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)


def licence_check_digit(first_10: str) -> int:
    """The commonly documented rule; unpublished, so it only raises confidence ([DLP] 4.7)."""
    remainder = sum(int(d) * w for d, w in zip(first_10, _LICENCE_WEIGHTS, strict=True)) % 11
    return 0 if remainder <= 1 else 11 - remainder


def licence_check_ok(digits: str) -> bool:
    return licence_check_digit(digits[:10]) == int(digits[10])


BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def crc32_base62(text: str) -> str:
    """CRC-32 of the text, in 6 base62 characters, zero-padded: the checksum of GitHub tokens and
    our API keys.
    """
    value = zlib.crc32(text.encode())
    out = ""
    while value:
        value, digit = divmod(value, 62)
        out = BASE62[digit] + out
    return out.rjust(6, "0")


def decode_base64(body: str) -> bytes | None:
    """Strict base64 with the whitespace removed, or None if it doesn't decode."""
    compact = "".join(body.split())
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
