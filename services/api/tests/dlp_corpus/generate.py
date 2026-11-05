"""The synthetic labelled DLP corpus ([DLP] section 8, NFR-25): generated from a fixed seed, never
committed.

Every value is random and attached to no person. Identifiers are made to pass their checks (that is
the point of a positive), so nothing here is written to the repository: the corpus exists in memory
while the tests run. Names, companies and places in the surrounding text come from fixed lists of
obviously fictional entries.

The corpus has three parts, as section 8 says:

- **positives** for each built-in detector: values that pass their checks; plain, grouped, in
  full-width digits and with IME dashes; with and without context; in running text and in table
  columns under a header; in English and Japanese text. Each carries its expected detector,
  canonical value and confidence.
- **hard negatives**: the same shapes with a wrong check digit, product codes, order numbers, dates,
  postal codes, versions and IP addresses, digit runs that are too long, Luhn failures, hashes and
  UUIDs near "key", and words that contain a confidentiality mark. Nothing is expected.
- **keywords**: a tenant keyword list's terms in full-width and half-width forms, both cases, split
  by line breaks between CJK characters, and ASCII terms inside longer words that must not match.

Rendering the documents into file formats (CSV in CP932, `.xlsx`, `.docx`, PDF, zips) is the
extraction tests' part (#99): each document is a list of text units, as extraction yields them.

Run it to see the corpus's shape (counts only, never values):

    uv run python -m tests.dlp_corpus.generate --seed 25 --scale 1 --score
"""

from __future__ import annotations

import argparse
import base64
import random
import string
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field

import phonenumbers

from sft.dlp.detect import checks
from sft.dlp.detect.normalise import keyword_term
from sft.dlp.units import Cell, Confidence, KeywordList, TextUnit

DEFAULT_SEED = 25
"""NFR-25."""

KEYWORD_LIST_ID = "corpus-keywords"


@dataclass(frozen=True, slots=True)
class Expected:
    """A labelled value: what the detector must find, and the confidence it must reach."""

    detector: str
    value: str = field(repr=False)
    confidence: Confidence


@dataclass(frozen=True, slots=True)
class Document:
    """One labelled document. `name` holds the detector, part, form and a number: never a value."""

    name: str
    part: str  # positives, hard_negatives, keywords
    detector: str
    layout: str  # text, lines, table
    units: tuple[TextUnit, ...]
    expected: tuple[Expected, ...] = ()


# Obviously fictional surroundings.
NAMES_JA = ("見本 太郎", "試験 花子", "架空 次郎", "例示 三郎", "仮名 葉子")
NAMES_EN = ("Taro Sample", "Hanako Example", "Jiro Fictional", "Demo Person", "Test User")
COMPANIES = (
    "株式会社サンプル商事",
    "架空工業株式会社",
    "Example Trading Ltd.",
    "Fictional Works Inc.",
)
PLACES = ("架空県見本市", "試験町", "Sampleton", "Exampleville")
DEPARTMENTS = ("営業部", "総務部", "開発部", "Sales", "Operations")
FILLER_JA = (
    "いつもお世話になっております。",
    "以下のとおりご確認ください。",
    "詳細は担当者までお問い合わせください。",
    "本件について、来週までにご回答をお願いします。",
    "添付の資料をご参照ください。",
)
FILLER_EN = (
    "Please find the details below.",
    "Let us know if anything needs to change.",
    "This was prepared for the quarterly review.",
    "Thanks for your help with this.",
    "See the attached notes for background.",
)

IME_DASHES = tuple(chr(c) for c in (0x30FC, 0x2212, 0x2010, 0x2013, 0x2014, 0xFF70, 0xFF0D, 0x2011))
"""Dashes IMEs type between digits: the prolonged sound mark, minus, hyphens and dashes."""
_FULL_WIDTH = {code: code + 0xFEE0 for code in range(0x21, 0x7F)} | {0x20: 0x3000}


def full_width(text: str) -> str:
    return text.translate(_FULL_WIDTH)


def _digits(rng: random.Random, count: int) -> str:
    return "".join(rng.choice(string.digits) for _ in range(count))


def _wrong_digit(rng: random.Random, right: int) -> str:
    return str(rng.choice([d for d in range(10) if d != right]))


# ---- Values. Each maker returns a value that passes its checks, unless asked for one that fails.
# ----


def my_number(rng: random.Random, valid: bool = True) -> str:
    base = _digits(rng, 11)
    check = checks.my_number_check_digit(base)
    return base + (str(check) if valid else _wrong_digit(rng, check))


def corporate_number(rng: random.Random, valid: bool = True) -> str:
    base = _digits(rng, 12)
    check = checks.corporate_number_check_digit(base)
    return (str(check) if valid else _wrong_digit(rng, check)) + base


def _luhn_digit(partial: str) -> int:
    for digit in range(10):
        if checks.luhn_ok(partial + str(digit)):
            return digit
    raise AssertionError("unreachable")


CARD_NETWORKS: dict[str, tuple[tuple[str, ...], tuple[int, ...]]] = {
    "Visa": (("4",), (13, 16, 19)),
    "Mastercard": (("51", "53", "55", "2221", "2720"), (16,)),
    "American Express": (("34", "37"), (15,)),
    "JCB": (("3528", "3550", "3589"), (16, 19)),
    "Diners Club": (("36", "300", "305", "38"), (14, 16)),
    "Discover": (("6011", "644", "65"), (16,)),
    "UnionPay": (("62",), (16, 19)),
}


def card_number(
    rng: random.Random, network: str, valid: bool = True, length: int | None = None
) -> str:
    prefixes, lengths = CARD_NETWORKS[network]
    prefix = rng.choice(prefixes)
    length = length or rng.choice(lengths)
    partial = prefix + _digits(rng, length - len(prefix) - 1)
    check = _luhn_digit(partial)
    return partial + (str(check) if valid else _wrong_digit(rng, check))


IBAN_SHAPES = {"DE": "n18", "GB": "a4n14", "FR": "n23", "NL": "a4n10", "ES": "n20", "IT": "a1n22"}


def iban(rng: random.Random, country: str, valid: bool = True) -> str:
    shape = IBAN_SHAPES[country]
    letters = int(shape[1]) if shape[0] == "a" else 0
    numbers = int(shape.split("n")[1])
    bban = "".join(rng.choice(string.ascii_uppercase) for _ in range(letters)) + _digits(
        rng, numbers
    )
    numeric = "".join(str(int(char, 36)) for char in bban + country + "00")
    check = 98 - int(numeric) % 97
    if not valid:
        check = (check + rng.randint(1, 50)) % 97 + 2
    return f"{country}{check:02d}{bban}"


def group_iban(value: str) -> str:
    return " ".join(value[i : i + 4] for i in range(0, len(value), 4))


_PHONE_REGIONS = ("US", "GB", "DE", "AU", "KR", "SG", "FR")
_PHONE_TYPES = (phonenumbers.PhoneNumberType.MOBILE, phonenumbers.PhoneNumberType.FIXED_LINE)


def _random_number(rng: random.Random, region: str) -> phonenumbers.PhoneNumber:
    while True:
        example = phonenumbers.example_number_for_type(region, rng.choice(_PHONE_TYPES))
        assert example is not None
        national = str(example.national_number)
        candidate = national[:-4] + _digits(rng, 4)
        number = phonenumbers.parse("+" + str(example.country_code) + candidate, None)
        if phonenumbers.is_valid_number(number):
            return number


_JP_SHAPES = ("90", "80", "70", "3", "6", "45", "52", "50", "120", "800")


def jp_phone(rng: random.Random) -> phonenumbers.PhoneNumber:
    while True:
        prefix = rng.choice(_JP_SHAPES)
        length = {"120": 6, "800": 7, "45": 7, "52": 7}.get(prefix, 8)
        number = phonenumbers.parse("+81" + prefix + _digits(rng, length), None)
        if phonenumbers.is_valid_number(number):
            return number


def e164(number: phonenumbers.PhoneNumber) -> str:
    return phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.E164)


LOCAL_PARTS = (
    "sample.user",
    "test.taro",
    "example.hanako",
    "demo",
    "info",
    "no-reply",
    "t_example",
)
DOMAINS = ("example.com", "example.org", "example.net", "example.co.jp", "test.example.jp")


def email(rng: random.Random) -> str:
    return f"{rng.choice(LOCAL_PARTS)}{rng.randint(1, 9999)}@{rng.choice(DOMAINS)}"


def jp_passport(rng: random.Random) -> str:
    return rng.choice(("TR", "TK", "TZ", "MU", "ME")) + _digits(rng, 7)


def _mrz_field(value: str, length: int) -> str:
    return (value + "<" * length)[:length]


def mrz(rng: random.Random, valid: bool = True) -> tuple[str, str]:
    country = rng.choice(("JPN", "GBR", "DEU", "FRA", "UTO"))
    surname, given = rng.choice((("SAMPLE", "TARO"), ("EXAMPLE", "HANAKO"), ("TEST", "PERSON")))
    line_1 = _mrz_field(f"P<{country}{surname}<<{given}", 44)
    document = rng.choice(("TR", "TK", "XA", "MZ")) + _digits(rng, 7)
    birth = f"{rng.randint(50, 99)}{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}"
    expiry = f"{rng.randint(27, 35)}{rng.randint(1, 12):02d}{rng.randint(1, 28):02d}"
    personal = "<" * 14
    part_1 = document + str(checks.mrz_check_digit(document))
    part_2 = birth + str(checks.mrz_check_digit(birth))
    part_3 = expiry + str(checks.mrz_check_digit(expiry))
    personal_check = str(checks.mrz_check_digit(personal))
    line_2 = f"{part_1}{country}{part_2}{rng.choice('MF')}{part_3}{personal}{personal_check}"
    composite = checks.mrz_check_digit(line_2[0:10] + line_2[13:20] + line_2[21:43])
    line_2 += str(composite) if valid else _wrong_digit(rng, composite)
    return line_1, line_2


def licence(rng: random.Random, check_ok: bool = True, commission_ok: bool = True) -> str:
    while True:
        if commission_ok:
            code = rng.choice(sorted(checks.LICENCE_COMMISSIONS))
        else:
            code = rng.choice((15, 16, 26, 35, 58, 75, 88, 99))
        first_10 = f"{code:02d}{_digits(rng, 8)}"
        check = checks.licence_check_digit(first_10)
        if check == 10:
            continue
        value = first_10 + (str(check) if check_ok else _wrong_digit(rng, check)) + _digits(rng, 1)
        # A licence number that also passes the My Number check is real-world noise; keep the labels
        # clean.
        if not checks.is_my_number(value):
            return value


_BASE32 = string.ascii_uppercase + "234567"
_BASE62 = string.digits + string.ascii_letters
_BASE64 = string.ascii_letters + string.digits + "+/"


def aws_key_id(rng: random.Random) -> str:
    return rng.choice(("AKIA", "ASIA")) + "".join(rng.choice(_BASE32) for _ in range(16))


def aws_secret(rng: random.Random) -> str:
    while True:
        value = "".join(rng.choice(_BASE64) for _ in range(40))
        if (
            any(c.isupper() for c in value)
            and any(c.islower() for c in value)
            and any(c.isdigit() for c in value)
        ):
            return value


def github_token(rng: random.Random, valid: bool = True) -> str:
    body = "".join(rng.choice(_BASE62) for _ in range(30))
    check = checks.crc32_base62(body)
    if not valid:
        check = check[:-1] + ("A" if check[-1] != "A" else "B")
    return rng.choice(("ghp_", "gho_", "ghu_", "ghs_", "ghr_")) + body + check


def github_pat(rng: random.Random) -> str:
    first = "".join(rng.choice(_BASE62) for _ in range(22))
    second = "".join(rng.choice(_BASE62) for _ in range(59))
    return f"github_pat_{first}_{second}"


def sft_api_key(rng: random.Random, valid: bool = True) -> str:
    head = f"sft_{rng.choice(('dev', 'stg', 'prd'))}_" + "".join(
        rng.choice(_BASE62) for _ in range(43)
    )
    check = checks.crc32_base62(head)
    if not valid:
        check = check[:-1] + ("A" if check[-1] != "A" else "B")
    return f"{head}_{check}"


def azure_connection(rng: random.Random) -> tuple[str, str]:
    account = f"sample{rng.randint(100, 999)}"
    key = base64.b64encode(rng.randbytes(64)).decode()
    text = (
        f"DefaultEndpointsProtocol=https;AccountName={account};AccountKey={key};"
        "EndpointSuffix=core.windows.net"
    )
    return text, account.lower() + ";" + key


_PRIVATE = "PRIVATE " + "KEY"
PEM_LABELS = ("RSA ", "EC ", "DSA ", "", "ENCRYPTED ", "OPENSSH ")


def _wrap(text: str, width: int) -> list[str]:
    return [text[i : i + width] for i in range(0, len(text), width)]


def private_key_lines(rng: random.Random, label: str, valid: bool = True) -> tuple[list[str], str]:
    """A fake PEM block's lines, and its canonical value (the decoded body in hex)."""
    if label == "OPENSSH ":
        body = b"openssh-key-v1\x00" + rng.randbytes(rng.randint(180, 400))
    else:
        body = b"\x30\x82" + rng.randbytes(rng.randint(120, 600))
    if not valid:
        body = b"\x04" + body[1:]
    encoded = base64.b64encode(body).decode()
    lines = [
        f"-----BEGIN {label}{_PRIVATE}-----",
        *_wrap(encoded, 64),
        f"-----END {label}{_PRIVATE}-----",
    ]
    return lines, body.hex()


LEGACY_CIPHERS = {"AES-128-CBC": 16, "AES-256-CBC": 16, "DES-EDE3-CBC": 8}


def legacy_encrypted_key_lines(
    rng: random.Random, label: str, cipher: str = "AES-128-CBC", valid: bool = True
) -> tuple[list[str], str]:
    """A fake PEM block encrypted the old OpenSSL way (Proc-Type and DEK-Info headers), and its
    canonical value. The body is random bytes, as ciphertext looks: a whole number of cipher blocks,
    or one byte short when `valid` is false.
    """
    block = LEGACY_CIPHERS[cipher]
    body = rng.randbytes(block * rng.randint(8, 40) - (0 if valid else 1))
    lines = [
        f"-----BEGIN {label}{_PRIVATE}-----",
        "Proc-Type: 4,ENCRYPTED",
        f"DEK-Info: {cipher},{rng.randbytes(block).hex().upper()}",
        "",
        *_wrap(base64.b64encode(body).decode(), 64),
        f"-----END {label}{_PRIVATE}-----",
    ]
    return lines, body.hex()


def pgp_key_lines(rng: random.Random) -> tuple[list[str], str]:
    body = bytes([0x95]) + rng.randbytes(rng.randint(200, 500))
    encoded = base64.b64encode(body).decode()
    checksum = "=" + base64.b64encode(rng.randbytes(3)).decode()
    label = "PGP " + _PRIVATE + " BLOCK"
    lines = [f"-----BEGIN {label}-----", "Version: Sample 1.0", "", *_wrap(encoded, 64)]
    return [*lines, checksum, f"-----END {label}-----"], body.hex()


def putty_key_lines(rng: random.Random) -> tuple[list[str], str]:
    public = base64.b64encode(rng.randbytes(51)).decode()
    private = rng.randbytes(rng.randint(30, 90))
    private_lines = _wrap(base64.b64encode(private).decode(), 64)
    lines = [
        f"PuTTY-User-Key-File-{rng.choice('23')}: ssh-ed25519",
        "Encryption: none",
        "Comment: sample-key",
        "Public-Lines: 2",
        public[:40],
        public[40:],
        f"Private-Lines: {len(private_lines)}",
        *private_lines,
        "Private-MAC: " + rng.randbytes(32).hex(),
    ]
    return lines, private.hex()


# ---- Documents. ----


def _text(
    name: str, part: str, detector: str, lines: list[str], expected: list[Expected]
) -> Document:
    units = tuple(TextUnit(f"line {index + 1}", line) for index, line in enumerate(lines))
    return Document(name, part, detector, "text", units, tuple(expected))


def _block(name: str, part: str, detector: str, text: str, expected: list[Expected]) -> Document:
    """One unit holding several lines, as a paragraph or a PDF page is extracted."""
    units = (TextUnit("page 1", text),)
    return Document(name, part, detector, "lines", units, tuple(expected))


def _row(location: str, values: list[str], headers: list[str]) -> TextUnit:
    cells: list[Cell] = []
    offset = 0
    for value, header in zip(values, headers, strict=True):
        cells.append(Cell(offset, offset + len(value), header))
        offset += len(value) + 1
    return TextUnit(location, "\t".join(values), tuple(cells))


def _table(
    name: str,
    part: str,
    detector: str,
    headers: list[str],
    rows: list[list[str]],
    expected: list[Expected],
) -> Document:
    sheet = "顧客一覧"
    units = [_row(f'sheet "{sheet}", row 1', headers, [""] * len(headers))]
    for index, row in enumerate(rows):
        units.append(_row(f'sheet "{sheet}", row {index + 2}', row, headers))
    return Document(name, part, detector, "table", tuple(units), tuple(expected))


def _grouped(value: str, sizes: tuple[int, ...], separator: str) -> str:
    out, start = [], 0
    for size in sizes:
        out.append(value[start : start + size])
        start += size
    return separator.join(out)


@dataclass(frozen=True, slots=True)
class _Form:
    """How a value is written: its text, and whether it was grouped."""

    text: str
    grouped: bool
    tag: str


def _number_form(rng: random.Random, value: str, sizes: tuple[int, ...]) -> _Form:
    """Plain, grouped with hyphens or spaces, full-width, or with an IME dash."""
    choice = rng.randrange(6)
    if choice == 0:
        return _Form(value, False, "plain")
    if choice == 1:
        return _Form(full_width(value), False, "full-width")
    if choice == 2:
        return _Form(_grouped(value, sizes, "-"), True, "hyphen")
    if choice == 3:
        return _Form(_grouped(value, sizes, " "), True, "space")
    if choice == 4:
        return _Form(_grouped(value, sizes, rng.choice(IME_DASHES)), True, "ime-dash")
    return _Form(full_width(_grouped(value, sizes, "-")), True, "full-width-grouped")


def _sentence(rng: random.Random, template: str, value: str) -> str:
    """A template with {v}, {name}, {company} and {place}, between filler sentences."""
    text = template.format(
        v=value,
        name=rng.choice(NAMES_JA + NAMES_EN),
        company=rng.choice(COMPANIES),
        place=rng.choice(PLACES),
    )
    filler = FILLER_JA if any(ord(c) > 0x3000 for c in template) else FILLER_EN
    before = rng.choice(filler) + " " if rng.random() < 0.5 else ""
    after = " " + rng.choice(filler) if rng.random() < 0.5 else ""
    return before + text + after


_FAR = "(この段落は制度の一般的な説明であり、特定の個人や取引を指すものではありません。)"
"""Over 40 characters, so a keyword before it is out of a value's context window."""


@dataclass(frozen=True, slots=True)
class _NumberSpec:
    detector: str
    make: Callable[[random.Random], str]
    sizes: tuple[int, ...]
    context_ja: tuple[str, ...]
    context_en: tuple[str, ...]
    plain_ja: tuple[str, ...]
    plain_en: tuple[str, ...]
    header: str
    plain_header: str
    # The confidence for (context, grouped): a function of both.
    confidence: Callable[[bool, bool], Confidence | None]


def _check_digit_confidence(context: bool, grouped: bool) -> Confidence:
    if context:
        return "high"
    return "medium" if grouped else "low"


def _number_positives(rng: random.Random, spec: _NumberSpec, count: int) -> list[Document]:
    docs: list[Document] = []
    for index in range(count):
        layout = rng.choice(("text", "text", "table"))
        context = rng.random() < 0.7
        values = [spec.make(rng) for _ in range(rng.randint(1, 3))]
        forms = [_number_form(rng, value, spec.sizes) for value in values]
        expected = []
        for value, form in zip(values, forms, strict=True):
            confidence = spec.confidence(context, form.grouped)
            if confidence is not None:
                expected.append(Expected(spec.detector, value, confidence))
        tag = f"{'context' if context else 'no-context'}-{forms[0].tag}"
        name = f"{spec.detector}/positives/{layout}-{tag}/{index:05d}"
        if layout == "table":
            header = spec.header if context else spec.plain_header
            rows = [[rng.choice(NAMES_JA), form.text, rng.choice(DEPARTMENTS)] for form in forms]
            docs.append(
                _table(name, "positives", spec.detector, ["氏名", header, "部署"], rows, expected)
            )
            continue
        lines = []
        for form in forms:
            if context:
                template = rng.choice(spec.context_ja + spec.context_en)
            else:
                template = rng.choice(spec.plain_ja + spec.plain_en)
                if rng.random() < 0.2 and spec.context_ja:
                    # The keyword appears, but further than 40 characters away: no context.
                    template = spec.context_ja[0].split("{v}")[0] + _FAR + " {v}"
            lines.append(_sentence(rng, template, form.text))
        docs.append(_text(name, "positives", spec.detector, lines, expected))
    return docs


MY_NUMBER_SPEC = _NumberSpec(
    detector="jp_my_number",
    make=my_number,
    sizes=(4, 4, 4),
    context_ja=(
        "{name}様のマイナンバー(個人番号)は{v}です。",
        "個人番号: {v}",
        "マイナンバー {v}",
    ),
    context_en=("My Number: {v}", "Individual Number {v} is on file for {name}."),
    plain_ja=("参照コード {v} を確認してください。", "受付 {v}"),
    plain_en=("Reference {v} was logged.", "Ticket {v} for {company}"),
    header="マイナンバー",
    plain_header="コード",
    confidence=_check_digit_confidence,
)

CORPORATE_SPEC = _NumberSpec(
    detector="jp_corporate_number",
    make=corporate_number,
    sizes=(1, 4, 4, 4),
    context_ja=("{company}の法人番号は{v}です。", "会社法人等番号 {v}"),
    context_en=("Corporate Number: {v} ({company})",),
    plain_ja=("管理コード {v}",),
    plain_en=("Record {v} for {company}",),
    header="法人番号",
    plain_header="管理コード",
    confidence=lambda context, grouped: "high" if context else "low",
)

LICENCE_SPEC = _NumberSpec(
    detector="jp_drivers_licence",
    make=licence,
    sizes=(4, 4, 4),
    context_ja=("運転免許証番号 第{v}号", "免許番号: {v}"),
    context_en=("Driver's licence No. {v}", "Driver" + chr(0x2019) + "s license {v} ({name})"),
    plain_ja=("番号 {v}",),
    plain_en=("No. {v}",),
    header="免許証番号",
    plain_header="番号",
    confidence=lambda context, grouped: "high" if context else None,
)


def _card_positives(rng: random.Random, count: int) -> list[Document]:
    groupings = {13: None, 14: (4, 6, 4), 15: (4, 6, 5), 16: (4, 4, 4, 4), 19: (4, 4, 4, 4, 3)}
    docs = []
    for index in range(count):
        network = rng.choice(sorted(CARD_NETWORKS))
        value = card_number(rng, network)
        sizes = groupings.get(len(value))
        mode = rng.choice(("context", "expiry", "none"))
        choice = rng.randrange(4) if sizes else 0
        separator = rng.choice(("-", " ", rng.choice(IME_DASHES)))
        text = value if choice == 0 else _grouped(value, sizes or (), separator)
        if choice == 3:
            text = full_width(text)
        grouped = choice != 0
        if mode == "none":
            confidence: Confidence = "medium" if grouped else "low"
        else:
            confidence = "high"
        expiry = f"{rng.randint(1, 12):02d}/{rng.randint(27, 34)}"
        template = {
            "context": rng.choice(
                ("カード番号: {v}", "Credit card {v} on file.", "card number {v}")
            ),
            "expiry": rng.choice(("{v} exp " + expiry, "{v}  " + expiry)),
            "none": rng.choice(("Ref {v}", "照会 {v} を処理しました。")),
        }[mode]
        layout = "table" if rng.random() < 0.25 else "text"
        shape = "grouped" if grouped else "plain"
        name = f"payment_card/positives/{layout}-{mode}-{shape}/{index:05d}"
        expected = [Expected("payment_card", value, confidence)]
        if layout == "table":
            header = "カード番号" if mode != "none" else "照会番号"
            if mode == "expiry":
                header = "番号"
                confidence = "medium" if grouped else "low"
                expected = [Expected("payment_card", value, confidence)]
            row = [rng.choice(NAMES_JA), text, rng.choice(DEPARTMENTS)]
            docs.append(
                _table(name, "positives", "payment_card", ["氏名", header, "部署"], [row], expected)
            )
        else:
            docs.append(
                _text(name, "positives", "payment_card", [_sentence(rng, template, text)], expected)
            )
    return docs


def _bank_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    for index in range(count):
        kind = rng.choice(("ordinary", "ordinary", "japan-post", "japan-post-keywords", "table"))
        if kind == "ordinary":
            value = _digits(rng, 7)
            template = rng.choice(
                (
                    "{company} 架空銀行 見本支店 普通 {v}",
                    "振込先: 当座 口座番号 {v}",
                    "Bank account: account number {v}",
                    "普通預金 {v} {name}",
                )
            )
            text = _sentence(rng, template, value if rng.random() < 0.7 else full_width(value))
            expected = [Expected("jp_bank_account", value, "medium")]
            name = f"jp_bank_account/positives/text-{kind}/{index:05d}"
            docs.append(_text(name, "positives", "jp_bank_account", [text], expected))
        elif kind == "japan-post":
            symbol, number = "1" + _digits(rng, 4), _digits(rng, 7) + "1"
            text = _sentence(rng, "ゆうちょ銀行 {v} {name}", f"{symbol}-{number}")
            expected = [Expected("jp_bank_account", symbol + number, "medium")]
            name = f"jp_bank_account/positives/text-{kind}/{index:05d}"
            docs.append(_text(name, "positives", "jp_bank_account", [text], expected))
        elif kind == "japan-post-keywords":
            symbol, number = "1" + _digits(rng, 4), _digits(rng, 7) + "1"
            text = f"ゆうちょ 記号 {symbol} 番号 {number}"
            expected = [Expected("jp_bank_account", symbol + number, "medium")]
            name = f"jp_bank_account/positives/text-{kind}/{index:05d}"
            docs.append(_text(name, "positives", "jp_bank_account", [text], expected))
        else:
            values = [_digits(rng, 7) for _ in range(rng.randint(1, 3))]
            rows = [[rng.choice(NAMES_JA), "見本支店", value] for value in values]
            expected = [Expected("jp_bank_account", value, "medium") for value in values]
            name = f"jp_bank_account/positives/table/{index:05d}"
            docs.append(
                _table(
                    name,
                    "positives",
                    "jp_bank_account",
                    ["名義", "支店", "口座番号"],
                    rows,
                    expected,
                )
            )
    return docs


def _iban_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    for index in range(count):
        value = iban(rng, rng.choice(sorted(IBAN_SHAPES)))
        grouped = rng.random() < 0.5
        context = rng.random() < 0.5
        text = group_iban(value) if grouped else value
        template = "IBAN: {v}" if context else rng.choice(("Ref {v}", "送金先 {v}"))
        confidence: Confidence = "high" if grouped or context else "medium"
        name = f"iban/positives/text-{'grouped' if grouped else 'compact'}/{index:05d}"
        expected = [Expected("iban", value, confidence)]
        docs.append(_text(name, "positives", "iban", [_sentence(rng, template, text)], expected))
    return docs


def _phone_text(
    rng: random.Random, number: phonenumbers.PhoneNumber, japanese: bool
) -> tuple[str, bool]:
    """A written form of the number, and whether it is formatted (hyphens, parentheses, +)."""
    international = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    if not japanese:
        return international, True
    national = phonenumbers.format_number(number, phonenumbers.PhoneNumberFormat.NATIONAL)
    choice = rng.randrange(6)
    if choice == 0:
        return national, True
    if choice == 1:
        return international, True
    if choice == 2:
        area, _, rest = national.partition("-")
        return f"({area}) {rest}", True
    if choice == 3:
        return full_width(national), True
    if choice == 4:
        return national.replace("-", rng.choice(IME_DASHES)), True
    return national.replace("-", ""), False


def _phone_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    for index in range(count):
        japanese = rng.random() < 0.75
        number = jp_phone(rng) if japanese else _random_number(rng, rng.choice(_PHONE_REGIONS))
        text, formatted = _phone_text(rng, number, japanese)
        context = rng.random() < 0.6
        if context:
            template = rng.choice(("電話: {v}", "TEL {v}", "携帯 {v}", "Phone: {v}", "連絡先 {v}"))
            confidence: Confidence = "high"
        else:
            template = rng.choice(("{name} {v}", "{company} {v} 見本", "Ask {name} at {v}."))
            confidence = "medium" if formatted else "low"
        layout = "table" if rng.random() < 0.2 else "text"
        name = (
            f"phone_number/positives/{layout}-{'context' if context else 'no-context'}/{index:05d}"
        )
        expected = [Expected("phone_number", e164(number), confidence)]
        if layout == "table":
            header = "電話番号" if context else "備考"
            row = [rng.choice(NAMES_JA), text]
            docs.append(
                _table(name, "positives", "phone_number", ["氏名", header], [row], expected)
            )
        else:
            docs.append(
                _text(name, "positives", "phone_number", [_sentence(rng, template, text)], expected)
            )
    return docs


def _email_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    for index in range(count):
        values = [email(rng) for _ in range(rng.randint(1, 3))]
        written = [v.upper() if rng.random() < 0.1 else v for v in values]
        templates = (
            "連絡先は{v}までお願いします。",
            "Email: <{v}>",
            "mailto:{v}",
            "{name} ({v})",
            "{v}",
        )
        lines = [_sentence(rng, rng.choice(templates), w) for w in written]
        layout = "table" if rng.random() < 0.2 else "text"
        expected = [Expected("email_address", v.lower(), "high") for v in values]
        name = f"email_address/positives/{layout}/{index:05d}"
        if layout == "table":
            rows = [[rng.choice(NAMES_JA), w] for w in written]
            docs.append(
                _table(name, "positives", "email_address", ["氏名", "メール"], rows, expected)
            )
        else:
            docs.append(_text(name, "positives", "email_address", lines, expected))
    return docs


def _passport_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    for index in range(count):
        value = jp_passport(rng)
        layout = "table" if rng.random() < 0.25 else "text"
        expected = [Expected("jp_passport", value, "medium")]
        name = f"jp_passport/positives/{layout}/{index:05d}"
        if layout == "table":
            row = [rng.choice(NAMES_JA), value]
            docs.append(
                _table(name, "positives", "jp_passport", ["氏名", "旅券番号"], [row], expected)
            )
        else:
            template = rng.choice(
                ("旅券番号 {v}", "パスポート番号: {v}", "Passport No. {v}", "passport {v}")
            )
            docs.append(
                _text(name, "positives", "jp_passport", [_sentence(rng, template, value)], expected)
            )
    return docs


def _mrz_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    for index in range(count):
        line_1, line_2 = mrz(rng)
        expected = [Expected("passport_mrz", line_1[2:5] + line_2[0:9], "high")]
        if rng.random() < 0.5:
            name = f"passport_mrz/positives/lines/{index:05d}"
            docs.append(
                _block(
                    name, "positives", "passport_mrz", f"PASSPORT\n{line_1}\n{line_2}\n", expected
                )
            )
        else:
            name = f"passport_mrz/positives/text/{index:05d}"
            docs.append(
                _text(name, "positives", "passport_mrz", ["PASSPORT", line_1, line_2], expected)
            )
    return docs


def _credential_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    detector = "cloud_credential"
    for index in range(count):
        kind = rng.choice(
            (
                "aws-id",
                "aws-pair",
                "aws-file",
                "aws-secret",
                "github",
                "github-pat",
                "sft",
                "azure",
                "gcp",
            )
        )
        name = f"{detector}/positives/{kind}/{index:05d}"
        if kind == "aws-id":
            key_id = aws_key_id(rng)
            lines = [_sentence(rng, rng.choice(("access key id {v}", "キー {v}", "{v}")), key_id)]
            docs.append(
                _text(name, "positives", detector, lines, [Expected(detector, key_id, "medium")])
            )
        elif kind == "aws-pair":
            key_id, secret = aws_key_id(rng), aws_secret(rng)
            lines = [f"export AWS_ACCESS_KEY_ID={key_id} AWS_SECRET_ACCESS_KEY={secret}"]
            docs.append(
                _text(name, "positives", detector, lines, [Expected(detector, key_id, "high")])
            )
        elif kind == "aws-file":
            key_id, secret = aws_key_id(rng), aws_secret(rng)
            lines = [
                "[default]",
                f"aws_access_key_id = {key_id}",
                f"aws_secret_access_key = {secret}",
            ]
            docs.append(
                _text(name, "positives", detector, lines, [Expected(detector, key_id, "high")])
            )
        elif kind == "aws-secret":
            secret = aws_secret(rng)
            template = rng.choice(("aws_secret_access_key: {v}", "シークレットアクセスキー {v}"))
            lines = [_sentence(rng, template, secret)]
            docs.append(
                _text(name, "positives", detector, lines, [Expected(detector, secret, "medium")])
            )
        elif kind == "github":
            token = github_token(rng)
            lines = [_sentence(rng, rng.choice(("token: {v}", "GITHUB_TOKEN={v}", "{v}")), token)]
            docs.append(
                _text(name, "positives", detector, lines, [Expected(detector, token, "high")])
            )
        elif kind == "github-pat":
            token = github_pat(rng)
            lines = [f"GH_TOKEN={token}"]
            docs.append(
                _text(name, "positives", detector, lines, [Expected(detector, token, "medium")])
            )
        elif kind == "sft":
            key = sft_api_key(rng)
            lines = [_sentence(rng, rng.choice(("Authorization: Bearer {v}", "API key {v}")), key)]
            docs.append(
                _text(name, "positives", detector, lines, [Expected(detector, key, "high")])
            )
        elif kind == "azure":
            text, value = azure_connection(rng)
            docs.append(
                _text(name, "positives", detector, [text], [Expected(detector, value, "high")])
            )
        else:
            key_id = rng.randbytes(20).hex()
            pem, key_value = private_key_lines(rng, "")
            client = f"sample-sa@example-project-{rng.randint(100, 999)}.iam.gserviceaccount.com"
            lines = [
                "{",
                '  "type": "service_account",',
                '  "project_id": "example-project",',
                f'  "private_key_id": "{key_id}",',
                '  "private_key": "' + "\\n".join(pem) + '\\n",',
                f'  "client_email": "{client}",',
                "}",
            ]
            expected = [
                Expected(detector, key_id, "high"),
                Expected("private_key", key_value, "high"),
                Expected("email_address", client, "high"),
            ]
            docs.append(_text(name, "positives", detector, lines, expected))
    return docs


def _private_key_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    for index in range(count):
        kind = rng.choice(("pem", "pem", "pem", "legacy", "pgp", "putty"))
        if kind == "pem":
            label = rng.choice(PEM_LABELS)
            lines, value = private_key_lines(rng, label)
        elif kind == "legacy":
            label = rng.choice(("RSA ", "EC ", "DSA "))
            cipher = rng.choice(sorted(LEGACY_CIPHERS))
            lines, value = legacy_encrypted_key_lines(rng, label, cipher)
        elif kind == "pgp":
            lines, value = pgp_key_lines(rng)
        else:
            lines, value = putty_key_lines(rng)
        layout = (
            rng.choice(("text", "lines", "flat"))
            if kind in ("pem", "legacy")
            else rng.choice(("text", "lines"))
        )
        expected = [Expected("private_key", value, "high")]
        name = f"private_key/positives/{kind}-{layout}/{index:05d}"
        if layout == "text":
            docs.append(_text(name, "positives", "private_key", ["key file:", *lines], expected))
        elif layout == "lines":
            docs.append(_block(name, "positives", "private_key", "\n".join(lines), expected))
        else:
            # A PDF text layer flattens the block's line breaks into spaces.
            docs.append(_block(name, "positives", "private_key", " ".join(lines), expected))
    return docs


_ALONE = ("{l}", "【{l}】", "[{l}]", "- {l} -", "★{l}★", "  {l}  ", "{l} / {m}")
_LABEL_EN = ("Confidential", "Strictly Confidential", "Internal Use Only", "Do Not Distribute")
_LABEL_JA = ("社外秘", "部外秘", "関係者外秘", "極秘", "機密", "秘密", "取扱注意")


def _label_positives(rng: random.Random, count: int) -> list[Document]:
    docs = []
    detector = "confidentiality_label"
    for index in range(count):
        label = rng.choice(_LABEL_JA + _LABEL_EN)
        other = rng.choice([x for x in _LABEL_JA + _LABEL_EN if x not in label and label not in x])
        form = rng.choice(_ALONE)
        written = form.format(l=label, m=other)
        if label in _LABEL_EN and rng.random() < 0.4:
            written = written.upper() if rng.random() < 0.5 else written.lower()
        if rng.random() < 0.2:
            written = full_width(written)
        labels = [label, other] if "{m}" in form else [label]
        expected = [Expected(detector, keyword_term(x), "medium") for x in labels]
        where = rng.choice(("line", "header", "footer", "document properties", "cell"))
        name = f"{detector}/positives/{where}/{index:05d}"
        body = rng.choice(FILLER_JA + FILLER_EN)
        if where == "cell":
            docs.append(
                _table(name, "positives", detector, ["区分", "備考"], [[written, body]], expected)
            )
        elif where == "line":
            docs.append(_text(name, "positives", detector, [body, written, body], expected))
        else:
            units = (TextUnit(where, written), TextUnit("paragraph 1", body))
            docs.append(Document(name, "positives", detector, "text", units, tuple(expected)))
        # The same labels inside running text count only at low.
    return docs


# ---- Hard negatives: nothing in them may be reported at the confidence the default rules use. ----


def _uuid(rng: random.Random) -> str:
    raw = rng.randbytes(16).hex()
    return f"{raw[:8]}-{raw[8:12]}-4{raw[13:16]}-a{raw[17:20]}-{raw[20:]}"


def _hard_negatives(rng: random.Random, detector: str, count: int) -> list[Document]:
    makers: dict[str, Callable[[random.Random], list[str]]] = {
        "jp_my_number": lambda r: [
            r.choice(("マイナンバー {v}", "個人番号: {v}", "My Number {v}")).format(
                v=_number_form(r, my_number(r, valid=False), (4, 4, 4)).text
            ),
            f"JAN {_digits(r, 13)} / UPC {_digits(r, 12)}",
            f"マイナンバー {_digits(r, 20)}",
            f"個人番号 {my_number(r)}{_digits(r, 3)}",
        ],
        "jp_corporate_number": lambda r: [
            f"法人番号 {corporate_number(r, valid=False)}",
            f"EAN-13 {_digits(r, 13)} 商品コード",
            f"法人番号 {_digits(r, 16)}",
        ],
        "payment_card": lambda r: [
            f"カード番号 {card_number(r, r.choice(sorted(CARD_NETWORKS)), valid=False)}",
            "Card number " + _grouped(card_number(r, "Visa", False, 16), (4, 4, 4, 4), " "),
            f"注文番号 {_digits(r, 16)} を受け付けました。",
            f"card number 9{_digits(r, 15)}",
        ],
        "jp_bank_account": lambda r: [
            f"社員コード {_digits(r, 7)}",
            f"〒{_digits(r, 3)}-{_digits(r, 4)} {r.choice(PLACES)}",
            f"受付 {_digits(r, 7)} 件",
        ],
        "iban": lambda r: [
            f"IBAN {iban(r, r.choice(sorted(IBAN_SHAPES)), valid=False)}",
            f"Ref DE{_digits(r, 25)}",
            f"Code GB12{_digits(r, 6)}",
        ],
        "phone_number": lambda r: [
            f"注文番号 ORD-{_digits(r, 4)}-{_digits(r, 6)}",
            f"請求書番号 INV{_digits(r, 10)}",
            f"日時 2026-{r.randint(1, 12):02d}-{r.randint(1, 28):02d} {r.randint(0, 23):02d}:30",
            f"version {r.randint(1, 20)}.{r.randint(0, 9)}.{_digits(r, 5)}.{_digits(r, 4)}",
            f"IP 192.168.{r.randint(0, 255)}.{r.randint(0, 255)}",
            f"Serial 01{_digits(r, 14)}",
            f"Tel +1 555 {_digits(r, 2)}",
        ],
        "email_address": lambda r: [
            "user@localhost を参照",
            f"pkg@{r.randint(1, 9)}.{r.randint(0, 9)}.{r.randint(0, 9)}",
            "@sample_handle をフォロー",
            f"name@example.invalidtld{r.randint(1, 9)}",
        ],
        "jp_passport": lambda r: [
            f"品番 {jp_passport(r)}",
            f"Passport No. {jp_passport(r)}{_digits(r, 1)}",
            f"Model {jp_passport(r)} shipped",
        ],
        "passport_mrz": lambda r: list(mrz(r, valid=False)),
        "jp_drivers_licence": lambda r: [
            f"運転免許証番号 {licence(r, commission_ok=False)}",
            f"管理番号 {licence(r)}",
            f"免許番号 {_digits(r, 14)}",
        ],
        "cloud_credential": lambda r: [
            f"key: {r.randbytes(20).hex()}",
            f"api key {_uuid(r)}",
            f"key = {base64.b64encode(r.randbytes(30)).decode()}",
            f"aws_secret_access_key = {r.randbytes(20).hex()}",
            f"token {github_token(r, valid=False)}",
            f"sft key {sft_api_key(r, valid=False)}",
            f"AKIA{''.join(r.choice(_BASE32) for _ in range(14))}",
            f"sha256 {r.randbytes(32).hex()}",
        ],
        "private_key": lambda r: [
            "-----BEGIN PUBLIC KEY-----",
            base64.b64encode(r.randbytes(48)).decode(),
            "-----END PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----",
            base64.b64encode(r.randbytes(48)).decode(),
            "-----END CERTIFICATE-----",
            f"-----BEGIN {_PRIVATE}-----",
            "this is not base64 !!",
            f"-----END {_PRIVATE}-----",
            *private_key_lines(r, "RSA ", valid=False)[0],
        ],
        "confidentiality_label": lambda r: [
            "機密性の高い情報の取り扱いについて",
            "機密保持契約書",
            "秘密鍵の管理手順",
            "The confidentiality agreement is attached.",
            "This document is confidential and should not be shared.",
            "本資料は社外秘です。",
            "Confidentially, the plan changed.",
        ],
    }
    docs = []
    for index in range(count):
        lines = makers[detector](rng)
        rng.shuffle(lines) if detector not in ("passport_mrz", "private_key") else None
        layout = "text"
        name = f"{detector}/hard_negatives/{layout}/{index:05d}"
        expected: list[Expected] = []
        if detector == "confidentiality_label":
            # Inside running text a label counts at low only: below what the default rule uses.
            expected = [
                Expected(detector, keyword_term(label), "low")
                for label in ("社外秘",)
                if any("社外秘です" in line for line in lines)
            ]
        docs.append(_text(name, "hard_negatives", detector, lines, expected))
    return docs


# ---- Tenant keywords. ----

KEYWORD_TERMS = (
    "青空計画",
    "サクラ開発",
    "ミカン",
    "極光プロジェクト",
    "Project Falcon",
    "Bluebird",
    "ORION-7",
    "Kestrel",
)
_HALF_WIDTH_KATAKANA = {
    "サ": "ｻ", "ク": "ｸ", "ラ": "ﾗ", "ミ": "ﾐ", "カ": "ｶ", "ン": "ﾝ", "プ": "ﾌﾟ", "ロ": "ﾛ",
    "ジ": "ｼﾞ", "ェ": "ｪ", "ト": "ﾄ",
}  # fmt: skip


def keyword_list() -> KeywordList:
    return KeywordList(KEYWORD_LIST_ID, KEYWORD_TERMS)


def _keyword_form(rng: random.Random, term: str) -> tuple[str, str]:
    cjk = any(ord(c) > 0x3000 for c in term)
    if cjk:
        choice = rng.choice(("exact", "half-width", "line-break", "spaced", "full-width"))
        if choice == "half-width" and any(c in _HALF_WIDTH_KATAKANA for c in term):
            return "".join(_HALF_WIDTH_KATAKANA.get(c, c) for c in term), choice
        if choice == "line-break":
            cut = rng.randint(1, len(term) - 1)
            return term[:cut] + "\n" + term[cut:], choice
        if choice == "spaced":
            cut = rng.randint(1, len(term) - 1)
            return term[:cut] + " " + term[cut:], choice
        if choice == "full-width":
            return full_width(term), choice
        return term, "exact"
    choice = rng.choice(("exact", "upper", "lower", "full-width"))
    if choice == "upper":
        return term.upper(), choice
    if choice == "lower":
        return term.lower(), choice
    if choice == "full-width":
        return full_width(term), choice
    return term, choice


def _keyword_docs(rng: random.Random, count: int) -> list[Document]:
    docs = []
    detector = "custom:" + KEYWORD_LIST_ID
    for index in range(count):
        if rng.random() < 0.2:
            # ASCII terms inside longer words, and nothing else: must not match.
            word = rng.choice(("Falconry", "bluebirds", "KestrelX", "orion-77", "subluebird"))
            text = f"{rng.choice(FILLER_EN)} {word} {rng.choice(FILLER_EN)}"
            name = f"{detector}/keywords/negative/{index:05d}"
            docs.append(_text(name, "keywords", detector, [text], []))
            continue
        term = rng.choice(KEYWORD_TERMS)
        written, form = _keyword_form(rng, term)
        filler = rng.choice(FILLER_JA + FILLER_EN)
        text = f"{filler}{written}について。" if rng.random() < 0.5 else f"{filler} {written}."
        name = f"{detector}/keywords/{form}/{index:05d}"
        expected = [Expected(detector, keyword_term(term), "high")]
        docs.append(_text(name, "keywords", detector, [text], expected))
    return docs


# ---- The corpus. ----

DETECTORS = (
    "jp_my_number",
    "jp_corporate_number",
    "payment_card",
    "jp_bank_account",
    "iban",
    "phone_number",
    "email_address",
    "jp_passport",
    "passport_mrz",
    "jp_drivers_licence",
    "cloud_credential",
    "private_key",
    "confidentiality_label",
)

POSITIVES_PER_DETECTOR = 1000
NEGATIVES_PER_DETECTOR = 400
KEYWORD_DOCUMENTS = 1500


def generate_corpus(seed: int = DEFAULT_SEED, scale: float = 1.0) -> list[Document]:
    """About 20,000 documents at scale 1; the nightly job runs scale 10."""
    rng = random.Random(seed)  # noqa: S311 - reproducible test data, not secrets
    positives = max(1, round(POSITIVES_PER_DETECTOR * scale))
    negatives = max(1, round(NEGATIVES_PER_DETECTOR * scale))
    makers: dict[str, Callable[[random.Random, int], list[Document]]] = {
        "jp_my_number": lambda r, n: _number_positives(r, MY_NUMBER_SPEC, n),
        "jp_corporate_number": lambda r, n: _number_positives(r, CORPORATE_SPEC, n),
        "jp_drivers_licence": lambda r, n: _number_positives(r, LICENCE_SPEC, n),
        "payment_card": _card_positives,
        "jp_bank_account": _bank_positives,
        "iban": _iban_positives,
        "phone_number": _phone_positives,
        "email_address": _email_positives,
        "jp_passport": _passport_positives,
        "passport_mrz": _mrz_positives,
        "cloud_credential": _credential_positives,
        "private_key": _private_key_positives,
        "confidentiality_label": _label_positives,
    }
    corpus: list[Document] = []
    for detector in DETECTORS:
        corpus.extend(makers[detector](rng, positives))
        corpus.extend(_hard_negatives(rng, detector, negatives))
    corpus.extend(_keyword_docs(rng, max(1, round(KEYWORD_DOCUMENTS * scale))))
    return corpus


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--scale", type=float, default=1.0)
    parser.add_argument(
        "--score", action="store_true", help="run the detectors and print the table"
    )
    arguments = parser.parse_args()
    corpus = generate_corpus(arguments.seed, arguments.scale)
    shape = Counter((doc.detector, doc.part) for doc in corpus)
    for (detector, part), count in sorted(shape.items()):
        print(f"{detector:32} {part:16} {count:7}")
    print(f"{'total':49} {len(corpus):7}")
    if arguments.score:
        from .score import failures, score, table  # score imports this module

        scores = score(corpus, [keyword_list()])
        print(table(scores))
        for line in failures(scores):
            print("BELOW TARGET:", line)


if __name__ == "__main__":
    main()
