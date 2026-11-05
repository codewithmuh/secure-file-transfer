"""The DLP detector library (sft.dlp.detect): each detector, normalisation, masking, the scanner.

No literal here passes a check digit or looks like a live credential: values come from the corpus
generator, made at run time (docs/design/dlp-detectors.md section 8).
"""

import base64
import random
from collections.abc import Iterator

import pytest

from dlp_corpus import generate as g
from sft.dlp.detect import (
    BUILTIN_DETECTORS,
    CUSTOM_PREFIX,
    DETECTORS_VERSION,
    Cell,
    DetectorError,
    Finding,
    KeywordList,
    Pattern,
    TextUnit,
    checks,
    inspect_text,
    new_scanner,
    scanner,
    validate,
)
from sft.dlp.detect.normalise import keyword_term, keyword_view, normalise
from sft.dlp.detect.prepared import Hit, Keywords
from sft.dlp.detect.regex import Regex, RegexError, RegexSet


@pytest.fixture
def rng() -> random.Random:
    return random.Random(98)  # noqa: S311 - reproducible test data


def found(
    text: str, detector: str, tenant: tuple[KeywordList | Pattern, ...] = ()
) -> Finding | None:
    return next((f for f in inspect_text(text, tenant) if f.detector == detector), None)


def level(text: str, detector: str) -> str | None:
    """The highest confidence the detector reached on the text, or None."""
    finding = found(text, detector)
    if finding is None:
        return None
    return next(c for c in ("high", "medium", "low") if finding.counts[c])


def scan(*units: TextUnit) -> dict[str, Finding]:
    s = new_scanner()
    for unit in units:
        s.feed(unit)
    return {f.detector: f for f in s.findings()}


def lines(*texts: str) -> Iterator[TextUnit]:
    for index, text in enumerate(texts):
        yield TextUnit(f"line {index + 1}", text)


# ---- Normalisation ----


def test_normalisation_makes_full_width_digits_and_ime_dashes_ascii() -> None:
    written = g.full_width("12") + chr(0x30FC) + g.full_width("3") + chr(0x2212) + g.full_width("4")
    assert normalise(written + "  5") == "12-3-4 5"
    assert normalise("ｻｸﾗ") == "サクラ"
    assert normalise("A　B") == "A B"


def test_the_keyword_view_folds_case_and_joins_cjk_across_line_breaks() -> None:
    assert keyword_view(normalise("青空\n計画 ABC")) == "青空計画 abc"
    assert keyword_view("見本\t試験") == "見本\t試験"  # a cell boundary stays
    assert keyword_view("driver" + chr(0x2019) + "s") == "driver's"
    assert keyword_term(g.full_width("  FALCON ")) == "falcon"


# ---- Check digits ----


def test_check_digit_validators(rng: random.Random) -> None:
    for _ in range(50):
        assert checks.is_my_number(g.my_number(rng))
        assert not checks.is_my_number(g.my_number(rng, valid=False))
        assert checks.is_corporate_number(g.corporate_number(rng))
        assert not checks.is_corporate_number(g.corporate_number(rng, valid=False))
        assert checks.luhn_ok(g.card_number(rng, "Visa"))
        assert not checks.luhn_ok(g.card_number(rng, "Visa", valid=False))
        assert checks.iban_ok(g.iban(rng, "DE"))
        assert not checks.iban_ok(g.iban(rng, "GB", valid=False))
        assert checks.mrz_line_2_ok(g.mrz(rng)[1])
        assert not checks.mrz_line_2_ok(g.mrz(rng, valid=False)[1])
    assert not checks.is_my_number("12345")
    assert not checks.luhn_ok("x")
    assert not checks.iban_ok("ZZ00")
    assert not checks.iban_ok("DEAB" + "0" * 18)
    assert not checks.mrz_line_2_ok("SHORT")
    assert checks.decode_base64("not base64!") is None


def test_card_networks_follow_the_issuer_ranges_and_lengths(rng: random.Random) -> None:
    for network in g.CARD_NETWORKS:
        assert checks.card_network(g.card_number(rng, network)) == network
    assert checks.card_network("9" * 16) is None
    assert checks.card_network("4" + "0" * 14) is None  # Visa has no 15-digit numbers


def test_the_github_checksum_matches_the_published_example() -> None:
    # The example from third-party validators of GitHub's token format: entropy and its checksum.
    assert checks.crc32_base62("zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ") == "0mLq17"


# ---- Numbers ----


def test_my_number_confidence_follows_context_and_grouping(rng: random.Random) -> None:
    value = g.my_number(rng)
    grouped = f"{value[:4]}-{value[4:8]}-{value[8:]}"
    assert level(f"マイナンバー {value}", "jp_my_number") == "high"
    assert level(f"My Number: {g.full_width(grouped)}", "jp_my_number") == "high"
    assert level(f"参照 {grouped}", "jp_my_number") == "medium"
    assert level(f"参照 {value}", "jp_my_number") == "low"
    # The keyword further than 40 characters away is no context.
    assert level(f"マイナンバー{'。' * 45}{value}", "jp_my_number") == "low"
    # Wrong check digit, a longer run, or letters next to it: nothing.
    assert found(f"マイナンバー {g.my_number(rng, valid=False)}", "jp_my_number") is None
    assert found(f"マイナンバー {value}123", "jp_my_number") is None
    assert found(f"マイナンバー A{value}", "jp_my_number") is None
    assert found(f"マイナンバー X-{value}", "jp_my_number") is None


def test_the_preview_of_a_my_number_keeps_nothing_of_it(rng: random.Random) -> None:
    finding = found(f"個人番号 {g.my_number(rng)}", "jp_my_number")
    assert finding is not None
    assert finding.previews == ("12 digits, check digit valid",)


def test_corporate_numbers(rng: random.Random) -> None:
    value = g.corporate_number(rng)
    finding = found(f"法人番号: {value}", "jp_corporate_number")
    assert finding is not None
    assert finding.counts == {"low": 0, "medium": 0, "high": 1}
    assert finding.previews == ("*********" + value[-4:],)
    assert (
        level(f"コード {value[0]}-{value[1:5]}-{value[5:9]}-{value[9:]}", "jp_corporate_number")
        == "low"
    )


def test_payment_cards(rng: random.Random) -> None:
    value = g.card_number(rng, "Mastercard")
    grouped = " ".join(value[i : i + 4] for i in range(0, 16, 4))
    assert level(f"カード番号 {value}", "payment_card") == "high"
    assert level(f"{grouped} 08/29", "payment_card") == "high"  # the expiry date
    assert level(f"{grouped} 2029/08/01", "payment_card") == "medium"  # a date isn't an expiry
    assert level(f"Ref {value}", "payment_card") == "low"
    assert found(f"card number {g.card_number(rng, 'Visa', valid=False)}", "payment_card") is None
    finding = found(f"card number {grouped}", "payment_card")
    assert finding is not None
    assert finding.previews == (f"Mastercard ****{value[-4:]}",)
    # A grouping the networks don't use.
    odd = f"{value[:3]}-{value[3:9]}-{value[9:]}"
    assert found(f"card number {odd}", "payment_card") is None


def test_a_card_run_holds_no_my_number(rng: random.Random) -> None:
    value = g.card_number(rng, "Visa", length=16)
    grouped = " ".join(value[i : i + 4] for i in range(0, 16, 4))
    findings = {f.detector for f in inspect_text(f"マイナンバー カード {grouped}")}
    assert "jp_my_number" not in findings


def test_bank_accounts_need_their_keywords(rng: random.Random) -> None:
    value = g._digits(rng, 7)
    assert level(f"普通 {value}", "jp_bank_account") == "medium"
    assert found(f"社員番号 {value}", "jp_bank_account") is None
    assert (
        level(f"ゆうちょ 1{g._digits(rng, 4)}-{g._digits(rng, 8)}", "jp_bank_account") == "medium"
    )
    assert found(f"1{g._digits(rng, 4)}-{g._digits(rng, 8)}", "jp_bank_account") is None
    finding = found(f"記号 1{g._digits(rng, 4)} 番号 {g._digits(rng, 7)}", "jp_bank_account")
    assert finding is not None
    assert finding.counts["medium"] == 1  # one account, not also a 7-digit one


def test_a_japan_post_number_ends_at_a_digit_boundary(rng: random.Random) -> None:
    # Nine digits after 番号 aren't a Japan Post account, and the run isn't cut to eight.
    symbol = "1" + g._digits(rng, 4)
    assert found(f"記号 {symbol} 番号 {g._digits(rng, 9)}", "jp_bank_account") is None
    # The whole run stays visible to the other detectors.
    my_number = g.my_number(rng)
    findings = {f.detector: f for f in inspect_text(f"マイナンバー 記号 {symbol} 番号 {my_number}")}
    assert "jp_bank_account" not in findings
    assert findings["jp_my_number"].counts["high"] == 1


def test_drivers_licences_need_context_and_rise_with_the_check_digit(rng: random.Random) -> None:
    value = g.licence(rng)
    assert level(f"運転免許証番号 第{value}号", "jp_drivers_licence") == "high"
    assert level(f"免許番号 {g.licence(rng, check_ok=False)}", "jp_drivers_licence") == "medium"
    assert found(value, "jp_drivers_licence") is None
    assert found(f"免許番号 {g.licence(rng, commission_ok=False)}", "jp_drivers_licence") is None


def test_ibans(rng: random.Random) -> None:
    value = g.iban(rng, "NL")
    assert level(f"Ref {value}", "iban") == "medium"
    assert level(f"IBAN {value}", "iban") == "high"
    assert level(f"Ref {g.group_iban(value)} END", "iban") == "high"
    finding = found(f"IBAN {value}", "iban")
    assert finding is not None
    assert finding.previews == (value[:2] + "*" * (len(value) - 6) + value[-4:],)
    assert found(f"IBAN {g.iban(rng, 'NL', valid=False)}", "iban") is None
    assert found("IBAN QQ12 3456 7890 1234", "iban") is None


def test_phone_numbers(rng: random.Random) -> None:
    number = g.jp_phone(rng)
    national = g.phonenumbers.format_number(number, g.phonenumbers.PhoneNumberFormat.NATIONAL)
    bare = national.replace("-", "")
    assert level(f"TEL {bare}", "phone_number") == "high"
    assert level(f"見本 {national}", "phone_number") == "medium"
    assert level(f"見本 {bare}", "phone_number") == "low"
    international = g._random_number(rng, "FR")
    written = g.phonenumbers.format_number(
        international, g.phonenumbers.PhoneNumberFormat.INTERNATIONAL
    )
    finding = found(f"Ask {written} 2026", "phone_number")
    assert finding is not None
    assert finding.previews[0].startswith("+33 ****")
    assert found("Order ORD-2026-000123, 2026-11-04 10:30, 192.168.0.1", "phone_number") is None
    assert found("+1 555 12", "phone_number") is None


def test_ascii_context_keywords_count_only_as_whole_words(rng: random.Random) -> None:
    number = g.jp_phone(rng)
    bare = g.phonenumbers.format_number(number, g.phonenumbers.PhoneNumberFormat.NATIONAL).replace(
        "-", ""
    )
    for inside in ("hotel", "excellent", "headphones", "Intel"):
        assert level(f"{inside} {bare}", "phone_number") == "low", inside
    for word in ("TEL", "Tel:", "TEL.", "phones:", "Cell", "(phone)", "電話", "携帯番号"):
        assert level(f"{word} {bare}", "phone_number") == "high", word
    # A digit may follow an ASCII keyword, and a plural "s"; no other letter may.
    tel = Keywords(("TEL",))
    for view in ("tel03-", "tels:", "(tel)"):
        assert tel.found_in(keyword_view(view)), view
    for view in ("telex", "hotel"):
        assert not tel.found_in(keyword_view(view)), view
    # The credential keywords also count inside identifiers.
    secret = g.aws_secret(rng)
    assert scan(*lines(f"awsSecretAccessKey={secret}"))["cloud_credential"].counts["medium"] == 1


def test_emails(rng: random.Random) -> None:
    finding = found("連絡先はsample.user1@example.co.jpまで。", "email_address")
    assert finding is not None
    assert finding.previews == ("s***@example.co.jp",)
    assert finding.counts["high"] == 1
    assert found("End: a@example.com.Next sentence", "email_address") is not None
    for text in ("user@localhost", "pkg@1.2.3", "@handle", "x@example.invalidtld"):
        assert found(text, "email_address") is None


def test_an_email_after_an_ellipsis_but_not_after_an_invalid_local_part() -> None:
    for text in (
        "Contact...taro@example.com",
        "Contact\u2026taro@example.com",
        "...taro@example.com",
    ):
        finding = found(text, "email_address")
        assert finding is not None, text
        assert finding.previews == ("t***@example.com",)
    # The tail of a local part that isn't a dot-atom isn't an address.
    for text in ("first..taro@example.com", ".taro@example.com", "x .taro@example.com"):
        assert found(text, "email_address") is None, text
    # Case doesn't make a second value.
    assert found("A@EXAMPLE.COM a@example.com", "email_address") == Finding(
        "email_address", {"low": 0, "medium": 0, "high": 1}, ("message",), ("A***@example.com",)
    )


def test_japanese_passports_need_context(rng: random.Random) -> None:
    value = g.jp_passport(rng)
    assert level(f"旅券番号 {value}", "jp_passport") == "medium"
    assert found(f"品番 {value}", "jp_passport") is None
    assert found(f"Passport {value}9", "jp_passport") is None


# ---- Lines and blocks ----


def test_machine_readable_zones_across_units_or_in_one(rng: random.Random) -> None:
    line_1, line_2 = g.mrz(rng)
    findings = scan(*lines("PASSPORT", line_1, line_2))
    assert findings["passport_mrz"].locations == ("line 2",)
    country = line_1[2:5].replace("<", "")
    assert findings["passport_mrz"].previews == (
        f"{country}, document number ending {line_2[0:9].rstrip('<')[-3:]}",
    )
    assert "passport_mrz" in scan(TextUnit("page 1", f"{line_1}\n{line_2}"))
    assert "passport_mrz" not in scan(*lines(line_1, "", line_2))
    assert "passport_mrz" not in scan(*lines(*g.mrz(rng, valid=False)))


@pytest.mark.parametrize("label", g.PEM_LABELS)
def test_pem_private_keys_in_every_layout(rng: random.Random, label: str) -> None:
    key_lines, _ = g.private_key_lines(rng, label)
    for units in (
        list(lines(*key_lines)),
        [TextUnit("page 1", "\n".join(key_lines))],
        [TextUnit("page 1", " ".join(key_lines))],
        [TextUnit("line 1", '"private_key": "' + "\\n".join(key_lines) + '\\n"')],
    ):
        finding = scan(*units)["private_key"]
        assert finding.counts["high"] == 1
        assert "private key" in finding.previews[0].lower()


def test_a_stray_begin_does_not_hide_the_key_after_it(rng: random.Random) -> None:
    key_lines, _ = g.private_key_lines(rng, "RSA ")
    for stray in (
        g.private_key_lines(rng, "")[0][:1],  # a BEGIN line alone
        g.private_key_lines(rng, "EC ")[0][:-1],  # a block cut before its END
        g.pgp_key_lines(rng)[0][:3],
        g.putty_key_lines(rng)[0][:4],
    ):
        for units in (
            list(lines(*stray, *key_lines)),
            [TextUnit("page 1", "\n".join([*stray, *key_lines]))],
            [TextUnit("page 1", " ".join([*stray, *key_lines]))],
        ):
            finding = scan(*units)["private_key"]
            assert finding.counts["high"] == 1
            assert finding.previews == ("RSA private key",)
    # A BEGIN inside a block restarts it, and the key that follows still counts once.
    two = g.private_key_lines(rng, "EC ")[0]
    assert scan(*lines(*key_lines, *two))["private_key"].counts["high"] == 2


@pytest.mark.parametrize("cipher", sorted(g.LEGACY_CIPHERS))
@pytest.mark.parametrize("label", ["RSA ", "EC ", "DSA "])
def test_keys_encrypted_the_old_openssl_way(rng: random.Random, label: str, cipher: str) -> None:
    # The body is ciphertext, so it rarely starts with a SEQUENCE: a run of them proves it doesn't
    # need to.
    for _ in range(20):
        key_lines, _value = g.legacy_encrypted_key_lines(rng, label, cipher)
        for units in (
            list(lines(*key_lines)),
            [TextUnit("page 1", "\n".join(key_lines))],
            [TextUnit("page 1", " ".join(key_lines))],
            [TextUnit("line 1", '"key": "' + "\\n".join(key_lines) + '\\n"')],
        ):
            finding = scan(*units)["private_key"]
            assert finding.counts["high"] == 1
            assert finding.previews == (f"Encrypted {label}private key",)


def test_legacy_encrypted_keys_need_whole_cipher_blocks_and_an_iv(rng: random.Random) -> None:
    short, _ = g.legacy_encrypted_key_lines(rng, "RSA ", "AES-128-CBC", valid=False)
    assert "private_key" not in scan(*lines(*short))
    key_lines, _ = g.legacy_encrypted_key_lines(rng, "RSA ")
    bad_iv = [
        line.split(",")[0] + ",ABC" if line.startswith("DEK-Info:") else line for line in key_lines
    ]
    assert "private_key" not in scan(*lines(*bad_iv))


def test_pgp_and_putty_private_keys(rng: random.Random) -> None:
    pgp, _ = g.pgp_key_lines(rng)
    assert scan(*lines(*pgp))["private_key"].previews == ("PGP private key",)
    putty, _ = g.putty_key_lines(rng)
    assert scan(*lines(*putty))["private_key"].previews == ("PuTTY private key",)


def test_blocks_that_do_not_decode_or_never_end_are_not_keys(rng: random.Random) -> None:
    bad, _ = g.private_key_lines(rng, "RSA ", valid=False)
    assert "private_key" not in scan(*lines(*bad))
    open_ended = g.private_key_lines(rng, "")[0][:-1]
    assert "private_key" not in scan(*lines(*open_ended))
    # A block past its bound is dropped, and the scanner keeps going.
    huge = [open_ended[0]] + [base64.b64encode(rng.randbytes(48)).decode()] * 2100
    key_lines, _ = g.private_key_lines(rng, "EC ")
    assert scan(*lines(*huge, *key_lines))["private_key"].counts["high"] == 1
    # Built in two parts so the detect-private-key hook does not flag this fake header.
    corrupt = ["PuTTY-User-" + "Key-File-2: ssh-rsa", "Private-Lines: x", "Private-MAC: 00"]
    assert "private_key" not in scan(*lines(*corrupt))


# ---- Credentials ----


def test_aws_keys(rng: random.Random) -> None:
    key_id, secret = g.aws_key_id(rng), g.aws_secret(rng)
    alone = scan(*lines(f"id {key_id}"))["cloud_credential"]
    assert alone.counts == {"low": 0, "medium": 1, "high": 0}
    assert alone.previews == ("AWS access key ID",)
    pair = scan(*lines(f"{key_id} {secret}"))["cloud_credential"]
    assert pair.counts == {"low": 0, "medium": 0, "high": 1}
    file = scan(
        *lines("[default]", f"aws_access_key_id={key_id}", f"aws_secret_access_key={secret}")
    )
    assert file["cloud_credential"].counts == {"low": 0, "medium": 0, "high": 1}
    reverse = scan(
        *lines("[default]", f"aws_secret_access_key={secret}", f"aws_access_key_id={key_id}")
    )
    assert reverse["cloud_credential"].counts == {"low": 0, "medium": 0, "high": 1}
    assert reverse["cloud_credential"].previews == ("AWS access key ID with its secret",)
    # Too far apart, they are two credentials; the secret counts where it was.
    apart = scan(*lines(f"aws_secret_access_key={secret}", "a", "b", "c", "d", f"key {key_id}"))[
        "cloud_credential"
    ]
    assert apart.counts == {"low": 0, "medium": 2, "high": 0}
    assert apart.locations == ("line 1", "line 6")
    anchored = scan(*lines(f"aws_secret_access_key: {secret}"))["cloud_credential"]
    assert anchored.counts["medium"] == 1
    assert anchored.previews == ("AWS secret access key",)
    # A secret-shaped string without its keyword, or a hex hash with it, is nothing.
    assert "cloud_credential" not in scan(*lines(f"value {secret}"))
    hex_hash = rng.randbytes(20).hex()
    assert "cloud_credential" not in scan(*lines(f"aws_secret_access_key = {hex_hash}"))


def test_tokens_and_keys_with_checksums(rng: random.Random) -> None:
    assert level(g.github_token(rng), "cloud_credential") == "high"
    assert found(g.github_token(rng, valid=False), "cloud_credential") is None
    assert level(g.github_pat(rng), "cloud_credential") == "medium"
    assert level(g.sft_api_key(rng), "cloud_credential") == "high"
    assert found(g.sft_api_key(rng, valid=False), "cloud_credential") is None
    text, _ = g.azure_connection(rng)
    finding = found(text, "cloud_credential")
    assert finding is not None
    assert finding.previews == ("Azure storage connection string",)
    short = text.replace("AccountKey=", "AccountKey=AAAA")[:-40]
    assert found(short, "cloud_credential") is None


def test_google_service_account_key_files(rng: random.Random) -> None:
    key_id = rng.randbytes(20).hex()
    type_line, id_line = '"type": "service_account",', f'"private_key_id": "{key_id}",'
    for order in ((type_line, id_line), (id_line, type_line)):
        finding = scan(*lines("{", *order, "}"))["cloud_credential"]
        assert finding.previews == ("Google Cloud service account key",)
        assert finding.counts["high"] == 1
    assert "cloud_credential" not in scan(*lines(id_line))


def test_no_credential_preview_holds_any_of_the_value(rng: random.Random) -> None:
    secrets = [g.github_token(rng), g.sft_api_key(rng), g.aws_key_id(rng), g.github_pat(rng)]
    for value in secrets:
        finding = found(value, "cloud_credential")
        assert finding is not None
        assert all(value[-4:] not in preview for preview in finding.previews)


# ---- Confidentiality labels ----


def test_confidentiality_labels_alone_or_in_running_text() -> None:
    assert level("【社外秘】", "confidentiality_label") == "medium"
    assert level("STRICTLY CONFIDENTIAL / Do Not Distribute", "confidentiality_label") == "medium"
    assert level("本資料は社外秘です。", "confidentiality_label") == "low"
    assert level("機密保持契約書", "confidentiality_label") == "low"
    assert found("The confidentiality agreement", "confidentiality_label") is None
    strictly = found("Strictly Confidential", "confidentiality_label")
    assert strictly is not None
    assert strictly.previews == ("Strictly Confidential",)  # not also "Confidential"
    cell = scan(TextUnit("row 2", "極秘\t備考です", (Cell(0, 2, "区分"), Cell(3, 7, "備考"))))
    assert cell["confidentiality_label"].counts["medium"] == 1


# ---- Tenant detectors ----


def test_keyword_lists_match_in_every_form() -> None:
    terms = KeywordList("kw-1", ("青空計画", "サクラ", "Falcon", "ORION-7"))
    text = "青空\n計画、ｻｸﾗ、" + g.full_width("FALCON") + " and orion-7. Falconry orion-77"
    finding = found(text, CUSTOM_PREFIX + "kw-1", (terms,))
    assert finding is not None
    assert finding.counts == {"low": 0, "medium": 0, "high": 4}
    assert set(finding.previews) <= set(terms.terms)
    assert found("Falconry and orion-77", CUSTOM_PREFIX + "kw-1", (terms,)) is None


def test_patterns_with_and_without_context() -> None:
    plain = Pattern("p-1", r"PRJ-[0-9]{4}")
    with_context = Pattern("p-2", r"prj-[0-9]{4}", ("project", "案件"), case_insensitive=True)
    findings = {
        f.detector: f
        for f in inspect_text(
            f"PRJ-1234 is the 案件 code. {'-' * 50} PRJ-9999", (plain, with_context)
        )
    }
    assert findings["custom:p-1"].counts == {"low": 0, "medium": 0, "high": 2}
    assert findings["custom:p-1"].previews == ("****1234", "****9999")
    assert findings["custom:p-2"].counts == {"low": 1, "medium": 0, "high": 1}
    short = Pattern("p-3", r"[0-9]+", min_length=4)
    assert found("12 3456", "custom:p-3", (short,)) == Finding(
        "custom:p-3", {"low": 0, "medium": 0, "high": 1}, ("message",), ("****",)
    )


@pytest.mark.parametrize(
    ("detectors", "reason"),
    [
        ((KeywordList("bad id!", ("x",)),), "invalid_id"),
        ((KeywordList("a", ("x",)), KeywordList("a", ("y",))), "invalid_id"),
        ((KeywordList("a", ()),), "invalid_term_count"),
        ((KeywordList("a", ("x" * 101,)),), "invalid_term"),
        ((KeywordList("a", ("   ",)),), "invalid_term"),
        ((Pattern("a", "x" * 513),), "expression_too_long"),
        ((Pattern("a", "(unclosed"),), "does_not_compile"),
        ((Pattern("a", "x*"),), "matches_empty_string"),
        ((Pattern("a", "x", ("",)),), "invalid_context_keywords"),
        ((Pattern("a", "x", min_length=-1),), "invalid_min_length"),
        (tuple(KeywordList(f"k{i}", ("x",)) for i in range(51)), "too_many_detectors"),
        (tuple(Pattern(f"p{i}", "x") for i in range(21)), "too_many_patterns"),
    ],
)
def test_invalid_tenant_detectors_are_refused(
    detectors: tuple[KeywordList | Pattern, ...], reason: str
) -> None:
    with pytest.raises(DetectorError) as error:
        new_scanner(detectors)
    assert error.value.reason == reason
    assert isinstance(error.value, ValueError)


def test_errors_never_quote_the_definition() -> None:
    with pytest.raises(DetectorError) as error:
        new_scanner([Pattern("p-1", "(project-secret-name")])
    assert "project-secret-name" not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__
    with pytest.raises(DetectorError) as unknown:
        new_scanner([object()])  # type: ignore[list-item]
    assert unknown.value.reason == "unknown_kind"


def test_save_time_validation() -> None:
    validate(Pattern("p-1", r"PRJ-[0-9]{4}"))
    validate(KeywordList("k-1", ("見本",)))
    with pytest.raises(DetectorError, match="matches_empty_string"):
        validate(Pattern("p-2", r"\b"))


def test_validation_is_deterministic() -> None:
    # A simple pattern that matches very often on the test text is accepted on any machine: nothing
    # is timed.
    validate(Pattern("p-1", r"[0-9]{3}"))
    validate(Pattern("p-2", r"(PRJ|案件)-([0-9]{4})"))
    # What decides is the size of RE2's program, which is the same everywhere.
    for expression in (r"\w{1,1000}", r"(.{0,60}){1,8}z"):
        with pytest.raises(DetectorError) as error:
            validate(Pattern("p-3", expression))
        assert error.value.reason == "too_complex"


def test_tenant_patterns_report_spans_without_capturing() -> None:
    grouped = Pattern("p-1", r"(PRJ)-([0-9]{4})")
    assert found("PRJ-1234", "custom:p-1", (grouped,)) == Finding(
        "custom:p-1", {"low": 0, "medium": 0, "high": 1}, ("message",), ("****1234",)
    )


def test_validation_compiles_a_pattern_once(monkeypatch: pytest.MonkeyPatch) -> None:
    compiled: list[str] = []

    class Counting(Regex):
        def __init__(self, expression: str, **options: bool) -> None:
            compiled.append(expression)
            super().__init__(expression, **options)

    monkeypatch.setattr("sft.dlp.detect.tenant.Regex", Counting)
    validate(Pattern("p-1", r"PRJ-[0-9]{4}"))
    assert compiled == [r"PRJ-[0-9]{4}"]


def test_lone_surrogates_neither_stop_a_scan_nor_move_offsets() -> None:
    text = "\ud800連絡先 sample.user1@example.co.jp \udfff"
    assert len(normalise(text)) == len(text)
    assert normalise("\ud800a") == "\ufffda"
    finding = found(text, "email_address")
    assert finding is not None
    assert finding.previews == ("s***@example.co.jp",)
    s = new_scanner([KeywordList("k-1", ("見本\udc00",))])
    s.feed(TextUnit("sheet \udc80", "見本\udc00 です"))
    (keywords,) = s.findings()
    assert keywords.locations == ("sheet \ufffd",)
    assert keywords.previews == ("見本\ufffd",)
    with pytest.raises(DetectorError) as error:
        validate(Pattern("p-1", "x\ud800"))
    assert error.value.reason == "does_not_compile"
    with pytest.raises(RegexError):
        RegexSet(["\ud800"], max_mem=1 << 20)


def test_the_regex_wrapper() -> None:
    with pytest.raises(RegexError):
        Regex("(")
    with pytest.raises(RegexError):
        RegexSet(["("], max_mem=1 << 20)
    assert Regex("a+").search("xyz") is None
    assert RegexSet(["a", "b"], max_mem=1 << 20).matching("zzz") == []


# ---- The scanner ----


def test_a_value_counts_once_at_its_highest_confidence(rng: random.Random) -> None:
    value = g.my_number(rng)
    findings = scan(*lines(f"参照 {value}", f"マイナンバー {value}", f"参照 {value}"))
    assert findings["jp_my_number"].counts == {"low": 0, "medium": 0, "high": 1}
    assert findings["jp_my_number"].locations == ("line 1", "line 2", "line 3")


def test_findings_keep_at_most_10_locations_and_3_previews(rng: random.Random) -> None:
    units = [TextUnit(f"page {i}", f"法人番号 {g.corporate_number(rng)}") for i in range(30)]
    finding = scan(*units)["jp_corporate_number"]
    assert finding.counts["high"] == 30
    assert len(finding.locations) == 10
    assert len(finding.previews) == 3


def test_locations_are_truncated() -> None:
    finding = scan(TextUnit("x" * 300, "【極秘】"))["confidentiality_label"]
    assert finding.locations == ("x" * 256,)


def test_past_the_distinct_limit_every_match_counts(
    rng: random.Random, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scanner, "MAX_DISTINCT", 2)
    value = g.corporate_number(rng)
    units = [TextUnit("p", f"法人番号 {g.corporate_number(rng)}") for _ in range(2)]
    units += [TextUnit("p", f"法人番号 {value}"), TextUnit("p", f"法人番号 {value}")]
    assert scan(*units)["jp_corporate_number"].counts["high"] == 4


def test_nothing_holds_a_value_in_its_repr(rng: random.Random) -> None:
    value = g.my_number(rng)
    hit = Hit("jp_my_number", 2, value, "12 digits, check digit valid")
    assert value not in repr(hit)
    s = new_scanner()
    s.feed(TextUnit("line 1", f"マイナンバー {value}"))
    assert value not in repr(s)
    assert value not in repr(s.findings())


def test_the_hash_key_is_new_per_scanner() -> None:
    first, second = new_scanner(), new_scanner()
    assert first._key != second._key  # type: ignore[attr-defined]


def test_table_rows_use_their_column_headers(rng: random.Random) -> None:
    value = g.my_number(rng)
    header = TextUnit("row 1", "氏名\tマイナンバー", (Cell(0, 2, ""), Cell(3, 9, "")))
    row = TextUnit(
        "row 2",
        f"見本 太郎\t{value}",
        (Cell(0, 5, "氏名"), Cell(6, 6 + len(value), "マイナンバー")),
    )
    assert scan(header, row)["jp_my_number"].counts["high"] == 1


def test_the_public_surface() -> None:
    assert len(BUILTIN_DETECTORS) == 13
    assert DETECTORS_VERSION == "2.banks-none"  # no bank code list is bundled yet (#146)
    assert inspect_text("") == []
    assert inspect_text("ordinary text with no data") == []
