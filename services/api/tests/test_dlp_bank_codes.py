"""The bank and branch code list and `jp_bank_account`'s high confidence ([DLP] 4.4, #146).

The list here is the synthetic fixture (tests/bank_codes_fixture.txt): nothing real is bundled
yet, and these tests never need a real code.
"""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

from dlp_corpus import generate as g
from sft.dlp.detect import bank_codes
from sft.dlp.detect.bank_codes import EMPTY, BankCodeError, BankCodes, parse, render
from sft.dlp.detect.scanner import _Scanner
from sft.dlp.units import Cell, TextUnit
from tools import bank_codes as refresh

FIXTURE = Path(__file__).with_name("bank_codes_fixture.txt")
CODES = parse(FIXTURE.read_text("utf-8"))
PAIR = sorted(CODES.codes)[0]
BANK, BRANCH = PAIR[:4], PAIR[4:]


@pytest.fixture
def rng() -> random.Random:
    return random.Random(146)  # noqa: S311 - reproducible test data


def account_level(*units: TextUnit, banks: BankCodes = CODES) -> str | None:
    scanner = _Scanner([], banks)
    for unit in units:
        scanner.feed(unit)
    finding = next((f for f in scanner.findings() if f.detector == "jp_bank_account"), None)
    if finding is None:
        return None
    return next(c for c in ("high", "medium", "low") if finding.counts[c])


def text(value: str) -> TextUnit:
    return TextUnit("line 1", value)


def unlisted(rng: random.Random) -> tuple[str, str]:
    while True:
        bank, branch = g._digits(rng, 4), g._digits(rng, 3)
        if not CODES.valid(bank, branch):
            return bank, branch


# ---- the detector ----


def test_a_listed_pair_near_the_account_makes_it_high(rng: random.Random) -> None:
    account = g._digits(rng, 7)
    for line in (
        f"架空銀行(銀行コード {BANK}) 見本支店(支店コード {BRANCH}) 普通 {account}",
        f"金融機関コード {BANK}-{BRANCH} 当座 口座番号 {account}",
        f"普通 {account} 銀行 {BANK} 支店 {BRANCH}",  # after the account works too
        f"Bank code {BANK}, branch code {BRANCH}, account number {account}",
    ):
        assert account_level(text(line)) == "high", line


def test_an_unlisted_pair_or_no_pair_stays_medium(rng: random.Random) -> None:
    account = g._digits(rng, 7)
    bank, branch = unlisted(rng)
    assert account_level(text(f"銀行コード {bank} 支店コード {branch} 普通 {account}")) == "medium"
    assert account_level(text(f"普通 {account}")) == "medium"
    # Branch before bank isn't a pair, and a code inside a longer number isn't one.
    assert account_level(text(f"支店 {BRANCH} 銀行 {BANK} 普通 {account}")) == "medium"
    assert account_level(text(f"番号 1{BANK} {BRANCH}9 普通 {account}")) == "medium"
    # Without its keywords there is still no account at all.
    assert account_level(text(f"{BANK} {BRANCH} 社員番号 {account}")) is None


def test_the_pair_counts_within_80_characters_only(rng: random.Random) -> None:
    account = g._digits(rng, 7)
    near = f"銀行コード {BANK} 支店コード {BRANCH}" + "。" * 40 + f" 普通 {account}"
    far = f"銀行コード {BANK} 支店コード {BRANCH}" + "。" * 90 + f" 普通 {account}"
    assert account_level(text(near)) == "high"
    assert account_level(text(far)) == "medium"


def test_a_number_cut_by_the_window_edge_is_no_code(rng: random.Random) -> None:
    # Review fix: the branch code's digits run on past the 80-character window, so the whole
    # number is 8 digits, not a branch code. The window's edge must not make it look like one.
    account = g._digits(rng, 7)
    head = f"普通 {account} 銀行 {BANK} "
    pad = "。" * (3 + 7 + 80 - 3 - len(head))  # the branch code ends right at the window's edge
    line = f"{head}{pad}{BRANCH}12345"
    assert line.index(BRANCH) + 3 == 3 + 7 + 80
    assert account_level(text(line)) == "medium"
    # The same digits standing alone, inside the window, are a pair.
    assert account_level(text(f"{head}{pad[:-2]}{BRANCH}")) == "high"


def test_in_a_table_the_pair_counts_anywhere_in_the_row(rng: random.Random) -> None:
    account = g._digits(rng, 7)
    filler = "見本支店" + "。" * 100  # puts the codes far from the account, in the same row
    cells = [BANK, BRANCH, filler, account]
    headers = ["銀行コード", "支店コード", "備考", "口座番号"]
    spans, offset = [], 0
    for cell, header in zip(cells, headers, strict=True):
        spans.append(Cell(offset, offset + len(cell), header))
        offset += len(cell) + 1
    row = TextUnit('sheet "口座", row 2', "\t".join(cells), tuple(spans))
    assert account_level(row) == "high"
    # The codes of another row don't count.
    other = TextUnit("row 3", account, (Cell(0, 7, "口座番号"),))
    codes = TextUnit("row 2", f"{BANK}\t{BRANCH}", (Cell(0, 4, "銀行"), Cell(5, 8, "支店")))
    assert account_level(codes, other) == "medium"


def test_without_a_list_high_is_never_reached(rng: random.Random) -> None:
    account = g._digits(rng, 7)
    line = text(f"銀行コード {BANK} 支店コード {BRANCH} 普通 {account}")
    assert account_level(line, banks=EMPTY) == "medium"
    assert account_level(line, banks=bank_codes.load()) == "medium"


def test_japan_post_accounts_stay_medium(rng: random.Random) -> None:
    line = f"ゆうちょ 銀行 {BANK} 支店 {BRANCH} 1{g._digits(rng, 4)}-{g._digits(rng, 8)}"
    assert account_level(text(line)) == "medium"


# ---- the list ----


def test_the_bundled_list_is_empty_and_says_so() -> None:
    # #146: no source whose licence allows bundling has been confirmed, so nothing is bundled.
    bundled = bank_codes.load()
    assert len(bundled) == 0
    assert (bundled.source, bundled.licence, bundled.retrieved) == ("none", "none", "none")
    assert bundled.version == "none"
    assert bank_codes.load() is bundled  # read once per process


def test_the_fixture_is_marked_as_test_data() -> None:
    assert "TEST DATA ONLY" in FIXTURE.read_text("utf-8")
    assert CODES.source.startswith("synthetic")
    assert len(CODES) == 40
    assert CODES.version == "20261105"
    assert PAIR not in repr(CODES)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ("# source: x\n# licence: y\n# retrieved: 2026-01-01\n123456\n", "line 4: not a 7-digit"),
        ("# source: x\n# licence: y\n# retrieved: 2026-01-01\n0000002\n0000001\n", "ascending"),
        ("# source: x\n# licence: y\n# retrieved: 2026-01-01\n0000001\n0000001\n", "ascending"),
        ("# source: x\n# licence: y\n0000001\n", "no retrieved"),
        ("# source: none\n# licence: none\n# retrieved: 2026-01-01\n0000001\n", "a source"),
        ("# source: x\n# licence: y\n# retrieved: soon\n0000001\n", "YYYY-MM-DD"),
    ],
)
def test_a_malformed_list_is_refused_naming_the_line_not_the_code(data: str, message: str) -> None:
    with pytest.raises(BankCodeError, match=message) as error:
        parse(data)
    assert "0000001" not in str(error.value)


def test_render_sorts_dedupes_and_round_trips() -> None:
    written = render(
        ["0002001", "0001002", "0001002"], source="s", licence="l", retrieved="2026-11-05"
    )
    codes = parse(written)
    assert sorted(codes.codes) == ["0001002", "0002001"]
    assert written.splitlines()[-2:] == ["0001002", "0002001"]
    with pytest.raises(BankCodeError):
        render(["12345678"], source="s", licence="l", retrieved="2026-11-05")
    with pytest.raises(BankCodeError):
        render([], source="", licence="l", retrieved="2026-11-05")


def test_a_full_sized_list_loads_quickly() -> None:
    # About 30,000 branches exist; 40,000 codes must parse well inside the inspector's start-up.
    data = render(
        (f"{n:07d}" for n in range(0, 4_000_000, 100)),
        source="s",
        licence="l",
        retrieved="2026-11-05",
    )
    started = time.perf_counter()
    codes = parse(data)
    assert len(codes) == 40_000
    assert time.perf_counter() - started < 1.0
    assert len(data.encode()) < 400_000


# ---- the refresh tool ----


def test_the_refresh_tool_writes_the_list_from_a_csv(tmp_path: Path) -> None:
    source = tmp_path / "codes.csv"
    source.write_text(
        "bank_code,branch_code,name\n0002,001,x\n0001,002,y\n0001,002,y\n", encoding="utf-8"
    )
    output = tmp_path / "bank_codes.txt"
    status = refresh.main(
        [
            str(source),
            "--source",
            "a test",
            "--licence",
            "CC-BY-4.0",
            "--retrieved",
            "2026-11-05",
            "--output",
            str(output),
        ]
    )
    assert status == 0
    written = parse(output.read_text("utf-8"))
    assert sorted(written.codes) == ["0001002", "0002001"]
    assert (written.source, written.licence) == ("a test", "CC-BY-4.0")


@pytest.mark.parametrize("csv_text", ["bank,branch\n0001,001\n", "bank_code,branch_code\n1,001\n"])
def test_the_refresh_tool_refuses_a_bad_csv(tmp_path: Path, csv_text: str) -> None:
    source = tmp_path / "codes.csv"
    source.write_text(csv_text, encoding="utf-8")
    output = tmp_path / "out.txt"
    arguments = [str(source), "--source", "s", "--licence", "l", "--retrieved", "2026-11-05"]
    assert refresh.main([*arguments, "--output", str(output)]) == 1
    assert not output.exists()
