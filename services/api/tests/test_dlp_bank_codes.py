"""The bank and branch code list and `jp_bank_account`'s high confidence ([DLP] 4.4, #146).

The list here is the synthetic fixture (tests/bank_codes_fixture.txt): nothing real is bundled
yet, and these tests never need a real code.
"""

from __future__ import annotations

import hashlib
import io
import json
import random
import tarfile
import time
from pathlib import Path

import pytest

from dlp_corpus import generate as g
from sft.dlp.detect import bank_codes
from sft.dlp.detect.bank_codes import EMPTY, BankCodeError, BankCodes, parse, render
from sft.dlp.detect.scanner import _Scanner
from sft.dlp.engine import EngineUnavailableError, load_engine
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
    # #146: no source whose licence allows bundling has been confirmed, so git holds only the
    # header; the image build fetches the list (Dockerfile, tools/bank_codes.py zengin-code).
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
            "csv",
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
    arguments = ["csv", str(source), "--source", "s", "--licence", "l", "--retrieved", "2026-11-05"]
    assert refresh.main([*arguments, "--output", str(output)]) == 1
    assert not output.exists()


# ---- the image build's source: zengin-code/source-data at a pinned commit ----

REF = "0" * 40
TOP = f"source-data-{REF}"
SYNTHETIC = {"9990": ["001", "002", "100"], "9991": ["001"]}
"""Made-up banks and branches in the archive's layout; nothing here is fetched."""


def zengin_archive(
    tmp_path: Path, branches: dict[str, object] | None = None, extra: dict[str, bytes] | None = None
) -> Path:
    """A `.tar.gz` laid out like the repository's archive: branches/NNNN.json, and other files."""
    files: dict[str, bytes] = {
        f"{TOP}/README.md": b"not data",
        f"{TOP}/data/banks.json": b"{}",
        f"{TOP}/data/branches/9990.yml": b"not counted",
    }
    for bank, value in (branches if branches is not None else SYNTHETIC).items():
        if isinstance(value, list):
            value = {code: {"code": code, "name": "見本"} for code in value}
        files[f"{TOP}/data/branches/{bank}.json"] = json.dumps(value).encode()
    files.update(extra or {})
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    path = tmp_path / "source-data.tar.gz"
    path.write_bytes(buffer.getvalue())
    return path


@pytest.fixture
def few_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(refresh, "MIN_CODES", 3)


def zengin(archive: Path, *extra: str) -> list[str]:
    return [
        "zengin-code",
        "--ref",
        REF,
        "--retrieved",
        "2026-08-24",
        "--archive",
        str(archive),
        *extra,
    ]


def expected_digest() -> str:
    codes = sorted(b + c for b, cs in SYNTHETIC.items() for c in cs)
    return hashlib.sha256("".join(f"{c}\n" for c in codes).encode()).hexdigest()


@pytest.mark.usefixtures("few_codes")
def test_zengin_code_reads_the_branch_files_and_reports_the_digest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    archive = zengin_archive(tmp_path)
    codes = refresh.codes_from_zengin_archive(archive.read_bytes())
    assert sorted(codes) == ["9990001", "9990002", "9990100", "9991001"]
    assert refresh.digest(codes) == refresh.digest(reversed(codes)) == expected_digest()
    # Without --output it only checks, and says what to pin.
    assert refresh.main(zengin(archive)) == 0
    assert f"4 codes, sha256 {expected_digest()}" in capsys.readouterr().out


@pytest.mark.usefixtures("few_codes")
def test_zengin_code_writes_only_the_pinned_list(tmp_path: Path) -> None:
    archive = zengin_archive(tmp_path)
    output = tmp_path / "bank_codes.txt"
    # Writing needs the pinned digest, and refuses any other.
    assert refresh.main(zengin(archive, "--output", str(output))) == 1
    assert refresh.main(zengin(archive, "--sha256", "f" * 64, "--output", str(output))) == 1
    assert not output.exists()
    assert (
        refresh.main(zengin(archive, "--sha256", expected_digest(), "--output", str(output))) == 0
    )
    written = parse(output.read_text("utf-8"))
    assert written.valid("9990", "100")
    assert written.source.startswith(f"zengin-code/source-data at {REF}")
    assert written.licence.startswith("MIT")
    assert written.version == "20260824"


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--ref", "master"], "40-character commit"),
        (["--sha256", "ABC"], "64 lowercase hex"),
    ],
)
def test_zengin_code_refuses_a_loose_pin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], arguments: list[str], message: str
) -> None:
    archive = zengin_archive(tmp_path)
    assert refresh.main([*zengin(archive), *arguments]) == 1
    assert message in capsys.readouterr().err


@pytest.mark.usefixtures("few_codes")
@pytest.mark.parametrize(
    ("branches", "extra", "message"),
    [
        ({"9990": {"01": {}}}, None, "3-digit codes"),
        ({"9990": ["001"], "9991": []}, None, "only 1 codes"),
        (None, {f"{TOP}/data/branches/9992.json": b"{not json"}, "JSONDecodeError"),
        (
            None,
            {f"{TOP}/data/branches/9993.json": b" " * (refresh.MAX_MEMBER_BYTES + 1)},
            "larger than",
        ),
    ],
)
def test_zengin_code_refuses_a_broken_archive(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    branches: dict[str, object] | None,
    extra: dict[str, bytes] | None,
    message: str,
) -> None:
    archive = zengin_archive(tmp_path, branches, extra)
    assert refresh.main(zengin(archive)) == 1
    error = capsys.readouterr().err
    assert message in error
    assert "9990001" not in error


def test_zengin_code_refuses_what_isnt_an_archive(tmp_path: Path) -> None:
    archive = tmp_path / "page.html"
    archive.write_bytes(b"<html>rate limited</html>")
    with pytest.raises(BankCodeError, match="can't be read"):
        refresh.codes_from_zengin_archive(archive.read_bytes())
    assert refresh.main(zengin(tmp_path / "missing.tar.gz")) == 1


def test_a_full_archive_falls_below_no_floor_by_accident() -> None:
    # The floor catches an emptied or truncated source; Japan has about 31,000 branches.
    assert 1_000 < refresh.MIN_CODES < 31_000 < bank_codes.MAX_CODES


# ---- the inspector with a damaged list ----


def test_a_damaged_list_stops_the_inspector_at_start(monkeypatch: pytest.MonkeyPatch) -> None:
    # The image build checks the digest, so this is a broken image: the inspector refuses to
    # start (EXIT_NO_ENGINE) rather than inspect without the list, or with half of it.
    def damaged(_name: str) -> object:
        raise BankCodeError("line 9: not a 7-digit bank and branch code")

    monkeypatch.setattr("importlib.import_module", damaged)
    with pytest.raises(EngineUnavailableError, match="BankCodeError"):
        load_engine()
