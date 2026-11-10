"""Make the bank and branch code list `jp_bank_account` needs for high ([DLP] 4.4, #146).

Two sources, one output format (`sft.dlp.detect.bank_codes`):

    # The image build and the refresh check: zengin-code/source-data at a pinned commit.
    uv run python -m tools.bank_codes zengin-code --ref <commit> --retrieved 2026-08-24
    uv run python -m tools.bank_codes zengin-code --ref <commit> --retrieved 2026-08-24 \\
        --sha256 <digest> --output src/sft/dlp/detect/bank_codes.txt

    # A list the maintainer obtained under terms that allow bundling, as CSV.
    uv run python -m tools.bank_codes csv CODES.csv --source "<publisher, URL>" \\
        --licence "<the terms>" --retrieved 2026-11-05

**zengin-code** downloads the repository's archive at one commit from GitHub, reads
`data/branches/NNNN.json` (one file per bank, keyed by branch code) without unpacking anything to
disk, and prints the number of codes and their digest: SHA-256 of the sorted codes, one per line,
each ending in a newline. That digest, not the archive's, is what the Dockerfile pins, since
GitHub doesn't promise byte-stable archives. Writing (`--output`) needs `--sha256`, and a list
whose digest differs is refused, so an image only ever holds the reviewed list. The list is never
committed: no licence for its data could be confirmed (dlp-detectors.md 4.4), so the inspector
image fetches it when it is built.

**csv** needs a header row with `bank_code` and `branch_code` columns (other columns are ignored),
4 and 3 digits, leading zeros kept, and writes `src/sft/dlp/detect/bank_codes.txt` by default.

The service README ("DLP bank and branch codes") gives the cadence and the steps. Exit status: 0
done, 1 the source or the digest is wrong, 2 bad arguments.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
import sys
import tarfile
import urllib.request
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final

from sft.dlp.detect.bank_codes import BankCodeError, render

OUTPUT: Final = Path(__file__).resolve().parents[1] / "src/sft/dlp/detect/bank_codes.txt"

ZENGIN_REPOSITORY: Final = "https://github.com/zengin-code/source-data"
ZENGIN_ARCHIVE: Final = "https://codeload.github.com/zengin-code/source-data/tar.gz/{ref}"
ZENGIN_SOURCE: Final = (
    "zengin-code/source-data at {ref} ({repository}), compiled by its authors from"
    " http://ykaku.net/ginkokensaku/"
)
ZENGIN_LICENCE: Final = (
    "MIT, as the repository's README states for the repository; the site it is compiled from"
    " states no terms. Fetched when the image is built, never committed (#146)"
)
MAX_ARCHIVE_BYTES: Final = 64 * 1024 * 1024
"""The archive is about 1.6 MB; anything near this is not the repository we pinned."""
MAX_MEMBER_BYTES: Final = 1024 * 1024
"""The biggest bank's branch file is about 100 KB."""
MIN_CODES: Final = 10_000
"""Japan has about 31,000 branches; far fewer means a broken source, not a smaller country."""
TIMEOUT_SECONDS: Final = 60

_REF = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_BANK = re.compile(r"[0-9]{4}")
_BRANCH = re.compile(r"[0-9]{3}")
_BRANCH_FILE = re.compile(r"[^/]+/data/branches/([0-9]{4})\.json")


def codes_from_csv(rows: Iterable[dict[str, str]]) -> list[str]:
    """The 7-digit codes of the CSV's rows. Raises `BankCodeError` naming the bad row."""
    codes = []
    for number, row in enumerate(rows, start=2):  # row 1 is the header
        bank = (row.get("bank_code") or "").strip()
        branch = (row.get("branch_code") or "").strip()
        if not (_BANK.fullmatch(bank) and _BRANCH.fullmatch(branch)):
            raise BankCodeError(f"row {number}: bank_code is 4 digits and branch_code 3")
        codes.append(bank + branch)
    return codes


def codes_from_zengin_archive(archive: bytes) -> list[str]:
    """The 7-digit codes in a zengin-code/source-data archive (a `.tar.gz` of the repository).

    Only `data/branches/NNNN.json` counts: the bank code is the file name, the branch codes are
    the object's keys. Nothing is extracted to disk. Raises `BankCodeError` naming the member,
    never a code.
    """
    codes: list[str] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for member in tar:
                match = _BRANCH_FILE.fullmatch(member.name)
                if match is None or not member.isfile():
                    continue
                if member.size > MAX_MEMBER_BYTES:
                    raise BankCodeError(f"{member.name}: larger than {MAX_MEMBER_BYTES} bytes")
                extracted = tar.extractfile(member)
                if extracted is None:  # pragma: no cover - a regular file always has data
                    continue
                branches = json.loads(extracted.read())
                if not isinstance(branches, dict) or not all(
                    _BRANCH.fullmatch(key) for key in branches
                ):
                    raise BankCodeError(f"{member.name}: not an object keyed by 3-digit codes")
                codes.extend(match.group(1) + branch for branch in branches)
    except BankCodeError:
        raise
    except (tarfile.TarError, OSError, EOFError, ValueError) as error:  # ValueError: bad JSON
        raise BankCodeError(f"the archive can't be read: {type(error).__name__}") from None
    if len(set(codes)) < MIN_CODES:
        raise BankCodeError(f"only {len(set(codes))} codes: fewer than {MIN_CODES}")
    return codes


def digest(codes: Iterable[str]) -> str:
    """SHA-256 of the sorted codes, one per line, each ending in a newline: what the image pins."""
    return hashlib.sha256("".join(f"{code}\n" for code in sorted(set(codes))).encode()).hexdigest()


def download(ref: str) -> bytes:  # pragma: no cover - network; tests pass --archive
    """The repository's archive at commit `ref`, from GitHub, at most `MAX_ARCHIVE_BYTES`."""
    url = ZENGIN_ARCHIVE.format(ref=ref)
    with urllib.request.urlopen(url, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310 - fixed https URL
        data: bytes = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise BankCodeError(f"the archive is larger than {MAX_ARCHIVE_BYTES} bytes")
    return data


def _write(output: Path, text: str, count: int) -> None:
    output.write_text(text, encoding="utf-8")
    print(f"bank_codes: {count} codes written to {output}")


def _from_csv(arguments: argparse.Namespace) -> int:
    with arguments.csv.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if not {"bank_code", "branch_code"} <= set(reader.fieldnames or ()):
            raise BankCodeError("the CSV needs bank_code and branch_code columns")
        codes = codes_from_csv(reader)
    text = render(
        codes, source=arguments.source, licence=arguments.licence, retrieved=arguments.retrieved
    )
    _write(arguments.output, text, len(set(codes)))
    return 0


def _from_zengin(arguments: argparse.Namespace) -> int:
    if not _REF.fullmatch(arguments.ref):
        raise BankCodeError("--ref is a full 40-character commit, never a branch or a tag")
    if arguments.output is not None and arguments.sha256 is None:
        raise BankCodeError("--output needs --sha256: an image holds only a reviewed list")
    if arguments.sha256 is not None and not _DIGEST.fullmatch(arguments.sha256):
        raise BankCodeError("--sha256 is 64 lowercase hex characters")
    archive = arguments.archive.read_bytes() if arguments.archive else download(arguments.ref)
    codes = codes_from_zengin_archive(archive)
    found = digest(codes)
    print(f"bank_codes: zengin-code {arguments.ref}: {len(set(codes))} codes, sha256 {found}")
    if arguments.sha256 is not None and found != arguments.sha256:
        raise BankCodeError(
            "the codes' digest isn't the pinned one: review the change, then pin it"
        )
    if arguments.output is not None:
        source = ZENGIN_SOURCE.format(ref=arguments.ref, repository=ZENGIN_REPOSITORY)
        text = render(codes, source=source, licence=ZENGIN_LICENCE, retrieved=arguments.retrieved)
        _write(arguments.output, text, len(set(codes)))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    sources = parser.add_subparsers(dest="source_kind", required=True)

    zengin = sources.add_parser("zengin-code", help="zengin-code/source-data at a pinned commit")
    zengin.add_argument("--ref", required=True, help="the commit, 40 hex characters")
    zengin.add_argument(
        "--retrieved", required=True, help="the commit's date, YYYY-MM-DD (its tag's name)"
    )
    zengin.add_argument("--sha256", help="the codes' pinned digest; required to write")
    zengin.add_argument("--output", type=Path, help="where to write the list; omit to check only")
    zengin.add_argument("--archive", type=Path, help="a downloaded archive, instead of GitHub")
    zengin.set_defaults(run=_from_zengin)

    from_csv = sources.add_parser("csv", help="a licensed CSV, UTF-8 with a header row")
    from_csv.add_argument("csv", type=Path, help="the licensed CSV, UTF-8 with a header row")
    from_csv.add_argument("--source", required=True, help="who publishes the list, and where")
    from_csv.add_argument("--licence", required=True, help="the terms that allow bundling it")
    from_csv.add_argument("--retrieved", required=True, help="when it was obtained, YYYY-MM-DD")
    from_csv.add_argument("--output", type=Path, default=OUTPUT)
    from_csv.set_defaults(run=_from_csv)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        status: int = arguments.run(arguments)
    except BankCodeError as error:
        print(f"bank_codes: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"bank_codes: {type(error).__name__}: {error.strerror or error}", file=sys.stderr)
        return 1
    return status


if __name__ == "__main__":
    sys.exit(main())
