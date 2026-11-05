"""Refresh the bundled bank and branch code list from a licensed CSV ([DLP] 4.4, #146).

    uv run python -m tools.bank_codes CODES.csv --source "<publisher, URL>" \\
        --licence "<the terms that allow bundling>" --retrieved 2026-11-05

The CSV needs a header row with `bank_code` and `branch_code` columns (other columns are ignored),
4 and 3 digits, leading zeros kept. It writes `src/sft/dlp/detect/bank_codes.txt`: sorted, each
code once, with the source, licence and retrieval date in its header. Nothing here fetches
anything: the maintainer obtains the file under its terms, and the source and licence are
recorded in the change that bundles it. The service README ("DLP bank and branch codes") gives
the cadence and the checks.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final

from sft.dlp.detect.bank_codes import BankCodeError, render

OUTPUT: Final = Path(__file__).resolve().parents[1] / "src/sft/dlp/detect/bank_codes.txt"
_BANK = re.compile(r"[0-9]{4}")
_BRANCH = re.compile(r"[0-9]{3}")


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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0] if __doc__ else None)
    parser.add_argument("csv", type=Path, help="the licensed CSV, UTF-8 with a header row")
    parser.add_argument("--source", required=True, help="who publishes the list, and where")
    parser.add_argument("--licence", required=True, help="the terms that allow bundling it")
    parser.add_argument("--retrieved", required=True, help="when it was obtained, YYYY-MM-DD")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    arguments = parser.parse_args(argv)
    try:
        with arguments.csv.open(encoding="utf-8-sig", newline="") as source:
            reader = csv.DictReader(source)
            if not {"bank_code", "branch_code"} <= set(reader.fieldnames or ()):
                raise BankCodeError("the CSV needs bank_code and branch_code columns")
            codes = codes_from_csv(reader)
        text = render(
            codes,
            source=arguments.source,
            licence=arguments.licence,
            retrieved=arguments.retrieved,
        )
    except BankCodeError as error:
        print(f"bank_codes: {error}", file=sys.stderr)
        return 1
    arguments.output.write_text(text, encoding="utf-8")
    print(f"bank_codes: {len(set(codes))} codes written to {arguments.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
