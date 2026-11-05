"""Plain text, CSV and TSV ([detectors] 2), in the encodings of ADR-0022."""

from __future__ import annotations

import csv
import io
import itertools
from typing import IO, Final

from sft.dlp.extract._core import Context
from sft.dlp.extract._sniff import candidates
from sft.dlp.units import Cell

_DECODE_CHUNK: Final = 1024 * 1024
_SNIFF_ROWS: Final = 10


def extract_text(ctx: Context, data: IO[bytes], prefix: bytes, path: tuple[str, ...]) -> None:
    """Decode `data`, which starts with `prefix`, and hand on its lines or rows."""
    complete = len(prefix) < ctx.limits.prefix_bytes
    encodings = candidates(prefix, complete=complete)
    encoding = _whole_file_encoding(data, encodings)
    errors = "strict"
    if encoding is None:
        # No candidate decodes all of it: read it with the best one, undecodable bytes replaced,
        # and say so.
        encoding, errors = encodings[0], "replace"
        ctx.report.add("parse_error")
    ctx.report.covered = True
    head = prefix.decode(encoding, errors="ignore")
    delimiter = _delimiter(head, complete=complete)
    data.seek(0)
    stream = io.TextIOWrapper(data, encoding=encoding, errors=errors, newline="")
    try:
        if delimiter is None:
            _lines(ctx, stream, path)
        else:
            _rows(ctx, stream, path, delimiter)
    finally:
        stream.detach()


def _whole_file_encoding(data: IO[bytes], encodings: list[str]) -> str | None:
    for encoding in encodings:
        data.seek(0)
        stream = io.TextIOWrapper(data, encoding=encoding, errors="strict", newline="")
        try:
            while stream.read(_DECODE_CHUNK):
                pass
        except UnicodeDecodeError:
            continue
        finally:
            stream.detach()
        return encoding
    return None


def _lines(ctx: Context, stream: io.TextIOWrapper, path: tuple[str, ...]) -> None:
    overlap = ctx.limits.unit_overlap_chars
    size = max(ctx.limits.max_unit_chars - overlap, 1)
    number = 0
    carry = ""  # the end of the piece before, when a line is longer than a unit
    cut = False
    while piece := stream.readline(size):
        if not cut:
            number += 1
        ctx.emit(path, f"line {number}", carry + piece.rstrip("\r\n"))
        cut = len(piece) == size and not piece.endswith(("\n", "\r"))
        carry = piece[-overlap:] if cut and overlap else ""


def _rows(ctx: Context, stream: io.TextIOWrapper, path: tuple[str, ...], delimiter: str) -> None:
    csv.field_size_limit(ctx.limits.max_unit_chars)
    reader = csv.reader(stream, delimiter=delimiter, strict=False)
    header: list[str] | None = None
    number = 0
    try:
        for row in reader:
            number += 1
            if not any(cell.strip() for cell in row):
                continue
            if header is None:
                header = row
            cells: list[Cell] = []
            start = 0
            for column, value in enumerate(row):
                name = header[column] if column < len(header) and row is not header else ""
                cells.append(Cell(start=start, end=start + len(value), header=name))
                start += len(value) + 1
            ctx.emit(path, f"row {number}", "\t".join(row), tuple(cells))
    except csv.Error:
        ctx.report.add("parse_error")


def _delimiter(head: str, *, complete: bool) -> str | None:
    """Tab or comma when the first rows all have the same number of fields, at least two."""
    lines = head.splitlines(keepends=True)
    if not complete and lines:
        lines = lines[:-1]  # the last line may be cut
    sample = "".join(line for line in lines if line.strip())
    for delimiter in ("\t", ","):
        try:
            reader = csv.reader(io.StringIO(sample), delimiter=delimiter, strict=True)
            rows = list(itertools.islice(reader, _SNIFF_ROWS))
        except csv.Error:
            continue
        widths = {len(row) for row in rows}
        if len(rows) >= 2 and len(widths) == 1 and widths.pop() >= 2:
            return delimiter
    return None
