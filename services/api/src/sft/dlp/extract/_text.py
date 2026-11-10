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
    """Decode `data`, which starts with `prefix`, and hand on its lines or rows.

    The file is read once, strictly, in the best candidate encoding (#166). Almost every file
    decodes all the way, and then this is the reading a check of the whole file first would have
    chosen, without decoding the file twice. Only a byte that doesn't decode costs more: the lines
    already handed on stay inspected, and the file is read again in the first other candidate
    that decodes all of it, handing on only the lines after them. A line is the same bytes in
    every candidate (no CR or LF byte is ever part of another character in them), so nothing is
    skipped that wasn't read; at worst the line the reading stopped in is inspected twice. If no
    candidate decodes all of it, the best one reads the rest with undecodable bytes replaced, and
    says so.
    """
    complete = len(prefix) < ctx.limits.prefix_bytes
    encodings = candidates(prefix, complete=complete)
    ctx.report.covered = True
    first = _Progress(ctx)
    try:
        _read(first, data, prefix, path, encodings[0], "strict", complete=complete)
        return
    except UnicodeDecodeError:
        pass
    encoding = _whole_file_encoding(data, encodings[1:])
    errors = "strict"
    if encoding is None:
        encoding, errors = encodings[0], "replace"
        ctx.report.add("parse_error")
    rest = _Progress(ctx, skip_through=first.done)
    _read(rest, data, prefix, path, encoding, errors, complete=complete)


class _Progress:
    """One reading's way through the file, counted in physical lines: `done` is the last line
    it handed on in full. A second reading passes over the units that end by `skip_through`."""

    def __init__(self, ctx: Context, skip_through: int = 0) -> None:
        self.ctx = ctx
        self.skip_through = skip_through
        self.done = 0

    def emit(
        self,
        last_line: int,
        path: tuple[str, ...],
        hint: str,
        text: str,
        cells: tuple[Cell, ...] = (),
    ) -> None:
        if last_line > self.skip_through:
            self.ctx.emit(path, hint, text, cells)


def _read(
    progress: _Progress,
    data: IO[bytes],
    prefix: bytes,
    path: tuple[str, ...],
    encoding: str,
    errors: str,
    *,
    complete: bool,
) -> None:
    head = prefix.decode(encoding, errors="ignore")
    delimiter = _delimiter(head, complete=complete)
    data.seek(0)
    stream = io.TextIOWrapper(data, encoding=encoding, errors=errors, newline="")
    try:
        if delimiter is None:
            _lines(progress, stream, path)
        else:
            _rows(progress, stream, path, delimiter)
    finally:
        stream.detach()


def _whole_file_encoding(data: IO[bytes], encodings: list[str]) -> str | None:
    """The first of `encodings` that decodes all of `data`, or None."""
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


def _lines(progress: _Progress, stream: io.TextIOWrapper, path: tuple[str, ...]) -> None:
    limits = progress.ctx.limits
    overlap = limits.unit_overlap_chars
    size = max(limits.max_unit_chars - overlap, 1)
    number = 0
    carry = ""  # the end of the piece before, when a line is longer than a unit
    cut = False
    after_cr = False  # the piece before was cut just after a CR
    while piece := stream.readline(size):
        if after_cr and piece == "\n":
            # The LF of a CRLF the cut split from its CR: the same line's end, not a new line.
            after_cr = False
            continue
        if not cut:
            number += 1
        progress.emit(number, path, f"line {number}", carry + piece.rstrip("\r\n"))
        cut = len(piece) == size and not piece.endswith(("\n", "\r"))
        after_cr = len(piece) == size and piece.endswith("\r")
        carry = piece[-overlap:] if cut and overlap else ""
        if not cut:
            progress.done = number


def _rows(
    progress: _Progress, stream: io.TextIOWrapper, path: tuple[str, ...], delimiter: str
) -> None:
    csv.field_size_limit(progress.ctx.limits.max_unit_chars)
    reader = csv.reader(stream, delimiter=delimiter, strict=False)
    header: list[str] | None = None
    number = 0
    try:
        for row in reader:
            number += 1
            if any(cell.strip() for cell in row):
                if header is None:
                    header = row
                cells: list[Cell] = []
                start = 0
                for column, value in enumerate(row):
                    name = header[column] if column < len(header) and row is not header else ""
                    cells.append(Cell(start=start, end=start + len(value), header=name))
                    start += len(value) + 1
                # A row may span lines (a quoted line break): it counts as read at its last.
                progress.emit(reader.line_num, path, f"row {number}", "\t".join(row), tuple(cells))
            progress.done = reader.line_num
    except csv.Error:
        progress.ctx.report.add("parse_error")


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
