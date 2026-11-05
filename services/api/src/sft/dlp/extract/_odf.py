"""OpenDocument text, spreadsheets and presentations (`.odt`, `.ods`, `.odp`), and templates."""

from __future__ import annotations

import functools
import re
import zipfile
from collections.abc import Callable
from typing import Final

from sft.dlp.extract import _xml
from sft.dlp.extract._core import Context, CountingReader, MemberLimit, StopExtraction
from sft.dlp.extract._xml import (
    ODF_DRAW,
    ODF_OFFICE,
    ODF_PRESENTATION,
    ODF_STYLE,
    ODF_TABLE,
    ODF_TEXT,
)
from sft.dlp.units import Cell

_MIMETYPES: Final = {
    "application/vnd.oasis.opendocument.text": "text",
    "application/vnd.oasis.opendocument.text-template": "text",
    "application/vnd.oasis.opendocument.spreadsheet": "spreadsheet",
    "application/vnd.oasis.opendocument.spreadsheet-template": "spreadsheet",
    "application/vnd.oasis.opendocument.presentation": "presentation",
    "application/vnd.oasis.opendocument.presentation-template": "presentation",
}
_PARAGRAPHS: Final = [f"{{{ODF_TEXT}}}p", f"{{{ODF_TEXT}}}h"]
_HEADERS: Final = tuple(
    f"{{{ODF_STYLE}}}{name}"
    for name in ("header", "header-left", "header-first", "footer", "footer-left", "footer-first")
)
_REPEAT_CAP: Final = 1_048_576  # the most rows a spreadsheet has; repeats past it are ignored
_EMBEDDED: Final = re.compile(r"^(Object [^/]+)/content\.xml$")


def odf_kind(zf: zipfile.ZipFile) -> str | None:
    """ "text", "spreadsheet" or "presentation" from the `mimetype` member, or None."""
    try:
        info = zf.getinfo("mimetype")
    except KeyError:
        return None
    if info.file_size > 100:
        return None
    with zf.open(info) as raw:
        return _MIMETYPES.get(raw.read(100).decode("ascii", errors="replace").strip())


def encrypted(zf: zipfile.ZipFile) -> bool:
    """An OpenDocument file saved with a password lists its encryption in the manifest."""
    try:
        info = zf.getinfo("META-INF/manifest.xml")
    except KeyError:
        return False
    with zf.open(info) as raw:
        return b"encryption-data" in raw.read(4 * 1024 * 1024)


def extract_odf(ctx: Context, zf: zipfile.ZipFile, kind: str, path: tuple[str, ...]) -> None:
    if encrypted(zf):
        ctx.report.add("encrypted")
        return
    names = {info.filename: info for info in zf.infolist() if not info.is_dir()}

    def each(name: str, read: Callable[[CountingReader], None]) -> None:
        info = names.get(name)
        if info is None:
            return
        ctx.budget.member()
        try:
            with zf.open(info) as raw:
                read(CountingReader(raw, ctx.budget, info.compress_size))
        except MemberLimit:
            ctx.report.add("limit_exceeded")
        except StopExtraction:
            raise
        except Exception:
            ctx.report.add("parse_error")
        else:
            ctx.report.covered = True

    if kind == "spreadsheet":
        each("content.xml", functools.partial(_spreadsheet, ctx, path))
    elif kind == "presentation":
        each("content.xml", functools.partial(_presentation, ctx, path))
    else:
        each("content.xml", functools.partial(_text, ctx, path, ""))
    each("styles.xml", functools.partial(_headers, ctx, path))
    each("meta.xml", functools.partial(_leaves, ctx, path, "document properties"))
    for name in sorted(names):
        if _EMBEDDED.match(name):
            each(name, functools.partial(_text, ctx, path, "embedded object"))


def _leaves(ctx: Context, path: tuple[str, ...], hint: str, reader: CountingReader) -> None:
    for text in _xml.leaf_texts(reader):
        ctx.emit(path, hint, text)


def _done(element: _xml.Element) -> None:
    if _xml.nested_in(element, *_PARAGRAPHS):
        element.clear(keep_tail=True)
    else:
        _xml.release(element)


def _text(ctx: Context, path: tuple[str, ...], hint: str, reader: CountingReader) -> None:
    number = 0
    for element in _xml.iterparse(reader, _PARAGRAPHS):
        text = _xml.odf_text(element)
        if text.strip():
            number += 1
            ctx.emit(path, hint or f"paragraph {number}", text)
        _done(element)


def _headers(ctx: Context, path: tuple[str, ...], reader: CountingReader) -> None:
    for element in _xml.iterparse(reader, _PARAGRAPHS):
        header = next(element.iterancestors(*_HEADERS), None)
        if header is not None:
            ctx.emit(
                path,
                "header" if "header" in _xml.local(header) else "footer",
                _xml.odf_text(element),
            )
        _done(element)


def _presentation(ctx: Context, path: tuple[str, ...], reader: CountingReader) -> None:
    page, number = None, 0
    for element in _xml.iterparse(reader, _PARAGRAPHS):
        current = next(element.iterancestors(f"{{{ODF_DRAW}}}page"), None)
        if current is not None and current is not page:
            page, number = current, number + 1
        notes = _xml.nested_in(element, f"{{{ODF_PRESENTATION}}}notes")
        hint = (
            f"slide {number}, notes" if notes else f"slide {number}" if number else "presentation"
        )
        ctx.emit(path, hint, _xml.odf_text(element))
        _done(element)


def _repeat(element: _xml.Element, attribute: str) -> int:
    value = element.get(f"{{{ODF_TABLE}}}{attribute}") or "1"
    return min(int(value), _REPEAT_CAP) if value.isdigit() and int(value) > 0 else 1


def _cell_text(cell: _xml.Element) -> str:
    value_type = cell.get(f"{{{ODF_OFFICE}}}value-type")
    raw = cell.get(f"{{{ODF_OFFICE}}}value")
    if value_type in ("float", "percentage", "currency") and raw:
        return str(raw)  # the stored number, not its display form ("1.23E+11")
    paragraphs = cell.iterdescendants(*_PARAGRAPHS)
    return "\n".join(_xml.odf_text(paragraph) for paragraph in paragraphs)


def _spreadsheet(ctx: Context, path: tuple[str, ...], reader: CountingReader) -> None:
    """Rows in order; the first non-empty row of each sheet is its header."""
    table, name, number, header = None, "", 0, None
    heading: dict[int, str]
    for row in _xml.iterparse(reader, [f"{{{ODF_TABLE}}}table-row"]):
        current = next(row.iterancestors(f"{{{ODF_TABLE}}}table"), None)
        if current is not table:
            table, number, header = current, 0, None
            name = current.get(f"{{{ODF_TABLE}}}name") or "" if current is not None else ""
            ctx.emit(path, "sheet names", name)
        rows = _repeat(row, "number-rows-repeated")
        values: list[tuple[int, str]] = []
        column = 0
        for cell in row:
            if _xml.local(cell) not in ("table-cell", "covered-table-cell"):
                continue
            text = _cell_text(cell)
            if text.strip():
                values.append((column, text))
            column += _repeat(cell, "number-columns-repeated")
        _xml.release(row)
        number += 1
        first = number
        number += rows - 1
        if not values:
            continue
        if header is None:
            header, heading = dict(values), {}
        else:
            heading = header
        cells, start = [], 0
        for col, value in values:
            cells.append(Cell(start=start, end=start + len(value), header=heading.get(col, "")))
            start += len(value) + 1
        ctx.emit(
            path, f'sheet "{name}", row {first}', "\t".join(v for _, v in values), tuple(cells)
        )
