"""Office Open XML: `.docx`, `.xlsx`, `.pptx` and their macro-enabled and template forms.

Parts are read as XML one at a time, streamed ([detectors] 2). Embedded files are members, one
level of nesting deeper. Parts that hold no text people wrote (styles, themes, settings, layouts
and masters) and media are skipped without a reason: v1 inspects no images (R-17).
"""

from __future__ import annotations

import functools
import posixpath
import re
import zipfile
from collections.abc import Callable
from typing import Final

from sft.dlp.extract import _xml
from sft.dlp.extract._core import Context, CountingReader, MemberLimit, StopExtraction
from sft.dlp.extract._xml import Element
from sft.dlp.units import Cell

_MAIN_TYPES: Final = (
    (
        "word",
        re.compile(
            r"wordprocessingml\.(document|template)\.main|ms-word\.(document|template)\.macroenabled"
        ),
    ),
    (
        "excel",
        re.compile(
            r"spreadsheetml\.(sheet|template)\.main|ms-excel\.(sheet|template)\.macroenabled\.main"
        ),
    ),
    (
        "powerpoint",
        re.compile(
            r"presentationml\.(presentation|slideshow|template)\.main|ms-powerpoint\.(presentation|slideshow|template)\.macroenabled"
        ),
    ),
    ("binary", re.compile(r"ms-excel\.sheet\.binary")),
)

_EMBEDDINGS: Final = re.compile(r"^(word|xl|ppt)/embeddings/[^/]+$")
_PROPERTIES: Final = re.compile(r"^docProps/(core|app|custom)\.xml$")
_CHART: Final = re.compile(r"^(word|xl|ppt)/charts/chart[^/]*\.xml$")
_DIAGRAM: Final = re.compile(r"^(word|xl|ppt)/diagrams/data[^/]*\.xml$")
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def office_kind(ctx: Context, zf: zipfile.ZipFile) -> str | None:
    """ "word", "excel", "powerpoint" or "binary" from the content types part, or None.

    The part is a member like any other: it counts against the member limit, the decompressed
    bytes and its own ratio, so a bomb here stops as one anywhere else would (`MemberLimit`,
    `StopExtraction`).
    """
    try:
        info = zf.getinfo("[Content_Types].xml")
    except KeyError:
        return None
    ctx.budget.member()
    with zf.open(info) as raw:
        reader = CountingReader(raw, ctx.budget, info.compress_size)
        for element in _xml.iterparse(reader, ["{*}Override"]):
            content_type = (element.get("ContentType") or "").lower()
            for kind, pattern in _MAIN_TYPES:
                if pattern.search(content_type):
                    return kind
            _xml.release(element)
    return None


class _Package:
    """One Office file being read: its parts, relationships and the context."""

    def __init__(
        self, ctx: Context, zf: zipfile.ZipFile, depth: int, path: tuple[str, ...]
    ) -> None:
        self.ctx = ctx
        self.zf = zf
        self.depth = depth
        self.path = path
        self.names = {info.filename: info for info in zf.infolist() if not info.is_dir()}
        self.read: set[str] = set()

    def part(self, name: str) -> CountingReader | None:
        info = self.names.get(name)
        if info is None or info.flag_bits & 0x1:
            return None
        self.ctx.budget.member()
        self.read.add(name)
        return CountingReader(self.zf.open(info), self.ctx.budget, info.compress_size)

    def each(self, name: str, read: Callable[[CountingReader], None], *, text: bool = True) -> None:
        """Read one part; a part that fails is a `parse_error`, the others still count.

        Only a part that holds text people wrote (`text`) makes the file covered: a package whose
        relationships and structure parts read but whose text parts all fail is `not_inspected`.
        """
        reader = self.part(name)
        if reader is None:
            return
        try:
            read(reader)
        except MemberLimit:
            self.ctx.report.add("limit_exceeded")
        except StopExtraction:
            raise
        except Exception:
            self.ctx.report.add("parse_error")
        else:
            if text:
                self.ctx.report.covered = True

    def relationships(self, part: str) -> dict[str, tuple[str, str]]:
        """Relationship ID -> (type, part name) for `part`, internal targets only."""
        folder, base = posixpath.split(part)
        rels = posixpath.join(folder, "_rels", base + ".rels")
        out: dict[str, tuple[str, str]] = {}

        def read(reader: CountingReader) -> None:
            for element in _xml.iterparse(reader, ["{*}Relationship"]):
                if element.get("TargetMode") != "External":
                    target = element.get("Target") or ""
                    if target.startswith("/"):
                        name = target.lstrip("/")
                    else:
                        name = posixpath.normpath(posixpath.join(folder, target))
                    out[element.get("Id") or ""] = (element.get("Type") or "", name)
                _xml.release(element)

        self.each(rels, read, text=False)
        return out

    def paragraphs(self, name: str, hint: str) -> None:
        """Each paragraph (`w:p` or `a:p`) of a part as a unit; `{n}` in `hint` numbers them."""
        ctx, path = self.ctx, self.path

        def read(reader: CountingReader) -> None:
            number = 0
            for element in _xml.iterparse(reader, ["{*}p"]):
                text = _xml.ooxml_text(element)
                if text.strip():
                    number += 1
                    ctx.emit(path, hint.replace("{n}", str(number)), text)
                if _xml.nested_in(element, "{*}p"):
                    element.clear(keep_tail=True)
                else:
                    _xml.release(element)

        self.each(name, read)

    def leaves(self, name: str, hint: str) -> None:
        """Each element's text as its own unit: document properties, chart labels."""

        def read(reader: CountingReader) -> None:
            for text in _xml.leaf_texts(reader):
                self.ctx.emit(self.path, hint, text)

        self.each(name, read)

    def common(self) -> None:
        """What every Office file has: properties, charts, diagrams and embedded files."""
        for name in sorted(self.names):
            if name in self.read:
                continue
            if _PROPERTIES.match(name):
                self.leaves(name, "document properties")
            elif _CHART.match(name):
                self.leaves(name, "chart")
            elif _DIAGRAM.match(name):
                self.paragraphs(name, "diagram")
        for name in sorted(self.names):
            if _EMBEDDINGS.match(name):
                self.embedded(name)

    def embedded(self, name: str) -> None:
        reader = self.part(name)
        if reader is None:
            self.ctx.report.add("encrypted")
            return
        try:
            with self.ctx.spool(reader) as member:
                self.ctx.nested(member, self.depth + 1, (*self.path, name))
        except MemberLimit:
            self.ctx.report.add("limit_exceeded")


def extract_office(
    ctx: Context, zf: zipfile.ZipFile, kind: str, depth: int, path: tuple[str, ...]
) -> None:
    """Read an Office file whose parts are one container level below `depth`."""
    if kind == "binary":  # .xlsb: binary parts, no extractor in v1
        ctx.report.add("unsupported_type")
        return
    package = _Package(ctx, zf, depth, path)
    {"word": _word, "excel": _excel, "powerpoint": _powerpoint}[kind](package)
    package.common()


def _main_part(package: _Package, fallback: str) -> str:
    root = package.relationships("")
    for rel_type, name in root.values():
        if rel_type.endswith("/officeDocument"):
            return name
    return fallback


# ---- Word ----

_WORD_PARTS: Final = (
    (re.compile(r"^word/header[^/]*\.xml$"), "header"),
    (re.compile(r"^word/footer[^/]*\.xml$"), "footer"),
    (re.compile(r"^word/footnotes\.xml$"), "footnotes"),
    (re.compile(r"^word/endnotes\.xml$"), "endnotes"),
    (re.compile(r"^word/comments\.xml$"), "comments"),
)


def _word(package: _Package) -> None:
    main = _main_part(package, "word/document.xml")
    package.paragraphs(main, "paragraph {n}")
    for name in sorted(package.names):
        for pattern, hint in _WORD_PARTS:
            if pattern.match(name):
                package.paragraphs(name, hint)


# ---- Excel ----


def _excel(package: _Package) -> None:
    ctx = package.ctx
    workbook = _main_part(package, "xl/workbook.xml")
    rels = package.relationships(workbook)
    sheets: list[tuple[str, str]] = []

    def read_workbook(reader: CountingReader) -> None:
        for element in _xml.iterparse(reader, ["{*}sheet"]):
            target = rels.get(element.get(f"{{{_REL}}}id") or "")
            name = element.get("name") or ""
            if target is not None:
                sheets.append((name, target[1]))
            _xml.release(element)

    package.each(workbook, read_workbook)
    for name, _part in sheets:
        ctx.emit(package.path, "sheet names", name)
    shared: list[str] = []
    for rel_type, part in rels.values():
        if rel_type.endswith("/sharedStrings"):
            package.each(part, functools.partial(_shared_strings, shared))
    for name, part in sheets:
        package.each(part, functools.partial(_sheet, package, name, shared))
    for part in sorted(package.names):
        if re.match(r"^xl/comments[^/]*\.xml$", part):
            _comments(package, part, "{*}comment")
        elif re.match(r"^xl/threadedComments/[^/]+\.xml$", part):
            _comments(package, part, "{*}threadedComment")
        elif re.match(r"^xl/drawings/drawing[^/]*\.xml$", part):
            package.paragraphs(part, "drawing")
        elif re.match(r"^xl/(pivotCache|externalLinks)/[^/]+\.xml$", part):
            _values(package, part)


def _shared_strings(out: list[str], reader: CountingReader) -> None:
    for element in _xml.iterparse(reader, ["{*}si"]):
        out.append(_xml.ooxml_text(element))
        _xml.release(element)


def _column(reference: str | None) -> int | None:
    """The 0-based column of a cell reference such as "BC12"."""
    if not reference:
        return None
    letters = re.match(r"[A-Z]{1,3}", reference)
    if letters is None:
        return None
    number = 0
    for char in letters.group(0):
        number = number * 26 + ord(char) - 64
    return number - 1


def _cell_value(cell: Element, shared: list[str]) -> str:
    kind = cell.get("t")
    if kind == "inlineStr":
        inline = next(cell.iterchildren("{*}is"), None)
        return _xml.ooxml_text(inline) if inline is not None else ""
    value = next(cell.iterchildren("{*}v"), None)
    text = value.text if value is not None and value.text else ""
    if kind == "s":
        return shared[int(text)] if text.isdigit() and int(text) < len(shared) else ""
    return text


def _sheet(package: _Package, name: str, shared: list[str], reader: CountingReader) -> None:
    """Rows in order, so each cell knows its column's header: the first non-empty row."""
    header: dict[int, str] | None = None
    number = 0
    for row in _xml.iterparse(reader, ["{*}row"]):
        number = int(row.get("r")) if (row.get("r") or "").isdigit() else number + 1
        values: list[tuple[int, str]] = []
        column = -1
        for cell in row.iterchildren("{*}c"):
            found = _column(cell.get("r"))
            column = found if found is not None else column + 1
            value = _cell_value(cell, shared)
            if value.strip():
                values.append((column, value))
        _xml.release(row)
        if not values:
            continue
        if header is None:
            header = dict(values)
            heading: dict[int, str] = {}
        else:
            heading = header
        cells, start = [], 0
        for column, value in values:
            cells.append(Cell(start=start, end=start + len(value), header=heading.get(column, "")))
            start += len(value) + 1
        package.ctx.emit(
            package.path,
            f'sheet "{name}", row {number}',
            "\t".join(v for _, v in values),
            tuple(cells),
        )


def _comments(package: _Package, part: str, tag: str) -> None:
    def read(reader: CountingReader) -> None:
        for element in _xml.iterparse(reader, [tag]):
            text = _xml.ooxml_text(element) or "".join(element.itertext())
            package.ctx.emit(package.path, "comments", text)
            _xml.release(element)

    package.each(part, read)


def _values(package: _Package, part: str) -> None:
    """Pivot caches and external link caches keep copies of cell values, in `v` attributes."""

    def read(reader: CountingReader) -> None:
        buffer: list[str] = []
        for element in _xml.iterparse(reader):
            value = element.get("v")
            if value:
                buffer.append(value)
            if element.text and element.text.strip() and len(element) == 0:
                buffer.append(element.text)
            if len(buffer) >= 64 or (buffer and _xml.local(element) in ("r", "row", "cacheField")):
                package.ctx.emit(package.path, "cached values", "\t".join(buffer))
                buffer = []
            _xml.release(element)
        if buffer:
            package.ctx.emit(package.path, "cached values", "\t".join(buffer))

    package.each(part, read)


# ---- PowerPoint ----


def _powerpoint(package: _Package) -> None:
    presentation = _main_part(package, "ppt/presentation.xml")
    rels = package.relationships(presentation)
    slides: list[str] = []

    def read(reader: CountingReader) -> None:
        for element in _xml.iterparse(reader, ["{*}sldId"]):
            target = rels.get(element.get(f"{{{_REL}}}id") or "")
            if target is not None:
                slides.append(target[1])
            _xml.release(element)

    package.each(presentation, read, text=False)  # the slide list: structure, no text
    for number, slide in enumerate(slides, start=1):
        package.paragraphs(slide, f"slide {number}")
        for rel_type, part in package.relationships(slide).values():
            if rel_type.endswith("/notesSlide"):
                package.paragraphs(part, f"slide {number}, notes")
            elif rel_type.endswith("/comments"):
                _comments(package, part, "{*}cm")
    for part in sorted(package.names):
        if re.match(r"^ppt/comments/[^/]+\.xml$", part) and part not in package.read:
            _comments(package, part, "{*}cm")
