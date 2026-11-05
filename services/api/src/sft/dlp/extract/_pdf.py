"""PDF text layers through PDFium (`pypdfium2`), page by page ([detectors] 2).

The PyPI wheels are PDFium builds without V8 or XFA, so no script in a PDF runs (ADR-0022). A page
with no text but with an image is a scan: `no_text`, as v1 has no OCR. A page with neither is blank
and needs no reason.
"""

from __future__ import annotations

from typing import IO

import pypdfium2 as pdfium
import pypdfium2.raw as pdfium_c

from sft.dlp.extract._core import Context, StopExtraction, chunks


def extract_pdf(ctx: Context, data: IO[bytes], path: tuple[str, ...]) -> bool:
    """Read a PDF's pages. False when PDFium can't open it at all, for a reason other than a
    password: the caller decides what it is then (text that starts like a PDF, or a parse error)."""
    try:
        document = pdfium.PdfDocument(data)
    except pdfium.PdfiumError as exc:
        if exc.err_code == pdfium_c.FPDF_ERR_PASSWORD:
            ctx.report.add("encrypted")
            return True
        return False
    try:
        pages = len(document)
        if pages > ctx.limits.max_pdf_pages:
            ctx.report.add("limit_exceeded")
        for index in range(min(pages, ctx.limits.max_pdf_pages)):
            try:
                _page(ctx, document, index, path)
            except StopExtraction:
                raise
            except Exception:
                ctx.report.add("parse_error")
    finally:
        document.close()
    return True


def _page(ctx: Context, document: pdfium.PdfDocument, index: int, path: tuple[str, ...]) -> None:
    page = document[index]
    try:
        textpage = page.get_textpage()
        try:
            text = textpage.get_text_bounded()
        finally:
            textpage.close()
        if text.strip():
            ctx.report.covered = True
            hint = f"page {index + 1}"
            limits = ctx.limits
            for piece in chunks(text, limits.max_unit_chars, limits.unit_overlap_chars):
                ctx.emit(path, hint, piece)
        elif next(page.get_objects(filter=[pdfium_c.FPDF_PAGEOBJ_IMAGE], max_depth=4), None):
            ctx.report.add("no_text")
    finally:
        page.close()
