"""Text extraction for the DLP inspector (ADR-0022, [detectors] 1 and 2).

`extract` reads one file and hands each unit of raw text, with its location hint, to the
detectors, within the limits of `sft.dlp.limits`; it returns the file's state and the reasons for
anything not fully inspected. `early_stop` is the decision on the first 64 KiB. Both run only in
the sandboxed child (`sft.dlp.sandbox`): they parse hostile bytes.

| Format | Recognised by | Extractor |
|---|---|---|
| Text, CSV, TSV | Decodes as UTF-8, UTF-16 with a BOM, ISO-2022-JP, CP932 or EUC-JP | `_text` |
| Word, Excel, PowerPoint | A zip whose content types part names their main part | `_office` |
| OpenDocument | A zip whose `mimetype` member names text, spreadsheet or presentation | `_odf` |
| PDF | `%PDF-` | `_pdf` |
| Zip, gzip, tar | Their headers | `_archive`, then each member as its own type |

Everything else gets a reason, never a pass: images, audio, video, executables, legacy Office
binaries, RTF, 7z, RAR, LZH, bzip2, xz and email files are `unsupported_type`; encrypted content is
`encrypted`; a PDF page that is only an image is `no_text`.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import IO, Final

from sft.dlp.extract import _archive, _odf, _office, _pdf, _text
from sft.dlp.extract._core import (
    Budget,
    Context,
    DetectorFailure,
    Emit,
    MemberLimit,
    StopExtraction,
)
from sft.dlp.extract._sniff import Kind, is_email, sniff, text_encoding
from sft.dlp.limits import Limits
from sft.dlp.protocol import Reason, State

__all__ = ["EXTRACT_VERSION", "DetectorFailure", "Emit", "Outcome", "early_stop", "extract"]

EXTRACT_VERSION: Final = "1"
"""Part of the inspection engine version: changes with any change to what is extracted."""

# "EncryptedPackage" in UTF-16LE: the stream an encrypted Office file keeps its package in.
_ENCRYPTED_PACKAGE: Final = "EncryptedPackage".encode("utf-16-le")
_SEARCH_CHUNK: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Outcome:
    state: State
    reasons: tuple[Reason, ...]


def early_stop(prefix: bytes) -> Reason | None:
    """The reason to stop reading after the prefix, or None to read the rest (architecture 4.6)."""
    return "unsupported_type" if sniff(prefix) is Kind.UNSUPPORTED else None


def extract(data: IO[bytes], *, emit: Emit, limits: Limits, scratch_dir: Path) -> Outcome:
    """Extract the whole of `data`, a seekable file, into `emit`.

    Raises DetectorFailure if `emit` raises. Everything a file can cause ends in an Outcome.
    """
    ctx = Context(limits=limits, emit_unit=emit, scratch_dir=scratch_dir, budget=Budget(limits))
    ctx.nested = lambda member, depth, path: _dispatch(ctx, member, depth, path)
    try:
        _dispatch(ctx, data, 0, ())
    except StopExtraction:
        ctx.report.add("limit_exceeded")
    except MemoryError:
        ctx.report.add("limit_exceeded")
    reasons = tuple(ctx.report.reasons)
    if not reasons:
        state: State = "inspected"
    elif ctx.report.covered or "limit_exceeded" in reasons:
        state = "partial"
    else:
        state = "not_inspected"
    return Outcome(state=state, reasons=reasons)


def _size(data: IO[bytes]) -> int:
    position = data.tell()
    size = data.seek(0, 2)
    data.seek(position)
    return size


def _dispatch(ctx: Context, data: IO[bytes], depth: int, path: tuple[str, ...]) -> None:
    """Read one file or member as the type its bytes say."""
    data.seek(0)
    prefix = data.read(ctx.limits.prefix_bytes)
    data.seek(0)
    kind = sniff(prefix)
    try:
        if kind is Kind.TEXT:
            _text.extract_text(ctx, data, prefix, path)
        elif kind is Kind.PDF:
            if not _pdf.extract_pdf(ctx, data, path):
                _not_a_pdf(ctx, data, prefix, path)
        elif kind is Kind.CFB:
            ctx.report.add("encrypted" if _encrypted_office(data) else "unsupported_type")
        elif kind is Kind.UNSUPPORTED:
            ctx.report.add("unsupported_type")
        elif depth + 1 > ctx.limits.max_depth:
            ctx.report.add("limit_exceeded")
        elif kind is Kind.GZIP:
            _archive.extract_gzip(ctx, data, _size(data), depth, path)
        elif kind is Kind.TAR:
            _archive.extract_tar(ctx, data, depth, path)
        else:
            _zip(ctx, data, depth, path)
    except (StopExtraction, DetectorFailure, MemoryError):
        raise
    except MemberLimit:
        ctx.report.add("limit_exceeded")
    except Exception:
        ctx.report.add("parse_error")


def _not_a_pdf(ctx: Context, data: IO[bytes], prefix: bytes, path: tuple[str, ...]) -> None:
    """PDFium couldn't open what started like a PDF: a `parse_error`. If it reads as text (a note
    that begins `%PDF-`, or a broken PDF with no binary part), its text is inspected too, so a
    header can't hide content from the detectors; the file is then `partial`."""
    ctx.report.add("parse_error")
    complete = len(prefix) < ctx.limits.prefix_bytes
    if text_encoding(prefix, complete=complete) is not None and not is_email(prefix):
        data.seek(0)
        _text.extract_text(ctx, data, prefix, path)


def _zip(ctx: Context, data: IO[bytes], depth: int, path: tuple[str, ...]) -> None:
    with _archive.open_zip(data) as zf:
        kind = _office.office_kind(ctx, zf)
        if kind is not None:
            _office.extract_office(ctx, zf, kind, depth, path)
            return
        odf = _odf.odf_kind(zf)
        if odf is not None:
            _odf.extract_odf(ctx, zf, odf, path)
            return
        _archive.extract_zip(ctx, zf, depth, path)


def _encrypted_office(data: IO[bytes]) -> bool:
    """An Office file saved with a password is a compound file holding an `EncryptedPackage`."""
    data.seek(0)
    tail = b""
    while chunk := data.read(_SEARCH_CHUNK):
        if _ENCRYPTED_PACKAGE in tail + chunk:
            return True
        tail = chunk[-len(_ENCRYPTED_PACKAGE) :]
    return False
