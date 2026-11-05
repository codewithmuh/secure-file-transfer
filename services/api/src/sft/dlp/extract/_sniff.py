"""The type of a file or member, from its bytes only ([detectors] 1, T-96).

Never from a name or a declared type. A zip is told apart from an Office or OpenDocument file
later, from its part list, because that is at the end of the file.
"""

from __future__ import annotations

import codecs
import re
from enum import Enum
from typing import Final


class Kind(Enum):
    TEXT = "text"
    PDF = "pdf"
    ZIP = "zip"
    GZIP = "gzip"
    TAR = "tar"
    CFB = "cfb"  # OLE compound file: legacy Office binaries, or an encrypted Office file
    UNSUPPORTED = "unsupported"


# Types with no extractor in v1 that are cheaper to name than to try decoding ([detectors] 10).
_UNSUPPORTED_MAGIC: Final = (
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",  # JPEG
    b"GIF87a",
    b"GIF89a",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd",  # zstd
    b"\x7fELF",
    b"{\\rtf",
    b"OggS",
    b"fLaC",
    b"ID3",
    b"RIFF",
    b"II*\x00",  # TIFF
    b"MM\x00*",
)
_CFB: Final = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_LZH: Final = re.compile(rb"^..-l[hz][0-9a-z ]-", re.DOTALL)

# The escape sequences of ISO-2022-JP (RFC 1468) that switch to JIS X 0208 or JIS X 0201.
_ISO2022_ESCAPES: Final = (b"\x1b$B", b"\x1b$@", b"\x1b(J", b"\x1b(I")

_EMAIL_HEADERS: Final = frozenset(
    {
        "from",
        "to",
        "cc",
        "subject",
        "date",
        "message-id",
        "received",
        "mime-version",
        "return-path",
        "reply-to",
        "content-type",
        "delivered-to",
    }
)
_HEADER_LINE: Final = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):")


def sniff(prefix: bytes) -> Kind:
    """The kind of content from its first bytes (up to 64 KiB). Text is checked separately.

    The unambiguous container signatures come first (zip, gzip, compound file, tar), so a member
    or a file can't pass for a PDF by holding `%PDF-` early, such as a tar whose first member is
    named `%PDF-notes.csv`. Then a PDF header where a reader would find one (`pdf_header`).
    """
    if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return Kind.ZIP
    if prefix.startswith(b"\x1f\x8b"):
        return Kind.GZIP
    if prefix.startswith(_CFB):
        return Kind.CFB
    if len(prefix) >= 263 and prefix[257:262] == b"ustar":
        return Kind.TAR
    if pdf_header(prefix):
        return Kind.PDF
    if prefix.startswith(_UNSUPPORTED_MAGIC) or _LZH.match(prefix[:8]):
        return Kind.UNSUPPORTED
    if prefix[4:8] == b"ftyp":  # MP4, MOV, HEIC
        return Kind.UNSUPPORTED
    if text_encoding(prefix, complete=False) is not None and not is_email(prefix):
        return Kind.TEXT
    return Kind.UNSUPPORTED


_PDF_HEADER: Final = b"%PDF-"
_PDF_SEARCH: Final = 1024
_BLANK: Final = b" \t\r\n\x0c\x00"


def pdf_header(prefix: bytes) -> bool:
    """`%PDF-` where a PDF reader looks for it: at the start, or within the first 1,024 bytes
    after only the leading junk readers tolerate (white space, NULs, a byte order mark, or bytes
    that aren't text, such as a MacBinary header). After text, such as a CSV row that mentions
    `%PDF-`, it is text that names a PDF, not a PDF.
    """
    at = prefix.find(_PDF_HEADER, 0, _PDF_SEARCH + len(_PDF_HEADER))
    if at < 0 or at >= _PDF_SEARCH:
        return False
    lead = prefix[:at].removeprefix(codecs.BOM_UTF8)
    if not lead.strip(_BLANK):
        return True
    return text_encoding(lead, complete=False) is None


def candidates(prefix: bytes, *, complete: bool) -> list[str]:
    """The encodings the prefix decodes as text in, best first ([detectors] 2).

    A byte order mark decides alone. Otherwise: ISO-2022-JP when its escape sequences appear (its
    bytes are 7-bit, so it would pass as UTF-8 too); strict UTF-8; then CP932 and EUC-JP. Much
    EUC-JP text also decodes as CP932, as half-width katakana, so when both decode, the one that
    reads as fewer half-width katakana goes first.
    """
    if prefix.startswith(codecs.BOM_UTF8):
        return ["utf-8-sig"]
    if prefix.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return ["utf-16"]
    found: list[str] = []
    if any(escape in prefix for escape in _ISO2022_ESCAPES) and _decodes(
        prefix, "iso2022_jp", complete
    ):
        found.append("iso2022_jp")
    if _decodes(prefix, "utf-8", complete):
        found.append("utf-8")
    japanese = [enc for enc in ("cp932", "euc_jp") if _decodes(prefix, enc, complete)]
    if len(japanese) == 2 and _halfwidth(prefix, "euc_jp") < _halfwidth(prefix, "cp932"):
        japanese.reverse()
    return found + japanese


def text_encoding(prefix: bytes, *, complete: bool) -> str | None:
    """The best encoding for the prefix, or None when it is binary."""
    found = candidates(prefix, complete=complete)
    if not found:
        return None
    text = codecs.getincrementaldecoder(found[0])().decode(prefix, final=complete)
    return None if _binary(text) else found[0]


def is_email(prefix: bytes) -> bool:
    """An email file (RFC 5322 headers, or an mbox): no extractor in v1 ([detectors] 10)."""
    text = prefix[:8192].decode("latin-1")
    if text.startswith("From "):
        return True
    names = set()
    for line in text.splitlines():
        if not line.strip():
            break
        if line[:1] in (" ", "\t"):
            continue
        match = _HEADER_LINE.match(line)
        if match is None:
            return False
        names.add(match.group(1).lower())
    return len(names & _EMAIL_HEADERS) >= 3


def _decodes(data: bytes, encoding: str, complete: bool) -> bool:
    try:
        codecs.getincrementaldecoder(encoding)().decode(data, final=complete)
    except UnicodeDecodeError:
        return False
    return True


def _halfwidth(data: bytes, encoding: str) -> int:
    text = codecs.getincrementaldecoder(encoding)().decode(data, final=False)
    return sum(1 for char in text if "｡" <= char <= "ﾟ")


def _binary(text: str) -> bool:
    """NUL, or more than 1 % control characters other than tab, line breaks and escape."""
    if "\x00" in text:
        return True
    controls = sum(
        1 for char in text if (char < " " and char not in "\t\n\r\f\v\x1b") or char == "\x7f"
    )
    return controls * 100 > len(text)
