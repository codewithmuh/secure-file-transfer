"""The detectors that read line by line, across units: `private_key` and `passport_mrz` ([DLP] 4,
4.6).

A text file is extracted one line per unit, so a PEM block or a machine-readable zone spans several
units. These detectors keep a little state between lines: the open block, or the previous line. A
block is bounded (64 KiB, 2,000 lines); past that it is dropped, so a stray BEGIN line can't make
the scanner hold a file.

`private_key`:

- PEM blocks whose label ends in `PRIVATE KEY` (PKCS #1, SEC 1, PKCS #8, encrypted PKCS #8,
  OpenSSH). The base64 body must decode; a DER body must start with a SEQUENCE, an OpenSSH body with
  its magic.
- PGP private key blocks: armour headers skipped, the body decodes to an OpenPGP packet.
- PuTTY private key files: the `Private-Lines` that follow their count decode.
- The same blocks inside JSON strings, with `\\n` for the line breaks, and blocks flattened onto one
  line.

The preview is the key's kind only (section 7).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field

from sft.dlp.detect import checks
from sft.dlp.detect.prepared import HIGH, Hit, Prepared
from sft.dlp.detect.regex import Regex

PRIVATE_KEY = "private_key"
PASSPORT_MRZ = "passport_mrz"

_MAX_BLOCK_CHARS = 64 * 1024
_MAX_BLOCK_LINES = 2000

# Written so that no source line holds a literal key header (the detect-private-key hook reads this
# file too).
_PRIVATE = "PRIVATE " + "KEY"
_BEGIN = Regex(
    r"-----BEGIN ((?:[A-Z0-9]+ )*)" + _PRIVATE + "-----"
    r"|-----BEGIN (PGP " + _PRIVATE + " BLOCK)-----"
    r"|(PuTTY-User-Key-File-[23]): *[A-Za-z0-9@.-]+"
)
_MRZ_1 = Regex(r"P[A-Z0-9<]{43}")
_MRZ_2 = Regex(r"[A-Z0-9<]{44}")

_KINDS = {
    "RSA ": "RSA private key",
    "EC ": "EC private key",
    "DSA ": "DSA private key",
    "": "PKCS #8 private key",
    "ENCRYPTED ": "Encrypted PKCS #8 private key",
    "OPENSSH ": "OpenSSH private key",
}
_OPENSSH_MAGIC = b"openssh-key-v1\x00"


@dataclass(slots=True)
class _Block:
    kind: str  # "pem", "pgp" or "putty"
    label: str
    location: str
    lines: list[str] = field(default_factory=list)
    chars: int = 0


def _pem_body_ok(label: str, lines: list[str]) -> bytes | None:
    body = [line for line in lines if ":" not in line]
    decoded = checks.decode_base64("".join(body))
    if not decoded or len(decoded) < 16:
        return None
    if label == "OPENSSH ":
        return decoded if decoded.startswith(_OPENSSH_MAGIC) else None
    return decoded if decoded[0] == 0x30 else None


def _pgp_body_ok(lines: list[str]) -> bytes | None:
    body = [
        line
        for line in lines
        if ":" not in line and not (line.startswith("=") and len(line.strip()) == 5)
    ]
    decoded = checks.decode_base64("".join(body))
    if not decoded or len(decoded) < 16:
        return None
    return decoded if decoded[0] & 0x80 else None


def _putty_body_ok(lines: list[str]) -> bytes | None:
    for index, line in enumerate(lines):
        if line.startswith("Private-Lines:"):
            count = line.split(":", 1)[1].strip()
            if not count.isdigit() or not 0 < int(count) <= 200:
                return None
            body = lines[index + 1 : index + 1 + int(count)]
            decoded = checks.decode_base64("".join(body))
            return decoded if decoded else None
    return None


class BlockDetector:
    """Feeds each unit's lines to the private key and MRZ state machines."""

    def __init__(self) -> None:
        self._block: _Block | None = None
        self._mrz_line_1: tuple[str, str] | None = None  # (line, location)

    def feed(self, unit: Prepared) -> Iterator[tuple[Hit, str]]:
        # JSON key files hold the PEM block in a string with "\n" escapes.
        for line in unit.text.replace("\\n", "\n").split("\n"):
            line = line.strip()
            yield from self._mrz(line, unit.location)
            yield from self._keys(line, unit.location)

    def _mrz(self, line: str, location: str) -> Iterator[tuple[Hit, str]]:
        previous = self._mrz_line_1
        self._mrz_line_1 = (line, location) if _MRZ_1.fullmatch(line) else None
        if previous is None or not _MRZ_2.fullmatch(line) or not checks.mrz_line_2_ok(line):
            return
        line_1, line_1_location = previous
        country = line_1[2:5].replace("<", "")
        document = line[0:9].rstrip("<")
        preview = f"{country}, document number ending {document[-3:]}"
        yield Hit(PASSPORT_MRZ, HIGH, line_1[2:5] + line[0:9], preview), line_1_location
        self._mrz_line_1 = None

    def _keys(self, line: str, location: str) -> Iterator[tuple[Hit, str]]:
        while line:
            if self._block is None:
                span = _BEGIN.search(line)
                if span is None:
                    return
                pem, pgp, putty = span.groups
                if putty is not None:
                    self._block = _Block("putty", putty, location)
                    return
                self._block = _Block(
                    "pgp" if pgp is not None else "pem", pgp or pem or "", location
                )
                line = line[span.end :].strip()
                continue
            block = self._block
            end_marker = self._end_marker(block)
            if end_marker is not None and end_marker in line:
                before, _, after = line.partition(end_marker)
                block.lines.extend(before.split())
                yield from self._finish(block)
                line = after.strip()
                continue
            if block.kind == "putty" and line.startswith("Private-MAC:"):
                yield from self._finish(block)
                return
            block.lines.append(line)
            block.chars += len(line)
            if block.chars > _MAX_BLOCK_CHARS or len(block.lines) > _MAX_BLOCK_LINES:
                self._block = None
            return

    @staticmethod
    def _end_marker(block: _Block) -> str | None:
        if block.kind == "putty":
            return None
        label = block.label if block.kind == "pgp" else block.label + _PRIVATE
        return f"-----END {label}-----"

    def _finish(self, block: _Block) -> Iterator[tuple[Hit, str]]:
        self._block = None
        if block.kind == "pem":
            decoded = _pem_body_ok(block.label, block.lines)
            kind = _KINDS.get(block.label, f"{block.label.strip()} private key".capitalize())
        elif block.kind == "pgp":
            decoded = _pgp_body_ok(block.lines)
            kind = "PGP private key"
        else:
            decoded = _putty_body_ok(block.lines)
            kind = "PuTTY private key"
        if decoded is not None:
            yield Hit(PRIVATE_KEY, HIGH, decoded.hex(), kind), block.location
