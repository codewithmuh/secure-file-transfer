"""What every extractor shares: the per-file budget, the report of reasons, and the context."""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Final, Protocol

from sft.dlp.limits import Limits
from sft.dlp.protocol import MAX_LOCATION_CHARS, Reason
from sft.dlp.units import Cell, TextUnit

_COPY_CHUNK: Final = 1024 * 1024


class StopExtraction(BaseException):
    """A limit for the whole file was passed: nothing more is read, the file is `partial`.

    A BaseException, so the broad `except Exception` that turns a parser's failure into
    `parse_error` can't swallow it.
    """


class MemberLimit(Exception):  # noqa: N818
    """A limit for one member or container was passed (ratio, nesting, pages): skip just that."""


class DetectorFailure(BaseException):
    """The detectors raised: an engine error for the whole file, never a parse error."""


@dataclass
class Report:
    """The reasons so far, and whether any content was read at all."""

    reasons: list[Reason] = field(default_factory=list)
    covered: bool = False

    def add(self, reason: Reason) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)


@dataclass
class Budget:
    """The per-file counters behind the limits of ADR-0022 that add up across the file."""

    limits: Limits
    members: int = 0
    decompressed: int = 0
    text_chars: int = 0
    scratch: int = 0

    def member(self) -> None:
        self.members += 1
        if self.members > self.limits.max_members:
            raise StopExtraction("members")

    def decompress(self, count: int) -> None:
        self.decompressed += count
        if self.decompressed > self.limits.max_decompressed_bytes:
            raise StopExtraction("decompressed bytes")

    def disk(self, count: int) -> None:
        self.scratch += count
        if self.scratch > self.limits.scratch_bytes:
            raise StopExtraction("scratch")


class Readable(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


class CountingReader:
    """A member's decompressed stream, counted against the budget and the member's ratio."""

    def __init__(self, raw: Readable, budget: Budget, compressed: int | None) -> None:
        self._raw = raw
        self._budget = budget
        self._compressed = compressed
        self.count = 0

    def read(self, size: int = -1, /) -> bytes:
        limits = self._budget.limits
        if size is None or size < 0 or size > _COPY_CHUNK:
            size = _COPY_CHUNK
        data = self._raw.read(size)
        self.count += len(data)
        self._budget.decompress(len(data))
        if (
            self._compressed is not None
            and self.count > limits.ratio_grace_bytes
            and self.count > limits.max_ratio * max(self._compressed, 1)
        ):
            raise MemberLimit("ratio")
        return data


Emit = Callable[[TextUnit], None]
Nested = Callable[[IO[bytes], int, tuple[str, ...]], None]


def _no_nesting(_data: IO[bytes], _depth: int, _path: tuple[str, ...]) -> None:
    raise RuntimeError("Context.nested isn't set")  # pragma: no cover


@dataclass
class Context:
    """One file's extraction: where text goes, the limits, the budget and the reasons."""

    limits: Limits
    emit_unit: Emit
    scratch_dir: Path
    budget: Budget
    report: Report = field(default_factory=Report)
    # Reads a member as its own type, one container level deeper; set by `extract`.
    nested: Nested = _no_nesting

    def emit(
        self, path: tuple[str, ...], hint: str, text: str, cells: tuple[Cell, ...] = ()
    ) -> None:
        """Hand one unit of raw text to the detectors, cut to the unit and text limits."""
        if not text.strip():
            return
        limits = self.limits
        location = _location((*path, hint))
        if len(text) > limits.max_unit_chars:
            # A long row is inspected as plain text: its column headers are lost, its text isn't.
            for piece in chunks(text, limits.max_unit_chars, limits.unit_overlap_chars):
                self._feed(TextUnit(location=location, text=piece))
            return
        self._feed(TextUnit(location=location, text=text, cells=cells))

    def _feed(self, unit: TextUnit) -> None:
        room = self.limits.max_text_chars - self.budget.text_chars
        over = len(unit.text) > room
        if over:
            unit = TextUnit(location=unit.location, text=unit.text[: max(room, 0)])
        self.budget.text_chars += len(unit.text)
        if unit.text:
            try:
                self.emit_unit(unit)
            except Exception as exc:
                raise DetectorFailure(type(exc).__name__) from None
        if over:
            raise StopExtraction("text")

    @contextmanager
    def spool(self, reader: Readable) -> Iterator[IO[bytes]]:
        """Copy a member to an unnamed scratch file, counted against the scratch budget."""
        written = 0
        with tempfile.TemporaryFile(dir=self.scratch_dir) as out:
            try:
                while data := reader.read(_COPY_CHUNK):
                    self.budget.disk(len(data))
                    written += len(data)
                    out.write(data)
                out.seek(0)
                yield out
            finally:
                self.budget.scratch -= written


def chunks(text: str, size: int, overlap: int) -> Iterator[str]:
    """`text` in pieces of at most `size` characters, each repeating `overlap` of the one before."""
    if len(text) <= size:
        yield text
        return
    step = max(size - overlap, 1)
    for start in range(0, len(text), step):
        yield text[start : start + size]
        if start + size >= len(text):
            return


def _location(parts: tuple[str, ...]) -> str:
    text = ", ".join(part for part in parts if part)
    text = "".join("?" if _unsafe(char) else char for char in text)
    if len(text) > MAX_LOCATION_CHARS:
        # Keep the end: the hint inside the member says more than the start of a long path.
        text = "…" + text[-(MAX_LOCATION_CHARS - 1) :]
    return text or "file"


def _unsafe(char: str) -> bool:
    code = ord(char)
    return code < 0x20 or 0x7F <= code <= 0x9F or 0xD800 <= code <= 0xDFFF
