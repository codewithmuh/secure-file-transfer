"""The scan worker's side of clamd's `INSTREAM` command (ADR-0019; abuse and rate limits 6.4).

clamd runs in its own pod beside the worker, with no credentials. The worker streams the bytes of
the recorded object version to it and reads one answer:

    zINSTREAM\\0  then  <4-byte big-endian length><chunk> …  then  <0 as 4 bytes>
    -> "stream: OK\\0" | "stream: <signature> FOUND\\0" | "<message> ERROR\\0"

The answer maps to a result (ADR-0019, "one result mapping"): `OK` is clean; a detection is
infected; an encrypted-content alert (`Heuristics.Encrypted.*`) or any limit alert
(`Heuristics.Limits.Exceeded.*`, an overlapping-files zip bomb, a stream over `StreamMaxLength`) is
unscannable, never clean. Anything else, a connection that fails or a scan that runs out of time,
is `ClamdError`: a failed attempt, retried, and `scan_failed` on the last (FR-19).

clamd may answer and close before it has read the whole stream (a stream over its limit); the
worker then stops sending and reads the answer clamd sent before it closed, as the inspector
client does (`sft.dlp.client`).
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

MAX_CHUNK: Final = 1024 * 1024
"""Bytes per INSTREAM chunk; clamd allows chunks up to `StreamMaxLength`."""
MAX_ANSWER: Final = 4096

_ENCRYPTED: Final = "Heuristics.Encrypted."
_LIMITS: Final = ("Heuristics.Limits.Exceeded", "Heuristics.Zip.OverlappingFiles")
_SIZE_LIMIT: Final = "INSTREAM size limit exceeded"


class Verdict(StrEnum):
    CLEAN = "clean"
    INFECTED = "infected"
    ENCRYPTED = "encrypted"
    LIMIT_EXCEEDED = "limit_exceeded"


@dataclass(frozen=True, slots=True)
class ClamdResult:
    verdict: Verdict
    signature: str | None = None
    """The detection's name, for the worker's log line only; never stored or audited."""


class ClamdError(Exception):
    """clamd couldn't scan the stream: an error answer, a broken connection or a timeout."""


def parse_answer(raw: bytes) -> ClamdResult:
    """One clamd answer, NUL and whitespace stripped; `ClamdError` for an error or nonsense."""
    text = raw.rstrip(b"\0").decode("utf-8", "replace").strip()
    if text.endswith("ERROR"):
        if text.startswith(_SIZE_LIMIT):
            return ClamdResult(Verdict.LIMIT_EXCEEDED, _SIZE_LIMIT)
        raise ClamdError("clamd answered with an error")
    if not text.startswith("stream:"):
        raise ClamdError("clamd's answer has no stream result")
    result = text.removeprefix("stream:").strip()
    if result == "OK":
        return ClamdResult(Verdict.CLEAN)
    if not result.endswith(" FOUND"):
        raise ClamdError("clamd's answer is neither OK nor a detection")
    signature = result.removesuffix(" FOUND").strip()
    if signature.startswith(_ENCRYPTED):
        return ClamdResult(Verdict.ENCRYPTED, signature)
    if signature.startswith(_LIMITS):
        return ClamdResult(Verdict.LIMIT_EXCEEDED, signature)
    return ClamdResult(Verdict.INFECTED, signature)


async def instream(
    host: str,
    port: int,
    body: AsyncIterator[bytes],
    *,
    connect_timeout: float,
) -> ClamdResult:
    """Stream `body` to clamd and return its result. The caller bounds the whole call in time."""
    try:
        async with asyncio.timeout(connect_timeout):
            reader, writer = await asyncio.open_connection(host, port)
    except (OSError, TimeoutError) as exc:
        raise ClamdError(f"can't reach clamd: {type(exc).__name__}") from exc
    try:
        writer.write(b"zINSTREAM\0")
        with contextlib.suppress(ConnectionResetError, BrokenPipeError):
            async for chunk in body:
                for start in range(0, len(chunk), MAX_CHUNK):
                    piece = chunk[start : start + MAX_CHUNK]
                    writer.write(struct.pack(">I", len(piece)) + piece)
                    await writer.drain()
            writer.write(struct.pack(">I", 0))
            await writer.drain()
        try:
            raw = await reader.readuntil(b"\0")
        except asyncio.IncompleteReadError as exc:
            if not exc.partial:
                raise ClamdError("clamd closed the connection without an answer") from None
            raw = exc.partial
        except asyncio.LimitOverrunError as exc:
            raise ClamdError("clamd's answer is too long") from exc
        except (ConnectionResetError, BrokenPipeError) as exc:
            raise ClamdError("the connection to clamd broke") from exc
        return parse_answer(raw[:MAX_ANSWER])
    finally:
        writer.close()
        with contextlib.suppress(OSError, ConnectionError):
            await writer.wait_closed()
