"""The scan worker's side of the inspector protocol (`sft.dlp.protocol`), for asyncio.

`inspect` sends one file and returns the inspector's result, checked in full against the schema:
the detector IDs too. Anything else raises: `InspectorError` for an error frame,
`MalformedAnswerError` for an answer that breaks the schema, `ProtocolError` for broken framing or
a connection that ended with no answer. The worker counts each of them as a failed attempt
(architecture 4.6), never as "no findings".

The inspector may answer before it has the whole file: a result first, instead of a decision,
when the child stopped at a limit before deciding, or an error. It then closes the connection,
and the bytes still being sent get a reset or a broken pipe. That isn't an error of its own: the
client stops sending and reads the answer the inspector sent before it closed.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator, Sequence
from typing import Final

from sft.dlp.limits import DEFAULT_LIMITS
from sft.dlp.protocol import (
    MAX_ANSWER_FRAME,
    PROTOCOL_VERSION,
    Answer,
    Decision,
    Error,
    ErrorCode,
    MalformedAnswerError,
    ProtocolError,
    Request,
    Result,
    TenantDetectorSpec,
    encode_frame,
    frame_length,
    parse_answer,
)

PREFIX_BYTES: Final = DEFAULT_LIMITS.prefix_bytes


class InspectorError(Exception):
    """The inspector answered with an error frame."""

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code)
        self.code = code


async def inspect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    *,
    size: int,
    body: AsyncIterator[bytes],
    builtin_detectors: frozenset[str],
    tenant_detectors: Sequence[TenantDetectorSpec] = (),
    prefix_bytes: int = PREFIX_BYTES,
) -> Result:
    """Inspect one file of `size` bytes, read from `body`, over one connection.

    Files over 2,000,000,000 bytes are never sent: the worker records them as `too_large`.
    """
    request = Request(
        type="inspect", version=PROTOCOL_VERSION, size=size, tenant_detectors=list(tenant_detectors)
    )
    custom = request.custom_detector_ids()
    writer.write(encode_frame(request))
    source = _Exactly(body, size)
    await _send(source, writer, min(prefix_bytes, size))
    decision = await _answer(reader, builtin_detectors, custom)
    if isinstance(decision, Result):  # answered before deciding: the child stopped at a limit
        return decision
    if not isinstance(decision, Decision):  # pragma: no cover - `_answer` raises for an error
        raise MalformedAnswerError("expected a decision")
    if decision.read_rest:
        await _send(source, writer, size - min(prefix_bytes, size))
    final = await _answer(reader, builtin_detectors, custom)
    if not isinstance(final, Result):
        raise MalformedAnswerError("expected a result")
    return final


async def _send(source: _Exactly, writer: asyncio.StreamWriter, count: int) -> None:
    """Send `count` bytes of the body; stop quietly if the inspector has answered and closed."""
    with contextlib.suppress(ConnectionResetError, BrokenPipeError):
        await source.send(writer, count)


async def _answer(
    reader: asyncio.StreamReader, builtin: frozenset[str], custom: frozenset[str]
) -> Answer:
    header = await _read(reader, 4)
    payload = await _read(reader, frame_length(header, MAX_ANSWER_FRAME))
    answer = parse_answer(payload, builtin_detectors=builtin, custom_detectors=custom)
    if isinstance(answer, Error):
        raise InspectorError(answer.code)
    return answer


async def _read(reader: asyncio.StreamReader, count: int) -> bytes:
    try:
        return await reader.readexactly(count)
    except asyncio.IncompleteReadError:
        raise ProtocolError("the inspector closed the connection") from None
    except (ConnectionResetError, BrokenPipeError):
        # The connection broke while we were still sending. asyncio reads as data arrives, so
        # what the inspector sent before it closed is in the reader's buffer: read it from there.
        held: bytearray = getattr(reader, "_buffer", bytearray())
        if len(held) < count:
            raise ProtocolError("the inspector closed the connection") from None
        data = bytes(held[:count])
        del held[:count]
        return data


class _Exactly:
    """`body`, cut into exactly the byte counts asked for, never more than `size` in all."""

    def __init__(self, body: AsyncIterator[bytes], size: int) -> None:
        self._body = body
        self._left = size
        self._held = b""

    async def send(self, writer: asyncio.StreamWriter, count: int) -> None:
        while count > 0:
            if not self._held:
                try:
                    self._held = await anext(self._body)
                except StopAsyncIteration:
                    raise ProtocolError("the body is shorter than its size") from None
                if len(self._held) > self._left:
                    raise ProtocolError("the body is longer than its size")
                self._left -= len(self._held)
            piece, self._held = self._held[:count], self._held[count:]
            writer.write(piece)
            count -= len(piece)
            await writer.drain()
