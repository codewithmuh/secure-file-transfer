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

**The client works on the socket itself** (`loop.sock_sendall`, `loop.sock_recv`), not on an
asyncio stream. A stream's transport closes its socket as soon as a write fails, so an answer the
kernel had already received, but the event loop hadn't read yet, was lost with it, and a file
whose inspector answered early failed its attempt now and then. The socket stays open until the
caller closes it, so the answer is always read (tests/test_dlp_protocol.py).
"""

from __future__ import annotations

import asyncio
import socket
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
_RECV: Final = 64 * 1024


class InspectorError(Exception):
    """The inspector answered with an error frame."""

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code)
        self.code = code


async def connect(host: str, port: int) -> socket.socket:
    """A non-blocking TCP socket connected to the inspector; the caller closes it."""
    loop = asyncio.get_running_loop()
    failure: OSError = OSError(f"no address for {host}")
    for family, kind, proto, _, address in await loop.getaddrinfo(
        host, port, type=socket.SOCK_STREAM
    ):
        sock = socket.socket(family, kind, proto)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, address)
        except OSError as exc:
            sock.close()
            failure = exc
            continue
        except BaseException:
            sock.close()
            raise
        return sock
    raise failure


async def inspect(
    sock: socket.socket,
    *,
    size: int,
    body: AsyncIterator[bytes],
    builtin_detectors: frozenset[str],
    tenant_detectors: Sequence[TenantDetectorSpec] = (),
    prefix_bytes: int = PREFIX_BYTES,
) -> Result:
    """Inspect one file of `size` bytes, read from `body`, over one connected socket, which the
    caller closes.

    Files over 2,000,000,000 bytes are never sent: the worker records them as `too_large`.
    """
    request = Request(
        type="inspect", version=PROTOCOL_VERSION, size=size, tenant_detectors=list(tenant_detectors)
    )
    custom = request.custom_detector_ids()
    connection = _Connection(sock)
    await connection.send(encode_frame(request))
    source = _Exactly(body, size)
    await source.send(connection, min(prefix_bytes, size))
    decision = await _answer(connection, builtin_detectors, custom)
    if isinstance(decision, Result):  # answered before deciding: the child stopped at a limit
        return decision
    if not isinstance(decision, Decision):  # pragma: no cover - `_answer` raises for an error
        raise MalformedAnswerError("expected a decision")
    if decision.read_rest:
        await source.send(connection, size - min(prefix_bytes, size))
    final = await _answer(connection, builtin_detectors, custom)
    if not isinstance(final, Result):
        raise MalformedAnswerError("expected a result")
    return final


class _Connection:
    """The socket, and what has been read from it but not used yet."""

    def __init__(self, sock: socket.socket) -> None:
        sock.setblocking(False)
        self._sock = sock
        self._loop = asyncio.get_running_loop()
        self._held = bytearray()
        self.broken = False
        """A send failed: the inspector has answered and closed. Nothing more is sent."""

    async def send(self, data: bytes) -> None:
        """Send `data`, or stop quietly if the inspector has closed; its answer stays readable."""
        if self.broken:
            return
        try:
            await self._loop.sock_sendall(self._sock, data)
        except (ConnectionResetError, BrokenPipeError):
            self.broken = True

    async def read(self, count: int) -> bytes:
        while len(self._held) < count:
            try:
                chunk = await self._loop.sock_recv(self._sock, max(_RECV, count - len(self._held)))
            except ConnectionResetError:
                chunk = b""  # what arrived before the reset was read first
            if not chunk:
                raise ProtocolError("the inspector closed the connection")
            self._held += chunk
        data = bytes(self._held[:count])
        del self._held[:count]
        return data


async def _answer(
    connection: _Connection, builtin: frozenset[str], custom: frozenset[str]
) -> Answer:
    header = await connection.read(4)
    payload = await connection.read(frame_length(header, MAX_ANSWER_FRAME))
    answer = parse_answer(payload, builtin_detectors=builtin, custom_detectors=custom)
    if isinstance(answer, Error):
        raise InspectorError(answer.code)
    return answer


class _Exactly:
    """`body`, cut into exactly the byte counts asked for, never more than `size` in all."""

    def __init__(self, body: AsyncIterator[bytes], size: int) -> None:
        self._body = body
        self._left = size
        self._held = b""

    async def send(self, connection: _Connection, count: int) -> None:
        while count > 0 and not connection.broken:
            if not self._held:
                try:
                    self._held = await anext(self._body)
                except StopAsyncIteration:
                    raise ProtocolError("the body is shorter than its size") from None
                if len(self._held) > self._left:
                    raise ProtocolError("the body is longer than its size")
                self._left -= len(self._held)
            piece, self._held = self._held[:count], self._held[count:]
            await connection.send(piece)
            count -= len(piece)
