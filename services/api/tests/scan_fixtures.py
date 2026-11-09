"""Stand-ins for the scan worker's tests (#175, #176): the files buckets, clamd and the DLP
inspector, each speaking the real protocol on a real socket, so the worker's tee, timeouts and
parsing run as they do against the engines. tests/test_scan_engines.py runs the same worker
against the real clamd and, in Linux, the real inspector.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import struct
import tempfile
from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from sft.data.models import StorageClass
from sft.dlp.engine import load_engine
from sft.dlp.extract import extract
from sft.dlp.limits import Limits
from sft.dlp.protocol import (
    Decision,
    Error,
    FindingModel,
    Request,
    Result,
    encode_frame,
    finding_model,
    parse_request,
    result,
)
from sft.service.objects import ObjectStoreError


def eicar() -> bytes:
    """The EICAR antivirus test file, built here so no file in the repository holds it."""
    parts = (
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    )
    return "".join(parts).encode()


@dataclass
class FakeScanObjects:
    """`ScannedObjects` in memory: versions of objects, their tags, and every read."""

    versions: dict[tuple[str, str], bytes] = field(default_factory=dict)
    tags: dict[tuple[str, str], dict[str, str]] = field(default_factory=dict)
    reads: list[tuple[str, str]] = field(default_factory=list)
    put_tags: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)
    on_put: Callable[[], None] | None = None
    chunk: int = 16 * 1024
    failing: bool = False

    def put(
        self, key: str, version: str, data: bytes, tags: Mapping[str, str] | None = None
    ) -> None:
        self.versions[(key, version)] = data
        self.tags[(key, version)] = dict(tags or {})

    async def read_version(
        self, storage_class: StorageClass, key: str, version_id: str
    ) -> AsyncIterator[bytes]:
        self.reads.append((key, version_id))
        if self.failing:
            raise ObjectStoreError("ServiceUnavailable")
        data = self.versions[(key, version_id)]
        for start in range(0, len(data), self.chunk):
            yield data[start : start + self.chunk]
            await asyncio.sleep(0)

    async def object_tags(
        self, storage_class: StorageClass, key: str, version_id: str
    ) -> Mapping[str, str]:
        return dict(self.tags.get((key, version_id), {}))

    async def put_object_tags(
        self, storage_class: StorageClass, key: str, version_id: str, tags: Mapping[str, str]
    ) -> None:
        if self.on_put is not None:
            self.on_put()
        self.tags[(key, version_id)] = dict(tags)
        self.put_tags.append((key, version_id, dict(tags)))

    async def close(self) -> None:
        return None


Answer = Callable[[bytes], bytes | None]
"""clamd's answer for the bytes it received, or None to never answer."""


def clamd_answer(data: bytes) -> bytes | None:
    """Like clamd with the test signature: EICAR anywhere is a detection."""
    if eicar() in data:
        return b"stream: Eicar-Test-Signature FOUND"
    if b"ENCRYPTED" in data:
        return b"stream: Heuristics.Encrypted.Zip FOUND"
    return b"stream: OK"


@dataclass
class FakeClamd:
    answer: Answer = clamd_answer
    received: list[bytes] = field(default_factory=list)
    delay: float = 0.0
    """Seconds it takes to scan, once it has the whole stream."""
    port: int = 0
    _server: asyncio.Server | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\0")
            data = bytearray()
            while True:
                (length,) = struct.unpack(">I", await reader.readexactly(4))
                if not length:
                    break
                data += await reader.readexactly(length)
            self.received.append(bytes(data))
            await asyncio.sleep(self.delay)
            answer = self.answer(bytes(data))
            if answer is None:
                await asyncio.sleep(3600)
                return
            writer.write(answer + b"\0")
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 1)


Mode = Literal["result", "stop", "error", "malformed", "hang", "close", "slow", "stall", "detect"]
"""`slow` reads the rest at `pace` seconds a chunk; `stall` asks for the rest and never reads it;
`detect` answers as the real inspector's child would, in process: extraction and the real
detectors, with the tenant's detectors the request carried (#218)."""


def detect(data: bytes, request: Request) -> Result:
    """What the inspector's child answers for `data`, without its sandbox (sft.dlp.child)."""
    engine = load_engine()
    scanner = engine.new_scanner(request.detectors())
    with tempfile.TemporaryDirectory() as scratch:
        outcome = extract(
            io.BytesIO(data), emit=scanner.feed, limits=Limits(), scratch_dir=Path(scratch)
        )
    return result(
        engine_version=engine.version,
        state=outcome.state,
        reasons=list(outcome.reasons),
        findings=[finding_model(f) for f in scanner.findings()],
    )


def finding(detector: str, high: int = 1, *, previews: int = 0) -> FindingModel:
    return FindingModel.model_validate(
        {
            "detector": detector,
            "counts": {"low": 0, "medium": 0, "high": high},
            "locations": [],
            "previews": ["****"] * previews,
        }
    )


@dataclass
class FakeInspector:
    """The inspector's side of `sft.dlp.protocol`, answering as `mode` says."""

    mode: Mode = "result"
    answer: Result = field(
        default_factory=lambda: result(engine_version="fake.1", state="inspected", reasons=[])
    )
    raw: dict[str, object] | None = None
    """For `malformed`: the answer to send as is, past the schema. By default, an unknown
    detector."""
    received: list[bytes] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)
    """Each request frame, with the tenant's detectors it carried (#218)."""
    prefix: int = 64 * 1024
    pace: float = 0.05
    port: int = 0
    _server: asyncio.Server | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            (length,) = struct.unpack(">I", await reader.readexactly(4))
            request = parse_request(await reader.readexactly(length))
            self.requests.append(request)
            data = await reader.readexactly(min(self.prefix, request.size))
            if self.mode == "hang":
                await asyncio.sleep(3600)
                return
            if self.mode == "close":
                return
            if self.mode == "error":
                writer.write(encode_frame(Error(type="error", code="engine_error")))
                return
            if self.mode == "stop":
                writer.write(encode_frame(Decision(type="decision", read_rest=False)))
                self.received.append(data)
                writer.write(
                    encode_frame(
                        result(
                            engine_version="fake.1",
                            state="not_inspected",
                            reasons=["unsupported_type"],
                        )
                    )
                )
                return
            writer.write(encode_frame(Decision(type="decision", read_rest=True)))
            if self.mode == "stall":
                await asyncio.sleep(3600)
                return
            if self.mode == "slow":
                while len(data) < request.size:
                    await asyncio.sleep(self.pace)
                    data += await reader.readexactly(min(64 * 1024, request.size - len(data)))
            data += await reader.readexactly(request.size - len(data))
            self.received.append(data)
            if self.mode == "malformed" and self.raw is not None:
                payload = json.dumps(self.raw).encode()
                writer.write(struct.pack(">I", len(payload)) + payload)
            elif self.mode == "malformed":
                raw = self.answer.model_dump()
                raw["findings"] = [
                    {
                        "detector": "not_a_detector",
                        "counts": {"low": 0, "medium": 0, "high": 1},
                        "locations": [],
                        "previews": [],
                    }
                ]
                payload = json.dumps(raw).encode()
                writer.write(struct.pack(">I", len(payload)) + payload)
            elif self.mode == "detect":
                # In a thread: loading the engine and detecting are CPU work, which on the event
                # loop held up the fake clamd beside it until the worker's clamd timeout fired
                # (test_dlp_received, flaky in CI).
                writer.write(encode_frame(await asyncio.to_thread(detect, data, request)))
            else:
                writer.write(encode_frame(self.answer))
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), 1)
