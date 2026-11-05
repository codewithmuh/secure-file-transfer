"""The DLP inspector: `python -m sft.dlp.inspector` (ADR-0022, architecture 4.6).

It listens for scan workers on INSPECTOR_PORT and inspects one file per connection, one connection
at a time: the pod sits beside one scan worker and has one scratch volume. For each file it writes
the stream to scratch, starts a fresh confined child (`sft.dlp.sandbox`) and relays the child's
decision and result, checked against the schema, to the worker (`sft.dlp.protocol`). It never
parses the file itself, and deletes the file's scratch directory when the file is done.

It holds nothing between files and has nothing to authenticate with: no token, no IAM role, no
database, no network out (architecture 2). It logs one line per file: the state, the reasons,
the size and the duration. Never a value, a hint or a file name (T-99).
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import signal
import socket
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import FrameType
from typing import IO, Final

from pydantic import ValidationError

from sft.core.logs import configure_logging
from sft.core.settings import EXIT_BAD_SETTINGS, InspectorSettings, load_settings
from sft.dlp.engine import Engine, EngineUnavailableError, load_engine
from sft.dlp.limits import DEFAULT_LIMITS, Limits
from sft.dlp.protocol import (
    MAX_REQUEST_FRAME,
    Decision,
    Error,
    ErrorCode,
    ProtocolError,
    Request,
    Result,
    encode_frame,
    frame_length,
    parse_request,
    result,
)
from sft.dlp.sandbox import Child, ChildDied

log = logging.getLogger(__name__)

EXIT_NO_ENGINE: Final = 3
_RECV: Final = 1024 * 1024


@dataclass(frozen=True, slots=True)
class Summary:
    """What one connection came to, for the log line and for tests."""

    outcome: str  # a result state, or "error:<code>", or "disconnected"
    reasons: tuple[str, ...] = ()


class Inspector:
    """Inspects one file per connection. Call `handle` with each accepted socket."""

    def __init__(
        self,
        *,
        scratch_root: Path,
        engine: Engine,
        limits: Limits = DEFAULT_LIMITS,
        io_timeout: float = 60.0,
        child_argv: Sequence[str] | None = None,
    ) -> None:
        self.scratch_root = scratch_root
        self.engine = engine
        self.limits = limits
        self.io_timeout = io_timeout
        self.child_argv = child_argv

    def handle(self, conn: socket.socket) -> Summary:
        conn.settimeout(self.io_timeout)
        try:
            header = _recv_exact(conn, 4)
            payload = _recv_exact(conn, frame_length(header, MAX_REQUEST_FRAME))
            request = parse_request(payload)
        except (ProtocolError, ValidationError):
            return self._error(conn, "bad_request")
        except OSError:
            return Summary("disconnected")
        if request.size > self.limits.max_input_bytes:
            # The worker records these as too_large itself and never streams them (ADR-0022).
            return self._error(conn, "bad_request")
        workdir = Path(tempfile.mkdtemp(prefix="file-", dir=self.scratch_root))
        try:
            return self._inspect(conn, request.size, request, workdir)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)

    def _inspect(self, conn: socket.socket, size: int, request: Request, workdir: Path) -> Summary:
        input_path = workdir / "input"
        scratch = workdir / "work"
        scratch.mkdir(mode=0o700)
        child = Child.spawn(
            input_path=input_path,
            scratch_dir=scratch,
            limits=self.limits,
            request=request,
            argv=self.child_argv,
        )
        try:
            with input_path.open("xb") as sink:
                prefix = min(self.limits.prefix_bytes, size)
                if not _copy(conn, sink, prefix, child):
                    return Summary("disconnected")
                child.go("prefix")
                decision = child.answer()
                if not isinstance(decision, Decision):
                    return self._relay(conn, decision)
                _send(conn, decision)
                if decision.read_rest and size > prefix:
                    # Only then does the child wait for the rest (`sft.dlp.child`): a file that
                    # fits in the prefix is already whole.
                    if not _copy(conn, sink, size - prefix, child):
                        return Summary("disconnected")
                    child.go("complete")
            return self._relay(conn, child.answer())
        except ChildDied as died:
            if died.limit:
                version = self.engine.version
                late = result(engine_version=version, state="partial", reasons=["limit_exceeded"])
                return self._relay(conn, late)
            return self._error(conn, "engine_error")
        except OSError:
            return Summary("disconnected")
        finally:
            child.kill()

    def _relay(self, conn: socket.socket, answer: Decision | Result | Error) -> Summary:
        if isinstance(answer, Decision):  # a second decision: the child broke the protocol
            return self._error(conn, "engine_error")
        with contextlib.suppress(OSError):
            _send(conn, answer)
        if isinstance(answer, Error):
            return Summary(f"error:{answer.code}")
        return Summary(answer.state, tuple(answer.reasons))

    def _error(self, conn: socket.socket, code: ErrorCode) -> Summary:
        with contextlib.suppress(OSError):
            _send(conn, Error(type="error", code=code))
        return Summary(f"error:{code}")


def _send(conn: socket.socket, frame: Decision | Result | Error) -> None:
    conn.sendall(encode_frame(frame))


def _recv_exact(conn: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = conn.recv(min(count - len(data), _RECV))
        if not chunk:
            raise ProtocolError("the stream ended early")
        data += chunk
    return bytes(data)


def _copy(conn: socket.socket, out: IO[bytes], count: int, child: Child) -> bool:
    """Copy `count` raw bytes from the worker to scratch; False if the worker went away."""
    left = count
    while left > 0:
        if child.remaining() <= 0:
            child.kill(deadline=True)
            raise ChildDied(limit=True)
        try:
            chunk = conn.recv(min(left, _RECV))
        except TimeoutError:
            return False
        if not chunk:
            return False
        out.write(chunk)
        left -= len(chunk)
    out.flush()
    return True


def serve(settings: InspectorSettings, inspector: Inspector) -> int:
    """Accept scan workers until SIGTERM, one at a time."""
    stopping = False

    def stop(_signum: int, _frame: FrameType | None) -> None:
        nonlocal stopping
        stopping = True
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    with socket.create_server((settings.bind_host, settings.inspector_port), backlog=8) as server:
        log.info("inspector listening", extra={"port": settings.inspector_port})
        try:
            while not stopping:
                conn, _address = server.accept()
                with conn:
                    started = time.monotonic()
                    summary = inspector.handle(conn)
                    log.info(
                        "file inspected",
                        extra={
                            "outcome": summary.outcome,
                            "reasons": list(summary.reasons),
                            "duration_ms": round((time.monotonic() - started) * 1000),
                        },
                    )
        except KeyboardInterrupt:
            log.info("inspector stopping")
    return 0


def main() -> int:
    settings = load_settings(InspectorSettings)
    if settings is None:
        return EXIT_BAD_SETTINGS
    configure_logging(settings.log_level)
    try:
        engine = load_engine()
    except EngineUnavailableError:
        log.critical("the detector library can't be loaded")
        return EXIT_NO_ENGINE
    inspector = Inspector(
        scratch_root=Path(settings.inspector_scratch_dir),
        engine=engine,
        io_timeout=settings.inspector_io_timeout_seconds,
    )
    return serve(settings, inspector)


if __name__ == "__main__":  # pragma: no cover - run as a process
    sys.exit(main())
