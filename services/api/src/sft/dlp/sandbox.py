"""The inspector's sandbox: a fresh child process per file (ADR-0022, T-91 to T-93).

The parent (`sft.dlp.inspector`) never parses. For each file it starts a new Python interpreter,
`python -I -m sft.dlp.child`, which inherits no memory from the parent or from earlier files, so
an exploited parser can reach only its own file's bytes and result. A fork would carry the
parent's heap, with what it last received, into the child.

The child, before it reads a byte of the file, calls `harden`:

- resource limits: address space (`memory_bytes`), CPU time (`cpu_seconds`, then the kernel kills
  it `cpu_grace_seconds` later), file size (`scratch_bytes`), 256 open files, no core dumps;
- not dumpable, so no other process of the same user can attach to it or read its memory;
- the seccomp filter of `sft.dlp.seccomp`: no sockets, no exec, no ptrace, no new processes.

Decompression, nesting, member, text and page limits are checked by the extractors themselves
(`sft.dlp.extract`). The parent kills the child at `wall_seconds`; the child stops itself
`wall_grace_seconds` before that, and at the soft CPU limit, so that it can still answer with the
findings so far and `limit_exceeded`.

Parent and child talk over two pipes, in the frames of `sft.dlp.protocol`: the parent sends a
start frame (the limits and the request), then "prefix" once the first 64 KiB are on scratch, then
"complete" once the whole file is; the child answers with a decision and a result.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import resource
import selectors
import signal
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import IO, Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from sft.dlp import seccomp
from sft.dlp.limits import Limits
from sft.dlp.protocol import (
    MAX_ANSWER_FRAME,
    Answer,
    MalformedAnswerError,
    ProtocolError,
    Request,
    encode_frame,
    frame_length,
    parse_answer,
)

PR_SET_DUMPABLE: Final = 4
MAX_OPEN_FILES: Final = 256

CHILD_MODULE: Final = "sft.dlp.child"


class SandboxUnavailableError(Exception):
    """The child can't be confined here; the inspector answers `sandbox_unavailable`."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class LimitsModel(_Strict):
    max_input_bytes: int
    prefix_bytes: Annotated[int, Field(ge=1)]
    max_depth: int
    max_members: int
    max_decompressed_bytes: int
    max_ratio: int
    ratio_grace_bytes: int
    max_text_chars: int
    max_pdf_pages: int
    cpu_seconds: Annotated[int, Field(ge=1)]
    wall_seconds: Annotated[int, Field(ge=1)]
    memory_bytes: int
    scratch_bytes: int
    max_unit_chars: Annotated[int, Field(ge=1)]
    unit_overlap_chars: Annotated[int, Field(ge=0)]
    wall_grace_seconds: Annotated[int, Field(ge=0)]
    cpu_grace_seconds: Annotated[int, Field(ge=1)]

    def limits(self) -> Limits:
        return Limits(**self.model_dump())


class Start(_Strict):
    """The parent's first frame to the child."""

    type: Literal["start"]
    limits: LimitsModel
    request: Request


class Go(_Strict):
    """The parent's next frames: the prefix is on scratch, then the whole file is."""

    type: Literal["prefix", "complete"]


# ---- the child's side ----


def harden(limits: Limits) -> None:
    """Confine the calling process for good. Raises SandboxUnavailableError if it can't."""
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (MAX_OPEN_FILES, MAX_OPEN_FILES))
        resource.setrlimit(resource.RLIMIT_FSIZE, (limits.scratch_bytes, limits.scratch_bytes))
        cpu = (limits.cpu_seconds, limits.cpu_seconds + limits.cpu_grace_seconds)
        resource.setrlimit(resource.RLIMIT_CPU, cpu)
        resource.setrlimit(resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
    except (OSError, ValueError) as exc:
        raise SandboxUnavailableError(f"resource limits: {type(exc).__name__}") from None
    if sys.platform != "linux":
        raise SandboxUnavailableError("not Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise SandboxUnavailableError("prctl PR_SET_DUMPABLE")
    try:
        seccomp.install()
    except seccomp.SeccompUnavailableError as exc:
        raise SandboxUnavailableError(str(exc)) from None


def read_frame(stream: IO[bytes], limit: int) -> bytes:
    """One frame from a blocking stream, or ProtocolError if it ends early."""
    length = frame_length(_read_exact(stream, 4), limit)
    return _read_exact(stream, length)


def _read_exact(stream: IO[bytes], count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = stream.read(count - len(data))
        if not chunk:
            raise ProtocolError("the stream ended early")
        data += chunk
    return data


# ---- the parent's side ----


class ChildDied(Exception):  # noqa: N818 - an outcome, not a bug
    """The child ended or was killed without a valid answer."""

    def __init__(self, *, limit: bool) -> None:
        super().__init__("limit" if limit else "crash")
        # True when a limit ended it: the wall-clock deadline, the CPU limit's SIGKILL or SIGXCPU,
        # or the kernel's out-of-memory kill. Then the file is `partial` with `limit_exceeded`.
        self.limit = limit


class Child:
    """One file's child process, seen from the parent."""

    def __init__(self, process: subprocess.Popen[bytes], deadline: float) -> None:
        self._process = process
        self._deadline = deadline
        self._killed_at_deadline = False
        self._buffer = b""
        if process.stdin is None or process.stdout is None:  # pragma: no cover - both are PIPE
            raise SandboxUnavailableError("no pipes")
        self._stdin = process.stdin
        self._stdout = process.stdout

    @classmethod
    def spawn(
        cls,
        *,
        input_path: Path,
        scratch_dir: Path,
        limits: Limits,
        request: Request,
        argv: Sequence[str] | None = None,
    ) -> Child:
        command = [
            *(argv or (sys.executable, "-I", "-m", CHILD_MODULE)),
            str(input_path),
            str(scratch_dir),
        ]
        process = subprocess.Popen(  # noqa: S603 - our own interpreter and module, no shell
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # parser messages never reach a log (T-99)
            env={},
            cwd=scratch_dir,
            close_fds=True,
            start_new_session=True,
        )
        child = cls(process, time.monotonic() + limits.wall_seconds)
        start = Start(type="start", limits=LimitsModel(**limits.as_dict()), request=request)
        child._send(encode_frame(start))
        return child

    def remaining(self) -> float:
        return self._deadline - time.monotonic()

    def go(self, step: Literal["prefix", "complete"]) -> None:
        """Tell the child to read on. A child that has already answered and gone (a refused
        tenant detector, say) can't take it: that is no failure, and `answer` then reads what it
        wrote, or says how it died."""
        with contextlib.suppress(BrokenPipeError, OSError):
            self._stdin.write(encode_frame(Go(type=step)))
            self._stdin.flush()

    def _send(self, data: bytes) -> None:
        try:
            self._stdin.write(data)
            self._stdin.flush()
        except (BrokenPipeError, OSError):
            raise self._died() from None

    def answer(self) -> Answer:
        """The child's next frame, checked against the schema, or ChildDied."""
        try:
            header = self._read(4)
            payload = self._read(frame_length(header, MAX_ANSWER_FRAME))
            return parse_answer(payload, builtin_detectors=None)
        except (ProtocolError, MalformedAnswerError):
            raise self._died() from None

    def _read(self, count: int) -> bytes:
        fd = self._stdout.fileno()
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while len(self._buffer) < count:
                remaining = self.remaining()
                if remaining <= 0 or not selector.select(remaining):
                    self.kill(deadline=True)
                    raise ProtocolError("deadline")
                chunk = os.read(fd, 65536)
                if not chunk:
                    raise ProtocolError("the child closed its output")
                self._buffer += chunk
        data, self._buffer = self._buffer[:count], self._buffer[count:]
        return data

    def _died(self) -> ChildDied:
        killed_by_us = False
        if self._process.poll() is None and not self._killed_at_deadline:
            try:
                self._process.wait(timeout=max(min(self.remaining(), 5.0), 0.1))
            except subprocess.TimeoutExpired:
                killed_by_us = True
        self.kill()
        status = self._process.returncode
        by_kernel = not killed_by_us and status in (-signal.SIGKILL, -signal.SIGXCPU)
        return ChildDied(limit=self._killed_at_deadline or by_kernel)

    def kill(self, *, deadline: bool = False) -> None:
        if deadline and self._process.poll() is None:
            self._killed_at_deadline = True
        if self._process.poll() is None:
            with contextlib.suppress(ProcessLookupError):  # it may end in between
                os.killpg(self._process.pid, signal.SIGKILL)
        self._process.wait()
        for stream in (self._stdin, self._stdout):
            with contextlib.suppress(OSError):  # a pipe already broken
                stream.close()

    @property
    def returncode(self) -> int | None:
        return self._process.returncode
