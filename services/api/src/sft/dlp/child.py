"""The inspector's child process: one file, confined (`python -I -m sft.dlp.child INPUT SCRATCH`).

Started by the parent for each file (`sft.dlp.sandbox`). It reads the start frame on stdin,
confines itself with `harden`, and only then opens the file. It writes nothing but frames to
stdout; stderr goes nowhere. Every failure ends in a frame with a fixed code, never a message
(T-99), and a failure is never "no findings" (T-92).
"""

from __future__ import annotations

import signal
import sys
from pathlib import Path
from types import FrameType
from typing import IO, Final

from pydantic import BaseModel, ValidationError

from sft.dlp.engine import Engine, EngineUnavailableError, Scanner, load_engine
from sft.dlp.extract import DetectorFailure, early_stop, extract
from sft.dlp.extract._core import StopExtraction
from sft.dlp.limits import Limits
from sft.dlp.protocol import (
    MAX_REQUEST_FRAME,
    Decision,
    Error,
    ErrorCode,
    ProtocolError,
    Reason,
    State,
    encode_frame,
    finding_model,
    result,
)
from sft.dlp.sandbox import Go, SandboxUnavailableError, Start, harden, read_frame
from sft.dlp.units import Finding

EXIT_OK: Final = 0
EXIT_FAILED: Final = 3


def _limit_reached(_signum: int, _frame: FrameType | None) -> None:
    raise StopExtraction("time")


def _arm(limits: Limits) -> None:
    """Stop at the soft CPU limit, and `wall_grace_seconds` before the parent's deadline."""
    signal.signal(signal.SIGXCPU, _limit_reached)
    signal.signal(signal.SIGALRM, _limit_reached)
    signal.setitimer(signal.ITIMER_REAL, max(limits.wall_seconds - limits.wall_grace_seconds, 1))


def _disarm() -> None:
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, signal.SIG_IGN)
    signal.signal(signal.SIGXCPU, signal.SIG_IGN)


def _write(out: IO[bytes], frame: BaseModel) -> None:
    out.write(encode_frame(frame))
    out.flush()


def _fail(out: IO[bytes], code: ErrorCode) -> int:
    _write(out, Error(type="error", code=code))
    return EXIT_FAILED


def _wait(control: IO[bytes], step: str) -> None:
    go = Go.model_validate_json(read_frame(control, 1024))
    if go.type != step:
        raise ProtocolError("out of order")


def run(
    control: IO[bytes],
    out: IO[bytes],
    input_path: Path,
    scratch_dir: Path,
    *,
    engine: Engine | None = None,
    confine: bool = True,
) -> int:
    """Inspect one file: the whole life of a child. Returns the process's exit status."""
    try:
        start = Start.model_validate_json(read_frame(control, MAX_REQUEST_FRAME + 65536))
    except (ProtocolError, ValidationError):
        return _fail(out, "bad_request")
    limits = start.limits.limits()
    if confine:
        try:
            harden(limits)
        except SandboxUnavailableError:
            return _fail(out, "sandbox_unavailable")
    try:
        engine = engine or load_engine()
    except EngineUnavailableError:
        return _fail(out, "engine_error")
    _arm(limits)
    try:
        return _inspect(control, out, input_path, scratch_dir, start, limits, engine)
    except ProtocolError:
        return _fail(out, "bad_request")
    except (DetectorFailure, ValidationError):
        return _fail(out, "engine_error")
    finally:
        _disarm()


def _inspect(
    control: IO[bytes],
    out: IO[bytes],
    input_path: Path,
    scratch_dir: Path,
    start: Start,
    limits: Limits,
    engine: Engine,
) -> int:
    version = engine.version
    try:
        _wait(control, "prefix")
        with input_path.open("rb") as data:
            prefix = data.read(limits.prefix_bytes)
    except StopExtraction:
        _write(out, Decision(type="decision", read_rest=False))
        _write(out, result(engine_version=version, state="partial", reasons=["limit_exceeded"]))
        return EXIT_OK
    stop = early_stop(prefix)
    _write(out, Decision(type="decision", read_rest=stop is None))
    if stop is not None:
        _write(out, result(engine_version=version, state="not_inspected", reasons=[stop]))
        return EXIT_OK
    try:
        scanner = engine.new_scanner(start.request.detectors())
    except ValueError:  # DetectorError: a tenant definition the detectors refuse
        _disarm()
        _write(out, Error(type="error", code="bad_request"))
        return EXIT_FAILED
    try:
        if start.request.size > len(prefix):
            _wait(control, "complete")
        with input_path.open("rb") as data:
            outcome = extract(data, emit=scanner.feed, limits=limits, scratch_dir=scratch_dir)
        _disarm()
        state: State = outcome.state
        reasons: list[Reason] = list(outcome.reasons)
    except StopExtraction:  # a limit while waiting for the rest of the file, or just after
        _disarm()
        state, reasons = "partial", ["limit_exceeded"]
    findings = [] if state == "not_inspected" else [finding_model(f) for f in _findings(scanner)]
    stopped = [] if state == "not_inspected" else _budget_exceeded(scanner)
    _write(
        out,
        result(
            engine_version=version,
            state=state,
            reasons=reasons,
            findings=findings,
            budget_exceeded=stopped,
        ),
    )
    return EXIT_OK


def _findings(scanner: Scanner) -> list[Finding]:
    # Called once, after the last unit, even after a limit stopped extraction: it also counts what
    # the detectors still hold, such as an AWS secret waiting for its key ID ([detectors] 4). A
    # failure here is an engine error, as in `feed` (T-92).
    try:
        return scanner.findings()
    except Exception as exc:
        raise DetectorFailure(type(exc).__name__) from None


def _budget_exceeded(scanner: Scanner) -> list[str]:
    # The tenant patterns stopped for their scan-time budget ([detectors] 5): IDs only. A failure
    # here is an engine error too.
    try:
        return scanner.budget_exceeded()
    except Exception as exc:
        raise DetectorFailure(type(exc).__name__) from None


def main(engine: Engine | None = None) -> int:
    """The child's entry point. A stub engine is for tests only; production loads the library."""
    if len(sys.argv) != 3:
        return EXIT_FAILED
    return run(
        sys.stdin.buffer, sys.stdout.buffer, Path(sys.argv[1]), Path(sys.argv[2]), engine=engine
    )


if __name__ == "__main__":  # pragma: no cover - run as a process
    sys.exit(main())
