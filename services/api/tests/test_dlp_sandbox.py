"""The inspector's process model (ADR-0022, DLP-2): a fresh confined child per file.

The child runs with the stub detector library (tests/dlp_stub.py). seccomp and the rlimits are
Linux only, as the inspector pod is; elsewhere these tests skip.
"""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
import sys
import threading
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

import dlp_fixtures as fx
import dlp_stub
from sft.dlp import client
from sft.dlp.inspector import Inspector, Summary
from sft.dlp.limits import MIB, Limits
from sft.dlp.protocol import KeywordListSpec, Result

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="the sandbox is Linux only")

TESTS = Path(__file__).parent
STUB_ARGV = (sys.executable, "-I", str(TESTS / "dlp_stub.py"))


def test_child_cannot_open_a_socket_exec_or_ptrace() -> None:
    done = subprocess.run(  # noqa: S603 - our interpreter and our probe
        [sys.executable, "-I", str(TESTS / "dlp_probe.py")],
        capture_output=True,
        check=True,
        timeout=60,
    )
    probe = json.loads(done.stdout)
    for action in ("socket", "unix_socket", "socketpair", "exec", "subprocess", "fork", "ptrace"):
        assert probe[action] == "refused", action
    assert probe["memory"] == "refused"
    # What the extractors need still works.
    assert probe["thread"] == "allowed"
    assert probe["open_file"] == "allowed"


async def _chunks(data: bytes) -> AsyncIterator[bytes]:
    for start in range(0, len(data), 8192):
        yield data[start : start + 8192]


def inspect(
    data: bytes,
    tmp_path: Path,
    limits: Limits | None = None,
    tenant: list[KeywordListSpec] | None = None,
) -> tuple[Result | Exception, Summary]:
    inspector = Inspector(
        scratch_root=tmp_path,
        engine=dlp_stub.ENGINE,
        limits=limits or Limits(),
        io_timeout=30,
        child_argv=STUB_ARGV,
    )
    server, worker = socket.socketpair()
    summaries: list[Summary] = []
    thread = threading.Thread(target=lambda: summaries.append(inspector.handle(server)))
    thread.start()

    async def scan() -> Result:
        with worker:
            return await client.inspect(
                worker,
                size=len(data),
                body=_chunks(data),
                builtin_detectors=dlp_stub.BUILTIN,
                tenant_detectors=tenant or [],
                prefix_bytes=(limits or Limits()).prefix_bytes,
            )

    answer: Result | Exception
    try:
        answer = asyncio.run(scan())
    except Exception as exc:
        answer = exc
    thread.join(timeout=60)
    server.close()
    assert not list(tmp_path.iterdir()), "the file's scratch directory is deleted"
    return answer, summaries[0]


def test_a_file_through_the_sandbox(tmp_path: Path) -> None:
    data = fx.docx(["TOKEN-0001 TOKEN-0002 secret-word"])
    tenant = [KeywordListSpec(kind="keywords", id="words", terms=["secret-word"])]
    answer, summary = inspect(data, tmp_path, tenant=tenant)
    assert isinstance(answer, Result)
    assert answer.state == "inspected"
    found = {finding.detector: finding.counts.high for finding in answer.findings}
    assert found == {"stub_token": 2, "custom:words": 1}
    assert summary.outcome == "inspected"


def test_unsupported_type_stops_after_the_prefix(tmp_path: Path) -> None:
    data = b"\x89PNG\r\n\x1a\n" + b"\0" * (200 * 1024)
    answer, _ = inspect(data, tmp_path)
    assert isinstance(answer, Result)
    assert (answer.state, answer.reasons) == ("not_inspected", ["unsupported_type"])


def test_a_bomb_ends_partial_with_findings_so_far(tmp_path: Path) -> None:
    answer, _ = inspect(fx.many_members(50), tmp_path, Limits(max_members=10))
    assert isinstance(answer, Result)
    assert (answer.state, answer.reasons) == ("partial", ["limit_exceeded"])
    assert answer.findings


def test_cpu_limit(tmp_path: Path) -> None:
    limits = Limits(cpu_seconds=1, cpu_grace_seconds=1, wall_seconds=20, wall_grace_seconds=5)
    answer, _ = inspect(b"SPIN-IN-DETECTOR TOKEN-0001", tmp_path, limits)
    assert isinstance(answer, Result)
    assert (answer.state, answer.reasons) == ("partial", ["limit_exceeded"])


def test_wall_clock_limit(tmp_path: Path) -> None:
    # A CPU limit past the wall limit: the parent's deadline is what stops the child.
    limits = Limits(cpu_seconds=60, wall_seconds=2, wall_grace_seconds=1)
    answer, _ = inspect(b"SPIN-IN-DETECTOR", tmp_path, limits)
    assert isinstance(answer, Result)
    assert answer.state == "partial"
    assert answer.reasons == ["limit_exceeded"]


def test_memory_limit(tmp_path: Path) -> None:
    data = fx.zip_bytes({"a.txt": "TOKEN-0001 " * (8 * MIB)})
    limits = Limits(memory_bytes=160 * MIB, max_unit_chars=64 * MIB)
    answer, _ = inspect(data, tmp_path, limits)
    assert isinstance(answer, Result)
    assert answer.state == "partial"
    assert "limit_exceeded" in answer.reasons


def test_a_detector_failure_is_an_engine_error(tmp_path: Path) -> None:
    answer, summary = inspect(b"RAISE-IN-DETECTOR", tmp_path)
    assert isinstance(answer, client.InspectorError)
    assert answer.code == "engine_error"
    assert summary.outcome == "error:engine_error"


# ---- the handshake (review fixes) ----


def test_many_small_files_in_a_row_are_never_an_engine_error(tmp_path: Path) -> None:
    # A file that fits in the prefix is whole after it: the child doesn't wait for "complete",
    # and the parent doesn't send it, so a child that has already answered isn't an engine error.
    for number in range(40):
        answer, summary = inspect(f"TOKEN-{number:04}".encode(), tmp_path)
        assert isinstance(answer, Result), (number, answer)
        assert answer.state == "inspected"
        assert summary.outcome == "inspected"


@pytest.mark.parametrize("size", [100, 200 * 1024], ids=["in-the-prefix", "past-the-prefix"])
def test_an_invalid_tenant_detector_is_a_bad_request(tmp_path: Path, size: int) -> None:
    # The child answers bad_request as soon as the detectors refuse it, without waiting for the
    # rest of the file: that answer is relayed, not taken for a dead child.
    tenant = [KeywordListSpec(kind="keywords", id="invalid", terms=["x"])]
    data = (b"TOKEN-0001 " * (size // 11 + 1))[:size]
    answer, summary = inspect(data, tmp_path, tenant=tenant)
    assert isinstance(answer, client.InspectorError)
    assert answer.code == "bad_request"
    assert summary.outcome == "error:bad_request"
