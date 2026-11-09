"""The NFR-23 benchmark (#250, tools/benchmark_inspection.py): its corpus, its pass and its verdict.

The pass runs against the scan worker's stand-ins (tests/scan_fixtures.py), on real sockets, with
the inspector in `detect` mode: the real extraction and detectors in process, so every format the
benchmark makes is read as the inspector reads it. The run against the real clamd and inspector is
the benchmark itself (docs/operations/performance.md).
"""

from __future__ import annotations

import asyncio
import io
import json
import random
import threading
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from scan_fixtures import FakeClamd, FakeInspector
from sft.dlp.detect import checks
from sft.workers.scan import Engines
from tools import benchmark_inspection as bench

pytestmark = pytest.mark.anyio


def test_the_corpus_follows_the_mix_and_every_format_is_well_formed() -> None:
    files = bench.corpus(seed=7, files=200, large=0, max_bytes=2 * bench.MB, max_large_bytes=0)
    kinds = {f.kind for f in files}
    assert kinds <= {*bench.TEXT_KINDS, "binary"}
    text = [f for f in files if f.kind != "binary"]
    assert 0.3 < len(text) / len(files) < 0.55  # about 42 % up to 100 MB ([CAP] A45)
    assert all(f.size_class == "small" for f in files)
    for f in files:
        if f.kind in ("docx", "xlsx", "zip"):
            assert zipfile.ZipFile(io.BytesIO(f.data)).testzip() is None
        if f.kind == "pdf":
            assert f.data.startswith(b"%PDF-1.4")
            assert f.data.rstrip().endswith(b"%%EOF")
    assert bench.corpus(7, 200, 0, 2 * bench.MB, 0) == files  # one seed, one corpus


def test_exact_sizes_and_the_large_class() -> None:
    rng = random.Random(1)  # noqa: S311 - test data
    for kind in ("txt", "txt-sjis", "csv", "binary"):
        assert len(bench.make_file(rng, kind, 12_345, marked=True)) == 12_345
    with pytest.raises(ValueError, match="nope"):
        bench.make_file(rng, "nope", 10, marked=False)
    [large] = bench.corpus(seed=3, files=0, large=1, max_bytes=0, max_large_bytes=101 * bench.MB)
    assert large.size_class == "large"
    assert large.kind != "pdf"


def test_a_my_number_passes_its_check() -> None:
    rng = random.Random(2)  # noqa: S311 - test data
    assert all(checks.is_my_number(bench.my_number(rng)) for _ in range(50))


@pytest.fixture
async def engines() -> Any:
    clamd, inspector = FakeClamd(), FakeInspector(mode="detect")
    await clamd.start()
    await inspector.start()
    yield Engines("127.0.0.1", clamd.port, "127.0.0.1", inspector.port), clamd, inspector
    await clamd.stop()
    await inspector.stop()


async def test_the_corpus_through_the_scan_pass(engines: Any) -> None:
    where, clamd, _ = engines
    files = bench.corpus(seed=11, files=24, large=0, max_bytes=300_000, max_large_bytes=0)
    results = await bench.run(files, where, concurrency=3)
    assert sum(map(len, clamd.received)) == sum(len(f.data) for f in files)
    assert {r.scan_state for r in results} == {"clean"}
    for r in results:
        # Every text format is read through (the PDFs, docx, xlsx and archives the tool makes
        # included); binaries stop after their first 64 KiB.
        expected = "not_inspected" if r.kind == "binary" else "inspected"
        assert r.inspection_state == expected, (r.kind, r.inspection_state, r.inspection_reasons)
    summary = bench.report(results)
    assert summary["passed"]
    assert summary["classes"]["small"]["files"] == 24
    assert summary["classes"]["large"] == {"files": 0}
    assert not summary["failures"]


async def test_a_dead_inspector_is_a_failure(engines: Any) -> None:
    where, _, _ = engines
    dead = Engines(where.clamd_host, where.clamd_port, "127.0.0.1", 9, connect_timeout=1.0)
    files = bench.corpus(seed=5, files=2, large=0, max_bytes=10_000, max_large_bytes=0)
    summary = bench.report(await bench.run(files, dead, concurrency=1))
    assert not summary["passed"]
    assert {f["inspection_state"] for f in summary["failures"]} == {"failed"}


def timed(seconds: float, size_class: str = "small") -> bench.Timed:
    return bench.Timed("txt", size_class, 10, False, seconds, "clean", "inspected", ())


def test_a_missed_percentile_fails_the_run() -> None:
    fast = [timed(1.0)] * 95 + [timed(70.0)] * 5
    assert bench.report(fast)["passed"]  # p95 is the 95th file: 1 s
    slow = [timed(1.0)] * 90 + [timed(70.0)] * 10
    summary = bench.report(slow)
    assert not summary["passed"]
    assert summary["classes"]["small"]["missed"] == {"p95": 70.0}
    large = bench.report([timed(700.0, "large")])
    assert large["classes"]["large"]["missed"] == {"p95": 700.0}
    assert bench.percentile([3.0, 1.0, 2.0], 50) == 2.0


@pytest.fixture
def engines_in_a_thread() -> Iterator[tuple[int, int]]:
    """The stand-ins on a loop of their own, for `main`, which runs its own."""
    loop = asyncio.new_event_loop()
    clamd, inspector = FakeClamd(), FakeInspector(mode="detect")
    ready = threading.Event()

    def serve() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(clamd.start())
        loop.run_until_complete(inspector.start())
        ready.set()
        loop.run_forever()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    ready.wait(10)
    yield clamd.port, inspector.port
    asyncio.run_coroutine_threadsafe(clamd.stop(), loop).result(5)
    asyncio.run_coroutine_threadsafe(inspector.stop(), loop).result(5)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(5)


def test_main_reports_and_exits_0(
    engines_in_a_thread: tuple[int, int], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    clamd, inspector = engines_in_a_thread
    out = tmp_path / "report.json"
    status = bench.main(
        [
            *("--clamd", f"127.0.0.1:{clamd}", "--inspector", f"127.0.0.1:{inspector}"),
            *("--files", "6", "--max-bytes", "50000", "--json", str(out)),
        ]
    )
    assert status == 0
    report = json.loads(out.read_text())
    assert report["passed"]
    assert len(report["files"]) == 6
    assert "small: 6 files" in capsys.readouterr().out


def test_main_refuses_bad_arguments() -> None:
    with pytest.raises(SystemExit):
        bench.main(["--clamd", "nohost"])
    with pytest.raises(SystemExit):
        bench.main(["--files", "0"])
