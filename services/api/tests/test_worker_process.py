"""WorkerProcess: a worker's probes, its SIGTERM and its drain (architecture 8), in process."""

import asyncio
import os
import signal
import socket
from collections.abc import Callable

import httpx2 as httpx
import pytest
from pydantic import SecretStr

from sft.core.settings import WorkerSettings
from sft.workers.process import EXIT_FAILED, EXIT_NO_LISTENER, EXIT_OK, WorkerProcess

pytestmark = pytest.mark.anyio

Logs = Callable[[], list[dict[str, object]]]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def settings(drain: int = 5, port: int | None = None) -> WorkerSettings:
    return WorkerSettings(
        internal_port=port or free_port(),
        shutdown_drain_seconds=drain,
        database_url=SecretStr("postgresql://sft_relay@127.0.0.1:1/sft"),
        sqs_queue_prefix="sft-test-",
    )


async def wait_until(check: Callable[[], bool]) -> None:
    for _ in range(250):  # 5 s
        if check():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out")


async def get(port: int, path: str) -> httpx.Response:
    async with httpx.AsyncClient() as client:
        return await client.get(f"http://127.0.0.1:{port}{path}")


async def test_probes_answer_and_sigterm_drains_the_loop_then_exits_0(json_logs: Logs) -> None:
    s = settings()
    process = WorkerProcess(s)
    batches: list[str] = []

    async def loop(stopping: asyncio.Event) -> None:
        await stopping.wait()
        await asyncio.sleep(0.2)  # the batch in hand
        batches.append("finished")

    task = asyncio.create_task(process.run(loop))
    await wait_until(lambda: process.readiness.started)
    assert (await get(s.internal_port, "/healthz")).json() == {"status": "ok"}
    assert (await get(s.internal_port, "/readyz")).status_code == 200
    assert b"python_info" in (await get(s.internal_port, "/metrics")).content

    os.kill(os.getpid(), signal.SIGTERM)
    await wait_until(lambda: process.readiness.stopping)
    assert (await get(s.internal_port, "/readyz")).json() == {"status": "stopping"}
    assert await task == EXIT_OK
    assert batches == ["finished"]
    os.kill(os.getpid(), 0)  # the handlers are gone and this process still runs
    assert [line["msg"] for line in json_logs()][-1] == "stopped"


async def test_a_loop_that_outlasts_the_drain_is_cancelled(json_logs: Logs) -> None:
    process = WorkerProcess(settings(drain=1))
    cancelled = asyncio.Event()

    async def stubborn(stopping: asyncio.Event) -> None:
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    task = asyncio.create_task(process.run(stubborn, handle_signals=False))
    await wait_until(lambda: process.readiness.started)
    process.shutdown()
    process.shutdown()  # a repeated signal changes nothing
    assert await task == EXIT_OK
    assert cancelled.is_set()
    messages = [line["msg"] for line in json_logs()]
    assert "the drain ran out: the work in hand is cancelled" in messages
    assert "already shutting down" in messages


async def test_a_second_sigint_cancels_the_work_at_once() -> None:
    process = WorkerProcess(settings(drain=30))

    async def stubborn(stopping: asyncio.Event) -> None:
        await asyncio.sleep(3600)

    task = asyncio.create_task(process.run(stubborn, handle_signals=False))
    await wait_until(lambda: process.readiness.started)
    process.handle_signal(signal.SIGINT)
    await asyncio.sleep(0.05)
    assert not task.done()
    process.handle_signal(signal.SIGINT)
    assert await asyncio.wait_for(task, timeout=5) == EXIT_OK


async def test_a_loop_that_fails_ends_the_process_with_status_1(json_logs: Logs) -> None:
    async def broken(stopping: asyncio.Event) -> None:
        raise RuntimeError("bug")

    assert await WorkerProcess(settings()).run(broken, handle_signals=False) == EXIT_FAILED
    assert any(line["msg"] == "the work loop failed" for line in json_logs())


async def test_a_loop_that_returns_on_its_own_ends_with_status_1() -> None:
    async def done(stopping: asyncio.Event) -> None:
        return None

    assert await WorkerProcess(settings()).run(done, handle_signals=False) == EXIT_FAILED


async def test_a_signal_during_startup_never_reports_ready() -> None:
    process = WorkerProcess(settings())
    process.shutdown()

    async def loop(stopping: asyncio.Event) -> None:
        await stopping.wait()

    assert await process.run(loop, handle_signals=False) == EXIT_OK
    assert not process.readiness.started


async def test_a_taken_port_ends_the_worker_with_status_3() -> None:
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        process = WorkerProcess(settings(port=taken.getsockname()[1]))
        started = False

        async def loop(stopping: asyncio.Event) -> None:
            nonlocal started
            started = True

        assert await process.run(loop, handle_signals=False) == EXIT_NO_LISTENER
    assert not started
    assert not process.readiness.started
