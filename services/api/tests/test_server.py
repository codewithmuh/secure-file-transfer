"""The runtime contract end to end: real listeners and sockets, and real signals in a subprocess."""

import asyncio
import contextlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable

import httpx2 as httpx
import pytest
import uvicorn
from fastapi import FastAPI
from pydantic import SecretStr

from api_settings import API_ENV, API_SETTINGS
from sft.api.app import create_app
from sft.api.server import ApiServer
from sft.core.settings import Settings

Logs = Callable[[], list[dict[str, object]]]


def free_ports(count: int) -> list[int]:
    """Ports nothing listens on now; the sockets stay open until all are picked, so they differ."""
    sockets = [socket.socket() for _ in range(count)]
    try:
        for s in sockets:
            s.bind(("127.0.0.1", 0))
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


# Nothing listens on port 1. The server never connects at startup, so these tests need no database.
DATABASE_URL = "postgresql+psycopg://sft_api@127.0.0.1:1/sft"


def settings(drain: int = 5) -> Settings:
    public, internal = free_ports(2)
    return Settings(
        bind_host="127.0.0.1",
        public_port=public,
        internal_port=internal,
        shutdown_drain_seconds=drain,
        database_url=SecretStr(DATABASE_URL),
        **API_SETTINGS,  # type: ignore[arg-type]
    )


def urls(s: Settings) -> tuple[str, str]:
    return f"http://127.0.0.1:{s.public_port}", f"http://127.0.0.1:{s.internal_port}"


def app_with_slow_route(in_flight: asyncio.Event, seconds: float) -> FastAPI:
    app = create_app()

    @app.get("/slow")
    async def slow() -> dict[str, str]:
        in_flight.set()
        await asyncio.sleep(seconds)
        return {"status": "done"}

    return app


async def wait_until_ready(client: httpx.AsyncClient, internal: str) -> None:
    for _ in range(100):
        try:
            if (await client.get(f"{internal}/readyz")).status_code == 200:
                return
        except httpx.TransportError:
            pass
        await asyncio.sleep(0.05)
    raise AssertionError("never became ready")


@pytest.mark.anyio
async def test_serves_probes_and_metrics_only_on_the_internal_port() -> None:
    s = settings()
    server = ApiServer(s)
    run = asyncio.create_task(server.run(handle_signals=False))
    public, internal = urls(s)
    async with httpx.AsyncClient() as client:
        await wait_until_ready(client, internal)
        assert (await client.get(f"{internal}/healthz")).status_code == 200
        assert (await client.get(f"{internal}/metrics")).status_code == 200
        for path in ("/healthz", "/readyz", "/metrics"):
            r = await client.get(f"{public}{path}")
            assert r.status_code == 404
            assert "server" not in r.headers  # uvicorn doesn't advertise itself
        server.shutdown()
    assert await run == 0


@pytest.mark.anyio
async def test_shutdown_fails_readiness_and_drains_in_flight_requests() -> None:
    s = settings(drain=5)
    in_flight = asyncio.Event()
    server = ApiServer(s, app_with_slow_route(in_flight, seconds=0.5))
    run = asyncio.create_task(server.run(handle_signals=False))
    public, internal = urls(s)
    async with httpx.AsyncClient() as client, httpx.AsyncClient() as newcomer:
        await wait_until_ready(client, internal)
        slow = asyncio.create_task(client.get(f"{public}/slow"))
        await in_flight.wait()

        server.shutdown()
        r = await client.get(f"{internal}/readyz")
        assert (r.status_code, r.json()) == (503, {"status": "stopping"})
        await asyncio.sleep(0.3)  # uvicorn notices within 0.1 s and closes the listener
        with pytest.raises(httpx.ConnectError):
            await newcomer.get(f"{public}/slow")
        assert (await client.get(f"{internal}/metrics")).status_code == 200  # still scraped

        r = await slow
        assert (r.status_code, r.json()) == (200, {"status": "done"})
    assert await run == 0


@pytest.mark.anyio
async def test_requests_still_running_after_the_drain_are_cut() -> None:
    s = settings(drain=1)
    in_flight = asyncio.Event()
    server = ApiServer(s, app_with_slow_route(in_flight, seconds=30))
    run = asyncio.create_task(server.run(handle_signals=False))
    public, internal = urls(s)
    async with httpx.AsyncClient() as client:
        await wait_until_ready(client, internal)
        slow = asyncio.create_task(client.get(f"{public}/slow"))
        await in_flight.wait()
        started = time.monotonic()
        server.shutdown()
        assert await run == 0
        assert time.monotonic() - started < 3
        # uvicorn cancels the request and answers 500 when it hadn't started a response.
        assert (await slow).status_code == 500


@pytest.mark.anyio
async def test_ctrl_c_during_the_drain_cuts_it_short() -> None:
    s = settings(drain=20)
    in_flight = asyncio.Event()
    server = ApiServer(s, app_with_slow_route(in_flight, seconds=30))
    run = asyncio.create_task(server.run(handle_signals=False))
    public, internal = urls(s)
    async with httpx.AsyncClient() as client:
        await wait_until_ready(client, internal)
        slow = asyncio.create_task(client.get(f"{public}/slow", timeout=40))
        await in_flight.wait()
        server.handle_signal(signal.SIGINT)
        await asyncio.sleep(0.3)  # the drain has begun
        started = time.monotonic()
        server.handle_signal(signal.SIGINT)
        assert await run == 0
        assert time.monotonic() - started < 3  # not the 20 s drain
        assert (await slow).status_code == 500  # the request was cancelled


@pytest.mark.anyio
async def test_a_repeated_sigterm_does_not_cut_the_drain() -> None:
    s = settings(drain=5)
    in_flight = asyncio.Event()
    server = ApiServer(s, app_with_slow_route(in_flight, seconds=0.5))
    run = asyncio.create_task(server.run(handle_signals=False))
    public, internal = urls(s)
    async with httpx.AsyncClient() as client:
        await wait_until_ready(client, internal)
        slow = asyncio.create_task(client.get(f"{public}/slow"))
        await in_flight.wait()
        server.handle_signal(signal.SIGTERM)
        await asyncio.sleep(0.1)
        server.handle_signal(signal.SIGTERM)
        r = await slow
        assert (r.status_code, r.json()) == (200, {"status": "done"})
    assert await run == 0


@pytest.mark.anyio
async def test_a_signal_during_startup_never_reports_ready(json_logs: Logs) -> None:
    server = ApiServer(settings())
    server.handle_signal(signal.SIGTERM)  # before the listeners have started
    assert await server.run(handle_signals=False) == 0
    assert not server.readiness.started
    messages = [line["msg"] for line in json_logs()]
    assert "shutting down: readiness fails, in-flight requests drain" in messages
    assert "ready" not in messages
    assert messages[-1] == "stopped"


def test_uvicorn_still_lets_us_replace_its_signal_handling() -> None:
    # server.py overrides this method; if a uvicorn upgrade renames it, the override is silently
    # ignored and SIGTERM handling changes. The signal tests below would fail too.
    assert callable(vars(uvicorn.Server).get("capture_signals"))


def start_process(env: dict[str, str]) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [sys.executable, "-m", "sft.api"],
        env={**os.environ, "DATABASE_URL": DATABASE_URL, **API_ENV, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_a_signal_drains_and_exits_zero(sig: signal.Signals) -> None:
    s = settings()
    proc = start_process(
        {
            "BIND_HOST": "127.0.0.1",
            "PUBLIC_PORT": str(s.public_port),
            "INTERNAL_PORT": str(s.internal_port),
            "APP_VERSION": "9.9.9",
            "LOG_LEVEL": "info",
        }
    )
    try:
        for _ in range(200):
            with contextlib.suppress(httpx.TransportError):
                if httpx.get(f"{urls(s)[1]}/readyz").status_code == 200:
                    break
            time.sleep(0.05)  # on a 503 too, not only when the port isn't open yet
        else:
            raise AssertionError("never became ready")
        proc.send_signal(sig)
        # Not PID 1 here, so this also shows the process exits 0 rather than dying by the signal.
        assert proc.wait(timeout=10) == 0
    finally:
        proc.kill()
    lines = [json.loads(line) for line in proc.stdout.read().splitlines()]  # type: ignore[union-attr]
    messages = [line["msg"] for line in lines]
    assert "ready" in messages
    assert "shutting down: readiness fails, in-flight requests drain" in messages
    assert messages[-1] == "stopped"
    ready = next(line for line in lines if line["msg"] == "ready")
    assert ready["version"] == "9.9.9"


def test_bad_settings_exit_2_without_echoing_the_value() -> None:
    proc = start_process({"PUBLIC_PORT": "not-a-port-and-maybe-a-secret"})
    assert proc.wait(timeout=10) == 2
    [line] = [json.loads(line) for line in proc.stdout.read().splitlines()]  # type: ignore[union-attr]
    assert line["msg"] == "invalid settings"
    assert line["errors"][0]["setting"] == "PUBLIC_PORT"
    assert "not-a-port" not in json.dumps(line)


def test_a_port_in_use_stops_the_process_with_status_3() -> None:
    s = settings()
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", s.internal_port))
        taken.listen()
        proc = start_process(
            {
                "BIND_HOST": "127.0.0.1",
                "PUBLIC_PORT": str(s.public_port),
                "INTERNAL_PORT": str(s.internal_port),
            }
        )
        assert proc.wait(timeout=10) == 3
