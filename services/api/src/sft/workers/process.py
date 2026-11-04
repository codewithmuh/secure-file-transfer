"""Runs a worker as a pod: its internal listener, its work loop, and the shutdown of architecture 8.

    process = WorkerProcess(settings)
    exit_status = await process.run(relay.run)

`run` starts the internal listener (`/healthz`, `/readyz`, `/metrics` on `INTERNAL_PORT`), reports
ready, and runs the work loop until a signal. On SIGTERM or SIGINT:

1. `/readyz` answers 503 and the loop's `stopping` event is set. A loop finishes the batch in hand
   and returns; it takes nothing new.
2. A loop still running after `SHUTDOWN_DRAIN_SECONDS` is cancelled. Its open transaction rolls
   back, so its rows or messages are handled again later: delivery is at least once.
3. The internal listener stops and the process exits 0.

A second SIGINT (Ctrl+C) cancels the loop at once. A loop that fails ends the process with status 1,
so Kubernetes restarts it; it should catch and retry what it can (database or SQS outages).
"""

from __future__ import annotations

import asyncio
import logging
import signal
from collections.abc import Callable, Coroutine
from typing import Any

from prometheus_client import CollectorRegistry

from sft.core.settings import WorkerSettings
from sft.runtime.internal import (
    Readiness,
    Server,
    create_internal_app,
    internal_config,
    process_registry,
)

log = logging.getLogger(__name__)

WorkLoop = Callable[[asyncio.Event], Coroutine[Any, Any, None]]

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_NO_LISTENER = 3


class WorkerProcess:
    def __init__(self, settings: WorkerSettings, registry: CollectorRegistry | None = None) -> None:
        self.settings = settings
        self.readiness = Readiness()
        self.registry = registry or process_registry()
        self.stopping = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None
        self._internal = Server(
            internal_config(
                create_internal_app(self.readiness, self.registry),
                settings.bind_host,
                settings.internal_port,
            )
        )

    def handle_signal(self, sig: signal.Signals) -> None:
        """A first signal starts the graceful shutdown; a second SIGINT forces it."""
        if self.stopping.is_set() and sig == signal.SIGINT:
            log.warning("forced shutdown: the work in hand is cancelled")
            if self._loop_task is not None:
                self._loop_task.cancel()
        else:
            self.shutdown()

    def shutdown(self) -> None:
        if self.stopping.is_set():
            log.info("already shutting down")
            return
        self.readiness.mark_stopping()
        self.stopping.set()
        log.info(
            "shutting down: readiness fails, the work in hand finishes",
            extra={"drain_seconds": self.settings.shutdown_drain_seconds},
        )

    async def run(self, work: WorkLoop, *, handle_signals: bool = True) -> int:
        """Serve the probes, run `work(stopping)` until a signal, drain, return the exit status."""
        loop = asyncio.get_running_loop()
        signals = (signal.SIGTERM, signal.SIGINT) if handle_signals else ()
        for sig in signals:
            loop.add_signal_handler(sig, self.handle_signal, sig)
        internal = asyncio.create_task(self._internal.serve())
        try:
            # uvicorn sets a plain `started` flag and offers nothing to await.
            while not self._internal.started and not internal.done():  # noqa: ASYNC110
                await asyncio.sleep(0.05)
            if not self._internal.started:  # uvicorn exits with status 3 when it can't bind
                log.critical("the internal listener could not start")
                return EXIT_NO_LISTENER
            return await self._run_loop(work)
        finally:
            self._internal.should_exit = True
            await asyncio.gather(internal, return_exceptions=True)
            for sig in signals:
                loop.remove_signal_handler(sig)
            log.info("stopped")

    async def _run_loop(self, work: WorkLoop) -> int:
        self._loop_task = asyncio.create_task(work(self.stopping))
        if not self.stopping.is_set():
            self.readiness.mark_started()
            log.info(
                "ready",
                extra={
                    "version": self.settings.app_version,
                    "internal_port": self.settings.internal_port,
                },
            )
        stop = asyncio.create_task(self.stopping.wait())
        try:
            await asyncio.wait({self._loop_task, stop}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            stop.cancel()
        if not self._loop_task.done():
            # Stopping: the loop gets the drain to finish its batch, then is cancelled.
            done, _ = await asyncio.wait(
                {self._loop_task}, timeout=self.settings.shutdown_drain_seconds
            )
            if not done:
                log.warning("the drain ran out: the work in hand is cancelled")
                self._loop_task.cancel()
        try:
            await self._loop_task
        except asyncio.CancelledError:
            if not self.stopping.is_set():
                raise
            return EXIT_OK
        except Exception:
            log.exception("the work loop failed")
            return EXIT_FAILED
        if not self.stopping.is_set():
            log.error("the work loop ended without a shutdown")
            return EXIT_FAILED
        return EXIT_OK
