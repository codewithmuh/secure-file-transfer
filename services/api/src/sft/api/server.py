"""Runs the API service: two listeners in one process, and the shutdown of architecture 8.

Two uvicorn servers share one event loop:

- public (`PUBLIC_PORT`, 8000): the API, the only port the load balancer's listener routes to;
- internal (`INTERNAL_PORT`, 8001): `/healthz`, `/readyz` and `/metrics`, for the kubelet, the
  load balancer's target health check and Prometheus. A routing mistake on the public side can't
  expose them, and probes and scrapes don't count as API requests.

On SIGTERM or SIGINT:

1. `/readyz` answers 503.
2. The public server closes its listening socket and its idle keep-alive connections, and gives
   in-flight requests up to `SHUTDOWN_DRAIN_SECONDS` (20) to finish; any still running then are
   cancelled. This is uvicorn's own graceful shutdown; the app's lifespan shutdown runs after it.
3. The internal server stops, so `/readyz` and `/metrics` answer until the drain is over.
4. The process exits 0.

What the app can't do is fail readiness *before* it stops accepting: uvicorn closes the public
listener in step 2, the moment the signal arrives. In Kubernetes a terminating pod leaves its
Service endpoints, and the load balancer starts to deregister it, at the same time as the kubelet
sends SIGTERM, so for a few seconds new connections can still arrive at a closed port. The pod spec
covers that window with a `preStop` sleep hook, which runs before SIGTERM is sent (M4 manifests);
the pod's 150 s grace period covers the hook plus the drain.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Iterator

import uvicorn
from starlette.types import ASGIApp

from sft.api.app import create_app
from sft.api.internal import Readiness, create_internal_app
from sft.api.observability import HttpMetrics, RequestContextMiddleware
from sft.core.settings import Settings

log = logging.getLogger(__name__)

_INTERNAL_DRAIN_SECONDS = 5  # probes and scrapes are quick


class _Server(uvicorn.Server):
    """A uvicorn server that leaves signal handling to `ApiServer`.

    uvicorn's own handler would stop only one of the two servers. After its graceful shutdown it
    also raises the signal again with the default handler, so the process ends killed by SIGTERM
    (exit status 143) instead of exiting 0, unless it runs as PID 1, where the kernel ignores it.
    """

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def _config(app: ASGIApp, host: str, port: int, *, drain: int, lifespan: bool) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=host,
        port=port,
        lifespan="on" if lifespan else "off",
        timeout_graceful_shutdown=drain,
        # Each request runs in a fresh context, so its IDs can't leak into another's logs.
        reset_contextvars=True,
        # The client address is the socket peer until the client-IP rule of ADR-0002 (trust only
        # our load balancer's X-Forwarded-For entry) is built.
        proxy_headers=False,
        server_header=False,
        access_log=False,  # RequestContextMiddleware logs each request
        log_config=None,  # logging is set up once, as JSON (sft.core.logs)
    )


class ApiServer:
    def __init__(self, settings: Settings, app: ASGIApp | None = None) -> None:
        self.settings = settings
        self.readiness = Readiness()
        self.metrics = HttpMetrics.create()
        public_app = RequestContextMiddleware(app or create_app(), self.metrics)
        internal_app = create_internal_app(self.readiness, self.metrics.registry)
        self._public = _Server(
            _config(
                public_app,
                settings.bind_host,
                settings.public_port,
                drain=settings.shutdown_drain_seconds,
                lifespan=True,
            )
        )
        self._internal = _Server(
            _config(
                internal_app,
                settings.bind_host,
                settings.internal_port,
                drain=_INTERNAL_DRAIN_SECONDS,
                lifespan=False,
            )
        )

    def shutdown(self) -> None:
        """Start the graceful shutdown. The signal handlers call it; a second call does nothing."""
        if self.readiness.stopping:
            log.info("already shutting down")
            return
        self.readiness.mark_stopping()
        log.info(
            "shutting down: readiness fails, in-flight requests drain",
            extra={"drain_seconds": self.settings.shutdown_drain_seconds},
        )
        self._public.should_exit = True

    async def run(self, *, handle_signals: bool = True) -> int:
        """Serve until `shutdown()`, drain, and return the exit status.

        If a server can't start (its port is taken, or the app's startup fails), uvicorn exits the
        process with status 3.
        """
        loop = asyncio.get_running_loop()
        signals = (signal.SIGTERM, signal.SIGINT) if handle_signals else ()
        for sig in signals:
            loop.add_signal_handler(sig, self.shutdown)
        try:
            internal = asyncio.create_task(self._internal.serve())
            public = asyncio.create_task(self._public.serve())

            def starting() -> bool:
                both_started = self._public.started and self._internal.started
                return not both_started and not public.done()

            # uvicorn sets a plain `started` flag and offers nothing to await.
            while starting():  # noqa: ASYNC110
                await asyncio.sleep(0.05)
            if self._public.started:
                self.readiness.mark_started()
                log.info(
                    "ready",
                    extra={
                        "version": self.settings.app_version,
                        "public_port": self.settings.public_port,
                        "internal_port": self.settings.internal_port,
                    },
                )
            await public
            self._internal.should_exit = True
            await internal
        finally:
            for sig in signals:
                loop.remove_signal_handler(sig)
        log.info("stopped")
        return 0
