"""Runs the API service: two listeners in one process, and the shutdown of architecture 8.

Two uvicorn servers share one event loop:

- public (`PUBLIC_PORT`, 8000): the API, the only port the load balancer's listener routes to. In
  AWS it serves TLS (`PUBLIC_TLS`, `sft.runtime.tls`; encryption and keys 2.2), because the target
  group speaks HTTPS to it;
- internal (`INTERNAL_PORT`, 8001): `/healthz`, `/readyz` and `/metrics`, for the kubelet, the
  load balancer's target health check and Prometheus, always plain HTTP. A routing mistake on the
  public side can't expose them, and probes and scrapes don't count as API requests.

On SIGTERM or SIGINT:

1. `/readyz` answers 503.
2. The public server closes its listening socket and its idle keep-alive connections, and gives
   in-flight requests up to `SHUTDOWN_DRAIN_SECONDS` (20) to finish; any still running then are
   cancelled. This is uvicorn's own graceful shutdown; the app's lifespan shutdown runs after it.
3. The internal server stops, so `/readyz` and `/metrics` answer until the drain is over.
4. The process exits 0.

Ctrl+C during the drain (a second SIGINT) cuts it short, as in uvicorn: in-flight requests are
cancelled, and the app's lifespan shutdown still runs, so its cleanup isn't skipped. A repeated
SIGTERM changes nothing, so whatever sent it can't cut the drain short by sending it again.

What the app can't do is fail readiness *before* it stops accepting: uvicorn closes the public
listener in step 2, the moment the signal arrives. In Kubernetes a terminating pod leaves its
Service endpoints, and the load balancer starts to deregister it, at the same time as the kubelet
sends SIGTERM, so for a few seconds new connections can still arrive at a closed port. The pod spec
covers that window with a `preStop` sleep hook, which runs before SIGTERM is sent (M4 manifests);
the pod's 150 s grace period covers the hook plus the drain.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import ssl
from collections.abc import Callable

import uvicorn
from prometheus_client import CollectorRegistry
from starlette.types import ASGIApp

from sft.api.app import create_app
from sft.api.observability import HttpMetrics, RequestContextMiddleware
from sft.core.settings import ServerSettings, Settings
from sft.runtime.internal import Readiness, Server, create_internal_app, internal_config
from sft.runtime.tls import server_context

log = logging.getLogger(__name__)


def _config(
    app: ASGIApp, host: str, port: int, *, drain: int, tls: ssl.SSLContext | None = None
) -> uvicorn.Config:
    return uvicorn.Config(
        app,
        host=host,
        port=port,
        # Our own context (sft.runtime.tls), so the generated key never needs a file.
        ssl_context_factory=None if tls is None else (lambda _config, _default: tls),
        lifespan="on",
        timeout_graceful_shutdown=drain,
        # Each request runs in a fresh context, so its IDs can't leak into another's logs.
        reset_contextvars=True,
        # The client address is the socket peer; sft.api.client_ip applies ADR-0002's rule (trust
        # only our load balancer's X-Forwarded-For entry) where the address is used.
        proxy_headers=False,
        server_header=False,
        access_log=False,  # RequestContextMiddleware logs each request
        log_config=None,  # logging is set up once, as JSON (sft.core.logs)
    )


class ApiServer:
    def __init__(
        self,
        settings: ServerSettings,
        app: ASGIApp | None = None,
        *,
        make_app: Callable[[CollectorRegistry], ASGIApp] | None = None,
    ) -> None:
        """`app` is the public listener's app; by default the public API's. `make_app` builds it
        instead, given the registry /metrics serves, so the app's own metrics are scraped too."""
        self.settings = settings
        self.readiness = Readiness()
        self.metrics = HttpMetrics.create()
        if make_app is not None:
            app = make_app(self.metrics.registry)
        if app is None:
            if not isinstance(settings, Settings):
                raise TypeError("the public app needs the public API's Settings")
            app = create_app(settings, registry=self.metrics.registry)
        public_app = RequestContextMiddleware(app, self.metrics)
        internal_app = create_internal_app(self.readiness, self.metrics.registry)
        tls = server_context(
            settings.public_tls,
            cert_file=settings.public_tls_cert_file,
            key_file=settings.public_tls_key_file,
        )
        self._public = Server(
            _config(
                public_app,
                settings.bind_host,
                settings.public_port,
                drain=settings.shutdown_drain_seconds,
                tls=tls,
            )
        )
        self._internal = Server(
            internal_config(internal_app, settings.bind_host, settings.internal_port)
        )

    def handle_signal(self, sig: signal.Signals) -> None:
        """A first signal starts the graceful shutdown; a second SIGINT forces it, like uvicorn."""
        if self.readiness.stopping and sig == signal.SIGINT:
            self.force_shutdown()
        else:
            self.shutdown()

    def shutdown(self) -> None:
        """Start the graceful shutdown; a second call does nothing."""
        if self.readiness.stopping:
            log.info("already shutting down")
            return
        self.readiness.mark_stopping()
        log.info(
            "shutting down: readiness fails, in-flight requests drain",
            extra={"drain_seconds": self.settings.shutdown_drain_seconds},
        )
        self._public.should_exit = True

    def force_shutdown(self) -> None:
        """Cut the drain short: cancel in-flight requests; the lifespan shutdown still runs."""
        self.readiness.mark_stopping()
        log.warning("forced shutdown: in-flight requests are cancelled")
        for server in (self._public, self._internal):
            server.should_exit = True
            # Cancelling the requests is what uvicorn itself does when the drain timeout runs out.
            # uvicorn's force_exit isn't set: it would still wait for the connections to close, and
            # it skips the app's lifespan shutdown, which later holds cleanup such as closing the
            # database pool.
            for task in server.server_state.tasks:
                task.cancel()

    async def run(self, *, handle_signals: bool = True) -> int:
        """Serve until `shutdown()`, drain, and return the exit status.

        If a server can't start (its port is taken, or the app's startup fails), uvicorn exits the
        process with status 3.
        """
        loop = asyncio.get_running_loop()
        signals = (signal.SIGTERM, signal.SIGINT) if handle_signals else ()
        for sig in signals:
            loop.add_signal_handler(sig, self.handle_signal, sig)
        try:
            internal = asyncio.create_task(self._internal.serve())
            public = asyncio.create_task(self._public.serve())

            def starting() -> bool:
                both_started = self._public.started and self._internal.started
                return not both_started and not public.done()

            # uvicorn sets a plain `started` flag and offers nothing to await.
            while starting():  # noqa: ASYNC110
                await asyncio.sleep(0.05)
            # A signal during startup has already begun the shutdown: never report ready after it.
            if self._public.started and not self.readiness.stopping:
                self.readiness.mark_started()
                log.info(
                    "ready",
                    extra={
                        "version": self.settings.app_version,
                        "public_port": self.settings.public_port,
                        "public_tls": self.settings.public_tls,
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
