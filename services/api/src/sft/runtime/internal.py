"""The internal listener: liveness, readiness and metrics (architecture 8).

It has its own port, which the public load balancer's listener doesn't route to. The kubelet probes
it, the load balancer's target health check uses the API's `/readyz`, and Prometheus scrapes
`/metrics` from inside the cluster (ADR-0009, ADR-0021). The API's public port serves only the API;
a worker has no other port.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

import uvicorn
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    GCCollector,
    PlatformCollector,
    ProcessCollector,
    generate_latest,
)
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp

INTERNAL_DRAIN_SECONDS = 5
"""Probes and scrapes are quick."""


class Readiness:
    """Whether this process should get traffic: not before it has started, nor once it stops."""

    def __init__(self) -> None:
        self.started = False
        self.stopping = False

    def mark_started(self) -> None:
        self.started = True

    def mark_stopping(self) -> None:
        self.stopping = True


def process_registry() -> CollectorRegistry:
    """A registry with the process, platform and garbage-collector metrics the default one has.

    Each process makes its own, so tests don't share state.
    """
    registry = CollectorRegistry()
    ProcessCollector(registry=registry)
    PlatformCollector(registry=registry)
    GCCollector(registry=registry)
    return registry


def create_internal_app(readiness: Readiness, registry: CollectorRegistry) -> Starlette:
    async def healthz(_: Request) -> Response:
        """Liveness: the process is up. Never checks dependencies, so an outage can't restart it."""
        return JSONResponse({"status": "ok"})

    async def readyz(_: Request) -> Response:
        """Readiness: 503 until started and during shutdown."""
        if readiness.stopping:
            return JSONResponse({"status": "stopping"}, status_code=503)
        if not readiness.started:
            return JSONResponse({"status": "starting"}, status_code=503)
        return JSONResponse({"status": "ready"})

    async def metrics(_: Request) -> Response:
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    return Starlette(
        routes=[
            Route("/healthz", healthz, methods=["GET"]),
            Route("/readyz", readyz, methods=["GET"]),
            Route("/metrics", metrics, methods=["GET"]),
        ]
    )


class Server(uvicorn.Server):
    """A uvicorn server that leaves signal handling to its entry point.

    uvicorn's own handler would stop only this server. After its graceful shutdown it also raises
    the signal again with the default handler, so the process ends killed by SIGTERM (exit status
    143) instead of exiting 0, unless it runs as PID 1, where the kernel ignores it.
    """

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def internal_config(app: ASGIApp, host: str, port: int) -> uvicorn.Config:
    """uvicorn's settings for the internal listener."""
    return uvicorn.Config(
        app,
        host=host,
        port=port,
        lifespan="off",
        timeout_graceful_shutdown=INTERNAL_DRAIN_SECONDS,
        reset_contextvars=True,
        proxy_headers=False,
        server_header=False,
        access_log=False,  # probes every few seconds would drown the logs
        log_config=None,  # logging is set up once, as JSON (sft.core.logs)
    )
