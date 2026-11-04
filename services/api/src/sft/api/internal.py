"""The internal listener: liveness, readiness and metrics (architecture 8).

It has its own port, which the public load balancer's listener doesn't route to. The kubelet probes
it, the load balancer's target health check uses its `/readyz`, and Prometheus scrapes its
`/metrics` from inside the cluster (ADR-0009, ADR-0021). The public port serves only the API.
"""

from __future__ import annotations

from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, generate_latest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route


class Readiness:
    """Whether this process should get traffic: not before it has started, nor once it stops."""

    def __init__(self) -> None:
        self.started = False
        self.stopping = False

    def mark_started(self) -> None:
        self.started = True

    def mark_stopping(self) -> None:
        self.stopping = True


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
