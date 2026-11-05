"""Request IDs, trace IDs, request metrics and one log line per request (architecture 5.5, 8).

OpenTelemetry arrives later (ADR-0009). Until then the trace ID comes from the W3C `traceparent`
header when a valid one is present, so logs already join up with the caller's trace, and is
generated otherwise.
"""

from __future__ import annotations

import logging
import re
import secrets
import time
from dataclasses import dataclass

from prometheus_client import CollectorRegistry, Counter, Histogram
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sft.core.logs import bind_context
from sft.runtime.internal import process_registry

log = logging.getLogger("sft.api.request")

# Bucket edges at 0.3 s and 1 s match NFR-2 (p95 <= 300 ms, p99 <= 1 s), so the SLIs are exact.
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 1.0, 2.5, 5.0, 10.0)

# Any other method is counted as "other", so a client can't add label values at will.
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

# version-traceid-parentid-flags; a later version may add fields after them (W3C Trace Context).
_TRACEPARENT = re.compile(r"([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}(-.*)?")


@dataclass(frozen=True)
class HttpMetrics:
    """The API's metrics, in a registry of their own so tests don't share state."""

    registry: CollectorRegistry
    requests: Counter
    duration: Histogram

    @classmethod
    def create(cls) -> HttpMetrics:
        registry = process_registry()
        requests = Counter(
            "http_requests_total",
            "HTTP requests on the public port.",
            ["method", "route", "status"],
            registry=registry,
        )
        duration = Histogram(
            "http_request_duration_seconds",
            "Time from the request to the end of its response, on the public port.",
            ["method", "route"],
            buckets=LATENCY_BUCKETS,
            registry=registry,
        )
        return cls(registry, requests, duration)


def new_request_id() -> str:
    """A fresh request ID, never the client's: it can't pick the ID that logs and support quote."""
    return f"req_{secrets.token_hex(16)}"


def new_trace_id() -> str:
    return secrets.token_hex(16)


def trace_id_from(traceparent: list[str]) -> str | None:
    """The trace ID of a valid `traceparent` header, or None, and the caller starts a new trace."""
    if len(traceparent) != 1:  # none, or more than one, which the spec treats as invalid
        return None
    match = _TRACEPARENT.fullmatch(traceparent[0])
    if match is None:
        return None
    version, trace_id, parent_id, rest = match.groups()
    if version == "ff" or (version == "00" and rest is not None):
        return None
    if trace_id == "0" * 32 or parent_id == "0" * 16:
        return None
    return trace_id


def _route_label(scope: Scope) -> str:
    """The route template, such as `/v1/transfers/{transfer_id}`, so IDs don't become labels."""
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else "unmatched"


class RequestContextMiddleware:
    """Gives each HTTP request its IDs, counts and times it, and logs one line for it.

    It wraps the whole FastAPI app, outside FastAPI's own error handling, so the 500 that FastAPI
    sends for an unhandled exception is counted, logged and carries `X-Request-Id` too.
    """

    def __init__(self, app: ASGIApp, metrics: HttpMetrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = new_request_id()
        trace_id = trace_id_from(Headers(scope=scope).getlist("traceparent")) or new_trace_id()
        # The server runs each request in a fresh context (`reset_contextvars` in server.py), so
        # these values end with the request. They aren't reset here on purpose: uvicorn logs an
        # unhandled exception after this middleware has returned, and that line carries them too.
        bind_context(request_id=request_id, trace_id=trace_id)

        status = 500  # what the client gets if the app fails before it starts a response

        async def send_with_request_id(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                MutableHeaders(scope=message).append("x-request-id", request_id)
            await send(message)

        start = time.perf_counter()
        try:
            await self.app(scope, receive, send_with_request_id)
        finally:
            elapsed = time.perf_counter() - start
            method = scope["method"] if scope["method"] in _METHODS else "other"
            route = _route_label(scope)
            self.metrics.requests.labels(method, route, str(status)).inc()
            self.metrics.duration.labels(method, route).observe(elapsed)
            log.info(
                "request",
                extra={
                    "method": method,
                    "route": route,
                    "status": status,
                    "duration_ms": round(elapsed * 1000, 2),
                },
            )
