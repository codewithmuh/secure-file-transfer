"""Request IDs, request spans, request metrics and one log line per request (architecture 5.5, 8).

Each request gets a SERVER span (ADR-0009, sft.core.telemetry). It continues the caller's trace
when the request has exactly one valid W3C `traceparent` header, so the web app's trace runs on
through the API, and starts a new trace otherwise. Its trace ID is the `trace_id` of every log
line of the request. The span is named by the route template and carries only the method, the
route template and the status: never the path, the query string, headers or the client address.
"""

from __future__ import annotations

import logging
import secrets
import time
from dataclasses import dataclass

from opentelemetry import trace
from opentelemetry.propagators.textmap import Getter
from opentelemetry.trace import SpanKind, StatusCode
from prometheus_client import CollectorRegistry, Counter, Histogram
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sft.core.logs import bind_context
from sft.core.telemetry import PROPAGATOR, trace_id_of
from sft.runtime.internal import process_registry

log = logging.getLogger("sft.api.request")

# Bucket edges at 0.3 s and 1 s match NFR-2 (p95 <= 300 ms, p99 <= 1 s), so the SLIs are exact.
LATENCY_BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 1.0, 2.5, 5.0, 10.0)

# Any other method is counted as "other", so a client can't add label values at will.
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


class _HeaderGetter(Getter[Headers]):
    """Every value of a header, so a repeated `traceparent` is seen, and refused."""

    def get(self, carrier: Headers, key: str) -> list[str] | None:
        return carrier.getlist(key) or None

    def keys(self, carrier: Headers) -> list[str]:
        return list(carrier.keys())


_HEADERS = _HeaderGetter()
_tracer = trace.get_tracer(__name__)


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


def _route_label(scope: Scope) -> str:
    """The route template, such as `/v1/transfers/{transfer_id}`, so IDs don't become labels."""
    route = scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) else "unmatched"


class RequestContextMiddleware:
    """Gives each HTTP request its IDs and span, counts and times it, and logs one line for it.

    It wraps the whole FastAPI app, outside FastAPI's own error handling, so the 500 that FastAPI
    sends for an unhandled exception is counted, logged, traced and carries `X-Request-Id` too.
    """

    def __init__(self, app: ASGIApp, metrics: HttpMetrics) -> None:
        self.app = app
        self.metrics = metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = new_request_id()
        method = scope["method"] if scope["method"] in _METHODS else "other"
        parent = PROPAGATOR.extract(Headers(scope=scope), getter=_HEADERS)
        status = 500  # what the client gets if the app fails before it starts a response

        async def send_with_request_id(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                MutableHeaders(scope=message).append("x-request-id", request_id)
            await send(message)

        span_name = "HTTP" if method == "other" else method  # then "GET /v1/transfers/{id}"
        with _tracer.start_as_current_span(
            span_name,
            context=parent,
            kind=SpanKind.SERVER,
            attributes={"http.request.method": "_OTHER" if method == "other" else method},
        ) as span:
            # The server runs each request in a fresh context (`reset_contextvars` in server.py),
            # so these values end with the request. They aren't reset here on purpose: uvicorn
            # logs an unhandled exception after this middleware has returned, and that line
            # carries them too.
            bind_context(request_id=request_id, trace_id=trace_id_of(span))
            start = time.perf_counter()
            try:
                await self.app(scope, receive, send_with_request_id)
            except BaseException as exc:
                span.set_attribute("error.type", type(exc).__qualname__)
                raise
            finally:
                elapsed = time.perf_counter() - start
                route = _route_label(scope)
                self.metrics.requests.labels(method, route, str(status)).inc()
                self.metrics.duration.labels(method, route).observe(elapsed)
                if route != "unmatched":
                    span.update_name(f"{span_name} {route}")
                    span.set_attribute("http.route", route)
                span.set_attribute("http.response.status_code", status)
                if status >= 500:
                    span.set_status(StatusCode.ERROR)
                log.info(
                    "request",
                    extra={
                        "method": method,
                        "route": route,
                        "status": status,
                        "duration_ms": round(elapsed * 1000, 2),
                    },
                )
