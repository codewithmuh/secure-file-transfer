"""Traces with OpenTelemetry (ADR-0009, architecture 5.3, 5.5).

`configure_tracing` runs once per process, at startup. After it, every span the service starts is
recorded: the API's request spans (sft.api.observability), each SQL statement
(sft.data.database), each counter store call (sft.data.counters, #136), each AWS call of a client
passed to `trace_aws_client`, and the message
spans of the outbox, the relay and the consumers (sft.data.outbox, sft.workers). Sampling
happens only in the collector gateway, whose tail
sampling keeps every error and slow trace and 10 % of the rest (ADR-0009). The service keeps
everything so the gateway sees every error; a caller's "not sampled" flag is ignored for the same
reason, so a client can't hide its requests from it.

With `OTEL_EXPORTER_OTLP_ENDPOINT` set, spans go over OTLP/HTTP to `<endpoint>/v1/traces`, the
node's collector agent. Without it spans are still made, so trace IDs reach the logs and the
outbox, but nothing is exported. An unreachable collector costs a warning, never a request.

**Only allowlisted attributes leave the process** (`ALLOWED_ATTRIBUTES`, ADR-0009, T-49, T-88).
The exporter drops every other span, event and link attribute, and the status description, which
can hold an exception's message. Never add a key that can hold a file name, message text, an
email address, a token, a code, a cookie, a header, a query string or a client IP address.

Trace context crosses processes as a W3C `traceparent` only. A caller's `tracestate` and baggage
are ignored: they are text a client chooses, and would otherwise ride along in every message.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.propagators.textmap import (
    CarrierT,
    Getter,
    Setter,
    TextMapPropagator,
    default_getter,
    default_setter,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import Event, ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.trace.sampling import ALWAYS_ON
from opentelemetry.trace import Link, Span, SpanKind, Status, StatusCode
from opentelemetry.util.types import Attributes, AttributeValue

from sft.core.logs import trace_id_var

log = logging.getLogger(__name__)

TRACEPARENT = "traceparent"

# The attribute keys that may leave the process, in the stable semantic conventions. Every span in
# the service gets its attributes from code in this repository, never from an auto-instrumentation
# library, so this list is the whole vocabulary.
ALLOWED_ATTRIBUTES = frozenset(
    {
        # HTTP server spans: the route template, never the path, which can hold a link token.
        "http.request.method",
        "http.route",
        "http.response.status_code",
        # SQL statements: the text has bound parameters, never their values.
        "db.system.name",
        "db.namespace",
        "db.operation.name",
        "db.query.text",
        "server.address",
        "server.port",
        # AWS calls.
        "rpc.system",
        "rpc.service",
        "rpc.method",
        "aws.request_id",
        "cloud.region",
        # Messages: the consumer, the queue, the outbox ID and how many go in one call.
        "messaging.system",
        "messaging.operation.type",
        "messaging.destination.name",
        "messaging.consumer.group.name",
        "messaging.message.id",
        "messaging.batch.message_count",
        # Errors: the type, never the message or the stack trace (the logs have the stack trace).
        "error.type",
        "exception.type",
    }
)

_EXPORT_TIMEOUT_SECONDS = 5.0

# version-traceid-parentid-flags; a later version may add fields after them (W3C Trace Context).
_TRACEPARENT = re.compile(r"([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?")


def parse_traceparent(values: Sequence[str] | None) -> trace.SpanContext | None:
    """The remote span context of a valid `traceparent`, or None, and a new trace starts.

    `values` holds every value the carrier has for the name: more than one is invalid.
    """
    if values is None or len(values) != 1:
        return None
    match = _TRACEPARENT.fullmatch(values[0])
    if match is None:
        return None
    version, trace_id, span_id, _flags, rest = match.groups()
    if version == "ff" or (version == "00" and rest is not None):
        return None
    if trace_id == "0" * 32 or span_id == "0" * 16:
        return None
    # The caller's flags aren't kept: the service records every span (module docstring).
    return trace.SpanContext(int(trace_id, 16), int(span_id, 16), is_remote=True)


class TraceparentPropagator(TextMapPropagator):
    """W3C Trace Context with `traceparent` alone: no `tracestate`, no baggage."""

    def extract(
        self,
        carrier: CarrierT,
        context: Context | None = None,
        getter: Getter[CarrierT] = default_getter,
    ) -> Context:
        context = Context() if context is None else context
        remote = parse_traceparent(getter.get(carrier, TRACEPARENT))
        if remote is None:
            return context
        return trace.set_span_in_context(trace.NonRecordingSpan(remote), context)

    def inject(
        self,
        carrier: CarrierT,
        context: Context | None = None,
        setter: Setter[CarrierT] = default_setter,
    ) -> None:
        span_context = trace.get_current_span(context).get_span_context()
        if not span_context.is_valid:
            return
        setter.set(
            carrier,
            TRACEPARENT,
            f"00-{span_context.trace_id:032x}-{span_context.span_id:016x}"
            f"-{int(span_context.trace_flags):02x}",
        )

    @property
    def fields(self) -> set[str]:
        return {TRACEPARENT}


PROPAGATOR = TraceparentPropagator()


def trace_id_of(span: Span) -> str | None:
    """The span's trace ID as logs and audit events write it: 32 lower-case hex digits."""
    span_context = span.get_span_context()
    return f"{span_context.trace_id:032x}" if span_context.is_valid else None


@contextmanager
def traced(
    name: str,
    *,
    kind: SpanKind = SpanKind.INTERNAL,
    context: Context | None = None,
    attributes: Mapping[str, AttributeValue] | None = None,
    links: Sequence[Link] | None = None,
) -> Iterator[Span]:
    """A span, current while the block runs, under the current one (or under `context`).

    The work's own spans (SQL, AWS calls) are its children, and log lines carry its trace ID. An
    exception is recorded on the span as its type, never its message; the span ends with an error
    status, and the exception is raised again.
    """
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span(
        name, context=context, kind=kind, attributes=attributes, links=links
    ) as span:
        token = trace_id_var.set(trace_id_of(span))
        try:
            yield span
        except BaseException as exc:
            span.set_attribute("error.type", type(exc).__qualname__)
            raise
        finally:
            trace_id_var.reset(token)


def mark_error(span: Span, error_type: str) -> None:
    """End `span` as an error that was handled, not raised: its type or code, never a message."""
    span.set_attribute("error.type", error_type)
    span.set_status(StatusCode.ERROR)


# ---- propagation through messages (architecture 5.3) ----

MESSAGING_SYSTEM = "aws_sqs"


def messaging_attributes(operation: str, queue: str) -> dict[str, AttributeValue]:
    """What every message span says: SQS, the operation (`create`, `send`, `process`), the queue.

    The queue is its name without the environment's prefix, such as `scan-small`.
    """
    return {
        "messaging.system": MESSAGING_SYSTEM,
        "messaging.operation.type": operation,
        "messaging.destination.name": queue,
    }


def current_trace_context() -> dict[str, str]:
    """The current trace context as a plain dict, to carry in a message.

    `{"traceparent": "00-<trace>-<span>-01"}` inside a span, `{}` outside one. It holds IDs only.
    """
    carrier: dict[str, str] = {}
    PROPAGATOR.inject(carrier)
    return carrier


def link_to(carrier: Mapping[str, str]) -> Link | None:
    """A link to the span whose context `carrier` holds, or None without a valid `traceparent`.

    A span that acts on many messages at once, such as the relay's send, can't be the child of
    each message's trace; it links to them instead.
    """
    remote = parse_traceparent(default_getter.get(carrier, TRACEPARENT))
    return None if remote is None else Link(remote)


@contextmanager
def continued_trace(
    carrier: Mapping[str, str],
    name: str,
    *,
    kind: SpanKind = SpanKind.CONSUMER,
    attributes: Mapping[str, AttributeValue] | None = None,
) -> Iterator[Span]:
    """A span that continues the trace in `carrier`, a dict from `current_trace_context`.

    It is the child of the span that wrote the message, whatever span is current here, and works
    as `traced` does. Without a valid `traceparent` a new trace starts.
    """
    with traced(
        name, kind=kind, context=PROPAGATOR.extract(carrier), attributes=attributes
    ) as span:
        yield span


# ---- AWS calls ----


def trace_aws_client(client: Any, *, untraced: Iterable[str] = ()) -> None:
    """Give every call of a boto3 client a CLIENT span: `SQS.SendMessageBatch`, say.

    It listens on botocore's own events, so it needs no wrapper around the SDK. The span's parent
    is the context the call runs in: run blocking calls with `asyncio.to_thread`, or in an executor
    through `contextvars.copy_context().run`, never with a bare `loop.run_in_executor`, which
    loses the context. Retries inside one call share its span. Calls of the operations in
    `untraced`, such as `ReceiveMessage`, get no span.
    """
    events = client.meta.events
    region = client.meta.region_name
    skip = frozenset(untraced)
    events.register(
        "before-call", _AwsCallTracer.before(region, skip), unique_id="sft-trace-before"
    )
    events.register("after-call", _AwsCallTracer.after, unique_id="sft-trace-after")
    events.register("after-call-error", _AwsCallTracer.error, unique_id="sft-trace-error")


class _AwsCallTracer:
    _KEY = "sft_span"  # where the span waits in botocore's per-call context dict

    @classmethod
    def before(cls, region: str | None, untraced: frozenset[str] = frozenset()) -> Any:
        def handler(*, model: Any, context: dict[str, Any], **_: Any) -> None:
            if model.name in untraced:
                return
            service = str(model.service_model.service_id)
            attributes: dict[str, AttributeValue] = {
                "rpc.system": "aws-api",
                "rpc.service": service,
                "rpc.method": model.name,
            }
            if region:
                attributes["cloud.region"] = region
            context[cls._KEY] = trace.get_tracer(__name__).start_span(
                f"{service}.{model.name}", kind=SpanKind.CLIENT, attributes=attributes
            )

        return handler

    @classmethod
    def after(
        cls, *, http_response: Any, parsed: Mapping[str, Any], context: dict[str, Any], **_: Any
    ) -> None:
        span: Span | None = context.pop(cls._KEY, None)
        if span is None:
            return
        status = int(http_response.status_code)
        span.set_attribute("http.response.status_code", status)
        request_id = parsed.get("ResponseMetadata", {}).get("RequestId")
        if isinstance(request_id, str):
            span.set_attribute("aws.request_id", request_id)
        if status >= 300:
            code = parsed.get("Error", {}).get("Code")
            span.set_attribute("error.type", code if isinstance(code, str) else str(status))
            span.set_status(StatusCode.ERROR)
        span.end()

    @classmethod
    def error(cls, *, exception: BaseException, context: dict[str, Any], **_: Any) -> None:
        span: Span | None = context.pop(cls._KEY, None)
        if span is None:
            return
        span.set_attribute("error.type", type(exception).__qualname__)
        span.set_status(StatusCode.ERROR)
        span.end()


# ---- export ----


def _allowed(attributes: Attributes) -> dict[str, AttributeValue]:
    return {key: value for key, value in (attributes or {}).items() if key in ALLOWED_ATTRIBUTES}


def scrubbed(span: ReadableSpan) -> ReadableSpan:
    """A copy of `span` with only allowlisted attributes, and no status description."""
    return ReadableSpan(
        name=span.name,
        context=span.context,
        parent=span.parent,
        resource=span.resource,
        attributes=_allowed(span.attributes),
        events=[Event(e.name, _allowed(e.attributes), e.timestamp) for e in span.events],
        links=[Link(link.context, _allowed(link.attributes)) for link in span.links],
        kind=span.kind,
        status=Status(span.status.status_code),
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


class AllowlistExporter(SpanExporter):
    """Exports through `exporter` only what `ALLOWED_ATTRIBUTES` lets out."""

    def __init__(self, exporter: SpanExporter) -> None:
        self.exporter = exporter

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        return self.exporter.export([scrubbed(span) for span in spans])

    def shutdown(self) -> None:
        self.exporter.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self.exporter.force_flush(timeout_millis)


def otlp_exporter(endpoint: str) -> SpanExporter:
    """OTLP/HTTP to `<endpoint>/v1/traces`, as `OTEL_EXPORTER_OTLP_ENDPOINT` means in the spec."""
    return OTLPSpanExporter(
        endpoint=f"{endpoint.rstrip('/')}/v1/traces", timeout=_EXPORT_TIMEOUT_SECONDS
    )


def build_tracer_provider(
    service: str,
    version: str,
    *,
    exporter: SpanExporter | None,
    batch: bool = True,
) -> TracerProvider:
    """A provider that records every span and exports them, allowlisted, through `exporter`.

    With no exporter it still makes spans and IDs, and exports nothing. `batch=False` exports each
    span as it ends, for tests.
    """
    resource = Resource.create(
        {"service.name": service, "service.namespace": "sft", "service.version": version}
    )
    # The process doesn't register an exit hook: the entry point shuts the provider down itself.
    provider = TracerProvider(sampler=ALWAYS_ON, resource=resource, shutdown_on_exit=False)
    if exporter is not None:
        allowlisted = AllowlistExporter(exporter)
        provider.add_span_processor(
            BatchSpanProcessor(allowlisted) if batch else SimpleSpanProcessor(allowlisted)
        )
    return provider


def configure_tracing(service: str, version: str, otlp_endpoint: str | None) -> TracerProvider:
    """Set up this process's traces. Call it once, at startup; `shutdown()` the result at exit.

    `shutdown()` exports what is still buffered, waiting at most a few seconds for the collector.
    """
    exporter = otlp_exporter(otlp_endpoint) if otlp_endpoint else None
    provider = build_tracer_provider(service, version, exporter=exporter)
    trace.set_tracer_provider(provider)
    log.info("tracing configured", extra={"exporting": exporter is not None})
    return provider
