"""Traces: propagation through messages, the attribute allowlist, export, and AWS call spans."""

import contextlib
import logging
import signal
import time
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any

import httpx2 as httpx
import pytest
from fastapi import FastAPI
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Link, SpanKind, StatusCode
from starlette.testclient import TestClient

from sft.api.app import create_app
from sft.core import telemetry
from sft.core.logs import bind_context, trace_id_var
from sft.core.telemetry import (
    build_tracer_provider,
    continued_trace,
    current_trace_context,
    link_to,
    mark_error,
    messaging_attributes,
    parse_traceparent,
    scrubbed,
    trace_aws_client,
    traced,
)

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT = "00f067aa0ba902b7"

Logs = Callable[[], list[dict[str, object]]]

tracer = trace.get_tracer(__name__)


def hex_trace(span: ReadableSpan) -> str:
    assert span.context is not None
    return f"{span.context.trace_id:032x}"


@pytest.mark.parametrize(
    ("values", "valid"),
    [
        ([f"00-{TRACE}-{PARENT}-01"], True),
        ([f"00-{TRACE}-{PARENT}-00"], True),  # not sampled is still a trace
        ([f"01-{TRACE}-{PARENT}-01-later-fields"], True),  # a later version may add fields
        ([f"01-{TRACE}-{PARENT}-01"], True),
        (None, False),
        ([], False),
        ([f"00-{TRACE}-{PARENT}-01", f"00-{TRACE}-{PARENT}-01"], False),  # more than one
        ([f"00-{TRACE}-{PARENT}-01-extra"], False),  # version 00 has exactly four fields
        ([f"ff-{TRACE}-{PARENT}-01"], False),  # version ff is invalid
        ([f"00-{'0' * 32}-{PARENT}-01"], False),  # all-zero trace ID
        ([f"00-{TRACE}-{'0' * 16}-01"], False),  # all-zero parent ID
        ([f"00-{TRACE.upper()}-{PARENT}-01"], False),  # hex must be lower case
        ([f"00-{TRACE[:-1]}-{PARENT}-01"], False),  # too short
        ([f" 00-{TRACE}-{PARENT}-01"], False),
        (["garbage"], False),
    ],
)
def test_parse_traceparent(values: list[str] | None, valid: bool) -> None:
    remote = parse_traceparent(values)
    assert (remote is not None) is valid
    if remote is not None:
        assert (f"{remote.trace_id:032x}", f"{remote.span_id:016x}") == (TRACE, PARENT)
        assert remote.is_remote


# ---- propagation through messages ----


def test_outside_a_span_there_is_no_trace_context() -> None:
    assert current_trace_context() == {}


def test_the_trace_context_is_a_traceparent_with_ids_only() -> None:
    with tracer.start_as_current_span("producer") as span:
        carrier = current_trace_context()
    ids = span.get_span_context()
    flags = f"{int(ids.trace_flags):02x}"  # sampled, and W3C level 2's "random" bit
    assert carrier == {"traceparent": f"00-{ids.trace_id:032x}-{ids.span_id:016x}-{flags}"}
    assert ids.trace_flags.sampled


def test_a_continued_trace_is_a_child_of_the_producer(
    spans: InMemorySpanExporter, json_logs: Logs
) -> None:
    with tracer.start_as_current_span("producer"):
        carrier = current_trace_context()
    with continued_trace(carrier, "consume", attributes={"messaging.system": "aws_sqs"}) as span:
        logging.getLogger("sft.workers.test").info("working")
        with tracer.start_as_current_span("inner"):
            pass
    assert trace_id_var.get() is None  # bound only while the block runs
    producer, inner, consumer = spans.get_finished_spans()
    assert consumer.kind == SpanKind.CONSUMER
    assert consumer.parent is not None
    assert producer.context is not None
    assert consumer.parent.span_id == producer.context.span_id
    assert {hex_trace(producer), hex_trace(inner), hex_trace(consumer)} == {
        telemetry.trace_id_of(span)
    }
    assert consumer.attributes == {"messaging.system": "aws_sqs"}
    [line] = [line for line in json_logs() if line["msg"] == "working"]
    assert line["trace_id"] == hex_trace(consumer)


@pytest.mark.parametrize(
    "carrier",
    [{}, {"trace_id": TRACE}, {"traceparent": "garbage"}],
    ids=["empty", "older-format", "invalid"],
)
def test_without_a_valid_traceparent_a_consumer_starts_a_new_trace(
    spans: InMemorySpanExporter, carrier: dict[str, str]
) -> None:
    with continued_trace(carrier, "consume"):
        pass
    [span] = spans.get_finished_spans()
    assert span.parent is None
    assert hex_trace(span) != TRACE


def test_a_failing_consumer_ends_its_span_as_an_error(spans: InMemorySpanExporter) -> None:
    with pytest.raises(ValueError, match="bad"), continued_trace({}, "consume"):
        raise ValueError("bad payload for someone@example.com")
    [span] = spans.get_finished_spans()
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description is None
    assert span.attributes == {"error.type": "ValueError"}
    assert "example.com" not in str(span.events)


def test_a_logged_trace_id_restores_after_a_nested_trace() -> None:
    bind_context(request_id=None, trace_id="a" * 32)
    with continued_trace({}, "consume"):
        assert trace_id_var.get() != "a" * 32
    assert trace_id_var.get() == "a" * 32
    bind_context(request_id=None, trace_id=None)


# The acceptance test of #108, a request's trace through the outbox, the relay and SQS to the
# consumer, is in test_message_traces.


def test_a_traced_block_is_a_child_of_the_current_span_with_its_links(
    spans: InMemorySpanExporter, json_logs: Logs
) -> None:
    other = trace.SpanContext(int(TRACE, 16), int(PARENT, 16), is_remote=True)
    with (
        tracer.start_as_current_span("outer") as outer,
        traced("inner", kind=SpanKind.PRODUCER, links=[Link(other)]) as inner,
    ):
        logging.getLogger("sft.test").info("inside")
        assert trace.get_current_span() is inner
    assert trace_id_var.get() is None
    span, _ = spans.get_finished_spans()
    assert span.kind == SpanKind.PRODUCER
    assert span.parent is not None
    assert span.parent.span_id == outer.get_span_context().span_id
    assert [link.context for link in span.links] == [other]
    [line] = [line for line in json_logs() if line["msg"] == "inside"]
    assert line["trace_id"] == hex_trace(span)


def test_a_handled_error_marks_the_span_with_its_type_alone(spans: InMemorySpanExporter) -> None:
    with traced("send"):
        mark_error(trace.get_current_span(), "AWS.SimpleQueueService.BatchRequestTooLong")
    [span] = spans.get_finished_spans()
    assert span.status.status_code == StatusCode.ERROR
    assert span.attributes == {"error.type": "AWS.SimpleQueueService.BatchRequestTooLong"}


@pytest.mark.parametrize(
    ("carrier", "linked"),
    [
        ({"traceparent": f"00-{TRACE}-{PARENT}-01"}, True),
        ({}, False),
        ({"trace_id": TRACE}, False),
        ({"traceparent": "garbage"}, False),
    ],
)
def test_a_link_points_at_the_span_a_message_was_written_in(
    carrier: dict[str, str], linked: bool
) -> None:
    link = link_to(carrier)
    assert (link is not None) is linked
    if link is not None:
        assert (f"{link.context.trace_id:032x}", f"{link.context.span_id:016x}") == (TRACE, PARENT)


def test_message_spans_name_sqs_the_operation_and_the_queue() -> None:
    assert messaging_attributes("send", "scan-small") == {
        "messaging.system": "aws_sqs",
        "messaging.operation.type": "send",
        "messaging.destination.name": "scan-small",
    }
    assert set(messaging_attributes("send", "x")) <= telemetry.ALLOWED_ATTRIBUTES


# ---- the allowlist ----


def test_only_allowlisted_attributes_leave_the_process() -> None:
    provider = build_tracer_provider("sft-test", "1.0.0", exporter=None)
    span = provider.get_tracer("test").start_span(
        "GET /v1/links/{token}",
        attributes={
            "http.route": "/v1/links/{token}",
            "url.path": "/v1/links/secret-token",
            "url.query": "code=123456",
            "client.address": "203.0.113.7",
            "user_agent.original": "curl",
        },
        links=[Link(trace.INVALID_SPAN_CONTEXT, {"email": "a@example.com", "error.type": "X"})],
    )
    span.add_event(
        "exception",
        {
            "exception.type": "KeyError",
            "exception.message": "report.pdf",
            "exception.stacktrace": "…",
        },
    )
    span.set_status(StatusCode.ERROR, "KeyError: report.pdf")
    span.end()
    assert isinstance(span, ReadableSpan)
    clean = scrubbed(span)
    assert dict(clean.attributes or {}) == {"http.route": "/v1/links/{token}"}
    assert [dict(e.attributes or {}) for e in clean.events] == [{"exception.type": "KeyError"}]
    assert [dict(link.attributes or {}) for link in clean.links] == [{"error.type": "X"}]
    assert clean.status.status_code == StatusCode.ERROR
    assert clean.status.description is None
    assert (clean.name, clean.context, clean.kind) == (span.name, span.context, span.kind)
    assert clean.resource.attributes["service.name"] == "sft-test"


def test_the_allowlist_holds_no_key_for_personal_data_or_secrets() -> None:
    banned = ("url.", "client.", "user", "email", "header", "cookie", "token", "query", "file")
    assert not [
        key
        for key in telemetry.ALLOWED_ATTRIBUTES
        if any(word in key for word in banned) and key != "db.query.text"
    ]


# ---- export ----


def test_without_an_endpoint_spans_have_ids_and_nothing_is_exported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    installed: list[Any] = []
    monkeypatch.setattr(trace, "set_tracer_provider", installed.append)
    provider = telemetry.configure_tracing("sft-api", "1.2.3", None)
    assert installed == [provider]
    assert provider._active_span_processor._span_processors == ()
    with provider.get_tracer("test").start_as_current_span("request") as span:
        assert span.get_span_context().is_valid
        assert span.get_span_context().trace_flags.sampled
        assert current_trace_context()["traceparent"].startswith("00-")
    provider.shutdown()


def test_with_an_endpoint_the_exporter_posts_to_v1_traces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(trace, "set_tracer_provider", lambda provider: None)
    provider = telemetry.configure_tracing("sft-api", "1.2.3", "http://otel-agent:4318/")
    [processor] = provider._active_span_processor._span_processors
    exporter = processor._batch_processor._exporter  # type: ignore[attr-defined]
    assert isinstance(exporter, telemetry.AllowlistExporter)
    assert isinstance(exporter.exporter, OTLPSpanExporter)
    assert exporter.exporter._endpoint == "http://otel-agent:4318/v1/traces"
    provider.shutdown()


def test_spans_reach_the_collector_allowlisted(
    collector: tuple[str, list[tuple[str, bytes]]],
) -> None:
    endpoint, received = collector
    provider = build_tracer_provider("sft-api", "1.2.3", exporter=telemetry.otlp_exporter(endpoint))
    with provider.get_tracer("test").start_as_current_span(
        "GET /v1/things/{id}", attributes={"http.route": "/v1/things/{id}", "url.query": "q=x"}
    ):
        pass
    provider.shutdown()  # flushes the batch
    [(path, body)] = received
    assert path == "/v1/traces"
    request = ExportTraceServiceRequest.FromString(body)
    [resource_spans] = request.resource_spans
    resource = {a.key: a.value.string_value for a in resource_spans.resource.attributes}
    assert resource["service.name"] == "sft-api"
    assert resource["service.version"] == "1.2.3"
    [scope_spans] = resource_spans.scope_spans
    [span] = scope_spans.spans
    assert span.name == "GET /v1/things/{id}"
    assert [a.key for a in span.attributes] == ["http.route"]


def test_an_unreachable_collector_fails_nothing() -> None:
    # Port 1: nothing listens. The export fails in the background; the work doesn't notice.
    exporter = OTLPSpanExporter(endpoint="http://127.0.0.1:1/v1/traces", timeout=0.5)
    provider = build_tracer_provider("sft-api", "1.2.3", exporter=exporter)
    with provider.get_tracer("test").start_as_current_span("request"):
        pass
    provider.shutdown()


def test_a_test_provider_exports_each_span_as_it_ends() -> None:
    memory = InMemorySpanExporter()
    provider = build_tracer_provider("sft-test", "0", exporter=memory, batch=False)
    with provider.get_tracer("test").start_as_current_span("one", attributes={"url.path": "/x"}):
        pass
    [span] = memory.get_finished_spans()
    assert span.attributes == {}
    assert provider.force_flush()
    provider.shutdown()


# ---- AWS calls ----


class FakeEvents:
    """botocore's event emitter, as far as `trace_aws_client` uses it."""

    def __init__(self) -> None:
        self.handlers: dict[str, Callable[..., Any]] = {}

    def register(self, name: str, handler: Callable[..., Any], unique_id: str) -> None:
        self.handlers[name] = handler

    def emit(self, name: str, **kwargs: Any) -> None:
        self.handlers[name](**kwargs)


def fake_client(region: str | None = "ap-northeast-1") -> Any:
    return SimpleNamespace(meta=SimpleNamespace(events=FakeEvents(), region_name=region))


def model(operation: str = "SendMessageBatch", service: str = "SQS") -> Any:
    return SimpleNamespace(name=operation, service_model=SimpleNamespace(service_id=service))


def test_an_aws_call_is_a_client_span_under_the_current_one(spans: InMemorySpanExporter) -> None:
    client = fake_client()
    trace_aws_client(client)
    events: FakeEvents = client.meta.events
    context: dict[str, Any] = {}
    with tracer.start_as_current_span("relay batch") as parent:
        events.emit("before-call", model=model(), params={}, request_signer=None, context=context)
        events.emit(
            "after-call",
            http_response=SimpleNamespace(status_code=200),
            parsed={"ResponseMetadata": {"RequestId": "req-aws-1"}},
            model=model(),
            context=context,
        )
    call, _ = spans.get_finished_spans()
    assert call.name == "SQS.SendMessageBatch"
    assert call.kind == SpanKind.CLIENT
    assert call.parent is not None
    assert call.parent.span_id == parent.get_span_context().span_id
    assert call.attributes == {
        "rpc.system": "aws-api",
        "rpc.service": "SQS",
        "rpc.method": "SendMessageBatch",
        "cloud.region": "ap-northeast-1",
        "http.response.status_code": 200,
        "aws.request_id": "req-aws-1",
    }
    assert call.status.status_code == StatusCode.UNSET


def test_an_untraced_operation_gets_no_span(spans: InMemorySpanExporter) -> None:
    client = fake_client()
    trace_aws_client(client, untraced={"ReceiveMessage"})
    events: FakeEvents = client.meta.events
    context: dict[str, Any] = {}
    events.emit("before-call", model=model("ReceiveMessage"), context=context)
    events.emit(
        "after-call", http_response=SimpleNamespace(status_code=200), parsed={}, context=context
    )
    assert context == {}
    assert spans.get_finished_spans() == ()


def test_an_aws_error_response_is_an_error_span(spans: InMemorySpanExporter) -> None:
    client = fake_client(region=None)
    trace_aws_client(client)
    events: FakeEvents = client.meta.events
    context: dict[str, Any] = {}
    events.emit("before-call", model=model("GetObject", "S3"), context=context)
    events.emit(
        "after-call",
        http_response=SimpleNamespace(status_code=403),
        parsed={"Error": {"Code": "AccessDenied", "Message": "for report.pdf"}},
        model=model(),
        context=context,
    )
    [call] = spans.get_finished_spans()
    assert call.status.status_code == StatusCode.ERROR
    assert call.attributes is not None
    assert call.attributes["error.type"] == "AccessDenied"
    assert "cloud.region" not in call.attributes
    assert "report.pdf" not in str(call.attributes)


def test_an_aws_call_that_raises_is_an_error_span(spans: InMemorySpanExporter) -> None:
    client = fake_client()
    trace_aws_client(client)
    events: FakeEvents = client.meta.events
    context: dict[str, Any] = {}
    events.emit("before-call", model=model(), context=context)
    events.emit("after-call-error", exception=ConnectionError("no route"), context=context)
    # A response that another handler short-circuited never had a span: nothing to end.
    events.emit("after-call", http_response=None, parsed={}, context={})
    events.emit("after-call-error", exception=ConnectionError("x"), context={})
    [call] = spans.get_finished_spans()
    assert call.status.status_code == StatusCode.ERROR
    assert call.attributes is not None
    assert call.attributes["error.type"] == "ConnectionError"


def test_a_real_boto3_client_is_traced(
    spans: InMemorySpanExporter, collector: tuple[str, list[tuple[str, bytes]]]
) -> None:
    """Against botocore itself, once a branch adds it (#51); skipped until then."""
    boto3 = pytest.importorskip("boto3")
    endpoint, _ = collector  # answers 200 with an empty body, which ListQueues accepts
    client = boto3.client(
        "sqs",
        region_name="ap-northeast-1",
        endpoint_url=endpoint,
        aws_access_key_id="fake-test-key",
        aws_secret_access_key="fake-test-secret",  # noqa: S106
    )
    trace_aws_client(client)
    with tracer.start_as_current_span("worker"):
        client.list_queues()
    call, _ = spans.get_finished_spans()
    assert call.name == "SQS.ListQueues"
    assert call.attributes is not None
    assert call.attributes["http.response.status_code"] == 200


def test_fastapi_makes_no_span_of_its_own(spans: InMemorySpanExporter) -> None:
    app: FastAPI = create_app()

    @app.get("/v1/ping")
    async def ping() -> dict[str, str]:
        return {}

    TestClient(app).get("/v1/ping")  # without our middleware: nothing at all
    assert spans.get_finished_spans() == ()


def test_the_api_process_exports_its_request_spans_and_flushes_at_shutdown(
    collector: tuple[str, list[tuple[str, bytes]]],
) -> None:
    from test_server import settings, start_process, urls

    endpoint, received = collector
    s = settings()
    public, internal = urls(s)
    proc = start_process(
        {
            "BIND_HOST": "127.0.0.1",
            "PUBLIC_PORT": str(s.public_port),
            "INTERNAL_PORT": str(s.internal_port),
            "APP_VERSION": "7.7.7",
            "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
        }
    )
    try:
        for _ in range(200):
            with contextlib.suppress(httpx.TransportError):
                if httpx.get(f"{internal}/readyz").status_code == 200:
                    break
            time.sleep(0.05)
        else:
            raise AssertionError("never became ready")
        httpx.get(
            f"{public}/v1/nothing-here?code=123456",
            headers={"traceparent": f"00-{TRACE}-{PARENT}-01"},
        )
        proc.send_signal(signal.SIGTERM)
        assert proc.wait(timeout=15) == 0
    finally:
        proc.kill()
    exported = [
        span
        for _, body in received
        for resource_spans in ExportTraceServiceRequest.FromString(body).resource_spans
        for scope_spans in resource_spans.scope_spans
        for span in scope_spans.spans
    ]
    # The probes on the internal port aren't traced. Besides the request's own span, only the
    # counter store's client spans under it (#136), which carry no key and no query.
    [span] = [s for s in exported if s.kind == s.SpanKind.SPAN_KIND_SERVER]
    assert span.trace_id.hex() == TRACE
    assert span.name == "GET"
    assert "123456" not in str(span)
    for child in exported:
        if child is not span:
            assert child.kind == child.SpanKind.SPAN_KIND_CLIENT, child.name
            assert child.name.startswith("counter."), child.name
            assert child.parent_span_id == span.span_id
            assert "123456" not in str(child)


def test_the_propagator_names_only_traceparent() -> None:
    assert telemetry.PROPAGATOR.fields == {"traceparent"}


def test_the_allowlist_exporter_passes_flush_and_shutdown_on() -> None:
    memory = InMemorySpanExporter()
    exporter = telemetry.AllowlistExporter(memory)
    assert exporter.force_flush()
    exporter.shutdown()
    assert memory._stopped
