import logging
import re
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import SpanKind, StatusCode
from starlette.testclient import TestClient

from sft.api.app import create_app
from sft.api.observability import HttpMetrics, RequestContextMiddleware

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT = "00f067aa0ba902b7"
REQUEST_ID = re.compile(r"req_[0-9a-f]{32}")

Logs = Callable[[], list[dict[str, object]]]


def app_with_routes() -> FastAPI:
    app = create_app()

    @app.get("/v1/things/{thing_id}")
    async def get_thing(thing_id: str) -> dict[str, str]:
        logging.getLogger("sft.service.things").info("found it")
        return {"id": thing_id}

    @app.get("/v1/boom")
    async def boom() -> None:
        raise RuntimeError("boom")

    return app


@pytest.fixture
def metrics() -> HttpMetrics:
    return HttpMetrics.create()


@pytest.fixture
def client(metrics: HttpMetrics) -> TestClient:
    return TestClient(
        RequestContextMiddleware(app_with_routes(), metrics), raise_server_exceptions=False
    )


def sample(metrics: HttpMetrics, name: str, **labels: str) -> float | None:
    return metrics.registry.get_sample_value(name, labels)


def request_lines(json_logs: Logs) -> list[dict[str, object]]:
    return [line for line in json_logs() if line["logger"] == "sft.api.request"]


def test_every_response_gets_a_fresh_request_id(client: TestClient) -> None:
    first = client.get("/v1/things/1").headers["x-request-id"]
    second = client.get("/v1/things/1").headers["x-request-id"]
    assert REQUEST_ID.fullmatch(first)
    assert REQUEST_ID.fullmatch(second)
    assert first != second


def test_a_client_cannot_choose_the_request_id(client: TestClient) -> None:
    r = client.get("/v1/things/1", headers={"x-request-id": "chosen-by-client"})
    assert REQUEST_ID.fullmatch(r.headers["x-request-id"])


def test_one_log_line_per_request_with_both_ids(client: TestClient, json_logs: Logs) -> None:
    r = client.get("/v1/things/42?q=secret", headers={"traceparent": f"00-{TRACE}-{PARENT}-01"})
    [line] = request_lines(json_logs)
    assert line["request_id"] == r.headers["x-request-id"]
    assert line["trace_id"] == TRACE
    assert line["method"] == "GET"
    assert line["route"] == "/v1/things/{thing_id}"  # the template: no IDs, no query string
    assert line["status"] == 200
    assert isinstance(line["duration_ms"], float)
    service_lines = [line for line in json_logs() if str(line["logger"]).startswith("sft.")]
    assert "secret" not in str(service_lines)


def test_lines_logged_inside_the_request_carry_its_ids(client: TestClient, json_logs: Logs) -> None:
    r = client.get("/v1/things/1")
    [inner] = [line for line in json_logs() if line["msg"] == "found it"]
    assert inner["request_id"] == r.headers["x-request-id"]
    assert re.fullmatch(r"[0-9a-f]{32}", str(inner["trace_id"]))


def test_without_a_valid_traceparent_a_new_trace_starts(
    client: TestClient, json_logs: Logs
) -> None:
    client.get("/v1/things/1", headers={"traceparent": "garbage"})
    client.get("/v1/things/1")
    first, second = (line["trace_id"] for line in request_lines(json_logs))
    assert re.fullmatch(r"[0-9a-f]{32}", str(first))
    assert first != second


def test_metrics_use_the_route_template(client: TestClient, metrics: HttpMetrics) -> None:
    client.get("/v1/things/1")
    client.get("/v1/things/2")
    labels = {"method": "GET", "route": "/v1/things/{thing_id}"}
    assert sample(metrics, "http_requests_total", **labels, status="200") == 2
    assert sample(metrics, "http_request_duration_seconds_count", **labels) == 2


def test_unknown_paths_and_methods_cannot_add_label_values(
    client: TestClient, metrics: HttpMetrics
) -> None:
    client.get("/no/such/path/1")
    client.get("/no/such/path/2")
    client.request("BREW", "/v1/things/1")
    assert (
        sample(metrics, "http_requests_total", method="GET", route="unmatched", status="404") == 2
    )
    other = {"method": "other", "route": "/v1/things/{thing_id}", "status": "405"}
    assert sample(metrics, "http_requests_total", **other) == 1


def test_an_unhandled_error_is_a_counted_and_logged_500_with_a_request_id(
    client: TestClient, metrics: HttpMetrics, json_logs: Logs
) -> None:
    r = client.get("/v1/boom")
    assert r.status_code == 500
    assert REQUEST_ID.fullmatch(r.headers["x-request-id"])
    assert sample(metrics, "http_requests_total", method="GET", route="/v1/boom", status="500") == 1
    [line] = request_lines(json_logs)
    assert line["status"] == 500
    assert line["request_id"] == r.headers["x-request-id"]


def test_lifespan_passes_through(metrics: HttpMetrics) -> None:
    with TestClient(RequestContextMiddleware(create_app(), metrics)) as c:
        assert c.get("/anything").status_code == 404


# ---- the request span ----


def test_a_request_continues_the_callers_trace(
    client: TestClient, spans: InMemorySpanExporter, json_logs: Logs
) -> None:
    client.get("/v1/things/42?q=secret", headers={"traceparent": f"00-{TRACE}-{PARENT}-01"})
    [span] = spans.get_finished_spans()
    assert span.kind == SpanKind.SERVER
    assert span.name == "GET /v1/things/{thing_id}"
    assert span.context is not None
    assert span.parent is not None
    assert f"{span.context.trace_id:032x}" == TRACE
    assert f"{span.parent.span_id:016x}" == PARENT
    assert dict(span.attributes or {}) == {
        "http.request.method": "GET",
        "http.route": "/v1/things/{thing_id}",
        "http.response.status_code": 200,
    }
    [line] = request_lines(json_logs)
    assert line["trace_id"] == TRACE


def test_the_callers_not_sampled_flag_is_ignored(
    client: TestClient, spans: InMemorySpanExporter
) -> None:
    # The collector's tail sampling decides (ADR-0009); a client can't hide a request from it.
    client.get("/v1/things/1", headers={"traceparent": f"00-{TRACE}-{PARENT}-00"})
    [span] = spans.get_finished_spans()
    assert span.context is not None
    assert span.context.trace_flags.sampled


def test_tracestate_and_baggage_from_a_client_are_dropped(
    client: TestClient, spans: InMemorySpanExporter
) -> None:
    client.get(
        "/v1/things/1",
        headers={
            "traceparent": f"00-{TRACE}-{PARENT}-01",
            "tracestate": "vendor=chosen-by-client",
            "baggage": "user=someone@example.com",
        },
    )
    [span] = spans.get_finished_spans()
    assert span.context is not None
    assert str(span.context.trace_state.to_header()) == ""


@pytest.mark.parametrize(
    ("headers", "continued"),
    [
        ([f"00-{TRACE}-{PARENT}-01"], True),
        ([f"01-{TRACE}-{PARENT}-01-later-fields"], True),  # a later version may add fields
        ([f"00-{TRACE}-{PARENT}-01", f"00-{TRACE}-{PARENT}-01"], False),  # more than one
        ([f"00-{TRACE}-{PARENT}-01-extra"], False),  # version 00 has exactly four fields
        ([f"ff-{TRACE}-{PARENT}-01"], False),
        ([f"00-{TRACE.upper()}-{PARENT}-01"], False),
        (["garbage"], False),
    ],
)
def test_only_one_valid_traceparent_is_continued(
    client: TestClient,
    spans: InMemorySpanExporter,
    headers: list[str],
    continued: bool,
) -> None:
    client.get("/v1/things/1", headers=[("traceparent", value) for value in headers])
    [span] = spans.get_finished_spans()
    assert span.context is not None
    assert (f"{span.context.trace_id:032x}" == TRACE) is continued
    assert (span.parent is not None) is continued


def test_a_500_is_an_error_span_with_the_type_but_not_the_message(
    client: TestClient, spans: InMemorySpanExporter
) -> None:
    client.get("/v1/boom")
    [span] = spans.get_finished_spans()
    assert span.name == "GET /v1/boom"
    assert span.status.status_code == StatusCode.ERROR
    assert span.status.description is None  # "RuntimeError: boom" stays out of the export
    assert span.attributes is not None
    assert span.attributes["error.type"] == "RuntimeError"
    assert span.attributes["http.response.status_code"] == 500
    [event] = span.events
    assert dict(event.attributes or {}) == {"exception.type": "RuntimeError"}


def test_unmatched_routes_and_unknown_methods_keep_span_names_fixed(
    client: TestClient, spans: InMemorySpanExporter
) -> None:
    client.get("/no/such/link-token-abc")
    client.request("BREW", "/v1/things/1")
    unmatched, other = spans.get_finished_spans()
    assert unmatched.name == "GET"
    assert "link-token" not in str(unmatched.attributes)
    assert unmatched.status.status_code == StatusCode.UNSET  # a 404 isn't a server error
    assert other.name == "HTTP /v1/things/{thing_id}"
    assert other.attributes is not None
    assert other.attributes["http.request.method"] == "_OTHER"


def test_a_websocket_or_lifespan_scope_gets_no_span(
    metrics: HttpMetrics, spans: InMemorySpanExporter
) -> None:
    with TestClient(RequestContextMiddleware(create_app(), metrics)):
        pass
    assert spans.get_finished_spans() == ()
