import logging
import re
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from sft.api.app import create_app
from sft.api.observability import HttpMetrics, RequestContextMiddleware, trace_id_from

TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
PARENT = "00f067aa0ba902b7"
REQUEST_ID = re.compile(r"req_[0-9a-f]{32}")

Logs = Callable[[], list[dict[str, object]]]


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([f"00-{TRACE}-{PARENT}-01"], TRACE),
        ([f"00-{TRACE}-{PARENT}-00"], TRACE),  # not sampled is still a trace
        ([f"01-{TRACE}-{PARENT}-01-later-fields"], TRACE),  # a later version may add fields
        ([f"01-{TRACE}-{PARENT}-01"], TRACE),
        ([], None),
        ([f"00-{TRACE}-{PARENT}-01", f"00-{TRACE}-{PARENT}-01"], None),  # more than one
        ([f"00-{TRACE}-{PARENT}-01-extra"], None),  # version 00 has exactly four fields
        ([f"ff-{TRACE}-{PARENT}-01"], None),  # version ff is invalid
        ([f"00-{'0' * 32}-{PARENT}-01"], None),  # all-zero trace ID
        ([f"00-{TRACE}-{'0' * 16}-01"], None),  # all-zero parent ID
        ([f"00-{TRACE.upper()}-{PARENT}-01"], None),  # hex must be lower case
        ([f"00-{TRACE[:-1]}-{PARENT}-01"], None),  # too short
        (["garbage"], None),
    ],
)
def test_trace_id_from_traceparent(headers: list[str], expected: str | None) -> None:
    assert trace_id_from(headers) == expected


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
