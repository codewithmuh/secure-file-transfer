import pytest
from starlette.testclient import TestClient

from sft.api.internal import Readiness, create_internal_app
from sft.api.observability import HttpMetrics


@pytest.fixture
def readiness() -> Readiness:
    return Readiness()


@pytest.fixture
def client(readiness: Readiness) -> TestClient:
    return TestClient(create_internal_app(readiness, HttpMetrics.create().registry))


def test_readyz_is_503_until_started(client: TestClient) -> None:
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "starting"}


def test_readyz_is_200_once_started(client: TestClient, readiness: Readiness) -> None:
    readiness.mark_started()
    r = client.get("/readyz")
    assert r.status_code == 200
    assert r.json() == {"status": "ready"}


def test_readyz_is_503_during_shutdown(client: TestClient, readiness: Readiness) -> None:
    readiness.mark_started()
    readiness.mark_stopping()
    r = client.get("/readyz")
    assert r.status_code == 503
    assert r.json() == {"status": "stopping"}


@pytest.mark.parametrize(("started", "stopping"), [(False, False), (True, False), (True, True)])
def test_healthz_is_200_whatever_the_readiness(
    client: TestClient, readiness: Readiness, started: bool, stopping: bool
) -> None:
    readiness.started, readiness.stopping = started, stopping
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_metrics_in_prometheus_format(client: TestClient) -> None:
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain; version=")
    assert "# TYPE http_requests_total counter" in r.text
    assert "# TYPE http_request_duration_seconds histogram" in r.text
    assert "python_info" in r.text  # the platform collector


def test_only_get(client: TestClient) -> None:
    assert client.post("/healthz").status_code == 405
