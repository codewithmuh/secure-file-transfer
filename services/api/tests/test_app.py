import re
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from sft.api.app import API_TITLE, API_VERSION, create_app

CONTRACT = Path(__file__).resolve().parents[3] / "docs" / "api" / "openapi.yaml"


@pytest.mark.parametrize(
    "path", ["/healthz", "/readyz", "/metrics", "/docs", "/redoc", "/openapi.json", "/v1/hello"]
)
def test_the_public_app_serves_only_the_api(path: str) -> None:
    # Probes and metrics are on the internal port; docs and the document aren't served (ADR-0002).
    assert TestClient(create_app()).get(path).status_code == 404


def test_the_openapi_document_can_still_be_generated() -> None:
    info = create_app().openapi()["info"]
    assert (info["title"], info["version"]) == (API_TITLE, API_VERSION)


def test_title_and_version_match_the_contract() -> None:
    info = CONTRACT.read_text().split("\nservers:")[0]
    assert re.search(r"^  title: (.+)$", info, re.MULTILINE)[1] == API_TITLE  # type: ignore[index]
    assert re.search(r"^  version: (.+)$", info, re.MULTILINE)[1] == API_VERSION  # type: ignore[index]
