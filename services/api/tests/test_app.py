import re
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from pydantic import SecretStr
from starlette.testclient import TestClient

from sft.api.app import API_TITLE, API_VERSION, create_app, get_database
from sft.core.settings import Settings
from sft.data.database import Database

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


def app_with_database_route(settings: Settings | None) -> FastAPI:
    app = create_app(settings)

    @app.get("/v1/pool")
    async def pool(database: Annotated[Database, Depends(get_database)]) -> dict[str, bool]:
        return {"same": database is app.state.database}

    return app


def test_the_lifespan_opens_the_pool_and_closes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    disposed: list[Database] = []
    original = Database.dispose

    async def record_dispose(self: Database) -> None:
        disposed.append(self)
        await original(self)

    monkeypatch.setattr(Database, "dispose", record_dispose)
    settings = Settings(
        database_url=SecretStr("postgresql://sft_api@127.0.0.1:1/sft"),
        database_pool_size=3,
        valkey_url=SecretStr("redis://u:p@127.0.0.1:1/0"),
    )
    app = app_with_database_route(settings)
    with TestClient(app) as client:
        # No connection is made: nothing listens on port 1, and the request still succeeds.
        assert client.get("/v1/pool").json() == {"same": True}
        assert app.state.database._engine.pool.size() == 3  # read here only to check the setting
        assert disposed == []
    assert disposed == [app.state.database]


def test_an_app_without_settings_has_no_database() -> None:
    client = TestClient(app_with_database_route(None), raise_server_exceptions=False)
    assert client.get("/v1/pool").status_code == 500
