"""Problem answers for every error (sft.api.errors, sft.core.errors; docs/api/README.md 3)."""

import logging
import re
from collections.abc import Callable
from typing import Annotated, Any, get_args
from uuid import UUID

import pytest
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.security import HTTPBearer
from pydantic import BaseModel, ConfigDict
from starlette.testclient import TestClient

from sft.api import errors as api_errors
from sft.api.app import create_app
from sft.api.errors import (
    MEDIA_TYPE,
    OWN_CODES,
    STATUSES,
    TITLES,
    TYPE_BASE,
    problem_response,
    problem_responses,
    status_of,
)
from sft.api.observability import HttpMetrics, RequestContextMiddleware
from sft.core import errors
from sft.core.errors import PROBLEM_CODES, FieldError, ProblemError, json_pointer
from tools.contract_check import CONTRACT, _diff, _Normaliser, load_contract

README = CONTRACT.with_name("README.md")
ID = "0190f3a4-7b6c-7def-8123-456789abcdef"


class Recipient(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str


class TransferCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str
    recipients: list[Recipient]


class RetryLater(errors.RateLimited):
    """A subclass, as service code may declare one: it maps as its parent does."""

    def __init__(self) -> None:
        super().__init__(retry_after=5)


RAISED: dict[str, ProblemError] = {
    "invalid_cursor": errors.InvalidRequest("invalid_cursor", "Start again from the first page."),
    "session_expired": errors.Unauthenticated("session_expired"),
    "passkey_required": errors.Forbidden("passkey_required", "Sign in with a passkey."),
    "not_found": errors.NotFound(),
    "invalid_state": errors.Conflict("invalid_state", current_state="cancelled"),
    "link_expired": errors.Gone("link_expired"),
    "file_too_large": errors.TooLarge("file_too_large"),
    "unsupported_media_type": errors.UnsupportedMediaType(),
    "range_not_satisfiable": errors.RangeNotSatisfiable(size=5242880),
    "code_invalid": errors.Unprocessable("code_invalid", attempts_remaining=3),
    "rate_limited": errors.RateLimited(retry_after=30),
    "service_unavailable": errors.ServiceUnavailable(retry_after=10, detail="Try again soon."),
    "retry_later": RetryLater(),
}


def service_app() -> FastAPI:
    """The service's app, with routes that fail in each way the tests need."""
    app = create_app()

    @app.get("/v1/raise/{name}")
    def raise_problem(name: str) -> None:
        raise RAISED[name]

    @app.post("/v1/transfers/{transfer_id}")
    def update_transfer(
        transfer_id: UUID,
        body: TransferCreate,
        limit: int = 25,
        idempotency_key: Annotated[str | None, Header(max_length=5)] = None,
    ) -> dict[str, str]:
        return {"ok": "yes"}

    @app.get("/v1/bearer")
    def bearer(_: Annotated[object, Depends(HTTPBearer())]) -> None:
        raise NotImplementedError

    @app.get("/v1/teapot")
    def teapot() -> None:
        raise HTTPException(status_code=418, detail="internal detail")

    @app.get("/v1/boom")
    def boom() -> None:
        raise RuntimeError("password=hunter2 at db.internal:5432")

    return app


@pytest.fixture
def client() -> TestClient:
    """The app wrapped as the server wraps it, so requests carry X-Request-Id."""
    app = RequestContextMiddleware(service_app(), HttpMetrics.create())
    return TestClient(app, raise_server_exceptions=False)


def problem(response: Any, status: int, code: str) -> dict[str, Any]:
    """The answer's problem document, after the checks every problem passes."""
    assert response.status_code == status
    assert response.headers["content-type"] == MEDIA_TYPE
    body: dict[str, Any] = response.json()
    assert body["type"] == f"{TYPE_BASE}{code}"
    assert body["title"] == TITLES[code]  # type: ignore[index]
    assert (body["status"], body["code"]) == (status, code)
    assert body["request_id"] == response.headers["x-request-id"]
    assert re.fullmatch(r"req_[0-9a-f]{32}", body["request_id"])
    assert None not in body.values()  # a field is left out, never sent as null
    return body


# ---- errors service code raises ----


@pytest.mark.parametrize(
    ("name", "status", "code", "headers", "extra"),
    [
        (
            "invalid_cursor",
            400,
            "invalid_cursor",
            {},
            {"detail": "Start again from the first page."},
        ),
        ("session_expired", 401, "session_expired", {}, {}),
        ("passkey_required", 403, "passkey_required", {}, {"detail": "Sign in with a passkey."}),
        ("not_found", 404, "not_found", {}, {}),
        ("invalid_state", 409, "invalid_state", {}, {"current_state": "cancelled"}),
        ("link_expired", 410, "link_expired", {}, {}),
        ("file_too_large", 413, "file_too_large", {}, {}),
        ("unsupported_media_type", 415, "unsupported_media_type", {}, {}),
        (
            "range_not_satisfiable",
            416,
            "range_not_satisfiable",
            {"content-range": "bytes */5242880"},
            {},
        ),
        ("code_invalid", 422, "code_invalid", {}, {"attempts_remaining": 3}),
        ("rate_limited", 429, "rate_limited", {"retry-after": "30"}, {}),
        (
            "service_unavailable",
            503,
            "service_unavailable",
            {"retry-after": "10"},
            {"detail": "Try again soon."},
        ),
        ("retry_later", 429, "rate_limited", {"retry-after": "5"}, {}),
    ],
)
def test_a_raised_error_is_its_problem(
    client: TestClient,
    name: str,
    status: int,
    code: str,
    headers: dict[str, str],
    extra: dict[str, object],
) -> None:
    response = client.get(f"/v1/raise/{name}")
    body = problem(response, status, code)
    for header, value in headers.items():
        assert response.headers[header] == value
    assert {k: v for k, v in body.items() if k not in {"type", "title", "status", "code"}} == {
        "request_id": response.headers["x-request-id"],
        **extra,
    }


@pytest.mark.parametrize("error", [errors.RateLimited(0), errors.ServiceUnavailable(-3)])
def test_retry_after_is_at_least_one_second(error: ProblemError) -> None:
    assert api_errors._headers_of(error) == {"Retry-After": "1"}


@pytest.mark.parametrize(
    ("code", "challenge"),
    [
        ("credentials_invalid", 'Bearer error="invalid_token"'),
        ("session_expired", 'Bearer error="invalid_token"'),
        ("authentication_required", "Bearer"),
    ],
)
def test_a_bearer_caller_gets_a_challenge(code: errors.UnauthenticatedCode, challenge: str) -> None:
    assert api_errors._headers_of(errors.Unauthenticated(code, bearer=True)) == {
        "WWW-Authenticate": challenge
    }
    assert api_errors._headers_of(errors.Unauthenticated(code)) == {}


def test_field_errors_are_listed() -> None:
    error = errors.Unprocessable(
        "recipient_undeliverable",
        "An address can't receive email.",
        errors=[FieldError("Can't receive email.", pointer=json_pointer("recipients", 3, "email"))],
    )
    response = problem_response(
        422, "recipient_undeliverable", error.detail, field_errors=error.errors
    )
    assert response.body is not None
    assert (
        b'"errors":[{"detail":"Can\'t receive email.","pointer":"#/recipients/3/email"}]'
        in bytes(response.body)
    )


def test_without_the_request_middleware_there_is_no_request_id() -> None:
    response = TestClient(service_app()).get("/v1/raise/not_found")
    assert response.status_code == 404
    assert "request_id" not in response.json()


def test_a_problem_error_takes_only_its_own_codes() -> None:
    with pytest.raises(ValueError, match="Conflict doesn't take the code 'not_found'"):
        errors.Conflict("not_found")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="ProblemError doesn't take"):
        ProblemError("not_found")


def test_a_field_error_names_one_place() -> None:
    with pytest.raises(ValueError, match="one place"):
        FieldError("bad", pointer="#/a", header="X-A")


def test_a_json_pointer_escapes_its_parts() -> None:
    assert json_pointer() == "#"
    assert json_pointer("a/b", "c~d", 0) == "#/a~1b/c~0d/0"


def test_an_error_kind_without_a_status_is_a_bug() -> None:
    class UnmappedError(ProblemError):
        codes = ("not_found",)

    with pytest.raises(TypeError, match="UnmappedError has no HTTP status"):
        status_of(UnmappedError("not_found"))


# ---- requests that don't validate (README 3.1) ----


def post(client: TestClient, path: str = f"/v1/transfers/{ID}", **kwargs: Any) -> Any:
    return client.post(path, **kwargs)


BODY = {"message": "hi", "recipients": [{"email": "a@example.com"}]}


def test_a_valid_request_still_succeeds(client: TestClient) -> None:
    assert post(client, json=BODY).json() == {"ok": "yes"}


def test_a_bad_path_parameter_is_not_found(client: TestClient) -> None:
    body = problem(post(client, "/v1/transfers/not-a-uuid", json=BODY), 404, "not_found")
    assert "errors" not in body


def test_a_bad_query_parameter_is_malformed(client: TestClient) -> None:
    body = problem(
        post(client, f"/v1/transfers/{ID}?limit=ten", json=BODY), 400, "malformed_request"
    )
    assert body["errors"] == [
        {
            "detail": "Input should be a valid integer, unable to parse string as an integer",
            "parameter": "limit",
        }
    ]
    assert "ten" not in str(body)  # the value sent is never echoed


def test_a_bad_header_is_malformed(client: TestClient) -> None:
    response = post(client, json=BODY, headers={"idempotency-key": "far-too-long"})
    body = problem(response, 400, "malformed_request")
    assert body["errors"] == [
        {"detail": "String should have at most 5 characters", "header": "idempotency-key"}
    ]


def test_a_body_that_isnt_json_is_malformed(client: TestClient) -> None:
    response = post(client, content=b"{nope", headers={"content-type": "application/json"})
    body = problem(response, 400, "malformed_request")
    assert body["detail"] == "The request body isn't valid JSON."
    assert "errors" not in body


@pytest.mark.parametrize("content_type", ["text/plain", "application/x-www-form-urlencoded", None])
def test_a_body_in_another_media_type_is_unsupported(
    client: TestClient, content_type: str | None
) -> None:
    headers = {} if content_type is None else {"content-type": content_type}
    response = post(client, content=b'{"message": "hi"}', headers=headers)
    problem(response, 415, "unsupported_media_type")


def test_a_json_media_type_with_a_suffix_is_json(client: TestClient) -> None:
    response = post(
        client, content=b'{"message": 1}', headers={"content-type": "application/merge-patch+json"}
    )
    problem(response, 422, "validation_failed")


def test_a_body_that_breaks_its_schema_points_at_each_field(client: TestClient) -> None:
    sent = {"message": 7, "recipients": [{"email": "a@example.com"}, {"address": "secret"}]}
    body = problem(post(client, json=sent), 422, "validation_failed")
    assert body["errors"] == [
        {"detail": "Input should be a valid string", "pointer": "#/message"},
        {"detail": "Field required", "pointer": "#/recipients/1/email"},
        {"detail": "Extra inputs are not permitted", "pointer": "#/recipients/1/address"},
    ]
    assert "secret" not in str(body)


def test_a_missing_body_is_a_validation_failure(client: TestClient) -> None:
    body = problem(post(client), 422, "validation_failed")
    assert body["errors"] == [{"detail": "Field required", "pointer": "#"}]


def test_path_errors_win_over_the_others(client: TestClient) -> None:
    problem(post(client, "/v1/transfers/x?limit=ten", content=b"{"), 404, "not_found")


def test_parameter_errors_win_over_body_errors(client: TestClient) -> None:
    body = problem(post(client, f"/v1/transfers/{ID}?limit=ten", json={}), 400, "malformed_request")
    assert [error.get("parameter") for error in body["errors"]] == ["limit"]


# ---- what Starlette and FastAPI raise, and everything else ----


def test_an_unknown_path_is_not_found(client: TestClient) -> None:
    problem(client.get("/v1/nothing-here"), 404, "not_found")


def test_a_method_the_path_doesnt_take_is_not_allowed(client: TestClient) -> None:
    response = client.delete(f"/v1/transfers/{ID}")
    problem(response, 405, "method_not_allowed")
    assert response.headers["allow"] == "POST"


def test_fastapi_security_errors_are_problems(client: TestClient) -> None:
    response = client.get("/v1/bearer")
    body = problem(response, 401, "authentication_required")
    assert response.headers["www-authenticate"] == "Bearer"
    assert "detail" not in body  # FastAPI's "Not authenticated" isn't passed on


def test_an_http_exception_outside_the_contract_is_an_internal_error(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="sft.api.errors"):
        response = client.get("/v1/teapot")
    body = problem(response, 500, "internal_error")
    assert "internal detail" not in response.text
    assert body["detail"] == api_errors._INTERNAL_DETAIL
    assert [record.__dict__.get("status") for record in caplog.records] == [418]


def test_an_unhandled_error_is_an_internal_error_without_internals(client: TestClient) -> None:
    response = client.get("/v1/boom")
    body = problem(response, 500, "internal_error")
    assert set(body) == {"type", "title", "status", "code", "detail", "request_id"}
    for secret in ("hunter2", "db.internal", "RuntimeError", "Traceback"):
        assert secret not in response.text


# ---- the codes, titles and statuses agree with the contract and the README ----


def readme_statuses() -> dict[int, set[str]]:
    """The README 3 table: status, then the codes before any `:` explanation."""
    section = README.read_text().split("## 3. Errors")[1].split("\n### 3.1")[0]
    table: dict[int, set[str]] = {}
    for status, codes in re.findall(r"^\| (\d{3}) \| (.+) \|$", section, re.MULTILINE):
        table[int(status)] = set(re.findall(r"`([a-z_]+)`", codes.split(":")[0]))
    return table


def code_statuses() -> dict[int, set[str]]:
    table: dict[int, set[str]] = {}
    for kind, status in STATUSES.items():
        table.setdefault(status, set()).update(kind.codes)
    for code, status in OWN_CODES.items():
        table.setdefault(status, set()).add(code)
    return table


def test_every_code_is_in_the_contract() -> None:
    contract = load_contract(CONTRACT)
    assert sorted(PROBLEM_CODES) == sorted(contract["components"]["schemas"]["ProblemCode"]["enum"])
    assert len(set(PROBLEM_CODES)) == len(PROBLEM_CODES)


def test_every_code_has_its_readme_status() -> None:
    assert code_statuses() == readme_statuses()


def test_every_code_has_a_title() -> None:
    assert set(TITLES) == set(PROBLEM_CODES)


def test_every_code_belongs_to_one_kind() -> None:
    owned = [code for kind in STATUSES for code in kind.codes] + list(OWN_CODES)
    assert sorted(owned) == sorted(PROBLEM_CODES)
    assert all(kind.codes for kind in STATUSES)
    assert get_args(errors.RateLimitedCode) == ("rate_limited",)


def test_the_problem_schema_is_the_contracts() -> None:
    contract = load_contract(CONTRACT)
    document = create_app().openapi()
    ref = {"$ref": "#/components/schemas/Problem"}
    assert _diff(_Normaliser(contract).schema(ref), _Normaliser(document).schema(ref)) == []


# ---- the OpenAPI document ----


def openapi_of(build: Callable[[FastAPI], None]) -> dict[str, Any]:
    app = create_app()
    build(app)
    return app.openapi()


def test_fastapis_own_422_is_gone_from_routes_without_a_body() -> None:
    def build(app: FastAPI) -> None:
        @app.get("/v1/things/{thing_id}", responses=problem_responses(404, 429))
        def thing(thing_id: UUID, limit: int = 25) -> None:
            raise NotImplementedError

    document = openapi_of(build)
    assert sorted(document["paths"]["/v1/things/{thing_id}"]["get"]["responses"]) == [
        "200",
        "404",
        "429",
    ]
    schemas = document["components"]["schemas"]
    assert "HTTPValidationError" not in schemas
    assert "ValidationError" not in schemas
    assert {"Problem", "ValidationIssue"} <= set(schemas)


def test_fastapis_own_422_is_a_problem_on_routes_with_a_body() -> None:
    def build(app: FastAPI) -> None:
        @app.post("/v1/transfers")
        def create(body: TransferCreate) -> None:
            raise NotImplementedError

    response = openapi_of(build)["paths"]["/v1/transfers"]["post"]["responses"]["422"]
    assert response["content"] == {MEDIA_TYPE: {"schema": {"$ref": "#/components/schemas/Problem"}}}


def test_a_declared_422_is_kept() -> None:
    def build(app: FastAPI) -> None:
        @app.get("/v1/report", responses=problem_responses(422))
        def report(days: int) -> None:
            raise NotImplementedError

    responses = openapi_of(build)["paths"]["/v1/report"]["get"]["responses"]
    assert responses["422"]["content"][MEDIA_TYPE]["schema"] == {
        "$ref": "#/components/schemas/Problem"
    }


def test_the_document_is_built_once() -> None:
    app = create_app()
    assert app.openapi() is app.openapi()


def test_problem_responses_declare_retry_after_and_default() -> None:
    responses = problem_responses(404, 429, 503, "default")
    assert responses[404]["description"] == "Not Found"
    assert "headers" not in responses[404]
    for status in (429, 503):
        assert responses[status]["headers"]["Retry-After"]["schema"] == {
            "type": "integer",
            "minimum": 1,
        }
    assert responses["default"]["description"].startswith("An unexpected server error")


def test_the_readme_lists_the_errors_by_status() -> None:
    # A guard on the parser above: it reads every status row of the table.
    assert sorted(readme_statuses()) == [
        400, 401, 403, 404, 405, 409, 410, 413, 415, 416, 422, 429, 500, 503
    ]  # fmt: skip
