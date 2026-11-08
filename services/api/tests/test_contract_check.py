"""The generated-spec check (tools/contract_check.py).

The routes here are temporary: each test builds its own app, never the service's. They are checked
against contract_sample.yaml, a frozen extract of the contract, so that a change to the contract
doesn't break these tests. The models are written the way M1 will write them, so a passing test also
shows that what FastAPI generates from ordinary Pydantic code compares equal to the hand-written
contract.
"""

import subprocess
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Literal
from uuid import UUID

import pytest
from fastapi import APIRouter, Body, FastAPI, Header, Query
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.applications import Starlette

from sft.api.errors import problem_responses, register_error_handlers
from tools import contract_check
from tools.contract_check import (
    CONTRACT,
    OPERATOR_SERVER,
    PUBLIC_SERVER,
    ContractError,
    _Normaliser,
    check,
    contract_operations,
    load_contract,
    main,
    service_apps,
)

SAMPLE = Path(__file__).with_name("contract_sample.yaml")
SAMPLE_TITLE = "secure-file-transfer API"  # the sample's info
SAMPLE_VERSION = "1.0.0-draft"

# ---- the contract's schemas, as M1 would write them ----

EmailAddress = Annotated[str, Field(max_length=254, json_schema_extra={"format": "email"})]
Locale = Literal["en", "ja"]
Role = Literal["admin", "member"]
UserStatus = Literal["invited", "active", "deactivated"]
IdempotencyKey = Annotated[
    str | None,
    Header(alias="Idempotency-Key", min_length=1, max_length=255, pattern=r"^[\x21-\x7E]+$"),
]
FILE_BYTES = {
    "application/octet-stream": {
        "schema": {"type": "string", "contentMediaType": "application/octet-stream"}
    }
}


class TenantCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, Field(min_length=1, max_length=200)]
    first_admin_email: EmailAddress
    recovery_contact: Annotated[str, Field(min_length=1, max_length=320)]
    default_locale: Locale = "en"


class Tenant(BaseModel):
    id: UUID
    name: str
    status: Literal["active", "suspended"]
    created_at: datetime


class User(BaseModel):
    id: UUID
    email: EmailAddress
    role: Role
    status: UserStatus
    sso_fallback: bool
    created_at: datetime


class TenantCreated(BaseModel):
    tenant: Tenant
    first_admin: User


class UserPage(BaseModel):
    items: list[User]
    next_cursor: str | None


class SignOutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    all_sessions: bool = False


class SignOutResult(BaseModel):
    logout_url: Annotated[str, Field(json_schema_extra={"format": "uri"})]


def plain_app(*routers: APIRouter, version: str = SAMPLE_VERSION) -> FastAPI:
    """An app with FastAPI's own error answers, as before #96."""
    result = FastAPI(
        title=SAMPLE_TITLE, version=version, docs_url=None, redoc_url=None, openapi_url=None
    )
    for router in routers:
        result.include_router(router)
    return result


def app(*routers: APIRouter, version: str = SAMPLE_VERSION) -> FastAPI:
    """An app built like create_app(), with the given routes."""
    result = plain_app(*routers, version=version)
    register_error_handlers(result)
    return result


# ---- routes that match the contract: five public operations and one operator operation ----

# The error statuses the contract declares for two of them.
LIST_USERS = (400, 401, 403, 429)
DELETE_FILE = (401, 403, 404, 409, 429)


def public_routes() -> APIRouter:
    router = APIRouter(prefix="/v1")

    @router.get(
        "/auth/sign-in",
        operation_id="startSignIn",
        status_code=302,
        response_class=RedirectResponse,
        responses=problem_responses(400, 422, 429, 503, "default"),
    )
    def start_sign_in(
        method: Literal["sso", "local"],
        sso_domain: Annotated[
            str | None, Query(max_length=253, json_schema_extra={"format": "hostname"})
        ] = None,
        return_to: Annotated[str, Query(max_length=512)] = "/",
    ) -> RedirectResponse:
        raise NotImplementedError

    @router.post(
        "/auth/sign-out",
        operation_id="signOut",
        responses=problem_responses(400, 401, 403, 422, 429),
    )
    def sign_out(body: Annotated[SignOutRequest | None, Body()] = None) -> SignOutResult:
        raise NotImplementedError

    @router.get("/users", operation_id="listUsers", responses=problem_responses(*LIST_USERS))
    def list_users(
        role: Role | None = None,
        status: UserStatus | None = None,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> UserPage:
        raise NotImplementedError

    @router.delete(
        "/files/{file_id}",
        operation_id="deleteFile",
        status_code=204,
        responses=problem_responses(*DELETE_FILE),
    )
    def delete_file(file_id: UUID) -> None:
        raise NotImplementedError

    @router.get(
        "/files/{file_id}/downloads/{grant_id}/content",
        operation_id="getReceivedFileDownloadContent",
        response_class=StreamingResponse,
        responses={
            200: {"content": FILE_BYTES},
            206: {"content": FILE_BYTES},
            **problem_responses(401, 403, 404, 416, 429, 503),
        },
    )
    def get_content(
        file_id: UUID,
        grant_id: UUID,
        range_: Annotated[
            str | None, Header(alias="Range", max_length=100, pattern=r"^bytes=(\d+-\d*|-\d+)$")
        ] = None,
        if_range: Annotated[str | None, Header(max_length=100)] = None,
    ) -> StreamingResponse:
        raise NotImplementedError

    return router


def operator_routes() -> APIRouter:
    router = APIRouter(prefix="/v1")

    @router.post(
        "/operator/tenants",
        operation_id="createTenant",
        status_code=201,
        responses=problem_responses(400, 401, 403, 409, 422, 429),
    )
    def create_tenant(body: TenantCreate, idempotency_key: IdempotencyKey = None) -> TenantCreated:
        raise NotImplementedError

    return router


@pytest.fixture(scope="module")
def contract() -> dict[str, Any]:
    return load_contract(SAMPLE)


def test_the_service_matches_the_contract() -> None:
    contract = load_contract(CONTRACT)
    report = check(service_apps(), contract)
    assert report.problems == []
    assert len(report.implemented) + len(report.remaining) == len(contract_operations(contract))


def test_routes_that_match_the_contract_pass(contract: dict[str, Any]) -> None:
    report = check(
        {PUBLIC_SERVER: app(public_routes()), OPERATOR_SERVER: app(operator_routes())}, contract
    )
    assert report.problems == []
    assert sorted(op.operation_id for op in report.implemented) == [
        "createTenant",
        "deleteFile",
        "getReceivedFileDownloadContent",
        "listUsers",
        "signOut",
        "startSignIn",
    ]
    assert [op.operation_id for op in report.remaining] == ["signOutUser"]
    assert "6 of 7 contract operations implemented, 1 remains." in report.render()


# ---- each wrong route fails, with a message that says what to fix ----


def undocumented() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.post("/widgets", operation_id="createWidget")
    def create_widget() -> None:
        raise NotImplementedError

    return app(router)


def hidden() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.get("/debug", include_in_schema=False)
    def debug() -> None:
        raise NotImplementedError

    return app(router)


def mounted() -> FastAPI:
    result = app()
    result.mount("/v1/files", Starlette())
    return result


def default_operation_id() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.delete("/files/{file_id}", status_code=204)
    def delete_file(file_id: UUID) -> None:
        raise NotImplementedError

    return app(router)


def wrong_method() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.put("/auth/sign-out", operation_id="signOut")
    def sign_out() -> SignOutResult:
        raise NotImplementedError

    return app(router)


def renamed_path_parameter() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.delete("/files/{id}", operation_id="deleteFile", status_code=204)
    def delete_file(id: UUID) -> None:
        raise NotImplementedError

    return app(router)


def extra_query_parameter() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.delete("/files/{file_id}", operation_id="deleteFile", status_code=204)
    def delete_file(file_id: UUID, force: bool = False) -> None:
        raise NotImplementedError

    return app(router)


def deprecated() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.delete("/files/{file_id}", operation_id="deleteFile", status_code=204, deprecated=True)
    def delete_file(file_id: UUID) -> None:
        raise NotImplementedError

    return app(router)


def missing_header_parameter() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.post("/operator/tenants", operation_id="createTenant", status_code=201)
    def create_tenant(body: TenantCreate) -> TenantCreated:
        raise NotImplementedError

    return app(router)


def parameter_schema() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.get("/users", operation_id="listUsers")
    def list_users(
        role: Role | None = None,
        status: UserStatus | None = None,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
        limit: Annotated[int, Query(ge=1, le=50)] = 25,
    ) -> UserPage:
        raise NotImplementedError

    return app(router)


def required_parameter() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.get(
        "/auth/sign-in",
        operation_id="startSignIn",
        status_code=302,
        response_class=RedirectResponse,
    )
    def start_sign_in(
        method: Literal["sso", "local"],
        sso_domain: Annotated[str, Query(max_length=253, json_schema_extra={"format": "hostname"})],
        return_to: Annotated[str, Query(max_length=512)] = "/",
    ) -> RedirectResponse:
        raise NotImplementedError

    return app(router)


def tenant_create_route(model: type[BaseModel], *, status_code: int = 201) -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.post("/operator/tenants", operation_id="createTenant", status_code=status_code)
    def create_tenant(body: model, idempotency_key: IdempotencyKey = None) -> TenantCreated:
        raise NotImplementedError

    return app(router)


class ShorterName(TenantCreate):
    name: Annotated[str, Field(min_length=1, max_length=100)]


class ExtraFieldsAllowed(BaseModel):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    first_admin_email: EmailAddress
    recovery_contact: Annotated[str, Field(min_length=1, max_length=320)]
    default_locale: Locale = "en"


class NullableContact(TenantCreate):
    recovery_contact: Annotated[str | None, Field(min_length=1, max_length=320)]


def missing_body() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.post("/auth/sign-out", operation_id="signOut")
    def sign_out() -> SignOutResult:
        raise NotImplementedError

    return app(router)


def required_body() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.post("/auth/sign-out", operation_id="signOut")
    def sign_out(body: SignOutRequest) -> SignOutResult:
        raise NotImplementedError

    return app(router)


class PageWithoutNull(BaseModel):
    items: list[User]
    next_cursor: str


class UserWithoutFallback(BaseModel):
    id: UUID
    email: EmailAddress
    role: Role
    status: UserStatus
    created_at: datetime


class PageOfIncompleteUsers(BaseModel):
    items: list[UserWithoutFallback]
    next_cursor: str | None


def list_users_route(page: type[BaseModel]) -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.get("/users", operation_id="listUsers", response_model=page)
    def list_users(
        role: Role | None = None,
        status: UserStatus | None = None,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> Any:
        raise NotImplementedError

    return app(router)


def json_instead_of_bytes() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.get(
        "/files/{file_id}/downloads/{grant_id}/content",
        operation_id="getReceivedFileDownloadContent",
    )
    def get_content(
        file_id: UUID,
        grant_id: UUID,
        range_: Annotated[
            str | None, Header(alias="Range", max_length=100, pattern=r"^bytes=(\d+-\d*|-\d+)$")
        ] = None,
        if_range: Annotated[str | None, Header(max_length=100)] = None,
    ) -> dict[str, str]:
        raise NotImplementedError

    return app(router)


def outside_base_path() -> FastAPI:
    router = APIRouter()

    @router.delete("/files/{file_id}", operation_id="deleteFile", status_code=204)
    def delete_file(file_id: UUID) -> None:
        raise NotImplementedError

    return app(router)


def unexpected_body() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.delete("/files/{file_id}", operation_id="deleteFile", status_code=204)
    def delete_file(file_id: UUID, body: SignOutRequest) -> None:
        raise NotImplementedError

    return app(router)


def constraint_only_in_the_code() -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.get("/users", operation_id="listUsers")
    def list_users(
        role: Role | None = None,
        status: UserStatus | None = None,
        cursor: Annotated[str | None, Query(min_length=1, max_length=512)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> UserPage:
        raise NotImplementedError

    return app(router)


def delete_file_route(responses: dict[int | str, dict[str, Any]]) -> FastAPI:
    router = APIRouter(prefix="/v1")

    @router.delete(
        "/files/{file_id}", operation_id="deleteFile", status_code=204, responses=responses
    )
    def delete_file(file_id: UUID) -> None:
        raise NotImplementedError

    return app(router)


# A problem document without the Problem component, which only register_error_handlers adds.
LIST_USERS_PLAIN = {
    status: {"description": "Error", "content": {"application/problem+json": {"schema": {}}}}
    for status in LIST_USERS
}


class NotAProblem(BaseModel):
    detail: str


def fastapi_errors() -> FastAPI:
    """listUsers on an app without register_error_handlers: FastAPI's own 422 shows."""
    router = APIRouter(prefix="/v1")

    @router.get("/users", operation_id="listUsers", responses=LIST_USERS_PLAIN)
    def list_users(
        role: Role | None = None,
        status: UserStatus | None = None,
        cursor: Annotated[str | None, Query(max_length=512)] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 25,
    ) -> UserPage:
        raise NotImplementedError

    return plain_app(router)


def openapi_3_0() -> FastAPI:
    result = app()
    result.openapi_version = "3.0.3"
    return result


WRONG: list[tuple[str, str, Callable[[], FastAPI], list[str]]] = [
    (
        "undocumented",
        PUBLIC_SERVER,
        undocumented,
        ["POST /v1/widgets (createWidget): not in the contract. Add it to docs/api/openapi.yaml"],
    ),
    (
        "hidden",
        PUBLIC_SERVER,
        hidden,
        ["/v1: GET /v1/debug: a route the OpenAPI document doesn't show"],
    ),
    ("mounted", PUBLIC_SERVER, mounted, ["/v1: Mount /v1/files: a route the OpenAPI document"]),
    (
        "unexpected body",
        PUBLIC_SERVER,
        unexpected_body,
        [
            "request body: the code takes one, the contract none",
            "error response 422: not in the contract, so the route may not answer with it",
        ],
    ),
    (
        "undeclared error status",
        PUBLIC_SERVER,
        lambda: delete_file_route(problem_responses(*DELETE_FILE, 410)),
        [
            "DELETE /v1/files/{file_id} (deleteFile): error response 410: not in the contract, "
            "so the route may not answer with it"
        ],
    ),
    (
        "missing error status",
        PUBLIC_SERVER,
        lambda: delete_file_route(problem_responses(401, 403, 404, 429)),
        [
            "error response 409: missing in the code; "
            "declare it with sft.api.errors.problem_responses()"
        ],
    ),
    (
        "error range instead of statuses",
        PUBLIC_SERVER,
        lambda: delete_file_route(
            problem_responses(*DELETE_FILE) | {"4XX": problem_responses(404)[404]}
        ),
        ["error response 4XX: not in the contract"],
    ),
    (
        "error media type",
        PUBLIC_SERVER,
        lambda: delete_file_route(
            problem_responses(401, 403, 409, 429) | {404: {"model": NotAProblem}}
        ),
        [
            "response 404: the contract has ['application/problem+json'], "
            "the code ['application/json']"
        ],
    ),
    (
        "error schema",
        PUBLIC_SERVER,
        lambda: delete_file_route(
            problem_responses(401, 403, 409, 429)
            | {
                404: {
                    "description": "Not found",
                    "content": {"application/problem+json": {"schema": {"type": "object"}}},
                }
            }
        ),
        ["response 404 application/problem+json at /properties: the contract has"],
    ),
    (
        "FastAPI's own 422",
        PUBLIC_SERVER,
        fastapi_errors,
        ["GET /v1/users (listUsers): error response 422: not in the contract"],
    ),
    (
        "constraint only in the code",
        PUBLIC_SERVER,
        constraint_only_in_the_code,
        ["query parameter cursor at /schema/minLength: the code has 1, the contract nothing"],
    ),
    ("OpenAPI 3.0", PUBLIC_SERVER, openapi_3_0, ["openapi: the contract is 3.1.0, the code 3.0.3"]),
    (
        "default operation ID",
        PUBLIC_SERVER,
        default_operation_id,
        [
            "operation ID: the contract has deleteFile, "
            "the code delete_file_v1_files__file_id__delete"
        ],
    ),
    (
        "wrong method",
        PUBLIC_SERVER,
        wrong_method,
        [
            "PUT /v1/auth/sign-out (signOut): not in the contract here; "
            "the contract has signOut (POST /auth/sign-out) on /v1"
        ],
    ),
    (
        "renamed path parameter",
        PUBLIC_SERVER,
        renamed_path_parameter,
        [
            "path: the contract has /files/{file_id}, the code /files/{id}",
            "path parameter file_id: missing in the code",
            "path parameter id: not in the contract",
        ],
    ),
    (
        "extra query parameter",
        PUBLIC_SERVER,
        extra_query_parameter,
        ["DELETE /v1/files/{file_id} (deleteFile): query parameter force: not in the contract"],
    ),
    (
        "deprecated",
        PUBLIC_SERVER,
        deprecated,
        ["deprecated: the contract has False, the code True"],
    ),
    (
        "missing header parameter",
        OPERATOR_SERVER,
        missing_header_parameter,
        ["header parameter Idempotency-Key: missing in the code"],
    ),
    (
        "parameter schema",
        PUBLIC_SERVER,
        parameter_schema,
        ["query parameter limit at /schema/maximum: the contract has 100, the code 50"],
    ),
    (
        "required parameter",
        PUBLIC_SERVER,
        required_parameter,
        ["query parameter sso_domain at /required: the contract has false, the code true"],
    ),
    (
        "request body field",
        OPERATOR_SERVER,
        lambda: tenant_create_route(ShorterName),
        [
            "request body application/json at /properties/name/maxLength: "
            "the contract has 200, the code 100"
        ],
    ),
    (
        "request body allows extra fields",
        OPERATOR_SERVER,
        lambda: tenant_create_route(ExtraFieldsAllowed),
        [
            "request body application/json at /additionalProperties: "
            "the contract has false, the code nothing"
        ],
    ),
    (
        "request body field nullable",
        OPERATOR_SERVER,
        lambda: tenant_create_route(NullableContact),
        [
            "request body application/json at /properties/recovery_contact/type: "
            'the contract has "string", the code ["null", "string"]'
        ],
    ),
    (
        "missing body",
        PUBLIC_SERVER,
        missing_body,
        ["request body: the contract has one, the code none"],
    ),
    (
        "required body",
        PUBLIC_SERVER,
        required_body,
        ["request body required: the contract has False, the code True"],
    ),
    (
        "success status",
        OPERATOR_SERVER,
        lambda: tenant_create_route(TenantCreate, status_code=200),
        ["success statuses: the contract has ['201'], the code ['200']"],
    ),
    (
        "response field not nullable",
        PUBLIC_SERVER,
        lambda: list_users_route(PageWithoutNull),
        [
            "response 200 application/json at /properties/next_cursor/type: "
            'the contract has ["null", "string"], the code "string"'
        ],
    ),
    (
        "response field missing",
        PUBLIC_SERVER,
        lambda: list_users_route(PageOfIncompleteUsers),
        [
            "response 200 application/json at /properties/items/items/properties/sso_fallback: "
            'the contract has {"type": "boolean"}, the code nothing',
            "response 200 application/json at /properties/items/items/required:",
        ],
    ),
    (
        "media type",
        PUBLIC_SERVER,
        json_instead_of_bytes,
        [
            "success statuses: the contract has ['200', '206'], the code ['200']",
            "response 200: the contract has ['application/octet-stream'], "
            "the code ['application/json']",
        ],
    ),
    (
        "operator operation on the public app",
        PUBLIC_SERVER,
        lambda: app(operator_routes()),
        [
            "the contract serves createTenant (POST /operator/tenants) from the server "
            "https://127.0.0.1:{local_port}/v1, not from this app's (/v1)"
        ],
    ),
    (
        "outside the base path",
        PUBLIC_SERVER,
        outside_base_path,
        ["DELETE /files/{file_id} (deleteFile): outside the server's base path /v1"],
    ),
    (
        "version",
        PUBLIC_SERVER,
        lambda: app(version="2.0.0"),
        ["/v1: info/version: the contract has '1.0.0-draft', the code '2.0.0'"],
    ),
]


@pytest.mark.parametrize(
    ("server", "build", "expected"),
    [case[1:] for case in WRONG],
    ids=[case[0] for case in WRONG],
)
def test_a_route_that_differs_from_the_contract_fails(
    contract: dict[str, Any], server: str, build: Callable[[], FastAPI], expected: list[str]
) -> None:
    report = check({server: build()}, contract)
    assert not report.ok
    for message in expected:
        assert any(message in problem for problem in report.problems), report.problems
    assert "FAILED" in report.render()


def test_an_app_for_a_server_the_contract_lacks_fails(contract: dict[str, Any]) -> None:
    report = check({"/v2": app()}, contract)
    assert report.problems == ["server /v2: the contract has no server with this URL"]


# ---- normalisation: two spellings of one schema compare equal ----


def schema(node: Any, components: dict[str, Any] | None = None) -> Any:
    return _Normaliser({"components": {"schemas": components or {}}}).schema(node)


def test_nullable_spellings_compare_equal() -> None:
    contract = {"type": ["string", "null"], "format": "date-time", "description": "When."}
    pydantic = {
        "anyOf": [{"type": "string", "format": "date-time"}, {"type": "null"}],
        "title": "When",
    }
    assert (
        schema(contract) == schema(pydantic) == {"type": ["null", "string"], "format": "date-time"}
    )


def test_a_nullable_enum_includes_null() -> None:
    contract = {"type": ["string", "null"], "enum": ["clamav", "guardduty", None]}
    pydantic = {"anyOf": [{"enum": ["guardduty", "clamav"], "type": "string"}, {"type": "null"}]}
    assert schema(contract) == schema(pydantic)


def test_annotations_and_extensions_are_ignored() -> None:
    assert schema({"type": "string", "title": "T", "examples": ["x"], "x-internal": True}) == {
        "type": "string"
    }


def test_const_is_a_one_value_enum_and_true_allows_anything() -> None:
    assert schema({"const": "a"}) == schema({"enum": ["a"]})
    assert schema({"type": "object", "additionalProperties": True}) == schema({"type": "object"})
    assert schema(True) == {}
    assert schema(False) == {"not": {}}


def test_keywords_beside_a_ref_apply_to_it() -> None:
    components = {"Locale": {"type": "string", "enum": ["en", "ja"], "description": "Language."}}
    node = {"$ref": "#/components/schemas/Locale", "default": "en", "description": "Default."}
    assert schema(node, components) == {"type": "string", "enum": ["en", "ja"], "default": "en"}


def test_all_of_object_schemas_are_flattened() -> None:
    components = {
        "ApiKey": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
    }
    contract = {
        "allOf": [
            {"$ref": "#/components/schemas/ApiKey"},
            {
                "type": "object",
                "required": ["secret"],
                "properties": {"secret": {"type": "string"}},
            },
        ]
    }
    pydantic = {
        "type": "object",
        "required": ["secret", "id"],
        "properties": {"id": {"type": "string"}, "secret": {"type": "string"}},
    }
    assert schema(contract, components) == schema(pydantic)


def test_conflicting_all_of_branches_are_kept() -> None:
    node = {
        "allOf": [
            {"properties": {"a": {"type": "string"}}},
            {"properties": {"a": {"type": "integer"}}},
        ]
    }
    assert "allOf" in schema(node)
    assert "allOf" in schema({"allOf": [{"type": "string"}, {"type": "integer"}]})


def test_a_recursive_schema_terminates() -> None:
    components = {
        "Node": {"type": "object", "properties": {"child": {"$ref": "#/components/schemas/Node"}}}
    }
    result = schema({"$ref": "#/components/schemas/Node"}, components)
    assert result["properties"]["child"] == {"$cycle": 1}


def test_a_discriminator_mapping_is_ignored() -> None:
    node = {"oneOf": [], "discriminator": {"propertyName": "kind", "mapping": {"a": "#/x"}}}
    assert schema(node)["discriminator"] == {"propertyName": "kind"}


@pytest.mark.parametrize(
    "node",
    [{"$ref": "other.yaml#/Thing"}, {"$ref": "#/components/schemas/Missing"}, "not a schema"],
)
def test_a_schema_that_cant_be_read_is_an_error(node: Any) -> None:
    with pytest.raises(ContractError):
        schema(node)


def test_a_reference_that_refers_to_itself_is_an_error() -> None:
    normaliser = _Normaliser(
        {"components": {"parameters": {"P": {"$ref": "#/components/parameters/P"}}}}
    )
    with pytest.raises(ContractError, match="refers to itself"):
        normaliser.resolve({"$ref": "#/components/parameters/P"})


def test_a_null_default_is_no_default() -> None:
    contract = {"type": ["integer", "null"], "minimum": 1, "default": None}
    pydantic = {"anyOf": [{"type": "integer", "minimum": 1}, {"type": "null"}]}
    assert schema(contract) == schema(pydantic)


def test_a_nullable_const_is_an_enum_with_null() -> None:
    pydantic = {"anyOf": [{"const": "a", "type": "string"}, {"type": "null"}]}
    assert schema(pydantic) == schema({"type": ["string", "null"], "enum": ["a", None]})


@pytest.mark.parametrize(
    "node",
    [
        {"anyOf": [{"items": {"type": "string"}}, {"type": "null"}]},  # a branch with no type
        {"anyOf": [{"type": "string", "format": "uuid"}, {"type": "null"}], "format": "email"},
        {"anyOf": [{"type": "string"}, {"type": "integer"}, {"type": "null"}]},
    ],
)
def test_a_nullable_that_cant_be_merged_stays_an_any_of(node: Any) -> None:
    assert "anyOf" in schema(node)


def test_a_parameter_can_be_left_out_but_not_sent_as_null() -> None:
    def parameter_schema(node: dict[str, Any]) -> Any:
        operation = {"parameters": [{"name": "p", "in": "query", "schema": node}]}
        return contract_check._parameters({}, operation, _Normaliser({}))[("query", "p")][1]

    plain = parameter_schema({"type": "array", "items": {"type": "string"}})
    assert parameter_schema({"anyOf": [plain["schema"], {"type": "null"}]}) == plain
    assert parameter_schema({"anyOf": [{"items": {}}, {"type": "null"}]})["schema"] == {"items": {}}


def test_a_parameter_with_content_compares_its_schema() -> None:
    operation = {
        "parameters": [
            {
                "name": "f",
                "in": "query",
                "content": {"application/json": {"schema": {"title": "F"}}},
            }
        ]
    }
    parameters = contract_check._parameters({}, operation, _Normaliser({}))
    assert parameters[("query", "f")][1]["content"] == {"application/json": {}}


def test_an_app_that_customises_its_document_is_checked_as_generated() -> None:
    """Path-level parameters and keys that aren't operations, as a hand-made openapi() may write."""
    contract = {
        "openapi": "3.1.0",
        "info": {"title": "T", "version": "1"},
        "servers": [{"url": "/v1"}],
        "paths": {
            "/things/{thing_id}": {
                "get": {
                    "operationId": "getThing",
                    "parameters": [
                        {
                            "name": "thing_id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {"204": {"description": "Done."}},
                }
            }
        },
    }
    generated = {
        "openapi": "3.1.1",
        "info": {"title": "T", "version": "1"},
        "paths": {
            "/v1/things/{thing_id}": {
                "summary": "A thing",
                "parameters": [{"name": "thing_id", "in": "path", "schema": {"type": "string"}}],
                "get": {"operationId": "getThing", "responses": {"204": {"description": "OK"}}},
            }
        },
    }
    custom = FastAPI(openapi_url=None)
    custom.openapi = lambda: generated  # type: ignore[method-assign]
    report = check({"/v1": custom}, contract)
    assert report.problems == []
    assert [op.operation_id for op in report.implemented] == ["getThing"]


# ---- reading the contract ----


def test_the_contract_is_read_as_yaml_1_2(tmp_path: Path) -> None:
    path = tmp_path / "openapi.yaml"
    path.write_text("enum: [yes, no, on, off]\nday: 2026-11-04\nflags: [true, False]\n")
    assert load_contract(path) == {
        "enum": ["yes", "no", "on", "off"],
        "day": "2026-11-04",
        "flags": [True, False],
    }


def test_a_contract_that_isnt_a_document_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "openapi.yaml"
    path.write_text("- just a list\n")
    with pytest.raises(ContractError):
        load_contract(path)


# ---- the command ----


def test_the_command_passes_on_the_service(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-remaining"]) == 0
    out = capsys.readouterr().out
    assert "contract operations implemented" in out
    assert "  remaining: " in out
    assert out.rstrip().endswith("OK: every implemented operation matches the contract.")


def test_the_command_fails_on_an_undocumented_route(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(contract_check, "service_apps", lambda: {PUBLIC_SERVER: undocumented()})
    assert main([]) == 1
    out = capsys.readouterr().out
    assert "POST /v1/widgets (createWidget): not in the contract" in out
    assert "FAILED: 1 difference." in out


def test_the_module_runs_as_ci_runs_it() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "tools.contract_check"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK: every implemented operation matches the contract." in result.stdout


def test_the_command_reports_a_contract_it_cant_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--contract", str(tmp_path / "missing.yaml")]) == 2
    assert "Generated spec check:" in capsys.readouterr().err
