"""Every error the API answers with is an RFC 9457 problem (docs/api/README.md section 3).

`register_error_handlers(app)` replaces FastAPI's `{"detail": ...}` answers with
`application/problem+json` documents of the contract's `Problem` schema, each with the `code`
clients branch on and the `request_id` that `X-Request-Id` and the logs carry:

- `sft.core.errors.ProblemError`, which service code raises: its kind gives the status, and
  `Retry-After`, `WWW-Authenticate` and `Content-Range` come from its fields;
- a request FastAPI can't validate (section 3.1): `400 malformed_request` for a body that isn't
  JSON or a bad query, header or cookie parameter, `404 not_found` for a bad path parameter, `415
  unsupported_media_type` for a body that isn't JSON, and `422 validation_failed` with a pointer to
  each field for a body that breaks its schema;
- the HTTP errors Starlette and FastAPI raise themselves: `404` for an unknown path, `405
  method_not_allowed` with `Allow`, and the `401` and `403` of FastAPI's security classes;
- any other exception: `500 internal_error`, with nothing about what went wrong. The traceback is
  logged, with the request ID, by the server.

It also makes the OpenAPI document say so: `problem_responses()` declares a route's error answers,
and FastAPI's own `422`, which no route sends any more, is replaced (section 11.1).
"""

from __future__ import annotations

import email.message
import logging
from collections.abc import Callable, Mapping, Sequence
from http import HTTPStatus
from typing import Annotated, Any, Final, Literal, cast

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from pydantic.json_schema import SkipJsonSchema
from starlette.exceptions import HTTPException

from sft.core import errors
from sft.core.errors import FieldError, ProblemCode, ProblemError, json_pointer
from sft.core.logs import request_id_var

log = logging.getLogger("sft.api.errors")

MEDIA_TYPE: Final = "application/problem+json"
# The host changes to the service's domain once its name is set (PRD open question 5).
TYPE_BASE: Final = "https://secure-file-transfer.example/problems/"


# ---- the contract's schemas ----


class ValidationIssue(BaseModel):
    detail: str
    pointer: str | SkipJsonSchema[None] = None
    parameter: str | SkipJsonSchema[None] = None
    header: str | SkipJsonSchema[None] = None


class Problem(BaseModel):
    """The contract's `Problem`. Fields left as None are left out of the answer, never sent null."""

    type: Annotated[str, Field(json_schema_extra={"format": "uri"})]
    title: str
    status: Annotated[int, Field(ge=400, le=599)]
    detail: str | SkipJsonSchema[None] = None
    instance: Annotated[
        str | SkipJsonSchema[None], Field(json_schema_extra={"format": "uri-reference"})
    ] = None
    code: ProblemCode
    request_id: str | SkipJsonSchema[None] = None
    errors: list[ValidationIssue] | SkipJsonSchema[None] = None
    attempts_remaining: Annotated[int, Field(ge=0)] | SkipJsonSchema[None] = None
    current_state: str | SkipJsonSchema[None] = None


# ---- codes, statuses and titles ----

# The HTTP status of each kind of ProblemError. A subclass gets its parent's.
STATUSES: Final[Mapping[type[ProblemError], int]] = {
    errors.InvalidRequest: 400,
    errors.Unauthenticated: 401,
    errors.Forbidden: 403,
    errors.NotFound: 404,
    errors.Conflict: 409,
    errors.Gone: 410,
    errors.TooLarge: 413,
    errors.UnsupportedMediaType: 415,
    errors.RangeNotSatisfiable: 416,
    errors.Unprocessable: 422,
    errors.RateLimited: 429,
    errors.ServiceUnavailable: 503,
}

# The status of the codes no ProblemError takes: the API raises them, never service code.
OWN_CODES: Final[Mapping[ProblemCode, int]] = {"method_not_allowed": 405, "internal_error": 500}

# The code for an HTTPException that Starlette or FastAPI raise. Any other status is a bug.
_HTTP_EXCEPTION_CODES: Final[Mapping[int, ProblemCode]] = {
    400: "malformed_request",
    401: "authentication_required",
    403: "permission_denied",
    404: "not_found",
    405: "method_not_allowed",
    413: "request_too_large",
    415: "unsupported_media_type",
}

# One title per code, as RFC 9457 has it: the same for every occurrence of the problem type.
TITLES: Final[Mapping[ProblemCode, str]] = {
    "malformed_request": "Malformed request",
    "invalid_cursor": "Invalid cursor",
    "authentication_required": "Authentication required",
    "session_expired": "Session expired",
    "credentials_invalid": "Credentials not accepted",
    "reauthentication_required": "Recent sign-in needed",
    "permission_denied": "Permission denied",
    "passkey_required": "Passkey sign-in needed",
    "csrf_failed": "CSRF check failed",
    "recipient_locked": "Locked out",
    "download_limit_reached": "Download limit reached",
    "download_grant_exhausted": "Download grant used up",
    "self_approval_forbidden": "Can't approve your own transfer",
    "not_found": "Not found",
    "link_not_found": "Link not found",
    "method_not_allowed": "Method not allowed",
    "idempotency_conflict": "Idempotency key reused",
    "idempotency_in_progress": "Request still in progress",
    "invalid_state": "Not allowed in this state",
    "transfer_revoked": "Transfer revoked",
    "transfer_expired": "Transfer expired",
    "upload_request_revoked": "Upload request revoked",
    "upload_request_expired": "Upload request expired",
    "transfer_empty": "Transfer has no files",
    "upload_incomplete": "Upload incomplete",
    "file_not_shareable": "File can't be shared",
    "user_exists": "User already exists",
    "last_admin": "Last admin",
    "dlp_decision_changed": "DLP decision changed",
    "dlp_policy_conflict": "DLP policy conflict",
    "detector_in_use": "Detector in use",
    "no_eligible_approver": "No eligible approver",
    "approval_limit_reached": "Approval limit reached",
    "link_revoked": "Link revoked",
    "link_expired": "Link expired",
    "file_too_large": "File too large",
    "total_too_large": "Total too large",
    "storage_quota_exceeded": "Storage quota exceeded",
    "request_too_large": "Request too large",
    "unsupported_media_type": "Unsupported media type",
    "range_not_satisfiable": "Range not satisfiable",
    "validation_failed": "Validation failed",
    "expiry_out_of_range": "Expiry out of range",
    "recipient_domain_not_allowed": "Recipient domain not allowed",
    "recipient_undeliverable": "Recipient undeliverable",
    "too_many_files": "Too many files",
    "upload_size_mismatch": "Upload size mismatch",
    "code_invalid": "Code not accepted",
    "code_expired": "Code expired",
    "code_attempts_exhausted": "Code used up",
    "export_too_large": "Export too large",
    "justification_required": "Justification required",
    "approvers_insufficient": "Not enough approvers",
    "rate_limited": "Too many requests",
    "internal_error": "Internal error",
    "service_unavailable": "Service unavailable",
}

_INTERNAL_DETAIL: Final = "Something went wrong on our side. Quote the request ID if you report it."


def status_of(error: ProblemError) -> int:
    for kind in type(error).__mro__:
        if kind in STATUSES:
            return STATUSES[kind]
    raise TypeError(f"{type(error).__name__} has no HTTP status")


# ---- building the answer ----


def problem_response(
    status: int,
    code: ProblemCode,
    detail: str | None = None,
    *,
    field_errors: Sequence[FieldError] = (),
    current_state: str | None = None,
    attempts_remaining: int | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    """The problem document for one error, with the request ID of the request being answered."""
    problem = Problem(
        type=f"{TYPE_BASE}{code}",
        title=TITLES[code],
        status=status,
        detail=detail,
        code=code,
        request_id=request_id_var.get(),
        errors=[
            ValidationIssue(
                detail=item.detail,
                pointer=item.pointer,
                parameter=item.parameter,
                header=item.header,
            )
            for item in field_errors
        ]
        or None,
        current_state=current_state,
        attempts_remaining=attempts_remaining,
    )
    return JSONResponse(
        problem.model_dump(mode="json", exclude_none=True),
        status_code=status,
        headers=dict(headers or {}),
        media_type=MEDIA_TYPE,
    )


def _retry_after(seconds: int) -> dict[str, str]:
    return {"Retry-After": str(max(1, seconds))}  # whole seconds, at least 1 (contract)


def _headers_of(error: ProblemError) -> dict[str, str]:
    if isinstance(error, errors.RateLimited | errors.ServiceUnavailable):
        return _retry_after(error.retry_after)
    if isinstance(error, errors.Unauthenticated) and error.bearer:
        token_error = error.code in ("credentials_invalid", "session_expired")
        return {"WWW-Authenticate": 'Bearer error="invalid_token"' if token_error else "Bearer"}
    if isinstance(error, errors.RangeNotSatisfiable):
        return {"Content-Range": f"bytes */{error.size}"}
    return {}


# Each handler is registered for one exception class, so Starlette passes it only those; the
# casts say so to mypy, since Starlette types every handler as taking any Exception.


def problem_for(error: ProblemError) -> JSONResponse:
    """The answer to a `ProblemError`, for code outside the handlers, such as a middleware."""
    return problem_response(
        status_of(error),
        cast(ProblemCode, error.code),  # each class takes only its own codes
        error.detail,
        field_errors=error.errors,
        current_state=error.current_state,
        attempts_remaining=error.attempts_remaining,
        headers=_headers_of(error),
    )


async def _problem_error(request: Request, exc: Exception) -> JSONResponse:
    error = cast(ProblemError, exc)
    # For the middleware outside: a step-up 401 isn't a failed authentication (rate_limits.py).
    request.state.problem_code = error.code
    return problem_for(error)


# ---- requests FastAPI can't validate ----


def _is_json(content_type: str | None) -> bool:
    """Whether FastAPI reads the body as JSON: `application/json` or `application/*+json`."""
    if not content_type:
        return False
    message = email.message.Message()
    message["content-type"] = content_type
    subtype = message.get_content_subtype()
    return message.get_content_maintype() == "application" and (
        subtype == "json" or subtype.endswith("+json")
    )


def _field_error(error: Mapping[str, Any]) -> FieldError:
    """Pydantic's message, never the value sent: that could be a secret or someone's address."""
    location, *path = error["loc"]
    detail = str(error["msg"])
    if location == "body":
        return FieldError(detail, pointer=json_pointer(*path))
    name = str(path[0]) if path else ""
    if location == "header":
        return FieldError(detail, header=name)
    return FieldError(detail, parameter=name)


async def _validation_error(request: Request, exc: Exception) -> JSONResponse:
    found = list(cast(RequestValidationError, exc).errors())
    where = {error["loc"][0] for error in found}
    if "path" in where:
        # An ID that can't exist is as unknown as one that doesn't (NFR-12).
        return problem_response(404, "not_found")
    if where - {"body"}:
        return problem_response(
            400,
            "malformed_request",
            "A parameter or header isn't valid.",
            field_errors=[_field_error(error) for error in found if error["loc"][0] != "body"],
        )
    if any(error["type"] == "json_invalid" for error in found):
        return problem_response(400, "malformed_request", "The request body isn't valid JSON.")
    missing = all(error["type"] == "missing" and len(error["loc"]) == 1 for error in found)
    if not missing and not _is_json(request.headers.get("content-type")):
        return problem_response(
            415, "unsupported_media_type", "Send the request body as application/json."
        )
    return problem_response(
        422,
        "validation_failed",
        "The request body isn't valid.",
        field_errors=[_field_error(error) for error in found],
    )


# ---- what Starlette and FastAPI raise, and everything else ----


async def _http_exception(_: Request, exc: Exception) -> JSONResponse:
    error = cast(HTTPException, exc)
    code = _HTTP_EXCEPTION_CODES.get(error.status_code)
    if code is None:
        # Raised by our own code with a status outside the contract: a bug, so it fails closed.
        log.error("an HTTPException the contract lacks", extra={"status": error.status_code})
        return problem_response(500, "internal_error", _INTERNAL_DETAIL)
    # error.detail isn't used: it can be anything a library wrote. Its headers (Allow,
    # WWW-Authenticate) are part of the answer.
    return problem_response(error.status_code, code, headers=error.headers)


async def _unexpected(_: Request, __: Exception) -> JSONResponse:
    # Starlette sends this, then raises the exception again for the server to log.
    return problem_response(500, "internal_error", _INTERNAL_DETAIL)


# ---- the OpenAPI document ----

_DESCRIPTIONS: Final[Mapping[str, str]] = {
    "default": "An unexpected server error, as a problem document.",
}


def problem_responses(*statuses: int | Literal["default"]) -> dict[int | str, dict[str, Any]]:
    """The error answers of a route, for `responses=`: `problem_responses(401, 403, 404, 429)`.

    Each is a problem document, `default` included. Declare those the contract declares for the
    operation; the generated-spec check compares them (docs/api/README.md section 11.1).
    """
    responses: dict[int | str, dict[str, Any]] = {}
    for status in statuses:
        response: dict[str, Any] = {
            "description": _DESCRIPTIONS.get(str(status)) or HTTPStatus(int(status)).phrase,
            "content": {MEDIA_TYPE: {"schema": {"$ref": "#/components/schemas/Problem"}}},
        }
        if str(status) in ("429", "503"):
            response["headers"] = {
                "Retry-After": {
                    "description": "Seconds to wait before retrying.",
                    "schema": {"type": "integer", "minimum": 1},
                }
            }
        responses[status] = response
    return responses


_FASTAPI_422: Final = {
    "application/json": {"schema": {"$ref": "#/components/schemas/HTTPValidationError"}}
}


def _with_problems(document: dict[str, Any]) -> dict[str, Any]:
    """FastAPI adds a `422` of its own to every route with parameters or a body; no route sends it.

    With a body it becomes the `422 validation_failed` the route does send; without one it goes,
    since a bad parameter is a 400 or a 404. The `Problem` schemas are added once.
    """
    for path_item in document.get("paths", {}).values():
        for operation in path_item.values():
            responses = operation.get("responses", {}) if isinstance(operation, dict) else {}
            if responses.get("422", {}).get("content") != _FASTAPI_422:
                continue
            if "requestBody" in operation:
                responses["422"] = problem_responses(422)[422]
            else:
                del responses["422"]
    schemas = document.setdefault("components", {}).setdefault("schemas", {})
    for name in ("HTTPValidationError", "ValidationError"):
        schemas.pop(name, None)
    problem = Problem.model_json_schema(ref_template="#/components/schemas/{model}")
    schemas.update(problem.pop("$defs", {}))
    schemas["Problem"] = problem
    return document


def _openapi(app: FastAPI) -> Callable[[], dict[str, Any]]:
    generate = app.openapi

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            app.openapi_schema = _with_problems(generate())
        return app.openapi_schema

    return openapi


def register_error_handlers(app: FastAPI) -> None:
    """Answer every error as a problem document, and say so in the OpenAPI document."""
    app.add_exception_handler(ProblemError, _problem_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(HTTPException, _http_exception)
    app.add_exception_handler(Exception, _unexpected)
    app.openapi = _openapi(app)  # type: ignore[method-assign]
