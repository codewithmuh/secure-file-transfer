"""Problem responses for the errors of `sft.core.errors` (docs/api/README.md section 3).

This is the part of issue #96's `sft.api.errors` that rate limiting needs: `429` and `503`. At
merge #96's module, which handles every error, replaces this one; `register_error_handlers` stays.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from sft.core.errors import ProblemError, RateLimited, ServiceUnavailable
from sft.core.logs import request_id_var

PROBLEM_TYPE = "https://secure-file-transfer.example/problems/{code}"

_STATUS: dict[type[ProblemError], tuple[int, str]] = {
    RateLimited: (429, "Too many requests"),
    ServiceUnavailable: (503, "Service unavailable"),
}


async def _problem(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RateLimited | ServiceUnavailable)  # noqa: S101 - registered for these
    status, title = next(value for cls, value in _STATUS.items() if isinstance(exc, cls))
    body: dict[str, object] = {
        "type": PROBLEM_TYPE.format(code=exc.code),
        "title": title,
        "status": status,
        "code": exc.code,
        "request_id": request_id_var.get(),
    }
    if exc.detail is not None:
        body["detail"] = exc.detail
    return JSONResponse(
        body,
        status_code=status,
        media_type="application/problem+json",
        headers={"Retry-After": str(exc.retry_after)},
    )


def register_error_handlers(app: FastAPI) -> None:
    """Answer each error of `sft.core.errors` with its Problem document."""
    app.add_exception_handler(RateLimited, _problem)
    app.add_exception_handler(ServiceUnavailable, _problem)
