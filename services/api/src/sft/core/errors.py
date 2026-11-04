"""The errors the API answers with, as exceptions any layer can raise (docs/api/README.md 3).

Service code raises one of these when a request can't succeed: `NotFound("not_found")`,
`Conflict("invalid_state", current_state="cancelled")`, `RateLimited(retry_after=30)`. The API
layer (`sft.api.errors`) turns each into an RFC 9457 problem with the right HTTP status, title and
headers. Nothing here knows about HTTP: a class names the kind of failure, and its `code` is the
contract's stable `ProblemCode`, which clients branch on.

Each class takes only the codes of its kind, as a `Literal`, so mypy rejects a code that belongs to
another kind or isn't in the contract. `tests/test_errors.py` checks the codes against the contract
and the README table, so they can't drift apart.

They live in core, the lowest layer, so the data layer and the workers can raise them too. Their
names say what went wrong, as `raise NotFound(...)` reads, without an `Error` suffix.
"""

# ruff: noqa: N818

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import ClassVar, Literal, get_args

InvalidRequestCode = Literal["malformed_request", "invalid_cursor"]
UnauthenticatedCode = Literal[
    "authentication_required", "session_expired", "credentials_invalid", "reauthentication_required"
]
ForbiddenCode = Literal[
    "permission_denied",
    "passkey_required",
    "csrf_failed",
    "recipient_locked",
    "download_limit_reached",
    "download_grant_exhausted",
    "self_approval_forbidden",
]
NotFoundCode = Literal["not_found", "link_not_found"]
MethodNotAllowedCode = Literal["method_not_allowed"]
ConflictCode = Literal[
    "idempotency_conflict",
    "idempotency_in_progress",
    "invalid_state",
    "transfer_revoked",
    "transfer_expired",
    "upload_request_revoked",
    "upload_request_expired",
    "transfer_empty",
    "upload_incomplete",
    "file_not_shareable",
    "user_exists",
    "last_admin",
    "dlp_decision_changed",
    "dlp_policy_conflict",
    "detector_in_use",
    "no_eligible_approver",
    "approval_limit_reached",
]
GoneCode = Literal["link_revoked", "link_expired"]
TooLargeCode = Literal[
    "file_too_large", "total_too_large", "storage_quota_exceeded", "request_too_large"
]
UnsupportedMediaTypeCode = Literal["unsupported_media_type"]
RangeNotSatisfiableCode = Literal["range_not_satisfiable"]
UnprocessableCode = Literal[
    "validation_failed",
    "expiry_out_of_range",
    "recipient_domain_not_allowed",
    "recipient_undeliverable",
    "too_many_files",
    "upload_size_mismatch",
    "code_invalid",
    "code_expired",
    "code_attempts_exhausted",
    "export_too_large",
    "justification_required",
    "approvers_insufficient",
]
RateLimitedCode = Literal["rate_limited"]
InternalErrorCode = Literal["internal_error"]
ServiceUnavailableCode = Literal["service_unavailable"]

# Every code of the contract's `ProblemCode` enum.
ProblemCode = Literal[
    InvalidRequestCode,
    UnauthenticatedCode,
    ForbiddenCode,
    NotFoundCode,
    MethodNotAllowedCode,
    ConflictCode,
    GoneCode,
    TooLargeCode,
    UnsupportedMediaTypeCode,
    RangeNotSatisfiableCode,
    UnprocessableCode,
    RateLimitedCode,
    InternalErrorCode,
    ServiceUnavailableCode,
]
PROBLEM_CODES: tuple[ProblemCode, ...] = get_args(ProblemCode)


def json_pointer(*parts: str | int) -> str:
    """A JSON Pointer into the request body, as the contract writes it: `#/recipients/3`."""
    escaped = (str(part).replace("~", "~0").replace("/", "~1") for part in parts)
    return "#" + "".join(f"/{part}" for part in escaped)


@dataclass(frozen=True, slots=True)
class FieldError:
    """One entry of a problem's `errors`: what is wrong, and where (one of the three, or none)."""

    detail: str
    pointer: str | None = None  # in the body, from json_pointer()
    parameter: str | None = None  # a query, path or cookie parameter
    header: str | None = None

    def __post_init__(self) -> None:
        if sum(where is not None for where in (self.pointer, self.parameter, self.header)) > 1:
            raise ValueError("a field error names one place: a pointer, a parameter or a header")


class ProblemError(Exception):
    """An error the API answers with a problem document. Raise a subclass, never this."""

    codes: ClassVar[tuple[str, ...]] = ()

    def __init__(self, code: str, detail: str | None = None) -> None:
        if code not in self.codes:
            raise ValueError(f"{type(self).__name__} doesn't take the code {code!r}")
        super().__init__(code if detail is None else f"{code}: {detail}")
        self.code: str = code
        # For people; shown to the caller, so it never names another tenant, address or key.
        self.detail = detail
        self.errors: tuple[FieldError, ...] = ()
        self.current_state: str | None = None
        self.attempts_remaining: int | None = None


class InvalidRequest(ProblemError):
    """The request can't be parsed: a malformed body, parameter or header, or a bad cursor."""

    codes = get_args(InvalidRequestCode)

    def __init__(
        self,
        code: InvalidRequestCode,
        detail: str | None = None,
        *,
        errors: Sequence[FieldError] = (),
    ) -> None:
        super().__init__(code, detail)
        self.errors = tuple(errors)


class Unauthenticated(ProblemError):
    """No valid credentials, or a sign-in too old for the operation (step-up).

    `bearer` is for callers that sent a bearer token, an API key or an operator token: the answer
    then carries the RFC 6750 challenge.
    """

    codes = get_args(UnauthenticatedCode)

    def __init__(
        self, code: UnauthenticatedCode, detail: str | None = None, *, bearer: bool = False
    ) -> None:
        super().__init__(code, detail)
        self.bearer = bearer


class Forbidden(ProblemError):
    """The caller is known but may not do this."""

    codes = get_args(ForbiddenCode)

    def __init__(self, code: ForbiddenCode, detail: str | None = None) -> None:
        super().__init__(code, detail)


class NotFound(ProblemError):
    """Nothing with this ID or token is visible to the caller, whether or not it exists (NFR-12)."""

    codes = get_args(NotFoundCode)

    def __init__(self, code: NotFoundCode = "not_found", detail: str | None = None) -> None:
        super().__init__(code, detail)


class Conflict(ProblemError):
    """The request conflicts with the item's current state or with an earlier request."""

    codes = get_args(ConflictCode)

    def __init__(
        self, code: ConflictCode, detail: str | None = None, *, current_state: str | None = None
    ) -> None:
        super().__init__(code, detail)
        self.current_state = current_state


class Gone(ProblemError):
    """The link belongs to a transfer or upload request that was revoked or has expired."""

    codes = get_args(GoneCode)

    def __init__(self, code: GoneCode, detail: str | None = None) -> None:
        super().__init__(code, detail)


class TooLarge(ProblemError):
    """A size, a total, the storage quota or the request body is over its limit."""

    codes = get_args(TooLargeCode)

    def __init__(self, code: TooLargeCode, detail: str | None = None) -> None:
        super().__init__(code, detail)


class UnsupportedMediaType(ProblemError):
    """The body is in a media type the operation doesn't take."""

    codes = get_args(UnsupportedMediaTypeCode)

    def __init__(self, detail: str | None = None) -> None:
        super().__init__("unsupported_media_type", detail)


class RangeNotSatisfiable(ProblemError):
    """The `Range` of a download isn't one range of this file. `size` is the file's, in bytes."""

    codes = get_args(RangeNotSatisfiableCode)

    def __init__(self, size: int, detail: str | None = None) -> None:
        super().__init__("range_not_satisfiable", detail)
        self.size = size


class Unprocessable(ProblemError):
    """The request is well formed but breaks a rule. `validation_failed` lists each in `errors`."""

    codes = get_args(UnprocessableCode)

    def __init__(
        self,
        code: UnprocessableCode,
        detail: str | None = None,
        *,
        errors: Sequence[FieldError] = (),
        attempts_remaining: int | None = None,
    ) -> None:
        super().__init__(code, detail)
        self.errors = tuple(errors)
        self.attempts_remaining = attempts_remaining


class RateLimited(ProblemError):
    """A rate limit was reached (NFR-14). `retry_after` is when the limiting key next admits one."""

    codes = get_args(RateLimitedCode)

    def __init__(self, retry_after: int, detail: str | None = None) -> None:
        super().__init__("rate_limited", detail)
        self.retry_after = retry_after


class ServiceUnavailable(ProblemError):
    """A dependency the call can't do without is unavailable. Retry after `retry_after` seconds."""

    codes = get_args(ServiceUnavailableCode)

    def __init__(self, retry_after: int, detail: str | None = None) -> None:
        super().__init__("service_unavailable", detail)
        self.retry_after = retry_after
