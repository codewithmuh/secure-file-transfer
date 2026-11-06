"""The caller of a request, for `Depends(get_caller)` (ADR-0002; authn and authz 3, 6.1).

`get_caller` turns the `__Host-sft_session` cookie into a `Caller` and refuses everything else:

- **One credential per request.** A session cookie with an `Authorization` header gets
  `401 credentials_invalid`. A bearer alone gets `401 credentials_invalid` too, with the RFC 6750
  `invalid_token` challenge: no bearer token is valid until API keys exist (M5).
- **The session** must be live (authn and authz 3.2). One that has ended gets
  `401 session_expired`; a cookie no session ever had gets `401 credentials_invalid`; no cookie
  at all is `401 authentication_required`. Only `credentials_invalid` counts as a failed
  authentication against the client's IP (abuse and rate limits 2.2, H; `sft.api.rate_limits`).
- **CSRF on unsafe methods** (3.4): `Origin` must be the web app's origin, `Sec-Fetch-Site`, when
  sent, `same-origin` or `same-site`, a body must be JSON, and `X-CSRF-Token` must be the token
  derived from this session's token. Otherwise `403 csrf_failed`.

It decides nothing about permissions: the service layer checks the caller (6.1). The cookie and
header are read from the request, not declared as parameters, so the generated OpenAPI document
shows them only as the contract's security schemes.

`get_tenant_caller` is the caller of the tenant API, a member session or an API key: what its
routes' rate limits count per (abuse and rate limits 2.2, H). Any other credential is one those
routes don't read, so it is `401` too, before a limit runs, as `authorize` would answer it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import Depends, Request

from sft.api.client_ip import client_address
from sft.core.errors import Forbidden, Unauthenticated
from sft.data.audit import Origin
from sft.service.caller import Caller, CallerKind
from sft.service.signin import SessionEnd, SignIn

SESSION_COOKIE: Final = "__Host-sft_session"
AUTH_COOKIE: Final = "__Host-sft_auth"
CSRF_HEADER: Final = "X-CSRF-Token"
UNSAFE_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_SAME_SITE: Final = frozenset({"same-origin", "same-site"})


@dataclass(frozen=True, slots=True)
class SessionContext:
    """What the sign-in routes need beyond the caller: the raw token, for its CSRF token."""

    caller: Caller
    token: str


def sign_in_service(request: Request) -> SignIn:
    """The process's sign-in service, opened by the app's lifespan."""
    service = getattr(request.app.state, "sign_in", None)
    if not isinstance(service, SignIn):
        raise RuntimeError("this app was created without settings, so it has no sign-in")
    return service


def origin_of(request: Request) -> Origin:
    """FR-27's source IP and user agent: the client's address by ADR-0002's rule, as rate limits
    read it."""
    source = client_address(request, getattr(request.app.state, "trusted_proxies", ()))
    return Origin(source_ip=source, user_agent=request.headers.get("user-agent"))


async def get_session(request: Request) -> SessionContext:
    """The caller and the raw session token: the dependency behind `get_caller`."""
    token = request.cookies.get(SESSION_COOKIE)
    if request.headers.get("authorization") is not None:
        raise Unauthenticated("credentials_invalid", bearer=not token)
    if not token:
        raise Unauthenticated("authentication_required")
    service = sign_in_service(request)
    resolved = await service.resolve(token)
    if resolved is SessionEnd.UNKNOWN:
        raise Unauthenticated("credentials_invalid")
    if resolved is SessionEnd.ENDED:
        raise Unauthenticated("session_expired")
    caller, _ = resolved
    if request.method in UNSAFE_METHODS:
        check_csrf(request, service, token)
    return SessionContext(caller, token)


def check_csrf(request: Request, service: SignIn, token: str) -> None:
    """The checks of authn and authz 3.4 on an unsafe request of a member session."""
    check_unsafe_request(
        request,
        service.config.web_origin,
        lambda presented: service.csrf_valid(token, presented),
    )


def check_unsafe_request(
    request: Request, web_origin: str, csrf_valid: Callable[[str | None], bool]
) -> None:
    """The checks of authn and authz 3.4 on an unsafe request of a cookie session, a member's or
    a link session's: the origin, `Sec-Fetch-Site`, a JSON body and the session's CSRF token."""
    headers = request.headers
    if headers.get("origin") != web_origin:
        raise Forbidden("csrf_failed")
    fetch_site = headers.get("sec-fetch-site")
    if fetch_site is not None and fetch_site not in _SAME_SITE:
        raise Forbidden("csrf_failed")
    has_body = headers.get("content-length", "0") != "0" or "transfer-encoding" in headers
    media_type = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if has_body and media_type != "application/json":
        raise Forbidden("csrf_failed")
    if not csrf_valid(headers.get(CSRF_HEADER)):
        raise Forbidden("csrf_failed")


async def get_caller(session: Annotated[SessionContext, Depends(get_session)]) -> Caller:
    """The request's caller; 401 or 403 when it carries no credential the API accepts."""
    return session.caller


async def get_tenant_caller(caller: Annotated[Caller, Depends(get_caller)]) -> Caller:
    """A member session or an API key of a tenant; 401 for any other caller."""
    if caller.kind not in (CallerKind.MEMBER, CallerKind.API_KEY) or caller.tenant_id is None:
        raise Unauthenticated("authentication_required", bearer=caller.bearer)
    return caller
