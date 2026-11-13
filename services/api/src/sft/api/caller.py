"""The caller of a request, for `Depends(get_caller)` (ADR-0002; authn and authz 3, 6.1).

`get_caller` turns the `__Host-sft_session` cookie, or an API key (#215, authn and authz 5), into a
`Caller` and refuses everything else:

- **One credential per request.** A session cookie with an `Authorization` header gets
  `401 credentials_invalid`.
- **An API key** comes only as `Authorization: Bearer sft_<env>_<secret>_<check>`, never in a query
  string or a body. A malformed key, one of another environment or one whose check fails is
  refused before any database query; one no live key has (unknown, revoked, expired, its owner
  no longer an active admin, its tenant suspended) too, after the lookup. Both are
  `401 credentials_invalid` with the RFC 6750 `invalid_token` challenge, and count as failed
  authentications (`sft.service.api_keys`). A live key on a route for web sessions only (`/me`,
  sign-out) is `403 permission_denied`; on the others the service layer answers it (T-55).
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
from sft.api.dependencies import get_database
from sft.core.errors import Forbidden, Unauthenticated
from sft.data.audit import Origin
from sft.data.member_sessions import LiveSession
from sft.service import api_keys
from sft.service.caller import Caller, CallerKind
from sft.service.signin import SessionEnd, SignIn

SESSION_COOKIE: Final = "__Host-sft_session"
AUTH_COOKIE: Final = "__Host-sft_auth"
CSRF_HEADER: Final = "X-CSRF-Token"
UNSAFE_METHODS: Final = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_SAME_SITE: Final = frozenset({"same-origin", "same-site"})
KEY_CALLER: Final = "api_key_caller"
"""Where a request's resolved API key caller is kept (`request.state`), for its use record."""
_SESSION: Final = "member_session"
_BEARER: Final = "bearer"


@dataclass(frozen=True, slots=True)
class SessionContext:
    """What the sign-in routes need beyond the caller: the raw token, for its CSRF token, and the
    session as the request's check found it, which `GET /me` answers from (#161)."""

    caller: Caller
    token: str
    live: LiveSession


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


def key_environment(request: Request) -> api_keys.KeyEnvironment:
    """`API_KEY_ENVIRONMENT`: the one environment whose keys this API makes (authn-authz 5.1)."""
    environment = _environment(request)
    if environment is None:
        raise RuntimeError("this app was created without settings, so it makes no API keys")
    return environment


def _environment(request: Request) -> api_keys.KeyEnvironment | None:
    environment = getattr(request.app.state, "api_key_environment", None)
    return environment if environment in api_keys.KEY_ENVIRONMENTS else None


async def get_api_key_caller(request: Request) -> Caller:
    """The live API key the request's bearer token is, as a caller; `401 credentials_invalid`
    otherwise. Resolved once per request; never cached across requests (authn and authz 5.2)."""
    found = getattr(request.state, KEY_CALLER, None)
    if isinstance(found, Caller):
        return found
    header = request.headers.get("authorization") or ""
    scheme, _, raw = header.strip().partition(" ")
    key = None
    environment = _environment(request)  # an app without settings takes no key at all
    if scheme.lower() == _BEARER and environment is not None:
        key = api_keys.parse_key(raw.strip(), environment)
    if key is None:
        raise Unauthenticated("credentials_invalid", bearer=True)
    caller = await api_keys.resolve(get_database(request), key)
    if caller is None:
        raise Unauthenticated("credentials_invalid", bearer=True)
    setattr(request.state, KEY_CALLER, caller)
    return caller


async def get_session(request: Request) -> SessionContext:
    """The caller and the raw session token: the dependency behind `get_caller` for a member
    session, and of the routes for web sessions only."""
    token = request.cookies.get(SESSION_COOKIE)
    if request.headers.get("authorization") is not None:
        if token:
            raise Unauthenticated("credentials_invalid")
        await get_api_key_caller(request)
        raise Forbidden("permission_denied", "API keys can't use the web app's session.")
    found = getattr(request.state, _SESSION, None)
    if isinstance(found, SessionContext):
        return found
    if not token:
        raise Unauthenticated("authentication_required")
    service = sign_in_service(request)
    resolved = await service.resolve(token)
    if resolved is SessionEnd.UNKNOWN:
        raise Unauthenticated("credentials_invalid")
    if resolved is SessionEnd.ENDED:
        raise Unauthenticated("session_expired")
    caller, live = resolved
    if request.method in UNSAFE_METHODS:
        check_csrf(request, service, token)
    context = SessionContext(caller, token, live)
    setattr(request.state, _SESSION, context)
    return context


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
    check_origin(request, web_origin)
    if not csrf_valid(request.headers.get(CSRF_HEADER)):
        raise Forbidden("csrf_failed")


def check_origin(request: Request, web_origin: str) -> None:
    """The checks of authn and authz 3.4 that need no session: the origin, `Sec-Fetch-Site` and a
    JSON body. Alone for the public unsafe `startInvitationSignIn` (#239)."""
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


async def get_caller(request: Request) -> Caller:
    """The request's caller, a member session or an API key; 401 or 403 when it carries no
    credential the API accepts."""
    if request.headers.get("authorization") is not None and not request.cookies.get(SESSION_COOKIE):
        return await get_api_key_caller(request)
    return (await get_session(request)).caller


async def get_tenant_caller(caller: Annotated[Caller, Depends(get_caller)]) -> Caller:
    """A member session or an API key of a tenant; 401 for any other caller."""
    if caller.kind not in (CallerKind.MEMBER, CallerKind.API_KEY) or caller.tenant_id is None:
        raise Unauthenticated("authentication_required", bearer=caller.bearer)
    return caller
