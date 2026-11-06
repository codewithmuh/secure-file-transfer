"""The link and recipient-session operations of the contract: `resolveLink`,
`requestVerificationCode`, `createLinkSession`, `getLinkSession`, `endLinkSession` and
`listSessionFiles` (#179; docs/api/openapi.yaml, tags "Links and verification" and "Recipient
session"; authn and authz 4).

Routes only speak HTTP: the token in the body, the `__Host-sft_link` cookie, `X-Link-Session`, the
CSRF check of `endLinkSession` and the problem answers. The rules are `sft.service.links`'s.

- **The cookie** (authn and authz 3.1, 4.3). `__Host-sft_link` holds up to 10 session tokens joined
  by `.`, HttpOnly, Secure, Path=/, SameSite=Strict, host-only and with no Max-Age, exactly as
  the member session's `__Host-sft_session`. **Locally too** (the open point of #179): browsers
  treat `http://localhost` as a secure context and keep `Secure` and `__Host-` cookies there, as
  they do the member session's (#113), and scripted clients send them as `local/smoke.py` does,
  so nothing differs between the local stack and AWS.
- **`X-Link-Session`** names the session of every `/session` call. A missing or malformed one is
  `401 authentication_required`, never `400`, so the header is read from the request and declared
  for the OpenAPI document by hand.
- **No caching.** Every response here is `Cache-Control: no-store`: they carry a session, a CSRF
  token, an address or file names.
- **Rate limits** (abuse and rate limits 2.2): the link steps apply group A in the service,
  failing closed with `503`; the `/session` reads count per link session (group C), failing open.
"""

from __future__ import annotations

from typing import Annotated, Any, Final
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Request, Response

from sft.api.caller import check_unsafe_request, origin_of
from sft.api.dependencies import get_database, now_of
from sft.api.errors import problem_responses
from sft.api.link_schemas import (
    LinkResolution,
    LinkSession,
    LinkSessionCreate,
    LinkTokenRequest,
    SessionFileList,
    SessionFileOut,
    VerificationCodeRequested,
)
from sft.api.rate_limits import client_ip, rate_limit
from sft.core.errors import Unauthenticated
from sft.data.database import Database
from sft.service import links
from sft.service.caller import Caller
from sft.service.links import LinkCaller, LinkServices
from sft.service.rate_limits.limits import LINK_SESSION_READ

PREFIX: Final = "/v1"
LINK_COOKIE: Final = "__Host-sft_link"
SESSION_HEADER: Final = "X-Link-Session"
NO_STORE: Final = {"Cache-Control": "no-store"}

_SESSION_PARAMETER: Final[dict[str, Any]] = {
    "parameters": [
        {
            "name": SESSION_HEADER,
            "in": "header",
            "required": True,
            "schema": {"type": "string", "format": "uuid"},
        }
    ]
}

router = APIRouter(prefix=PREFIX)
DatabaseDep = Annotated[Database, Depends(get_database)]


def get_link_services(request: Request) -> LinkServices:
    services = getattr(request.app.state, "link_services", None)
    if not isinstance(services, LinkServices):
        raise RuntimeError("this app was created without settings, so it has no link services")
    return services


ServicesDep = Annotated[LinkServices, Depends(get_link_services)]


def link_cookie(request: Request) -> list[str]:
    """The session tokens of this browser's `__Host-sft_link` cookie."""
    return links.cookie_tokens(request.cookies.get(LINK_COOKIE))


_cookie = link_cookie


def _set_cookie(response: Response, tokens: tuple[str, ...] | list[str]) -> None:
    if not tokens:
        response.delete_cookie(LINK_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
        return
    response.set_cookie(
        LINK_COOKIE,
        links.cookie_value(tokens),
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )


async def get_link_session(request: Request, database: DatabaseDep) -> LinkCaller:
    """The link session `X-Link-Session` names, from this browser's cookie; 401 or 410 otherwise.
    Unsafe methods also pass the CSRF checks with that session's own token."""
    raw = request.headers.get(SESSION_HEADER)
    try:
        session_id = None if raw is None else UUID(raw)
    except ValueError:
        raise Unauthenticated("authentication_required") from None
    if request.headers.get("authorization") is not None:
        raise Unauthenticated("credentials_invalid")
    link = await links.session_caller(database, _cookie(request), session_id, now=now_of(request))
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        services = get_link_services(request)
        origin = request.app.state.web_origin
        check_unsafe_request(
            request, origin, lambda presented: services.csrf.verify(link.token, presented)
        )
    return link


async def get_link_session_caller(
    link: Annotated[LinkCaller, Depends(get_link_session)],
) -> Caller:
    """The session's caller, for its group C limit (per link session)."""
    return link.caller


LinkDep = Annotated[LinkCaller, Depends(get_link_session)]
SESSION_LIMITS: Final = rate_limit(LINK_SESSION_READ, caller=get_link_session_caller)


# ---- the link steps ----


@router.post(
    "/links/resolve",
    operation_id="resolveLink",
    response_model=LinkResolution,
    response_model_exclude_unset=True,
    summary="Resolve a link token",
    tags=["Links and verification"],
    responses=problem_responses(400, 404, 410, 422, 429, 503),
)
async def resolve_link(
    body: LinkTokenRequest,
    request: Request,
    response: Response,
    database: DatabaseDep,
    services: ServicesDep,
) -> LinkResolution:
    """What the link is and whether this browser has verified it already (FR-14)."""
    resolution = await links.resolve_link(
        database,
        services,
        body.token,
        cookie=_cookie(request),
        ip=client_ip(request),
        now=now_of(request),
    )
    response.headers.update(NO_STORE)
    return LinkResolution.of(resolution)


@router.post(
    "/links/codes",
    operation_id="requestVerificationCode",
    status_code=202,
    response_model=VerificationCodeRequested,
    summary="Email a verification code",
    tags=["Links and verification"],
    responses=problem_responses(400, 403, 404, 410, 422, 429, 503),
)
async def request_verification_code(
    body: LinkTokenRequest,
    request: Request,
    response: Response,
    database: DatabaseDep,
    services: ServicesDep,
) -> VerificationCodeRequested:
    """A code is on its way to the invited address (FR-14, NFR-14)."""
    await links.request_code(
        database,
        services,
        body.token,
        ip=client_ip(request),
        origin=origin_of(request),
        now=now_of(request),
    )
    response.headers.update(NO_STORE)
    return VerificationCodeRequested(
        code_valid_for_seconds=links.CODE_VALID_FOR_SECONDS, max_attempts=links.MAX_ATTEMPTS
    )


@router.post(
    "/links/sessions",
    operation_id="createLinkSession",
    status_code=201,
    response_model=LinkSession,
    response_model_exclude_unset=True,
    summary="Verify a code and start a link session",
    tags=["Links and verification"],
    responses=problem_responses(400, 403, 404, 410, 422, 429, 503),
)
async def create_link_session(
    body: LinkSessionCreate,
    request: Request,
    response: Response,
    database: DatabaseDep,
    services: ServicesDep,
) -> LinkSession:
    """Check the code and start a link session bound to this browser (FR-14, FR-15)."""
    created = await links.create_session(
        database,
        services,
        body.token,
        body.code,
        cookie=_cookie(request),
        ip=client_ip(request),
        origin=origin_of(request),
        now=now_of(request),
    )
    _set_cookie(response, created.cookie)
    response.headers.update(NO_STORE)
    return LinkSession.of(created.view)


# ---- the session ----


@router.get(
    "/session",
    operation_id="getLinkSession",
    response_model=LinkSession,
    response_model_exclude_unset=True,
    summary="Get the current link session",
    tags=["Recipient session"],
    dependencies=[SESSION_LIMITS],
    responses=problem_responses(401, 403, 410, 429),
    openapi_extra=_SESSION_PARAMETER,
)
async def get_link_session_route(
    response: Response, link: LinkDep, database: DatabaseDep, services: ServicesDep
) -> LinkSession:
    """The verified recipient's transfer, and the session's CSRF token (FR-14, FR-15)."""
    view = await links.get_session(database, services, link)
    response.headers.update(NO_STORE)
    return LinkSession.of(view)


@router.delete(
    "/session",
    operation_id="endLinkSession",
    status_code=204,
    response_class=Response,
    summary="End the current link session",
    tags=["Recipient session"],
    dependencies=[SESSION_LIMITS],
    responses=problem_responses(401, 403, 429),
    openapi_extra=_SESSION_PARAMETER,
)
async def end_link_session(request: Request, link: LinkDep, database: DatabaseDep) -> Response:
    """End this session; the browser's other link sessions carry on (FR-15)."""
    await links.end_session(database, link, origin=origin_of(request))
    response = Response(status_code=204, headers=NO_STORE)
    _set_cookie(response, [t for t in _cookie(request) if t != link.token])
    return response


@router.get(
    "/session/files",
    operation_id="listSessionFiles",
    response_model=SessionFileList,
    response_model_exclude_unset=True,
    summary="List the files of the session",
    tags=["Recipient session"],
    dependencies=[SESSION_LIMITS],
    responses=problem_responses(401, 403, 410, 429),
    openapi_extra=_SESSION_PARAMETER,
)
async def list_session_files(
    response: Response, link: LinkDep, database: DatabaseDep
) -> SessionFileList:
    """The transfer's shareable files, with this recipient's downloads (FR-6, FR-16, FR-18)."""
    found = await links.session_files(database, link)
    response.headers.update(NO_STORE)
    return SessionFileList(items=[SessionFileOut.of(f) for f in found])


def register(app: FastAPI) -> None:
    """Add the link and session routes to the public app."""
    app.include_router(router)
