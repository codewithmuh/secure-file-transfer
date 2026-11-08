"""The sign-in routes and `GET /me`: startSignIn, completeSignIn, signOut, getCurrentMember.

The operations are the contract's (docs/api/openapi.yaml); the rules are in authentication and
authorization 2.4 and 3, and the work is `sft.service.signin`'s. This module only speaks HTTP:
cookies, redirects and problem responses (`sft.api.errors`).

- **Cookies** (3.1). `__Host-sft_auth` (SameSite=Lax, 10 minutes) finds the pre-auth record;
  `__Host-sft_session` (SameSite=Strict, no Max-Age) holds the session token. Both are HttpOnly,
  Secure, Path=/ and host-only. The web app never sees either value.
- **No caching.** Every response here is `Cache-Control: no-store`: they carry cookies, a CSRF
  token or a member's details.
- **Outages.** Sign-in fails closed: when the sign-in state store, the user pool or the database
  can't be reached, start and callback answer `503` with `Retry-After`, and the callback still
  clears `__Host-sft_auth`.
- **Rate limits** (abuse and rate limits 2.2): 60 sign-in starts and 60 callbacks per IP a minute
  (group B), failing closed with `503`; `GET /me` and sign-out count against the caller's and the
  tenant's budget (group H), like every other member operation.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Final, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, FastAPI, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from sft.api.caller import (
    AUTH_COOKIE,
    SESSION_COOKIE,
    SessionContext,
    get_session,
    get_tenant_caller,
    origin_of,
    sign_in_service,
)
from sft.api.errors import problem_for, problem_responses
from sft.api.members import UserOut
from sft.api.rate_limits import rate_limit
from sft.core.errors import FieldError, ServiceUnavailable, Unprocessable
from sft.core.settings import Settings
from sft.data.counters import ValkeyIam
from sft.data.database import Database
from sft.data.models import Role
from sft.data.signin_state import LIFETIME_SECONDS, StateStoreUnavailableError, ValkeyStateStore
from sft.service.caller import AuthMethod
from sft.service.csrf import CsrfKeyring
from sft.service.oidc import OidcClient
from sft.service.rate_limits.limits import SIGN_IN_CALLBACK, SIGN_IN_START, TENANT_OPERATION
from sft.service.signin import SignIn, SignInConfig, SignInMethod, SignInUnavailableError

PREFIX: Final = "/v1"
NO_STORE: Final = {"Cache-Control": "no-store"}
RETRY_AFTER_SECONDS: Final = 5
"""The wait a sign-in that can't reach the state store or the pool tells the browser."""

SessionDep = Annotated[SessionContext, Depends(get_session)]
MEMBER_LIMITS: Final = rate_limit(TENANT_OPERATION, caller=get_tenant_caller)

router = APIRouter(prefix=PREFIX)


# ---- schemas, as the contract's ----

CsrfToken = Annotated[
    str, Field(min_length=45, max_length=108, pattern=r"^[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{43}$")
]
Uri = Annotated[str, Field(json_schema_extra={"format": "uri"})]


class TenantOut(BaseModel):
    """The contract's `Tenant`."""

    model_config = ConfigDict(title="Tenant")

    id: UUID
    name: str
    status: Literal["active", "suspended"]
    created_at: datetime


class CurrentSession(BaseModel):
    auth_method: AuthMethod
    auth_time: datetime
    effective_role: Role
    expires_at: datetime


class CurrentMember(BaseModel):
    user: UserOut
    tenant: TenantOut
    session: CurrentSession
    csrf_token: CsrfToken


class SignOutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    all_sessions: bool = False


class SignOutResult(BaseModel):
    logout_url: Uri


# ---- cookies ----


def _set_cookie(response: Response, name: str, value: str, *, lax: bool = False) -> None:
    response.set_cookie(
        name,
        value,
        max_age=LIFETIME_SECONDS if lax else None,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax" if lax else "strict",
    )


def _clear_cookie(response: Response, name: str, *, lax: bool = False) -> None:
    response.delete_cookie(
        name, path="/", secure=True, httponly=True, samesite="lax" if lax else "strict"
    )


def _redirect(location: str) -> RedirectResponse:
    return RedirectResponse(location, status_code=302, headers=NO_STORE)


def _unavailable() -> ServiceUnavailable:
    return ServiceUnavailable(RETRY_AFTER_SECONDS, "Sign-in is unavailable. Try again shortly.")


# ---- routes ----


@router.get(
    "/auth/sign-in",
    operation_id="startSignIn",
    status_code=302,
    response_class=RedirectResponse,
    summary="Start a member sign-in",
    tags=["Sign-in"],
    dependencies=[rate_limit(SIGN_IN_START)],
    responses=problem_responses(400, 422, 429, 503, "default"),
)
async def start_sign_in(
    request: Request,
    method: Annotated[Literal["sso", "local"], Query()],
    sso_domain: Annotated[
        str | None, Query(max_length=253, json_schema_extra={"format": "hostname"})
    ] = None,
    return_to: Annotated[str, Query(max_length=512)] = "/",
) -> RedirectResponse:
    """Store the pre-auth record and redirect to the user pool."""
    if method == "sso" and not sso_domain:
        detail = "sso_domain is required for method=sso."
        raise Unprocessable(
            "validation_failed", detail, errors=[FieldError(detail, parameter="sso_domain")]
        )
    service = sign_in_service(request)
    try:
        started = await service.start(method=SignInMethod(method), return_to=return_to)
    except (StateStoreUnavailableError, SignInUnavailableError) as exc:
        raise _unavailable() from exc
    response = _redirect(started.location)
    _set_cookie(response, AUTH_COOKIE, started.cookie, lax=True)
    return response


@router.get(
    "/auth/callback",
    operation_id="completeSignIn",
    status_code=302,
    response_class=RedirectResponse,
    summary="Complete a member sign-in",
    tags=["Sign-in"],
    dependencies=[rate_limit(SIGN_IN_CALLBACK)],
    responses=problem_responses(429, 503, "default"),
)
async def complete_sign_in(
    request: Request,
    code: Annotated[str | None, Query(max_length=2048)] = None,
    state: Annotated[str | None, Query(max_length=512)] = None,
    error: Annotated[str | None, Query(max_length=128)] = None,
    error_description: Annotated[str | None, Query(max_length=1024)] = None,
) -> Response:
    """A new session cookie, or the web app's sign-in page with an error."""
    del error_description  # the provider's text is never shown or audited
    service = sign_in_service(request)
    try:
        completed = await service.complete(
            cookie=request.cookies.get(AUTH_COOKIE),
            code=code,
            state=state,
            error=error,
            previous_session=request.cookies.get(SESSION_COOKIE),
            origin=origin_of(request),
        )
    except (StateStoreUnavailableError, SignInUnavailableError):
        # Fail closed, and drop the pre-auth cookie: its record is used up either way.
        unavailable = problem_for(_unavailable())
        _clear_cookie(unavailable, AUTH_COOKIE, lax=True)
        unavailable.headers.update(NO_STORE)
        return unavailable
    response = _redirect(completed.location)
    _clear_cookie(response, AUTH_COOKIE, lax=True)
    if completed.session_token is not None:
        _set_cookie(response, SESSION_COOKIE, completed.session_token)
    return response


@router.post(
    "/auth/sign-out",
    operation_id="signOut",
    response_model=SignOutResult,
    summary="Sign out",
    tags=["Sign-in"],
    dependencies=[MEMBER_LIMITS],
    responses=problem_responses(400, 401, 403, 422, 429),
)
async def sign_out(
    request: Request,
    response: Response,
    context: SessionDep,
    body: SignOutRequest | None = None,
) -> SignOutResult:
    """Revoke this session (or all of the member's), clear the cookie, return the logout URL."""
    service = sign_in_service(request)
    all_sessions = body.all_sessions if body is not None else False
    logout_url = await service.sign_out(
        context.caller, all_sessions=all_sessions, origin=origin_of(request)
    )
    _clear_cookie(response, SESSION_COOKIE)
    response.headers.update(NO_STORE)
    return SignOutResult(logout_url=logout_url)


@router.get(
    "/me",
    operation_id="getCurrentMember",
    response_model=CurrentMember,
    summary="Get the signed-in member",
    tags=["Account"],
    dependencies=[MEMBER_LIMITS],
    responses=problem_responses(401, 403, 429),
)
async def get_current_member(
    request: Request, response: Response, context: SessionDep
) -> CurrentMember:
    """The signed-in member, their tenant, the session and its CSRF token."""
    service = sign_in_service(request)
    member = await service.current_member(context.caller)
    response.headers.update(NO_STORE)
    caller = context.caller
    tenant = member.tenant
    return CurrentMember(
        user=UserOut.of(member.user),
        tenant=TenantOut(
            id=tenant.id,
            name=tenant.name,
            status=tenant.status,  # type: ignore[arg-type] # the table's CHECK allows only these
            created_at=tenant.created_at,
        ),
        session=CurrentSession(
            auth_method=member.auth_method,
            auth_time=member.auth_time,
            effective_role=Role.ADMIN if caller.acts_as_admin else Role.MEMBER,
            expires_at=member.expires_at,
        ),
        csrf_token=service.csrf_token(context.token),
    )


def open_sign_in(
    settings: Settings, database: Database, csrf: CsrfKeyring, *, iam: ValkeyIam | None = None
) -> SignIn:
    """The sign-in service for the app's lifespan: nothing connects until the first sign-in. The
    CSRF keyring is the app's, so a refresh reaches sign-in too."""
    oidc = OidcClient(
        issuer=settings.oidc_issuer,
        client_id=settings.oidc_client_id,
        client_secret=settings.oidc_client_secret.get_secret_value(),
        redirect_uri=settings.oidc_redirect_uri,
        discovery_url=settings.oidc_discovery_url,
        revocation_url=settings.oidc_revocation_url,
    )
    states = ValkeyStateStore.from_url(settings.valkey_url.get_secret_value(), iam=iam)
    config = SignInConfig(
        provider_name=settings.oidc_provider_name,
        web_origin=settings.web_origin,
        logout_url=settings.oidc_logout_url,
        passkey_rule=settings.admin_passkey_rule,
    )
    return SignIn(database, oidc, states, csrf, config)


def register(app: FastAPI, settings: Settings | None) -> None:
    """The sign-in routes, and CORS for the web app's origin only, with credentials, never `*`
    (authn and authz 3.4)."""
    app.include_router(router)
    if settings is not None:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[settings.web_origin],
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token", "X-Link-Session", "Idempotency-Key"],
            expose_headers=["X-Request-Id", "Retry-After", "Location"],
            max_age=600,
        )
