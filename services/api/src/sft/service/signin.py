"""Member sign-in, sessions and sign-out (ADR-0016; authentication and authorization 2.4 and 3).

`SignIn` holds the parts: the database, the OIDC client of the environment's pool, the sign-in
state store and the CSRF keyring. The API's routes call it; it knows nothing of HTTP.

**Start** (`start`). Picks the connection: the pool's, found by its `provider_name`. A tenant's
SSO provider, found by a proven email domain, arrives with SSO (M6); until then `method=sso`
falls back to local sign-in, as the contract allows. Stores the pre-auth record and returns the
cookie value and the URL of the pool's authorization endpoint.

**Complete** (`complete`). Takes the pre-auth record once, compares `state`, exchanges the code,
revokes the refresh token and validates the ID token. Then it resolves the identity from rows,
never from a claim: the connection is the one the record chose, and, for SSO, the provider the
token's `identities` claim names must be that connection; the identity is `(connection, subject)`
and gives the user and the tenant. A local identity's user must equal `cognito:username`. In the
tenant's scope it checks the tenant and the user, activates an invited user, creates the session
under the cap of 10, and audits the sign-in, in one transaction. Every refusal is audited with its
reason: in the tenant's log when the identity is known, otherwise as a platform event, since there
is no tenant (authn and authz 2.4). The caller only learns `sign_in_failed`.

**Resolve** (`resolve`). The per-request check of 3.2, through the member session lookup, then in
the session's tenant: live, not idle, user and tenant active, role from `users`.

**Sign out** (`sign_out`). Revokes the session, or every session of the member, audited.
"""

from __future__ import annotations

import hmac
import logging
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final
from urllib.parse import urlencode
from uuid import UUID

from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError

from sft.core.errors import Unauthenticated
from sft.data import audit, member_sessions
from sft.data.audit import Actor, Origin, Target
from sft.data.database import Database
from sft.data.identities import Connection, Identity, find_connection, find_identity
from sft.data.member_sessions import LiveSession, RevokedReason
from sft.data.models import ActorType, Outcome, Role, Tenant, User, UserStatus
from sft.data.scope import Scope
from sft.data.signin_state import PendingSignIn, StateStore
from sft.data.tenants import get_tenant
from sft.data.users import accept_invitation, get_user
from sft.service.caller import AuthMethod, Caller, CallerKind
from sft.service.csrf import CsrfKeyring
from sft.service.oidc import IdToken, OidcClient, OidcError, Pkce
from sft.service.permissions import authorize

log = logging.getLogger(__name__)

SESSION_TARGET: Final = "member_session"
LOCAL_IDENTITY_PROVIDER: Final = "COGNITO"
"""Cognito's name for its own sign-in, sent as `identity_provider` (authn and authz 2.4)."""
FRESH_SIGN_IN: Final = timedelta(minutes=11)
"""How old the token's `auth_time` may be: the 10 minutes of the pre-auth record, plus leeway.
`prompt=login` makes the pool authenticate again, and this checks that it did."""
DEFAULT_RETURN: Final = "/"
_RETURN_SHAPE: Final = re.compile(r"/[A-Za-z0-9\-._~/]*(\?[A-Za-z0-9\-._~=&]*)?")
_RETURN_MAX: Final = 512


class SignInRefusal(StrEnum):
    """Why a sign-in was refused, for the audit log only (`details.reason`)."""

    STATE_MISSING = "state_missing"
    """No pre-auth cookie, or no record for it: expired, already used, or never made."""
    STATE_MISMATCH = "state_mismatch"
    PROVIDER_ERROR = "provider_error"
    PROVIDER_UNAVAILABLE = "provider_unavailable"
    CODE_REJECTED = "code_rejected"
    TOKEN_INVALID = "token_invalid"  # noqa: S105 - a reason code, not a secret
    NONCE_MISMATCH = "nonce_mismatch"
    STALE_AUTHENTICATION = "stale_authentication"
    CONNECTION_INACTIVE = "connection_inactive"
    CONNECTION_MISMATCH = "connection_mismatch"
    UNKNOWN_IDENTITY = "unknown_identity"
    IDENTITY_EXPIRED = "identity_expired"
    USER_MISMATCH = "user_mismatch"
    USER_DEACTIVATED = "user_deactivated"
    TENANT_SUSPENDED = "tenant_suspended"


class SessionEnd(StrEnum):
    """Why a session token resolves to no caller."""

    UNKNOWN = "unknown"
    """No session has this token: deleted by the daily job, or never made."""
    ENDED = "ended"
    """Revoked, expired, idle too long, or its user or tenant is no longer active."""


DATABASE_UNAVAILABLE: Final = (OperationalError, InterfaceError, PoolTimeoutError, OSError)
"""What the database's outage looks like: no connection, a lost one, or a full pool."""


class SignInMethod(StrEnum):
    SSO = "sso"
    LOCAL = "local"


class SignInUnavailableError(Exception):
    """Sign-in can't start: the pool's connection is missing or inactive, or the provider can't be
    reached. Answered with 503, like the state store's outage."""


@dataclass(frozen=True, slots=True)
class Started:
    cookie: str
    """The new `__Host-sft_auth` value."""
    location: str


@dataclass(frozen=True, slots=True)
class Completed:
    """A sign-in's outcome: a new session token, or none, and where the browser goes."""

    location: str
    session_token: str | None = None


@dataclass(frozen=True, slots=True)
class CurrentMember:
    """What `GET /me` shows: the member's rows, and how and until when the session lasts."""

    user: User
    tenant: Tenant
    auth_method: AuthMethod
    auth_time: datetime
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class SignInConfig:
    provider_name: str
    web_origin: str
    logout_url: str
    passkey_rule: bool = False


class _RefusedError(Exception):
    def __init__(self, reason: SignInRefusal, identity: Identity | None = None) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.identity = identity


def safe_return_path(raw: str | None) -> str:
    """A relative path on the web app, or `/`: the API is never an open redirect (2.4)."""
    if not raw or len(raw) > _RETURN_MAX or not _RETURN_SHAPE.fullmatch(raw):
        return DEFAULT_RETURN
    path = raw.split("?", 1)[0]
    segments = path.split("/")[1:]
    if path.startswith("//") or any(
        s in (".", "..") or (s == "" and i < len(segments) - 1) for i, s in enumerate(segments)
    ):
        return DEFAULT_RETURN
    return raw


def auth_method_of(token: IdToken, *, federated: bool) -> AuthMethod:
    """`auth_method` from how the pool says the member signed in (authn and authz 3.3)."""
    if federated:
        return AuthMethod.SSO
    amr = set(token.amr)
    if amr & {"hwk", "swk"}:
        return AuthMethod.PASSKEY
    if "pwd" in amr and "otp" in amr:
        return AuthMethod.PASSWORD_TOTP
    return AuthMethod.LOCAL


class SignIn:
    def __init__(
        self,
        database: Database,
        oidc: OidcClient,
        states: StateStore,
        csrf: CsrfKeyring,
        config: SignInConfig,
    ) -> None:
        self.database = database
        self.oidc = oidc
        self.states = states
        self.csrf = csrf
        self.config = config

    async def aclose(self) -> None:
        await self.oidc.aclose()
        await self.states.aclose()

    # ---- start ----

    async def start(self, *, method: SignInMethod, return_to: str | None) -> Started:
        # method=sso finds a tenant's provider by its proven domain once SSO exists (M6); until
        # then every sign-in is local, which the contract allows for an unproven domain.
        del method
        try:
            connection = await self._pool_connection()
        except DATABASE_UNAVAILABLE as exc:
            log.warning("sign-in can't reach the database", extra={"error": type(exc).__name__})
            raise SignInUnavailableError from exc
        if connection is None or connection.status != "active":
            log.error("the user pool's connection is missing or inactive")
            raise SignInUnavailableError
        pkce = Pkce.new()
        pending = PendingSignIn(
            state=secrets.token_urlsafe(32),
            verifier=pkce.verifier,
            nonce=secrets.token_urlsafe(32),
            connection_id=connection.id,
            return_to=safe_return_path(return_to),
        )
        try:
            location = await self.oidc.authorization_url(
                state=pending.state,
                nonce=pending.nonce,
                pkce=pkce,
                identity_provider=LOCAL_IDENTITY_PROVIDER,
            )
        except OidcError as exc:
            raise SignInUnavailableError from exc
        cookie = secrets.token_urlsafe(32)
        await self.states.put(cookie, pending)  # StateStoreUnavailableError: the route answers 503
        return Started(cookie=cookie, location=location)

    async def _pool_connection(self) -> Connection | None:
        async with self.database.transaction(Scope.lookup()) as session:
            connection = await find_connection(session, self.config.provider_name)
        if connection is not None and (connection.kind != "local" or connection.tenant_id):
            return None
        return connection

    # ---- complete ----

    async def complete(
        self,
        *,
        cookie: str | None,
        code: str | None,
        state: str | None,
        error: str | None,
        previous_session: str | None,
        origin: Origin,
    ) -> Completed:
        """Finish a sign-in. Refusals redirect; `StateStoreUnavailableError` and
        `SignInUnavailableError` (the database is unreachable) are the route's `503`: sign-in
        fails closed."""
        pending = None if not cookie else await self.states.take(cookie)
        try:
            return await self._complete(pending, code, state, error, previous_session, origin)
        except DATABASE_UNAVAILABLE as exc:
            log.warning("sign-in can't reach the database", extra={"error": type(exc).__name__})
            raise SignInUnavailableError from exc

    async def _complete(
        self,
        pending: PendingSignIn | None,
        code: str | None,
        state: str | None,
        error: str | None,
        previous_session: str | None,
        origin: Origin,
    ) -> Completed:
        try:
            if pending is None:
                raise _RefusedError(SignInRefusal.STATE_MISSING)
            if error:
                raise _RefusedError(SignInRefusal.PROVIDER_ERROR)
            if not code or not state or not _same(state, pending.state):
                raise _RefusedError(SignInRefusal.STATE_MISMATCH)
            token = await self._token(code, pending)
            identity, method = await self._identity(token, pending)
            session_token = await self._create_session(identity, token, method, origin)
        except _RefusedError as refused:
            await self._audit_refusal(refused, origin)
            return Completed(location=self._web("/sign-in?error=sign_in_failed"))
        if previous_session:
            await self._end_previous(previous_session, origin)
        # Encoded whole: a return path's own query (`?tab=log&page=2`) stays inside the parameter.
        query = urlencode({"return_path": pending.return_to})
        return Completed(location=self._web(f"/auth/callback?{query}"), session_token=session_token)

    async def _token(self, code: str, pending: PendingSignIn) -> IdToken:
        try:
            id_token, refresh_token = await self.oidc.exchange(code, pending.verifier)
            if refresh_token:  # nothing keeps it, and it is revoked whatever happens next
                await self.oidc.revoke(refresh_token)
            token = await self.oidc.validate(id_token, pending.nonce)
        except OidcError as exc:
            raise _RefusedError(SignInRefusal(exc.reason.value)) from exc
        if token.auth_time is not None:
            signed_in = datetime.fromtimestamp(token.auth_time, UTC)
            if datetime.now(UTC) - signed_in > FRESH_SIGN_IN:
                raise _RefusedError(SignInRefusal.STALE_AUTHENTICATION)
        return token

    async def _identity(
        self, token: IdToken, pending: PendingSignIn
    ) -> tuple[Identity, AuthMethod]:
        federated = bool(token.identities)
        async with self.database.transaction(Scope.lookup()) as session:
            if federated:
                # The connection comes from how the sign-in arrived: the provider the token names
                # must be the one the pre-auth record chose. Its subject is the provider's.
                first = token.identities[0]
                provider, subject = first.get("providerName"), first.get("userId")
                if not isinstance(provider, str) or not isinstance(subject, str):
                    raise _RefusedError(SignInRefusal.TOKEN_INVALID)
                connection = await find_connection(session, provider)
            else:
                subject = token.subject
                connection = await find_connection(session, self.config.provider_name)
            if connection is None or connection.id != pending.connection_id:
                raise _RefusedError(SignInRefusal.CONNECTION_MISMATCH)
            if connection.status != "active":
                raise _RefusedError(SignInRefusal.CONNECTION_INACTIVE)
            identity = await find_identity(session, connection.id, subject)
        if identity is None:
            raise _RefusedError(SignInRefusal.UNKNOWN_IDENTITY)
        if connection.tenant_id is not None and identity.tenant_id != connection.tenant_id:
            # One tenant's provider can never sign anyone in to another tenant.
            raise _RefusedError(SignInRefusal.UNKNOWN_IDENTITY)
        if identity.expires_at is not None and identity.expires_at <= datetime.now(UTC):
            raise _RefusedError(SignInRefusal.IDENTITY_EXPIRED, identity)
        if not federated and token.username != str(identity.user_id):
            raise _RefusedError(SignInRefusal.USER_MISMATCH, identity)
        return identity, auth_method_of(token, federated=federated)

    async def _create_session(
        self, identity: Identity, token: IdToken, method: AuthMethod, origin: Origin
    ) -> str:
        auth_time = (
            datetime.fromtimestamp(token.auth_time, UTC)
            if token.auth_time is not None
            else datetime.now(UTC)
        )
        async with self.database.transaction(Scope.tenant(identity.tenant_id)) as session:
            tenant = await get_tenant(session, identity.tenant_id)
            if tenant is None or tenant.status != "active":
                raise _RefusedError(SignInRefusal.TENANT_SUSPENDED, identity)
            user = await get_user(session, identity.user_id, for_update=True)
            if user is None:
                raise _RefusedError(SignInRefusal.UNKNOWN_IDENTITY, identity)
            if user.status == UserStatus.DEACTIVATED:
                raise _RefusedError(SignInRefusal.USER_DEACTIVATED, identity)
            # The caller as the new session will see it, before the session exists: its actor.
            caller = Caller(
                CallerKind.MEMBER,
                tenant_id=identity.tenant_id,
                user_id=user.id,
                role=Role(user.role),
                auth_method=method,
                auth_time=auth_time,
                passkey_rule=self.config.passkey_rule,
            )
            if user.status == UserStatus.INVITED:
                # A local member's first sign-in activates them (authn and authz 2.5).
                await accept_invitation(session, user.id, actor=caller.actor(), origin=origin)
            session_token, row, ended = await member_sessions.create_session(
                session,
                user_id=user.id,
                identity_id=identity.id,
                auth_method=method.value,
                auth_time=auth_time,
                created_ip=origin.source_ip,
                user_agent=origin.user_agent,
            )
            await audit.record(
                session,
                action="member.signed_in",
                actor=caller.actor(),
                target=Target(SESSION_TARGET, row.id),
                origin=origin,
                details={
                    "auth_method": method,
                    "identity_id": identity.id,
                    "sessions_ended": ended,
                },
            )
        return session_token

    async def _audit_refusal(self, refused: _RefusedError, origin: Origin) -> None:
        identity = refused.identity
        details = {"reason": refused.reason}
        log.info("sign-in refused", extra={"reason": refused.reason.value})
        if identity is None:
            # Nobody is known, so there is no tenant: a platform event, by the sign-in itself.
            async with self.database.transaction(Scope.platform()) as session:
                await audit.record(
                    session,
                    action="member.sign_in_refused",
                    actor=Actor(ActorType.SYSTEM),
                    outcome=Outcome.FAILURE,
                    origin=origin,
                    details=details,
                )
            return
        async with self.database.transaction(Scope.tenant(identity.tenant_id)) as session:
            await audit.record(
                session,
                action="member.sign_in_refused",
                actor=Actor(ActorType.MEMBER, identity.user_id),
                target=Target("user", identity.user_id),
                outcome=Outcome.FAILURE,
                origin=origin,
                details={**details, "identity_id": identity.id},
            )

    async def _end_previous(self, token: str, origin: Origin) -> None:
        """Revoke the session cookie the browser sent before signing in, so a planted cookie
        can't be carried into the new sign-in (authn and authz 3.3)."""
        async with self.database.transaction(Scope.lookup()) as session:
            found = await member_sessions.lookup_session(session, token)
        if found is None or not found.live:
            return
        session_id, tenant_id = found.session_id, found.tenant_id
        async with self.database.transaction(Scope.tenant(tenant_id)) as session:
            user_id = await member_sessions.revoke_session(
                session, session_id, reason=RevokedReason.SIGN_IN_REPLACED
            )
            if user_id is not None:
                await audit.record(
                    session,
                    action="member.signed_out",
                    actor=Actor(ActorType.MEMBER, user_id),
                    target=Target(SESSION_TARGET, session_id),
                    origin=origin,
                    details={"reason": RevokedReason.SIGN_IN_REPLACED, "sessions_ended": 1},
                )

    # ---- every request ----

    async def resolve(self, token: str) -> tuple[Caller, LiveSession] | SessionEnd:
        """The caller a session token stands for, or why there is none (3.2): no session ever
        had this token (`UNKNOWN`, a failed authentication), or it has ended (`ENDED`)."""
        async with self.database.transaction(Scope.lookup()) as session:
            found = await member_sessions.lookup_session(session, token)
        if found is None:
            return SessionEnd.UNKNOWN
        if not found.live:
            return SessionEnd.ENDED
        async with self.database.transaction(Scope.tenant(found.tenant_id)) as session:
            live = await member_sessions.get_live_session(session, found.session_id)
        if live is None:
            return SessionEnd.ENDED
        caller = Caller.member(
            tenant_id=live.tenant_id,
            user_id=live.user_id,
            role=Role(live.role),
            auth_method=AuthMethod(live.auth_method),
            auth_time=live.auth_time,
            session_id=live.session_id,
            passkey_rule=self.config.passkey_rule,
        )
        return caller, live

    async def current_member(self, caller: Caller) -> CurrentMember:
        """The member's user and tenant rows and the session's end, for `GET /me`."""
        authorize(caller, "getCurrentMember", now=datetime.now(UTC))
        tenant_id, user_id, session_id = _member_session(caller)
        async with self.database.transaction(Scope.tenant(tenant_id)) as session:
            user = await get_user(session, user_id)
            tenant = await get_tenant(session, tenant_id)
            expires_at = await member_sessions.expires_at(session, session_id)
        if user is None or tenant is None or expires_at is None or caller.auth_time is None:
            # Ended between the request's session check and this read.
            raise Unauthenticated("session_expired")
        method = caller.auth_method or AuthMethod.LOCAL
        return CurrentMember(user, tenant, method, caller.auth_time, expires_at)

    def csrf_token(self, session_token: str) -> str:
        return self.csrf.token_for(session_token)

    def csrf_valid(self, session_token: str, presented: str | None) -> bool:
        return self.csrf.verify(session_token, presented)

    # ---- sign-out ----

    async def sign_out(self, caller: Caller, *, all_sessions: bool, origin: Origin) -> str:
        """End this session, or every session of the member, and return the pool's logout URL."""
        authorize(caller, "signOut", now=datetime.now(UTC))
        tenant_id, user_id, session_id = _member_session(caller)
        async with self.database.transaction(Scope.tenant(tenant_id)) as session:
            if all_sessions:
                ended = await member_sessions.revoke_user_sessions(
                    session, user_id, reason=RevokedReason.SIGNED_OUT
                )
            else:
                revoked = await member_sessions.revoke_session(
                    session, session_id, reason=RevokedReason.SIGNED_OUT
                )
                ended = 0 if revoked is None else 1
            if ended:
                await audit.record(
                    session,
                    action="member.signed_out",
                    actor=caller.actor(),
                    target=Target(SESSION_TARGET, session_id),
                    origin=origin,
                    details={
                        "reason": RevokedReason.SIGNED_OUT,
                        "all_sessions": all_sessions,
                        "sessions_ended": ended,
                    },
                )
        return self.config.logout_url

    def _web(self, path: str) -> str:
        return f"{self.config.web_origin}{path}"


def _member_session(caller: Caller) -> tuple[UUID, UUID, UUID]:
    """The tenant, user and session of a member session's caller; 401 for any other."""
    if (
        caller.kind is not CallerKind.MEMBER
        or caller.tenant_id is None
        or caller.user_id is None
        or caller.credential_id is None
    ):
        raise Unauthenticated("authentication_required", bearer=caller.bearer)
    return caller.tenant_id, caller.user_id, caller.credential_id


def _same(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


__all__ = [
    "Completed",
    "CurrentMember",
    "SessionEnd",
    "SignIn",
    "SignInConfig",
    "SignInMethod",
    "SignInRefusal",
    "SignInUnavailableError",
    "Started",
    "auth_method_of",
    "safe_return_path",
]
