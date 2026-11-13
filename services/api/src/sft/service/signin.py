"""Member sign-in, sessions and sign-out (ADR-0016; authentication and authorization 2.4 and 3).

`SignIn` holds the parts: the database, the OIDC client of the environment's pool, the sign-in
state store and the CSRF keyring. The API's routes call it; it knows nothing of HTTP.

**Start** (`start`). Picks the connection: the pool's, found by its `provider_name`, or, for
`method=sso`, the tenant's provider that a proven domain is linked to (`lookup_sso_domain`, #231),
when that connection is active. Anything else, an unproven or unlinked domain included, falls back
to local sign-in, as the contract says, so an unproven domain never routes a sign-in. Stores the
pre-auth record and returns the cookie value and the URL of the pool's authorization endpoint,
naming the provider (`identity_provider`, or `kc_idp_hint` for the local stand-in).

**Complete** (`complete`). Takes the pre-auth record once, compares `state`, exchanges the code,
revokes the refresh token and validates the ID token. Then it resolves the identity from rows,
never from a claim: the connection is the one the record chose, and, for SSO, the provider the
token's `identities` claim names must be that connection; the identity is `(connection, subject)`
and gives the user and the tenant. A local identity's user must equal `cognito:username`. In the
tenant's scope it checks the tenant and the user, activates an invited user, creates the session
under the cap of 10, and audits the sign-in, in one transaction. Every refusal is audited with its
reason: in the tenant's log when the identity or the tenant's connection is known, otherwise as a
platform event, since there is no tenant (authn and authz 2.4). The caller only learns
`sign_in_failed`.

**Just in time** (#231). An SSO subject with no identity yet, through a tenant's connection,
binds to that tenant's user whose address the token names, when the address is on one of the
domains linked to the connection and the user isn't deactivated and has no identity there yet
(`user.identity_bound`); otherwise, with the tenant's `sso_jit` on, the member is created, active,
with the role the token's groups map to or `member` (`user.provisioned`). The address never
reaches another tenant or a domain the tenant hasn't proven. **SSO required**: a local sign-in
to a tenant that requires SSO is refused, except for its fallback admins and an operator's
temporary local sign-in (`recoverTenantAdmin`, #239), whose identity expires after 72 hours. Both
are security-critical records.

**Invitation** (`start_invitation`, #239). An SSO invitation's token finds the invited user
(`lookup_invitation`, in lookup scope); the pre-auth record names them, the token's hash and their
tenant's active connection. At the callback the provider's subject is bound to that user, unless
it already is, and the invitation is consumed, which activates them, in the sign-in's transaction
(`user.identity_bound`, `user.activated`). A subject bound to another user, an invitation used or
replaced meanwhile, or a sign-in that didn't come through the tenant's provider is refused.

**The previous session** (#159). The start keeps the SHA-256 of the session cookie the browser
sent in the pre-auth record: the start is a same-site navigation, so the Strict cookie arrives
there. The callback is a cross-site redirect from the user pool and carries none, so it ends that
session by its hash, and a cookie that did arrive too (a same-site pool, as locally). A session
planted in the browser before sign-in never outlives it (authn and authz 3.3).

**Resolve** (`resolve`). The per-request check of 3.2, through the member session lookup, then in
the session's tenant: live, not idle, user and tenant active, role from `users`.

**Sign out** (`sign_out`). Revokes the session, or every session of the member, audited.
"""

from __future__ import annotations

import hmac
import logging
import re
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Final
from urllib.parse import urlencode
from uuid import UUID

from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.errors import Unauthenticated
from sft.core.tokens import token_hash
from sft.data import audit, member_sessions, sso
from sft.data.access import NotFoundError
from sft.data.audit import Actor, Origin, Target
from sft.data.database import Database
from sft.data.identities import (
    Connection,
    Identity,
    find_connection,
    find_identity,
    has_identity,
)
from sft.data.member_sessions import LiveSession, RevokedReason
from sft.data.models import ActorType, Outcome, Role, SsoGroupRole, Tenant, User, UserStatus
from sft.data.scope import Scope
from sft.data.signin_state import PendingSignIn, StateStore
from sft.data.tenants import get_tenant
from sft.data.users import accept_invitation, find_invitation, get_user, get_user_by_email
from sft.service.caller import AuthMethod, Caller, CallerKind
from sft.service.csrf import CsrfKeyring
from sft.service.domain_rules import DomainError, domain_of, normalize_domain
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
    SSO_REQUIRED = "sso_required"
    """A local sign-in to a tenant that requires SSO, by someone who isn't a fallback admin."""
    DOMAIN_NOT_PROVEN = "domain_not_proven"
    """Just in time: the token's address isn't on a domain linked to the connection."""
    PROVISIONING_OFF = "provisioning_off"
    """Just in time: nobody has the address, and the tenant creates no member at sign-in."""
    IDENTITY_CONFLICT = "identity_conflict"
    """Just in time: the user already has another identity at this connection. An invitation:
    the subject is bound to another user."""
    INVITATION_INVALID = "invitation_invalid"
    """An invitation that was used, replaced or expired between its start and the callback."""


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


class InvitationNotFoundError(Exception):
    """No live invitation has the token, or its tenant can't sign anyone in by SSO now:
    `404 not_found`, which says nothing about which (contract, `startInvitationSignIn`)."""


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
    def __init__(
        self,
        reason: SignInRefusal,
        identity: Identity | None = None,
        *,
        tenant_id: UUID | None = None,
    ) -> None:
        super().__init__(reason.value)
        self.reason = reason
        self.identity = identity
        self.tenant_id = tenant_id
        """The tenant whose connection the sign-in came through, when no identity is known."""


@dataclass(frozen=True, slots=True)
class _Resolved:
    """Who a validated token stands for: the identity, or none yet for a first SSO sign-in."""

    connection: Connection
    subject: str
    identity: Identity | None
    method: AuthMethod


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


def role_for_groups(groups: Sequence[str], mapping: Sequence[SsoGroupRole]) -> Role:
    """The role a member created just in time gets: `admin` if any of their groups maps to it,
    otherwise `member` (#231)."""
    held = set(groups)
    if any(m.group_name in held and m.role == Role.ADMIN for m in mapping):
        return Role.ADMIN
    return Role.MEMBER


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

    async def start(
        self,
        *,
        method: SignInMethod,
        return_to: str | None,
        sso_domain: str | None = None,
        previous_session: str | None = None,
    ) -> Started:
        """`previous_session` is the session cookie the browser sent, if any: its hash goes into
        the pre-auth record, so the callback can end that session without the cookie (#159)."""
        try:
            route = None
            if method is SignInMethod.SSO and sso_domain:
                route = await self._domain_route(sso_domain)
            connection = await self._pool_connection()
        except DATABASE_UNAVAILABLE as exc:
            log.warning("sign-in can't reach the database", extra={"error": type(exc).__name__})
            raise SignInUnavailableError from exc
        if connection is None or connection.status != "active":
            log.error("the user pool's connection is missing or inactive")
            raise SignInUnavailableError
        provider = LOCAL_IDENTITY_PROVIDER
        if route is not None:
            # The tenant's provider: the pool sends the browser on to it (authn and authz 2.4).
            connection = Connection(route.connection_id, route.tenant_id, "sso", route.status)
            provider = route.provider_name
        return await self._redirect(
            connection.id, provider, safe_return_path(return_to), previous_session
        )

    async def start_invitation(self, *, token: str, previous_session: str | None) -> Started:
        """`startInvitationSignIn` (authn and authz 2.5): the invited user and their tenant's
        active SSO connection go into the pre-auth record, and the browser to that provider.
        `InvitationNotFoundError` for a token no live invitation has, or a tenant that can't use
        it now: suspended, or without an active connection. Nothing is consumed until the
        callback."""
        digest = token_hash(token)
        try:
            async with self.database.transaction(Scope.lookup()) as session:
                match = await find_invitation(session, digest)
            if match is None:
                raise InvitationNotFoundError
            async with self.database.transaction(Scope.tenant(match.tenant_id)) as session:
                tenant = await get_tenant(session, match.tenant_id)
                connection = await sso.get_connection(session)
        except DATABASE_UNAVAILABLE as exc:
            log.warning("sign-in can't reach the database", extra={"error": type(exc).__name__})
            raise SignInUnavailableError from exc
        if (
            tenant is None
            or tenant.status != "active"
            or connection is None
            or connection.status != "active"
        ):
            raise InvitationNotFoundError
        return await self._redirect(
            connection.id,
            connection.provider_name,
            DEFAULT_RETURN,
            previous_session,
            invited_user_id=match.user_id,
            invitation=digest.hex(),
        )

    async def _redirect(
        self,
        connection_id: UUID,
        provider: str,
        return_to: str,
        previous_session: str | None,
        *,
        invited_user_id: UUID | None = None,
        invitation: str | None = None,
    ) -> Started:
        """Store the pre-auth record and return its cookie and the pool's authorization URL."""
        pkce = Pkce.new()
        pending = PendingSignIn(
            state=secrets.token_urlsafe(32),
            verifier=pkce.verifier,
            nonce=secrets.token_urlsafe(32),
            connection_id=connection_id,
            return_to=return_to,
            previous_session=None
            if not previous_session
            else member_sessions.token_hash(previous_session).hex(),
            invited_user_id=invited_user_id,
            invitation=invitation,
        )
        try:
            location = await self.oidc.authorization_url(
                state=pending.state,
                nonce=pending.nonce,
                pkce=pkce,
                identity_provider=provider,
            )
        except OidcError as exc:
            raise SignInUnavailableError from exc
        cookie = secrets.token_urlsafe(32)
        await self.states.put(cookie, pending)  # StateStoreUnavailableError: the route answers 503
        return Started(cookie=cookie, location=location)

    async def _domain_route(self, raw_domain: str) -> sso.DomainRoute | None:
        """The active connection a proven, linked domain routes to; None falls back to local."""
        try:
            domain = normalize_domain(raw_domain)
        except DomainError:
            return None
        async with self.database.transaction(Scope.lookup()) as session:
            route = await sso.route_domain(session, domain)
        if route is None or route.status != "active":
            return None
        return route

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
            resolved = await self._identity(token, pending)
            session_token = await self._create_session(resolved, token, origin, pending)
        except _RefusedError as refused:
            await self._audit_refusal(refused, origin)
            return Completed(location=self._web("/sign-in?error=sign_in_failed"))
        # The session the browser held when sign-in started, from the record: the callback is a
        # cross-site redirect and carries no Strict cookie (#159). A cookie that did arrive (a
        # same-site pool, as locally) is ended too.
        previous: set[bytes] = set()
        if pending.previous_session is not None:
            previous.add(bytes.fromhex(pending.previous_session))
        if previous_session:
            previous.add(member_sessions.token_hash(previous_session))
        for session_hash in previous:
            await self._end_previous(session_hash, origin)
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

    async def _identity(self, token: IdToken, pending: PendingSignIn) -> _Resolved:
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
        method = auth_method_of(token, federated=federated)
        if pending.invited_user_id is not None:
            # An invitation (authn and authz 2.5): only through the tenant's provider, and only a
            # subject that is new or already the invited user's.
            if not federated or connection.tenant_id is None:
                raise _RefusedError(SignInRefusal.CONNECTION_MISMATCH)
            if identity is not None and identity.user_id != pending.invited_user_id:
                raise _RefusedError(SignInRefusal.IDENTITY_CONFLICT, identity)
        if identity is None:
            if federated and connection.tenant_id is not None:
                # A first SSO sign-in: bound or created just in time, in the tenant's scope.
                return _Resolved(connection, subject, None, method)
            raise _RefusedError(SignInRefusal.UNKNOWN_IDENTITY)
        if connection.tenant_id is not None and identity.tenant_id != connection.tenant_id:
            # One tenant's provider can never sign anyone in to another tenant.
            raise _RefusedError(SignInRefusal.UNKNOWN_IDENTITY)
        if identity.expires_at is not None and identity.expires_at <= datetime.now(UTC):
            raise _RefusedError(SignInRefusal.IDENTITY_EXPIRED, identity)
        if not federated and token.username != str(identity.user_id):
            raise _RefusedError(SignInRefusal.USER_MISMATCH, identity)
        return _Resolved(connection, subject, identity, method)

    async def _provision(
        self, session: AsyncSession, resolved: _Resolved, token: IdToken, tenant: Tenant
    ) -> Identity:
        """Bind a first SSO sign-in to the tenant's user with its address, or create the member
        (module docstring, "Just in time"). In the tenant's scope; refusals name the tenant."""
        connection, tenant_id = resolved.connection, tenant.id
        domain = None if token.email is None else domain_of(token.email)
        linked = await sso.connection_domains(session, connection.id)
        if token.email is None or domain is None or domain not in linked:
            raise _RefusedError(SignInRefusal.DOMAIN_NOT_PROVEN, tenant_id=tenant_id)
        system = Actor(ActorType.SYSTEM)
        user = await get_user_by_email(session, token.email)
        if user is not None:
            if user.status == UserStatus.DEACTIVATED:
                raise _RefusedError(SignInRefusal.USER_DEACTIVATED, tenant_id=tenant_id)
            if await has_identity(session, user_id=user.id, connection_id=connection.id):
                raise _RefusedError(SignInRefusal.IDENTITY_CONFLICT, tenant_id=tenant_id)
            action = "user.identity_bound"
        else:
            if not tenant.sso_jit:
                raise _RefusedError(SignInRefusal.PROVISIONING_OFF, tenant_id=tenant_id)
            role = role_for_groups(token.groups, await sso.group_roles(session))
            user = await sso.provision_user(session, email=token.email, role=role)
            action = "user.provisioned"
        identity_id = await sso.bind_identity(
            session, user_id=user.id, connection_id=connection.id, subject=resolved.subject
        )
        if identity_id is None:
            raise _RefusedError(SignInRefusal.IDENTITY_CONFLICT, tenant_id=tenant_id)
        await audit.record(
            session,
            action=action,
            actor=system,
            target=Target("user", user.id),
            details={
                "idp_connection_id": connection.id,
                "identity_id": identity_id,
                "role": Role(user.role),
            },
        )
        return Identity(identity_id, tenant_id, user.id, None)

    async def _accept(
        self,
        session: AsyncSession,
        resolved: _Resolved,
        pending: PendingSignIn,
        tenant_id: UUID,
        origin: Origin,
    ) -> Identity:
        """An invitation's sign-in: bind the subject to the invited user, unless it is bound to
        them already, and consume the token, which activates them. In the tenant's scope, in the
        sign-in's transaction; a used, replaced or expired invitation is refused."""
        user_id, invitation = pending.invited_user_id, pending.invitation
        if user_id is None or invitation is None:  # pragma: no cover - the caller checks
            raise _RefusedError(SignInRefusal.INVITATION_INVALID, tenant_id=tenant_id)
        user = await get_user(session, user_id, for_update=True)
        if user is None or user.status != UserStatus.INVITED:
            raise _RefusedError(SignInRefusal.INVITATION_INVALID, tenant_id=tenant_id)
        identity = resolved.identity
        if identity is None:
            identity_id = await sso.bind_identity(
                session,
                user_id=user.id,
                connection_id=resolved.connection.id,
                subject=resolved.subject,
            )
            if identity_id is None:
                raise _RefusedError(SignInRefusal.IDENTITY_CONFLICT, tenant_id=tenant_id)
            identity = Identity(identity_id, tenant_id, user.id, None)
            await audit.record(
                session,
                action="user.identity_bound",
                actor=Actor(ActorType.SYSTEM),
                target=Target("user", user.id),
                origin=origin,
                details={
                    "idp_connection_id": resolved.connection.id,
                    "identity_id": identity_id,
                    "role": Role(user.role),
                    "invitation": True,
                },
            )
        try:
            await accept_invitation(
                session,
                user.id,
                actor=Actor(ActorType.MEMBER, user.id),
                origin=origin,
                token_hash=bytes.fromhex(invitation),
            )
        except NotFoundError as exc:
            raise _RefusedError(SignInRefusal.INVITATION_INVALID, tenant_id=tenant_id) from exc
        return identity

    async def _create_session(
        self, resolved: _Resolved, token: IdToken, origin: Origin, pending: PendingSignIn
    ) -> str:
        identity, method = resolved.identity, resolved.method
        tenant_id = identity.tenant_id if identity is not None else resolved.connection.tenant_id
        if tenant_id is None:
            raise _RefusedError(SignInRefusal.UNKNOWN_IDENTITY)
        auth_time = (
            datetime.fromtimestamp(token.auth_time, UTC)
            if token.auth_time is not None
            else datetime.now(UTC)
        )
        async with self.database.transaction(Scope.tenant(tenant_id)) as session:
            tenant = await get_tenant(session, tenant_id)
            if tenant is None or tenant.status != "active":
                raise _RefusedError(SignInRefusal.TENANT_SUSPENDED, identity, tenant_id=tenant_id)
            if pending.invited_user_id is not None:
                identity = await self._accept(session, resolved, pending, tenant_id, origin)
            elif identity is None:
                identity = await self._provision(session, resolved, token, tenant)
            user = await get_user(session, identity.user_id, for_update=True)
            if user is None:
                raise _RefusedError(SignInRefusal.UNKNOWN_IDENTITY, identity)
            if user.status == UserStatus.DEACTIVATED:
                raise _RefusedError(SignInRefusal.USER_DEACTIVATED, identity)
            # An operator's temporary local sign-in (#239) is the one local identity that expires.
            temporary = identity.expires_at is not None
            local_by_exception = method is not AuthMethod.SSO and tenant.sso_required
            if local_by_exception and not (user.sso_fallback or temporary):
                # Only the identity provider signs this tenant's members in (authn and authz 2.5).
                raise _RefusedError(SignInRefusal.SSO_REQUIRED, identity)
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
                    "idp_connection_id": resolved.connection.id,
                    "sessions_ended": ended,
                    # A fallback admin's local sign-in to a tenant that requires SSO (2.5), or an
                    # operator's temporary one (#239).
                    "sso_fallback_sign_in": local_by_exception and not temporary,
                    "temporary_sign_in": temporary,
                },
                security_critical=local_by_exception or temporary,
            )
        return session_token

    async def _audit_refusal(self, refused: _RefusedError, origin: Origin) -> None:
        identity = refused.identity
        details = {"reason": refused.reason}
        log.info("sign-in refused", extra={"reason": refused.reason.value})
        if identity is None and refused.tenant_id is not None:
            # Through the tenant's connection, with no identity yet: the tenant's log.
            async with self.database.transaction(Scope.tenant(refused.tenant_id)) as session:
                await audit.record(
                    session,
                    action="member.sign_in_refused",
                    actor=Actor(ActorType.SYSTEM),
                    outcome=Outcome.FAILURE,
                    origin=origin,
                    details=details,
                )
            return
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

    async def _end_previous(self, session_hash: bytes, origin: Origin) -> None:
        """Revoke the session the browser held before signing in, by its token's hash, so a
        planted cookie can't be carried into the new sign-in (authn and authz 3.3)."""
        async with self.database.transaction(Scope.lookup()) as session:
            found = await member_sessions.lookup_session_hash(session, session_hash)
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

    def current_member(self, caller: Caller, live: LiveSession) -> CurrentMember:
        """`GET /me`: the member's user and tenant rows and the session's end, as the request's
        session check read them (`resolve`), so it needs no transaction of its own (#161)."""
        authorize(caller, "getCurrentMember", now=datetime.now(UTC))
        _, _, session_id = _member_session(caller)
        if live.session_id != session_id or caller.auth_time is None:  # pragma: no cover
            raise Unauthenticated("session_expired")
        method = caller.auth_method or AuthMethod.LOCAL
        return CurrentMember(live.user, live.tenant, method, caller.auth_time, live.expires_at)

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
    "InvitationNotFoundError",
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
