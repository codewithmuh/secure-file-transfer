"""Member sessions: created at sign-in, checked on every request, revoked (authn and authz 3).

A session token is 256 random bits (`new_token`). The browser holds it in the HttpOnly
`__Host-sft_session` cookie; the database holds only its SHA-256 (`token_hash`).

- `lookup_session` is the credential lookup (data model 4.2): in lookup scope, a session's ID, its
  tenant and whether it is still live (not revoked, not expired) by the token's hash, across
  tenants. A live one continues in that tenant's scope with `get_live_session`, which checks
  everything else. An ended one is told apart from a token no session ever had, so only the latter
  counts as a failed authentication (abuse and rate limits 2.2, H).
- Lifetime: 12 hours from sign-in (`SESSION_LIFETIME`), 30 minutes idle (`IDLE_TIMEOUT`).
  `last_seen_at` is written at most once a minute (`TOUCH_INTERVAL`). Times are the database's,
  so every pod agrees on them.
- A user has at most `MAX_SESSIONS` live sessions; creating one more revokes the oldest.
- Revocation sets `revoked_at` and `revoked_reason`. The audit trigger requires an audit event in
  the same transaction for every creation and revocation; these functions write none themselves,
  because the action that causes them (a sign-in, a sign-out, a deactivation) does.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import IPv4Address, IPv6Address
from typing import Final
from uuid import UUID

from sqlalchemy import func, select, text, true, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.core.tokens import token_hash
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.audit import USER_AGENT_MAX
from sft.data.models import MemberSession, SessionRevokedReason, Tenant, User
from sft.data.scope import ScopeKind

SESSION_LIFETIME: Final = timedelta(hours=12)
IDLE_TIMEOUT: Final = timedelta(minutes=30)
TOUCH_INTERVAL: Final = timedelta(minutes=1)
MAX_SESSIONS: Final = 10
TOKEN_BYTES: Final = 32

RevokedReason = SessionRevokedReason

__all__ = [
    "IDLE_TIMEOUT",
    "MAX_SESSIONS",
    "SESSION_LIFETIME",
    "FoundSession",
    "LiveSession",
    "RevokedReason",
    "create_session",
    "get_live_session",
    "lookup_session",
    "lookup_session_hash",
    "new_token",
    "revoke_session",
    "revoke_tenant_sessions",
    "revoke_user_sessions",
    "token_hash",
]


def new_token() -> str:
    """A new session token: 256 bits from the operating system's generator, base64url."""
    return secrets.token_urlsafe(TOKEN_BYTES)


@dataclass(frozen=True, slots=True)
class LiveSession:
    """A session that passed every check of authn and authz 3.2, with its user's current role.

    `user` and `tenant` are the rows the check joined, as they were then: `GET /me` answers from
    them, with no transaction of its own (#161)."""

    session_id: UUID
    tenant_id: UUID
    user_id: UUID
    identity_id: UUID
    role: str
    auth_method: str
    auth_time: datetime
    expires_at: datetime
    user: User
    tenant: Tenant


@dataclass(frozen=True, slots=True)
class FoundSession:
    """What the credential lookup returns: IDs and a status, never the hash."""

    session_id: UUID
    tenant_id: UUID
    live: bool


async def lookup_session(session: AsyncSession, token: str) -> FoundSession | None:
    """The session a token belongs to, its tenant and whether it is live: the credential
    lookup. None if no session has the token."""
    return await lookup_session_hash(session, token_hash(token))


async def lookup_session_hash(session: AsyncSession, session_hash: bytes) -> FoundSession | None:
    """`lookup_session` by the token's SHA-256, for a sign-in that kept only the hash of the
    session the browser held when it started (#159)."""
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text("SELECT session_id, owner_tenant_id, live FROM lookup_member_session(:hash)"),
            {"hash": session_hash},
        )
    ).first()
    return None if row is None else FoundSession(row[0], row[1], bool(row[2]))


async def get_live_session(session: AsyncSession, session_id: UUID) -> LiveSession | None:
    """The session, if it is live: not revoked, not past its 12 hours, not idle for 30 minutes,
    and its user and tenant active. Moves `last_seen_at` when it is a minute old."""
    now = func.now()
    statement = (
        select(MemberSession, User, Tenant)
        .join(
            User, (User.tenant_id == MemberSession.tenant_id) & (User.id == MemberSession.user_id)
        )
        .join(Tenant, Tenant.id == MemberSession.tenant_id)
        .where(
            MemberSession.id == session_id,
            in_scope(MemberSession, session),
            in_scope(User, session),
            in_scope(Tenant, session),
            MemberSession.revoked_at.is_(None),
            MemberSession.expires_at > now,
            MemberSession.last_seen_at > now - IDLE_TIMEOUT,
            User.status == "active",
            Tenant.status == "active",
        )
    )
    row = (await session.execute(statement)).first()
    if row is None:
        return None
    found: MemberSession = row[0]
    user: User = row[1]
    tenant: Tenant = row[2]
    await session.execute(
        update(MemberSession)
        .where(
            MemberSession.id == found.id,
            in_scope(MemberSession, session),
            MemberSession.last_seen_at <= now - TOUCH_INTERVAL,
        )
        .values(last_seen_at=now)
    )
    return LiveSession(
        session_id=found.id,
        tenant_id=found.tenant_id,
        user_id=found.user_id,
        identity_id=found.identity_id,
        role=str(user.role),
        auth_method=found.auth_method,
        auth_time=found.auth_time,
        expires_at=found.expires_at,
        user=user,
        tenant=tenant,
    )


async def create_session(
    session: AsyncSession,
    *,
    user_id: UUID,
    identity_id: UUID,
    auth_method: str,
    auth_time: datetime,
    created_ip: IPv4Address | IPv6Address | None,
    user_agent: str | None,
) -> tuple[str, MemberSession, int]:
    """A new session for the user, in the scope's tenant: its token, its row, and how many older
    sessions the cap of `MAX_SESSIONS` ended. Lock the user row first, so two sign-ins of one user
    can't both stay under the cap."""
    token = new_token()
    row = MemberSession(
        id=uuid7(),
        tenant_id=tenant_of(session),
        user_id=user_id,
        identity_id=identity_id,
        session_hash=token_hash(token),
        auth_time=auth_time,
        auth_method=auth_method,
        expires_at=func.now() + SESSION_LIFETIME,
        created_ip=created_ip,
        user_agent=None if user_agent is None else user_agent[:USER_AGENT_MAX],
    )
    session.add(row)
    await session.flush()
    await session.refresh(row)
    live = (
        select(MemberSession.id)
        .where(
            MemberSession.user_id == user_id,
            in_scope(MemberSession, session),
            MemberSession.revoked_at.is_(None),
            MemberSession.expires_at > func.now(),
        )
        .order_by(MemberSession.created_at.desc(), MemberSession.id.desc())
        .offset(MAX_SESSIONS)
    )
    ended = await _revoke(
        session, MemberSession.id.in_(live.scalar_subquery()), RevokedReason.SESSION_LIMIT
    )
    return token, row, ended


async def revoke_session(
    session: AsyncSession, session_id: UUID, *, reason: RevokedReason
) -> UUID | None:
    """End one session, if it isn't revoked yet and is in the scope's tenant: its user's ID, or
    None if nothing changed."""
    user_id: UUID | None = await session.scalar(
        update(MemberSession)
        .where(
            MemberSession.id == session_id,
            in_scope(MemberSession, session),
            MemberSession.revoked_at.is_(None),
        )
        .values(revoked_at=func.now(), revoked_reason=RevokedReason(reason).value)
        .returning(MemberSession.user_id),
        execution_options={"synchronize_session": False},
    )
    return user_id


async def revoke_user_sessions(
    session: AsyncSession, user_id: UUID, *, reason: RevokedReason
) -> int:
    """End every live session of the user, in the scope's tenant: for sign-out everywhere, a role
    change, a deactivation, a sign-in reset or an admin's forced sign-out (authn and authz 3.3).
    Write the action's audit event in the same transaction. Returns how many ended."""
    return await _revoke(session, MemberSession.user_id == user_id, reason)


async def revoke_tenant_sessions(session: AsyncSession, *, reason: RevokedReason) -> int:
    """End every live session of the scope's tenant, when the operator API suspends it (authn and
    authz 3.3). Write the suspension's audit event in the same transaction. Returns how many
    ended."""
    require_scope(session, ScopeKind.TENANT)
    return await _revoke(session, true(), reason)


async def _revoke(session: AsyncSession, condition: object, reason: RevokedReason) -> int:
    result = await session.execute(
        update(MemberSession)
        .where(
            condition,  # type: ignore[arg-type]
            in_scope(MemberSession, session),
            MemberSession.revoked_at.is_(None),
        )
        .values(revoked_at=func.now(), revoked_reason=RevokedReason(reason).value)
    )
    return int(result.rowcount)  # type: ignore[attr-defined]
