"""Link sessions: a verified browser's session for one recipient (data model 2.4; authn and authz
4.3; #179).

A session token is 256 random bits (`new_token`). The browser holds the tokens of up to 10 link
sessions in the HttpOnly `__Host-sft_link` cookie; the database holds only each one's SHA-256.

- `lookup` is the credential lookup (data model 4.2): in lookup scope, the sessions of one
  cookie's tokens, each with its tenant, its recipient and whether it is live, across tenants.
  Each request then continues in that session's tenant (or resource) scope.
- Lifetime: 24 hours at most and never past the transfer's expiry (`create`), 1 hour idle.
  `last_seen_at` moves at most once a minute (`TOUCH_INTERVAL`). Times are the database's.
- Revocation sets `revoked_at` (`revoke`, `revoke_for_recipient`). The audit trigger requires an
  audit event in the same transaction for every creation and revocation; the caller writes it.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import ColumnElement, delete, func, insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import DownloadGrant, LinkSession, TransferRecipient
from sft.data.scope import ScopeKind

LIFETIME: Final = timedelta(hours=24)
IDLE_TIMEOUT: Final = timedelta(hours=1)
TOUCH_INTERVAL: Final = timedelta(minutes=1)
TOKEN_BYTES: Final = 32
MAX_PER_BROWSER: Final = 10
"""Sessions one `__Host-sft_link` cookie holds; an 11th ends the oldest (authn and authz 4.3)."""


def new_token() -> str:
    """A new session token: 256 bits from the operating system's generator, base64url."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


@dataclass(frozen=True, slots=True)
class FoundLinkSession:
    """What the credential lookup returns for one token: IDs and a status, never the hash."""

    session_id: UUID
    tenant_id: UUID
    recipient_id: UUID
    live: bool
    token: str
    """The cookie's token that found it, which the caller already holds."""


async def lookup(session: AsyncSession, tokens: Sequence[str]) -> list[FoundLinkSession]:
    """The sessions these tokens belong to, oldest first (IDs are UUIDv7).

    The lookup returns no hash, so each token is looked up on its own: a cookie holds at most 10,
    and each is one probe of a unique index.
    """
    require_scope(session, ScopeKind.LOOKUP)
    found: list[FoundLinkSession] = []
    for token in dict.fromkeys(tokens):
        row = (
            await session.execute(
                text(
                    "SELECT session_id, owner_tenant_id, recipient_id, live "
                    "FROM lookup_link_sessions(:hashes)"
                ),
                {"hashes": [token_hash(token)]},
            )
        ).first()
        if row is not None:
            found.append(FoundLinkSession(row[0], row[1], row[2], bool(row[3]), token))
    return sorted(found, key=lambda s: s.session_id)


async def create(
    session: AsyncSession, recipient_id: UUID, *, ends_by: datetime | None
) -> tuple[str, LinkSession]:
    """A new session for the recipient, in the scope's tenant: 24 hours, or until `ends_by` (the
    transfer's expiry) if that is sooner. Its token and its row."""
    require_scope(session, ScopeKind.TENANT)
    token = new_token()
    expires = func.now() + LIFETIME
    if ends_by is not None:
        expires = func.least(expires, ends_by)
    session_id = uuid7()
    await session.execute(
        insert(LinkSession).values(
            id=session_id,
            tenant_id=tenant_of(session),
            recipient_id=recipient_id,
            session_hash=token_hash(token),
            expires_at=expires,
        )
    )
    row: LinkSession | None = await session.scalar(
        select(LinkSession).where(LinkSession.id == session_id, in_scope(LinkSession, session))
    )
    if row is None:  # pragma: no cover - the row was just inserted in this scope
        raise RuntimeError("the new session isn't readable")
    return token, row


@dataclass(frozen=True, slots=True)
class LiveLinkSession:
    session_id: UUID
    recipient_id: UUID
    expires_at: datetime


async def get_live(session: AsyncSession, session_id: UUID) -> LiveLinkSession | None:
    """The session, if it is live: not revoked, not past its expiry, not idle for an hour. Moves
    `last_seen_at` when it is a minute old."""
    now = func.now()
    found = (
        await session.execute(
            select(LinkSession.id, LinkSession.recipient_id, LinkSession.expires_at).where(
                LinkSession.id == session_id,
                in_scope(LinkSession, session),
                LinkSession.revoked_at.is_(None),
                LinkSession.expires_at > now,
                LinkSession.last_seen_at > now - IDLE_TIMEOUT,
            )
        )
    ).first()
    if found is None:
        return None
    await session.execute(
        update(LinkSession)
        .where(
            LinkSession.id == session_id,
            in_scope(LinkSession, session),
            LinkSession.last_seen_at <= now - TOUCH_INTERVAL,
        )
        .values(last_seen_at=now)
        .execution_options(synchronize_session=False)
    )
    return LiveLinkSession(found[0], found[1], found[2])


async def revoke(session: AsyncSession, session_id: UUID) -> bool:
    """End one session if it is still open: False if it had ended."""
    result = await session.execute(
        update(LinkSession)
        .where(
            LinkSession.id == session_id,
            in_scope(LinkSession, session),
            LinkSession.revoked_at.is_(None),
        )
        .values(revoked_at=func.now())
        .returning(LinkSession.id)
        .execution_options(synchronize_session=False)
    )
    return result.first() is not None


async def live_for_recipient(session: AsyncSession, recipient_id: UUID) -> list[UUID]:
    """The recipient's open sessions, oldest first."""
    rows = await session.scalars(
        select(LinkSession.id)
        .where(
            LinkSession.recipient_id == recipient_id,
            in_scope(LinkSession, session),
            LinkSession.revoked_at.is_(None),
            LinkSession.expires_at > func.now(),
        )
        .order_by(LinkSession.id)
    )
    return list(rows)


async def revoke_for_transfer(session: AsyncSession, transfer_id: UUID) -> int:
    """End every open session of the transfer's recipients, in the revocation's transaction (data
    model 2.4); how many were open. The revocation's audit event covers them."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        update(LinkSession)
        .where(
            LinkSession.recipient_id.in_(
                select(TransferRecipient.id).where(
                    TransferRecipient.transfer_id == transfer_id,
                    in_scope(TransferRecipient, session),
                )
            ),
            LinkSession.revoked_at.is_(None),
            in_scope(LinkSession, session),
        )
        .values(revoked_at=func.now())
        .returning(LinkSession.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())


# ---- the daily cleanup (sft_jobs, data model 6) ----


def _no_unarchived_grant() -> ColumnElement[bool]:
    """A session whose grants' committed records are all confirmed: deleting it cascades to its
    grants, so one with a grant still waiting stays for reconciliation (NFR-15, #181 review)."""
    # The grant's ID only: the jobs' role reads named columns of grants (revision 0015).
    return ~(
        select(DownloadGrant.id)
        .where(
            DownloadGrant.link_session_id == LinkSession.id,
            DownloadGrant.archived_at.is_(None),
        )
        .exists()
    )


async def tenants_with_expired(
    session: AsyncSession, *, before: datetime, limit: int
) -> list[UUID]:
    """Tenants with sessions past their expiry, across tenants, in system scope."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.scalars(
        select(LinkSession.tenant_id)
        .where(
            LinkSession.expires_at <= before,
            _no_unarchived_grant(),
            in_scope(LinkSession, session),
        )
        .group_by(LinkSession.tenant_id)
        .limit(limit)
    )
    return list(rows)


async def delete_expired(session: AsyncSession, *, before: datetime, limit: int) -> int:
    """Delete up to `limit` of the scope's tenant's sessions past their expiry; their grants go
    with them (data model 6), so a session with a grant still waiting for its committed record
    stays."""
    require_scope(session, ScopeKind.TENANT)
    found = (
        select(LinkSession.id)
        .where(
            LinkSession.expires_at <= before,
            _no_unarchived_grant(),
            in_scope(LinkSession, session),
        )
        .limit(limit)
    )
    result = await session.execute(
        delete(LinkSession)
        .where(LinkSession.id.in_(found.scalar_subquery()), in_scope(LinkSession, session))
        .returning(LinkSession.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())


__all__ = [
    "IDLE_TIMEOUT",
    "LIFETIME",
    "MAX_PER_BROWSER",
    "FoundLinkSession",
    "LiveLinkSession",
    "create",
    "delete_expired",
    "get_live",
    "live_for_recipient",
    "lookup",
    "new_token",
    "revoke",
    "revoke_for_transfer",
    "tenants_with_expired",
    "token_hash",
]
