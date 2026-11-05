"""Data access for `operator_sessions`, a platform table (data model 2.6, authn and authz 8.2).

Every function runs in platform scope as `sft_operator`, the only role granted the table. A row is
an operator token: the SHA-256 of the token, never the token, and the SHA-256 of the signature of
the STS request it was made from, so the same signed request can't make a second token.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import require_scope
from sft.data.models import OperatorSession
from sft.data.scope import ScopeKind


@dataclass(frozen=True, slots=True)
class ActiveOperatorSession:
    """What a request learns from its operator token."""

    id: UUID
    operator_name: str
    aws_account_id: str
    expires_at: datetime


async def signature_seen(session: AsyncSession, signature_hash: bytes) -> bool:
    """Whether a token was already made from a request with this signature."""
    require_scope(session, ScopeKind.PLATFORM)
    statement = select(OperatorSession.id).where(OperatorSession.signature_hash == signature_hash)
    return await session.scalar(statement) is not None


async def create_operator_session(
    session: AsyncSession,
    *,
    token_hash: bytes,
    signature_hash: bytes,
    aws_account_id: str,
    operator_name: str,
    expires_at: datetime,
) -> UUID | None:
    """The new session's ID, or None if a session with this signature exists: a replay.

    One statement, so two requests with the same signature can't both get a token.
    """
    require_scope(session, ScopeKind.PLATFORM)
    statement = (
        insert(OperatorSession)
        .values(
            id=uuid7(),
            token_hash=token_hash,
            signature_hash=signature_hash,
            aws_account_id=aws_account_id,
            operator_name=operator_name,
            expires_at=expires_at,
        )
        .on_conflict_do_nothing(index_elements=[OperatorSession.signature_hash])
        .returning(OperatorSession.id)
    )
    session_id: UUID | None = await session.scalar(statement)
    return session_id


async def find_operator_session(
    session: AsyncSession, token_hash: bytes
) -> ActiveOperatorSession | None:
    """The session of a token that is neither expired nor revoked, by the token's hash."""
    require_scope(session, ScopeKind.PLATFORM)
    statement = select(
        OperatorSession.id,
        OperatorSession.operator_name,
        OperatorSession.aws_account_id,
        OperatorSession.expires_at,
    ).where(
        OperatorSession.token_hash == token_hash,
        OperatorSession.revoked_at.is_(None),
        OperatorSession.expires_at > func.now(),
    )
    row = (await session.execute(statement)).one_or_none()
    return None if row is None else ActiveOperatorSession(*row)
