"""Data access for `verification_codes` (data model 2.4; #179, #212).

A code is stored as its HMAC under the `code-hmac` keyring, never as the code (encryption and keys
6.2). A code belongs to a recipient or an uploader (an upload request), its subject; `create` and
`newest` take a recipient's ID, `create_for` and `newest_for` either subject. Both sides work in
the subject's tenant scope:

- **The notification worker** creates a code (`create_for`): it supersedes every older live code
  of the subject in the same transaction, so only the newest can ever match. Its role may read
  only the columns that needs, never an HMAC (revisions 0013, 0019).
- **The API** checks one: `newest_for` finds the subject's newest code, `take_attempt` counts one
  attempt with one conditional update that also returns the HMAC to compare (step 2 of data model
  2.4), and `consume` marks a matched code used. A code past 5 attempts, past its 10 minutes,
  superseded or used returns nothing from `take_attempt`; `why_unusable` says which.

Every change commits only with an audit event (`audit_required`); the caller writes it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final
from uuid import UUID

from sqlalchemy import ColumnElement, delete, func, insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import VerificationCode
from sft.data.scope import ScopeKind, Subject, SubjectKind

LIFETIME: Final = timedelta(minutes=10)
MAX_ATTEMPTS: Final = 5
"""NFR-14: a code is valid at most 10 minutes and allows at most 5 attempts."""


def _owner(subject: Subject) -> dict[str, UUID]:
    """The code's owner column for `subject`."""
    if subject.kind is SubjectKind.UPLOAD_REQUEST:
        return {"upload_request_id": subject.id}
    return {"recipient_id": subject.id}


def _of(subject: Subject) -> ColumnElement[bool]:
    if subject.kind is SubjectKind.UPLOAD_REQUEST:
        return VerificationCode.upload_request_id == subject.id
    return VerificationCode.recipient_id == subject.id


async def create(
    session: AsyncSession, recipient_id: UUID, *, code_id: UUID, code_hmac: bytes, key_id: str
) -> int:
    """A new code for the recipient, valid 10 minutes; the number of older codes it supersedes."""
    return await create_for(
        session,
        Subject.recipient(recipient_id),
        code_id=code_id,
        code_hmac=code_hmac,
        key_id=key_id,
    )


async def create_for(
    session: AsyncSession, subject: Subject, *, code_id: UUID, code_hmac: bytes, key_id: str
) -> int:
    """A new code for the recipient or uploader, valid 10 minutes; the number of older codes it
    supersedes."""
    require_scope(session, ScopeKind.TENANT)
    superseded = await session.execute(
        update(VerificationCode)
        .where(
            _of(subject),
            VerificationCode.superseded_at.is_(None),
            VerificationCode.consumed_at.is_(None),
            in_scope(VerificationCode, session),
        )
        .values(superseded_at=func.now())
        .execution_options(synchronize_session=False)
    )
    await session.execute(
        insert(VerificationCode).values(
            id=code_id,
            tenant_id=tenant_of(session),
            **_owner(subject),
            code_hmac=code_hmac,
            hmac_key_id=key_id,
            expires_at=func.now() + LIFETIME,
        )
    )
    return int(superseded.rowcount)  # type: ignore[attr-defined]


async def newest(session: AsyncSession, recipient_id: UUID) -> UUID | None:
    """The recipient's newest code, live or not: the only one a code is checked against."""
    return await newest_for(session, Subject.recipient(recipient_id))


async def newest_for(session: AsyncSession, subject: Subject) -> UUID | None:
    """The recipient's or uploader's newest code, live or not: the only one a code is checked
    against."""
    require_scope(session, ScopeKind.TENANT)
    found: UUID | None = await session.scalar(
        select(VerificationCode.id)
        .where(_of(subject), in_scope(VerificationCode, session))
        .order_by(VerificationCode.created_at.desc(), VerificationCode.id.desc())
        .limit(1)
    )
    return found


@dataclass(frozen=True, slots=True)
class Attempt:
    """An attempt taken on a live code: what to compare, and how many it has had now."""

    code_id: UUID
    code_hmac: bytes
    key_id: str
    attempts: int


async def take_attempt(session: AsyncSession, code_id: UUID) -> Attempt | None:
    """Step 2 (data model 2.4): count one attempt, if the code can still be used. None means it
    can't: used up, expired, superseded or used."""
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            update(VerificationCode)
            .where(
                VerificationCode.id == code_id,
                VerificationCode.attempts < MAX_ATTEMPTS,
                VerificationCode.superseded_at.is_(None),
                VerificationCode.consumed_at.is_(None),
                VerificationCode.expires_at > func.now(),
                in_scope(VerificationCode, session),
            )
            .values(attempts=VerificationCode.attempts + 1)
            .returning(
                VerificationCode.id,
                VerificationCode.code_hmac,
                VerificationCode.hmac_key_id,
                VerificationCode.attempts,
            )
            .execution_options(synchronize_session=False)
        )
    ).first()
    return None if row is None else Attempt(row[0], row[1], row[2], int(row[3]))


class Unusable(StrEnum):
    """Why a code can't be used: the contract's two codes."""

    EXPIRED = "code_expired"
    """Past its 10 minutes, superseded, already used, or no code was ever sent."""
    ATTEMPTS_EXHAUSTED = "code_attempts_exhausted"


async def why_unusable(session: AsyncSession, code_id: UUID | None) -> Unusable:
    if code_id is None:
        return Unusable.EXPIRED
    attempts = await session.scalar(
        select(VerificationCode.attempts).where(
            VerificationCode.id == code_id,
            VerificationCode.superseded_at.is_(None),
            VerificationCode.consumed_at.is_(None),
            VerificationCode.expires_at > func.now(),
            in_scope(VerificationCode, session),
        )
    )
    if attempts is not None and attempts >= MAX_ATTEMPTS:
        return Unusable.ATTEMPTS_EXHAUSTED
    return Unusable.EXPIRED


async def consume(session: AsyncSession, code_id: UUID) -> None:
    """Step 4: the code matched, and can't be used again."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(VerificationCode)
        .where(VerificationCode.id == code_id, in_scope(VerificationCode, session))
        .values(consumed_at=func.now())
        .execution_options(synchronize_session=False)
    )


# ---- the daily cleanup (sft_jobs, data model 6) ----


async def tenants_with_expired(
    session: AsyncSession, *, before: datetime, limit: int
) -> list[UUID]:
    """Tenants with codes past their expiry, across tenants, in system scope."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.scalars(
        select(VerificationCode.tenant_id)
        .where(VerificationCode.expires_at <= before, in_scope(VerificationCode, session))
        .group_by(VerificationCode.tenant_id)
        .limit(limit)
    )
    return list(rows)


async def delete_expired(session: AsyncSession, *, before: datetime, limit: int) -> int:
    """Delete up to `limit` of the scope's tenant's codes past their expiry: unusable from then
    (data model 6). The caller writes the audit event the table's trigger asks for."""
    require_scope(session, ScopeKind.TENANT)
    found = (
        select(VerificationCode.id)
        .where(VerificationCode.expires_at <= before, in_scope(VerificationCode, session))
        .limit(limit)
    )
    result = await session.execute(
        delete(VerificationCode)
        .where(
            VerificationCode.id.in_(found.scalar_subquery()), in_scope(VerificationCode, session)
        )
        .returning(VerificationCode.id)
        .execution_options(synchronize_session=False)
    )
    return len(result.all())
