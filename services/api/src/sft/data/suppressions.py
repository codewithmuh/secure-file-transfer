"""Data access for `email_suppressions`, the tenant's own suppression list (data model 2.5; abuse
and rate limits 7.4).

An entry names an address by its pseudonym under the `email-hmac` keyring (`sft.core.pseudonyms`),
never by the address, and belongs to one tenant: a bounce or complaint on one tenant's email never
stops another tenant's (NFR-12). An entry suppresses while `expires_at` is empty or in the future.

- **A lookup** takes the address's pseudonym under every key version the keyring still holds, so an
  entry written under an older key is still found after a rotation (encryption and keys 6.5). The
  API looks addresses up in the tenant's scope; it may only read the table.
- **An entry is added** by the notification worker's role, which records SES's bounces and
  complaints from the `ses-events` queue (`sft.service.ses_events`, #185; ADR-0015); test fixtures
  and the local seed (#182) add them too. No API operation does. Each addition writes its audit
  event in the same transaction (`audit_required`).
- **Re-keying.** An entry found under an older key moves to the active key's pseudonym when the
  worker next records the address, because it holds the address then (encryption and keys 6.5).

Releasing an address from SES's own tenant list arrives with SES tenant management (ADR-0015).
"""

from __future__ import annotations

from collections.abc import Collection
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, or_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import EmailSuppression, SuppressionReason
from sft.data.scope import ScopeKind

TARGET = "email_suppression"
"""An entry's type in audit targets."""


async def suppressed(session: AsyncSession, pseudonyms: Collection[str]) -> set[str]:
    """Which of `pseudonyms` the scope's tenant suppresses now.

    Pass every pseudonym of every address to check, under each key version the keyring holds; the
    answer holds the ones with a live entry.
    """
    require_scope(session, ScopeKind.TENANT)
    if not pseudonyms:
        return set()
    rows = await session.scalars(
        select(EmailSuppression.email_hmac).where(
            EmailSuppression.email_hmac.in_(list(pseudonyms)),
            or_(EmailSuppression.expires_at.is_(None), EmailSuppression.expires_at > func.now()),
            in_scope(EmailSuppression, session),
        )
    )
    return set(rows)


async def add_suppression(
    session: AsyncSession,
    *,
    pseudonym: str,
    key_id: str,
    reason: SuppressionReason,
    expires_at: datetime | None = None,
) -> UUID:
    """Suppress the address of `pseudonym` (under the key `key_id`) for the scope's tenant.

    An entry for the same pseudonym is replaced: its reason and expiry are the new ones, and a
    second hard bounce counts in `bounce_count`. The caller writes the audit event.
    """
    require_scope(session, ScopeKind.TENANT)
    entry_id: UUID | None = await session.scalar(
        pg_insert(EmailSuppression)
        .values(
            id=uuid7(),
            tenant_id=tenant_of(session),
            email_hmac=pseudonym,
            hmac_key_id=key_id,
            reason=reason.value,
            expires_at=expires_at,
        )
        .on_conflict_do_update(
            index_elements=[EmailSuppression.tenant_id, EmailSuppression.email_hmac],
            set_={
                "reason": reason.value,
                "expires_at": expires_at,
                "bounce_count": EmailSuppression.bounce_count + 1,
                "updated_at": func.now(),
            },
        )
        .returning(EmailSuppression.id)
    )
    if entry_id is None:  # pragma: no cover - INSERT … ON CONFLICT DO UPDATE always returns it
        raise RuntimeError("the upsert returned no row")
    return entry_id


async def find_entry(session: AsyncSession, pseudonyms: Collection[str]) -> EmailSuppression | None:
    """The scope's tenant's entry for an address, live or ended, under any of `pseudonyms`."""
    require_scope(session, ScopeKind.TENANT)
    if not pseudonyms:
        return None
    entry: EmailSuppression | None = await session.scalar(
        select(EmailSuppression)
        .where(
            EmailSuppression.email_hmac.in_(list(pseudonyms)), in_scope(EmailSuppression, session)
        )
        .order_by(EmailSuppression.updated_at.desc())
        .limit(1)
    )
    return entry


async def rekey(session: AsyncSession, entry_id: UUID, *, pseudonym: str, key_id: str) -> None:
    """Move an entry made under an older key to `pseudonym` under `key_id`, the active key's."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(EmailSuppression)
        .where(EmailSuppression.id == entry_id, in_scope(EmailSuppression, session))
        .values(email_hmac=pseudonym, hmac_key_id=key_id, updated_at=func.now())
        .execution_options(synchronize_session=False)
    )
