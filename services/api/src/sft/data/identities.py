"""The connection and identity lookups that sign-in resolves a caller with (data model 4.2).

Both are credential lookups, in lookup scope, through `SECURITY DEFINER` functions that return IDs
and status only:

- `find_connection`: an `idp_connections` row by `provider_name`, the pool's ID or a tenant
  provider's name, never by an issuer string (data model 2.1);
- `find_identity`: a `user_identities` row by `(idp_connection_id, subject)`, with its user and
  that user's tenant.

The tenant of a sign-in comes from these rows, never from a token's claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import require_scope
from sft.data.scope import ScopeKind


@dataclass(frozen=True, slots=True)
class Connection:
    id: UUID
    tenant_id: UUID | None
    """Empty for one of the platform's pools."""
    kind: str
    status: str


@dataclass(frozen=True, slots=True)
class Identity:
    id: UUID
    tenant_id: UUID
    user_id: UUID
    expires_at: datetime | None


async def find_connection(session: AsyncSession, provider_name: str) -> Connection | None:
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text(
                "SELECT connection_id, owner_tenant_id, kind, status "
                "FROM lookup_idp_connection(:name)"
            ),
            {"name": provider_name},
        )
    ).first()
    return None if row is None else Connection(row[0], row[1], row[2], row[3])


async def find_identity(
    session: AsyncSession, connection_id: UUID, subject: str
) -> Identity | None:
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text(
                "SELECT identity_id, owner_tenant_id, user_id, expires_at "
                "FROM lookup_user_identity(:connection, :subject)"
            ),
            {"connection": connection_id, "subject": subject},
        )
    ).first()
    return None if row is None else Identity(row[0], row[1], row[2], row[3])
