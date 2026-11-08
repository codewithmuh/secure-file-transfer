"""The connection and identity lookups that sign-in resolves a caller with (data model 4.2), and
the writes of a local identity (authn and authz 2.5).

The lookups are credential lookups, in lookup scope, through `SECURITY DEFINER` functions that
return IDs and status only:

- `find_connection`: an `idp_connections` row by `provider_name`, the pool's ID or a tenant
  provider's name, never by an issuer string (data model 2.1);
- `find_identity`: a `user_identities` row by `(idp_connection_id, subject)`, with its user and
  that user's tenant.

The tenant of a sign-in comes from these rows, never from a token's claim.

The writes run in a tenant's scope (revision 0016):

- `pool_connection`: the user pool's own connection by its provider name, which the notification
  worker reads to record an identity; it reaches the pool rows only, never a tenant's provider.
- `record_identity`: the notification worker records `(pool connection, sub)` for a member once
  it has created their user in the pool, replacing their earlier identity on that pool.
- `delete_identities`: a sign-in reset removes the member's identities on the pool connections,
  so no old credential maps to them; the caller writes the reset's own audit event.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from sft.core.ids import uuid7
from sft.data.access import require_scope, tenant_of
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


async def pool_connection(session: AsyncSession, provider_name: str) -> Connection | None:
    """The user pool's connection named `provider_name`: a pool row (no tenant, `kind = 'local'`),
    read in a tenant's scope by the notification worker."""
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            text(
                "SELECT id, tenant_id, kind, status FROM idp_connections "
                "WHERE provider_name = :name AND tenant_id IS NULL AND kind = 'local'"
            ),
            {"name": provider_name},
        )
    ).first()
    return None if row is None else Connection(row[0], row[1], row[2], row[3])


async def record_identity(
    session: AsyncSession, *, user_id: UUID, connection_id: UUID, subject: str
) -> bool:
    """Bind the pool's `subject` to the user, in the scope's tenant, replacing any other identity
    of the user on that connection: one identity per user and pool, so a pool user created again
    leaves no orphan behind. False when the identity is there already: a redelivery of the
    message that wrote it, which writes nothing again. The caller writes the audit event of the
    transaction (the trigger requires one): the worker records it with the invitation's email,
    so the tenant's log reads the same whatever the pool answered (authn and authz 2.5)."""
    require_scope(session, ScopeKind.TENANT)
    tenant_id = tenant_of(session)
    await session.execute(
        text(
            "DELETE FROM user_identities WHERE tenant_id = :tenant AND user_id = :user "
            "AND idp_connection_id = :connection AND subject <> :subject"
        ),
        {"tenant": tenant_id, "user": user_id, "connection": connection_id, "subject": subject},
    )
    identity_id = uuid7()
    inserted = (
        await session.execute(
            text(
                "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
                "VALUES (:id, :tenant, :user, :connection, :subject) "
                "ON CONFLICT (idp_connection_id, subject) DO NOTHING RETURNING id"
            ),
            {
                "id": identity_id,
                "tenant": tenant_id,
                "user": user_id,
                "connection": connection_id,
                "subject": subject,
            },
        )
    ).first()
    return inserted is not None


async def delete_identities(
    session: AsyncSession, user_id: UUID, connection_ids: Sequence[UUID]
) -> int:
    """Delete the user's identities on `connection_ids`, in the scope's tenant; how many went.
    The caller writes the audit event of the change in the same transaction."""
    require_scope(session, ScopeKind.TENANT)
    if not connection_ids:
        return 0
    result = await session.execute(
        text(
            "DELETE FROM user_identities WHERE tenant_id = :tenant AND user_id = :user "
            "AND idp_connection_id = ANY(:connections)"
        ),
        {"tenant": tenant_of(session), "user": user_id, "connections": list(connection_ids)},
    )
    return int(result.rowcount or 0)  # type: ignore[attr-defined]
