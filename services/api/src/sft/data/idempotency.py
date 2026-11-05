"""Data access for `idempotency_keys`: what a creating `POST` did (architecture 5.4).

A row is a caller's key: `(caller_type, caller_id, key)`, the fingerprint of the request that used
it, the status it answered and the resource it created. The service (`sft.service.idempotency`)
decides what a retry gets; this module only reads and writes rows:

- `lock` takes a transaction-scoped advisory lock on the key, without waiting. While the first
  request holds it, a second one with the same key can't, and is told the first is in progress.
  The lock ends with the transaction, which also commits or discards the row.
- `find` reads the key's live row; an expired one counts as none.
- `save` writes the row, in the transaction that created the resource. It overwrites an expired
  row of the same key, so a key works again after 24 hours, before the daily job deletes it.
- `tenants_with_expired` and `delete_expired` are the daily job's (`sft_jobs`): find across in
  system scope, then delete within each tenant's scope.

Every function filters with `in_scope` and writes the scope's tenant, like every data-access
function; the key's caller is the service's to choose.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import delete, func, select, text, tuple_
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import IdempotencyKey
from sft.data.scope import ScopeKind

LIFETIME: Final = timedelta(hours=24)
"""How long a key is kept (API README 5)."""

FINGERPRINT_BYTES: Final = 32
"""A SHA-256 digest."""


@dataclass(frozen=True, slots=True)
class Stored:
    """A live key's row: the request it was used for, and what that request answered."""

    fingerprint: bytes
    status: int
    resource_type: str
    resource_id: UUID


async def lock(session: AsyncSession, caller_type: str, caller_id: UUID, key: str) -> bool:
    """Take the key's advisory lock for this transaction, if no other transaction holds it."""
    require_scope(session, ScopeKind.TENANT, ScopeKind.RESOURCE)
    name = f"idempotency/{tenant_of(session)}/{caller_type}/{caller_id}/{key}"
    taken = await session.scalar(
        text("SELECT pg_try_advisory_xact_lock(hashtextextended(:name, 0))"), {"name": name}
    )
    return bool(taken)


async def find(session: AsyncSession, caller_type: str, caller_id: UUID, key: str) -> Stored | None:
    """The key's row, if it hasn't expired."""
    statement = select(
        IdempotencyKey.request_fingerprint,
        IdempotencyKey.response_status,
        IdempotencyKey.resource_type,
        IdempotencyKey.resource_id,
    ).where(
        IdempotencyKey.caller_type == caller_type,
        IdempotencyKey.caller_id == caller_id,
        IdempotencyKey.key == key,
        IdempotencyKey.expires_at > func.now(),
        in_scope(IdempotencyKey, session),
    )
    row = (await session.execute(statement)).first()
    return None if row is None else Stored(bytes(row[0]), row[1], row[2], row[3])


async def save(
    session: AsyncSession,
    caller_type: str,
    caller_id: UUID,
    key: str,
    *,
    fingerprint: bytes,
    status: int,
    resource_type: str,
    resource_id: UUID,
) -> bool:
    """Record what the key's request did, for `LIFETIME`, in the scope's tenant.

    Returns False, writing nothing, if the key already has a live row: the caller didn't hold the
    key's lock, or its row was written by another transaction first.
    """
    require_scope(session, ScopeKind.TENANT, ScopeKind.RESOURCE)
    if len(fingerprint) != FINGERPRINT_BYTES:
        raise ValueError("a request fingerprint is a 32-byte SHA-256 digest")
    values = {
        "request_fingerprint": fingerprint,
        "response_status": status,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "created_at": func.now(),
        "expires_at": func.now() + LIFETIME,
    }
    statement = (
        insert(IdempotencyKey)
        .values(
            tenant_id=tenant_of(session),
            caller_type=caller_type,
            caller_id=caller_id,
            key=key,
            **values,
        )
        .on_conflict_do_update(
            index_elements=[
                IdempotencyKey.caller_type,
                IdempotencyKey.caller_id,
                IdempotencyKey.key,
            ],
            set_=values,
            # Only an expired row of this tenant gives way.
            where=(IdempotencyKey.expires_at <= func.now())
            & (IdempotencyKey.tenant_id == tenant_of(session)),
        )
        .returning(IdempotencyKey.key)
    )
    return (await session.scalar(statement)) is not None


# ---- the daily job (data model 6) ----


async def tenants_with_expired(session: AsyncSession, *, limit: int = 1000) -> Sequence[UUID]:
    """The tenants that have expired keys: the job's find step, in system scope."""
    require_scope(session, ScopeKind.SYSTEM)
    statement = (
        select(IdempotencyKey.tenant_id)
        .where(IdempotencyKey.expires_at <= func.now(), in_scope(IdempotencyKey, session))
        .group_by(IdempotencyKey.tenant_id)
        .order_by(IdempotencyKey.tenant_id)
        .limit(limit)
    )
    return (await session.scalars(statement)).all()


async def delete_expired(session: AsyncSession, *, limit: int = 1000) -> int:
    """Delete up to `limit` expired keys of the scope's tenant; how many went."""
    require_scope(session, ScopeKind.TENANT)
    pk = tuple_(IdempotencyKey.caller_type, IdempotencyKey.caller_id, IdempotencyKey.key)
    expired = (
        select(IdempotencyKey.caller_type, IdempotencyKey.caller_id, IdempotencyKey.key)
        .where(IdempotencyKey.expires_at <= func.now(), in_scope(IdempotencyKey, session))
        .limit(limit)
    )
    result = await session.execute(
        delete(IdempotencyKey)
        .where(pk.in_(expired), in_scope(IdempotencyKey, session))
        .execution_options(synchronize_session=False)
    )
    return int(result.rowcount)  # type: ignore[attr-defined]
