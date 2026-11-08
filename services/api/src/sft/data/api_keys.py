"""Tenant API keys: created by an admin, checked on every request that carries one, revoked
(authn and authz 5; data model 2.1; #215).

A key is 256 random bits with a fixed prefix and a checksum (`sft.service.api_keys` makes and
parses it). The database holds only its SHA-256 (`key_hash`) and `key_prefix`.

- `lookup_key` is the credential lookup (data model 4.2): in lookup scope, the key's ID and tenant
  by the hash, across tenants, and nothing else. The request then continues in that tenant's scope
  with `live_key`, which checks everything else: not revoked, not expired, its owner an active
  admin and its tenant active. Lookups aren't cached, so a revocation applies to the next request.
- `last_used_at` moves at most once an hour (`TOUCH_INTERVAL`), in `live_key`'s transaction.
- Revocation sets `revoked_at` and `revoked_reason`. The audit trigger requires an audit event in
  the same transaction for every creation and revocation; these functions write none themselves,
  because the action that causes them (`api_key.created`, `api_key.revoked`) does.
- The daily job finds keys close to expiry across tenants in system scope (`expiring`), then
  records each notice in the key's tenant scope (`mark_notice`).
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final
from uuid import UUID

from sqlalchemy import func, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import ApiKey, ApiKeyRevokedReason, Role, Tenant, User, UserStatus
from sft.data.scope import ScopeKind

TOUCH_INTERVAL: Final = timedelta(hours=1)
"""`last_used_at` moves at most this often (data model 2.1)."""
TARGET: Final = "api_key"
"""A key's type in audit targets."""

__all__ = [
    "TARGET",
    "TOUCH_INTERVAL",
    "Expiring",
    "FoundKey",
    "LiveKey",
    "NoticeKey",
    "count_active",
    "expiring",
    "get_key",
    "insert_key",
    "list_keys",
    "live_key",
    "lookup_key",
    "mark_first_export",
    "mark_notice",
    "notice_key",
    "owner_keys",
    "revoke_key",
    "revoke_owner_keys",
]


@dataclass(frozen=True, slots=True)
class FoundKey:
    """What the credential lookup returns: IDs only, never the hash."""

    key_id: UUID
    tenant_id: UUID


@dataclass(frozen=True, slots=True)
class LiveKey:
    """A key that passed every check of authn and authz 5.2."""

    key_id: UUID
    tenant_id: UUID
    owner_id: UUID
    scopes: frozenset[str]


@dataclass(frozen=True, slots=True)
class Expiring:
    """A key the daily job may email about: its tenant, ID, expiry and last notice."""

    tenant_id: UUID
    key_id: UUID
    expires_at: datetime
    expiry_notice: int | None


@dataclass(frozen=True, slots=True)
class NoticeKey:
    """What the notification worker reads of a key: no hash, no name."""

    key_id: UUID
    owner_id: UUID
    key_prefix: str
    expires_at: datetime
    revoked: bool


async def lookup_key(session: AsyncSession, key_hash: bytes) -> FoundKey | None:
    """The key with this hash and its tenant: the credential lookup. None if no key has it."""
    require_scope(session, ScopeKind.LOOKUP)
    row = (
        await session.execute(
            text("SELECT api_key_id, owner_tenant_id FROM lookup_api_key(:hash)"),
            {"hash": key_hash},
        )
    ).first()
    return None if row is None else FoundKey(row[0], row[1])


async def live_key(session: AsyncSession, key_id: UUID) -> LiveKey | None:
    """The key, if it is live: not revoked, not expired, its owner an active admin and its tenant
    active. Moves `last_used_at` when it is an hour old."""
    require_scope(session, ScopeKind.TENANT)
    now = func.now()
    statement = (
        select(ApiKey)
        .join(User, (User.tenant_id == ApiKey.tenant_id) & (User.id == ApiKey.created_by))
        .join(Tenant, Tenant.id == ApiKey.tenant_id)
        .where(
            ApiKey.id == key_id,
            in_scope(ApiKey, session),
            in_scope(User, session),
            in_scope(Tenant, session),
            ApiKey.revoked_at.is_(None),
            ApiKey.expires_at > now,
            User.status == UserStatus.ACTIVE.value,
            User.role == Role.ADMIN.value,
            Tenant.status == "active",
        )
    )
    found: ApiKey | None = await session.scalar(statement)
    if found is None:
        return None
    await session.execute(
        update(ApiKey)
        .where(
            ApiKey.id == found.id,
            in_scope(ApiKey, session),
            or_(ApiKey.last_used_at.is_(None), ApiKey.last_used_at <= now - TOUCH_INTERVAL),
        )
        .values(last_used_at=now)
        .execution_options(synchronize_session=False)
    )
    return LiveKey(found.id, found.tenant_id, found.created_by, frozenset(found.scopes))


async def count_active(session: AsyncSession) -> int:
    """The scope's tenant's keys that are neither revoked nor expired (at most 25, 5.2)."""
    require_scope(session, ScopeKind.TENANT)
    value = await session.scalar(
        select(func.count())
        .select_from(ApiKey)
        .where(
            in_scope(ApiKey, session),
            ApiKey.revoked_at.is_(None),
            ApiKey.expires_at > func.now(),
        )
    )
    return int(value or 0)


async def insert_key(
    session: AsyncSession,
    *,
    key_id: UUID,
    created_by: UUID,
    name: str,
    key_prefix: str,
    key_hash: bytes,
    scopes: Sequence[str],
    expires_at: datetime,
) -> ApiKey:
    """A new key of the scope's tenant, owned by `created_by`. The caller writes the event."""
    require_scope(session, ScopeKind.TENANT)
    key = ApiKey(
        id=key_id,
        tenant_id=tenant_of(session),
        created_by=created_by,
        name=name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        scopes=list(scopes),
        expires_at=expires_at,
    )
    session.add(key)
    await session.flush()
    await session.refresh(key)
    return key


async def list_keys(
    session: AsyncSession, *, before: UUID | None = None, limit: int
) -> list[ApiKey]:
    """Up to `limit` of the scope's tenant's keys, newest first (IDs are UUIDv7), after `before`."""
    require_scope(session, ScopeKind.TENANT)
    statement = select(ApiKey).where(in_scope(ApiKey, session))
    if before is not None:
        statement = statement.where(ApiKey.id < before)
    return list((await session.scalars(statement.order_by(ApiKey.id.desc()).limit(limit))).all())


async def get_key(
    session: AsyncSession, key_id: UUID, *, for_update: bool = False
) -> ApiKey | None:
    """One key of the scope's tenant, or None."""
    require_scope(session, ScopeKind.TENANT)
    statement = select(ApiKey).where(ApiKey.id == key_id, in_scope(ApiKey, session))
    if for_update:
        statement = statement.with_for_update()
    key: ApiKey | None = await session.scalar(statement.execution_options(populate_existing=True))
    return key


async def revoke_key(
    session: AsyncSession, key_id: UUID, *, reason: ApiKeyRevokedReason
) -> ApiKey | None:
    """Revoke a live key of the scope's tenant; None if it is unknown or revoked already."""
    require_scope(session, ScopeKind.TENANT)
    key: ApiKey | None = await session.scalar(
        update(ApiKey)
        .where(ApiKey.id == key_id, in_scope(ApiKey, session), ApiKey.revoked_at.is_(None))
        .values(revoked_at=func.now(), revoked_reason=reason.value)
        .returning(ApiKey)
        .execution_options(populate_existing=True, synchronize_session=False)
    )
    return key


async def revoke_owner_keys(
    session: AsyncSession, user_id: UUID, *, reason: ApiKeyRevokedReason
) -> list[UUID]:
    """Revoke every key `user_id` owns that isn't revoked yet, expired ones included, so none can
    come back; their IDs."""
    require_scope(session, ScopeKind.TENANT)
    rows = await session.scalars(
        update(ApiKey)
        .where(
            ApiKey.created_by == user_id,
            in_scope(ApiKey, session),
            ApiKey.revoked_at.is_(None),
        )
        .values(revoked_at=func.now(), revoked_reason=reason.value)
        .returning(ApiKey.id)
        .execution_options(synchronize_session=False)
    )
    return list(rows.all())


async def owner_keys(
    session: AsyncSession, user_id: UUID, *, reason: ApiKeyRevokedReason
) -> list[UUID]:
    """The keys of `user_id` revoked for `reason`: what a retried deactivation re-archives."""
    require_scope(session, ScopeKind.TENANT)
    rows = await session.scalars(
        select(ApiKey.id).where(
            ApiKey.created_by == user_id,
            in_scope(ApiKey, session),
            ApiKey.revoked_reason == reason.value,
        )
    )
    return list(rows.all())


async def expiring(
    session: AsyncSession, *, now: datetime, within: timedelta, limit: int
) -> list[Expiring]:
    """Live keys of every tenant that expire within `within` of `now`: the daily job's find step,
    in system scope. The caller decides which notice each is due."""
    require_scope(session, ScopeKind.SYSTEM)
    rows = await session.execute(
        select(ApiKey.tenant_id, ApiKey.id, ApiKey.expires_at, ApiKey.expiry_notice)
        .where(
            in_scope(ApiKey, session),
            ApiKey.revoked_at.is_(None),
            ApiKey.expires_at > now,
            ApiKey.expires_at <= now + within,
        )
        .order_by(ApiKey.expires_at)
        .limit(limit)
    )
    return [Expiring(row[0], row[1], row[2], row[3]) for row in rows]


async def mark_notice(
    session: AsyncSession, key_id: UUID, *, stage: int, before: int | None
) -> bool:
    """Record that the `stage`-day notice is asked for, if the key's last notice is still
    `before` and it is live: a second run, or a run racing this one, finds it changed."""
    require_scope(session, ScopeKind.TENANT)
    last = ApiKey.expiry_notice.is_(None) if before is None else ApiKey.expiry_notice == before
    result = await session.execute(
        update(ApiKey)
        .where(ApiKey.id == key_id, in_scope(ApiKey, session), last, ApiKey.revoked_at.is_(None))
        .values(expiry_notice=stage)
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


async def mark_first_export(session: AsyncSession, key_id: UUID) -> bool:
    """Record the key's first audit export; False if it exported before (#216)."""
    require_scope(session, ScopeKind.TENANT)
    result = await session.execute(
        update(ApiKey)
        .where(
            ApiKey.id == key_id,
            in_scope(ApiKey, session),
            ApiKey.first_exported_at.is_(None),
        )
        .values(first_exported_at=func.now())
        .execution_options(synchronize_session=False)
    )
    return bool(result.rowcount)  # type: ignore[attr-defined]


async def notice_key(session: AsyncSession, key_id: UUID) -> NoticeKey | None:
    """What an email about the key may say: its owner, prefix and expiry, and whether it is
    revoked. Never its hash or its name."""
    require_scope(session, ScopeKind.TENANT)
    row = (
        await session.execute(
            select(
                ApiKey.id,
                ApiKey.created_by,
                ApiKey.key_prefix,
                ApiKey.expires_at,
                ApiKey.revoked_at,
            ).where(ApiKey.id == key_id, in_scope(ApiKey, session))
        )
    ).first()
    if row is None:
        return None
    return NoticeKey(row[0], row[1], row[2], row[3], row[4] is not None)
