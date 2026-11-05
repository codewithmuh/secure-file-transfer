"""Data access for `tenant_usage`: the storage quota's reservations (data model 2.5, abuse 6.1).

A limit is enforced by one conditional statement, never by reading and then writing (data model 1),
so parallel declarations can't pass the quota together: they serialise on the tenant's row. The
tenant is always the scope's.
"""

from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope, require_scope, tenant_of
from sft.data.models import TenantUsage
from sft.data.scope import ScopeKind


async def reserve_storage(session: AsyncSession, nbytes: int, *, quota: int) -> bool:
    """Reserve `nbytes` for the scope's tenant if its total stays within `quota`; False if not.

    The tenant's row is made by its first reservation.
    """
    require_scope(session, ScopeKind.TENANT)
    if nbytes < 1:
        raise ValueError("reserve at least one byte")
    if nbytes > quota:
        return False
    statement = insert(TenantUsage).values(tenant_id=tenant_of(session), bytes_reserved=nbytes)
    statement = statement.on_conflict_do_update(
        index_elements=[TenantUsage.tenant_id],
        set_={"bytes_reserved": TenantUsage.bytes_reserved + nbytes},
        where=(TenantUsage.bytes_reserved + nbytes <= quota) & in_scope(TenantUsage, session),
    )
    result = await session.execute(statement.returning(TenantUsage.bytes_reserved))
    return result.first() is not None


async def release_storage(session: AsyncSession, nbytes: int) -> None:
    """Release a reservation, once per file: when it is rejected or removed (data model 2.5)."""
    require_scope(session, ScopeKind.TENANT)
    await session.execute(
        update(TenantUsage)
        .where(TenantUsage.tenant_id == tenant_of(session), in_scope(TenantUsage, session))
        .values(bytes_reserved=TenantUsage.bytes_reserved - nbytes)
    )


async def reserved_bytes(session: AsyncSession) -> int:
    """What the scope's tenant has reserved; 0 before its first reservation."""
    value = await session.scalar(
        select(TenantUsage.bytes_reserved).where(in_scope(TenantUsage, session))
    )
    return int(value or 0)
