"""Data access for `tenants` (data model 2.1).

M0 needs only the read: the API checks its caller's tenant, and a link session the tenant of its
link. Creating and suspending tenants arrive with the operator API in M1, with their audit events
(FR-27, FR-34).
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import in_scope
from sft.data.models import Tenant


async def get_tenant(session: AsyncSession, tenant_id: UUID) -> Tenant | None:
    """The tenant, if the session's scope reaches it: only the scope's own tenant ever does."""
    statement = select(Tenant).where(Tenant.id == tenant_id, in_scope(Tenant, session))
    tenant: Tenant | None = await session.scalar(statement)
    return tenant
