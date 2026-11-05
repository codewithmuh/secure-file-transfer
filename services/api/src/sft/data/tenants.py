"""Data access for `tenants` and `tenant_policies` (data model 2.1).

Two ways in, by scope:

- **A tenant's own row, in its scope.** The API reads its caller's tenant, and a link session the
  tenant of its link. The operator API creates a tenant in the new tenant's scope, so the new row's
  ID is the scope's tenant, and suspends one in that tenant's scope (FR-34).
- **The tenant directory, in platform scope, for `sft_operator` only.** Listing tenants and
  reading one by ID are the operator API's only reads across tenants (authn and authz 7.2): its
  `operator_directory` policy lets `sft_operator` read `tenants` rows, and no other table, in
  platform scope. The directory functions refuse any other role or scope before the database
  does. Rows of a tenant's other tables stay out of reach: platform scope sets no tenant.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data import roles
from sft.data.access import ScopeNotAllowedError, in_scope, require_scope, tenant_of
from sft.data.models import Tenant, TenantPolicy
from sft.data.scope import ScopeKind

ACTIVE = "active"
SUSPENDED = "suspended"


async def get_tenant(session: AsyncSession, tenant_id: UUID) -> Tenant | None:
    """The tenant, if the session's scope reaches it: only the scope's own tenant ever does."""
    require_scope(session, ScopeKind.TENANT, ScopeKind.RESOURCE)
    statement = select(Tenant).where(Tenant.id == tenant_id, in_scope(Tenant, session))
    tenant: Tenant | None = await session.scalar(statement)
    return tenant


async def insert_tenant(
    session: AsyncSession, *, name: str, recovery_contact: str, default_locale: str
) -> Tenant | None:
    """A new active tenant with its policy, whose ID is the scope's tenant (FR-34).

    None if the scope's tenant exists already: nothing is written then. Commits only with an audit
    event in the same transaction (`audit_required`).
    """
    require_scope(session, ScopeKind.TENANT)
    tenant_id = tenant_of(session)
    tenant: Tenant | None = await session.scalar(
        pg_insert(Tenant)
        .values(id=tenant_id, name=name, status=ACTIVE, recovery_contact=recovery_contact)
        .on_conflict_do_nothing(index_elements=[Tenant.id])
        .returning(Tenant)
    )
    if tenant is not None:
        await session.execute(
            insert(TenantPolicy).values(tenant_id=tenant_id, default_locale=default_locale)
        )
    return tenant


async def suspend_tenant(session: AsyncSession) -> Tenant | None:
    """Suspend the scope's tenant, if it is active; None if it isn't (or doesn't exist)."""
    require_scope(session, ScopeKind.TENANT)
    tenant: Tenant | None = await session.scalar(
        update(Tenant)
        .where(Tenant.id == tenant_of(session), Tenant.status == ACTIVE, in_scope(Tenant, session))
        .values(status=SUSPENDED)
        .returning(Tenant)
        .execution_options(synchronize_session=False, populate_existing=True)
    )
    return tenant


def _require_directory(session: AsyncSession) -> None:
    require_scope(session, ScopeKind.PLATFORM)
    if session.info.get("role") != roles.OPERATOR:
        raise ScopeNotAllowedError("only the operator API reads the tenant directory")


async def directory_tenant(session: AsyncSession, tenant_id: UUID) -> Tenant | None:
    """One tenant from the directory, by ID: operator API only, platform scope."""
    _require_directory(session)
    tenant: Tenant | None = await session.scalar(select(Tenant).where(Tenant.id == tenant_id))
    return tenant


async def list_directory(
    session: AsyncSession,
    *,
    limit: int,
    status: str | None = None,
    before: UUID | None = None,
) -> list[Tenant]:
    """Tenants newest first, up to `limit`, after the tenant `before`: operator API only."""
    _require_directory(session)
    statement = select(Tenant).order_by(Tenant.id.desc()).limit(limit)
    if status is not None:
        statement = statement.where(Tenant.status == status)
    if before is not None:
        statement = statement.where(Tenant.id < before)
    return list((await session.scalars(statement)).all())
