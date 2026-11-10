"""The recorded SSO configuration of every tenant, for the daily drift check (#239; authn and authz
2.5).

`sft_operator` reads the tenants' `idp_connections` rows in platform scope through the
`sso_drift_read` policy (revision 0038): the kind, the provider's name, the issuer and the status,
nothing else of a tenant. It is the one read across tenants the operator API makes besides the
tenant directory, and it changes nothing.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sft.data.access import require_scope
from sft.data.models import IdpConnection
from sft.data.scope import ScopeKind


@dataclass(frozen=True, slots=True)
class RecordedProvider:
    connection_id: UUID
    tenant_id: UUID
    kind: str
    """`oidc` or `saml`."""
    provider_name: str
    issuer: str
    status: str


async def recorded_providers(session: AsyncSession) -> Sequence[RecordedProvider]:
    """Every tenant's connection, as `configureTenantSso` recorded it."""
    require_scope(session, ScopeKind.PLATFORM)
    rows = await session.execute(
        select(
            IdpConnection.id,
            IdpConnection.tenant_id,
            IdpConnection.kind,
            IdpConnection.provider_name,
            IdpConnection.issuer,
            IdpConnection.status,
        )
        .where(IdpConnection.tenant_id.is_not(None))
        .order_by(IdpConnection.provider_name)
    )
    return [
        RecordedProvider(row[0], row[1], row[2], row[3], row[4], row[5])
        for row in rows.all()
        if row[1] is not None
    ]


__all__ = ["RecordedProvider", "recorded_providers"]
