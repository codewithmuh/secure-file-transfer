"""The tenant isolation suite (NFR-12): each data-access function, given the other tenant's IDs.

One case per data-access function, and later per endpoint (delivery plan 2, point 3). The harness
is `isolation.py`; the README's "The isolation suite" says how to add a case.
"""

from sqlalchemy.ext.asyncio import AsyncSession

from isolation import Cases, Tenants
from sft.data.roles import API, OPERATOR
from sft.data.scope import ScopeKind
from sft.data.tenants import get_tenant

TENANT, RESOURCE = ScopeKind.TENANT, ScopeKind.RESOURCE

cases = Cases()


@cases.add(scopes={API: [TENANT, RESOURCE], OPERATOR: [TENANT]})
async def get_tenant_of_another_tenant(session: AsyncSession, tenants: Tenants) -> object:
    return await get_tenant(session, tenants.theirs.tenant_id)


test_isolation = cases.test()
