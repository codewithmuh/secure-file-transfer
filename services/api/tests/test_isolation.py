"""The tenant isolation suite (NFR-12): each data-access function, given the other tenant's IDs.

One case per data-access function, and later per endpoint (delivery plan 2, point 3). The harness
is `isolation.py`; the README's "The isolation suite" says how to add a case.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from isolation import Cases, Tenants
from sft.data.access import in_scope
from sft.data.models import ProcessedMessage
from sft.data.outbox import (
    Queue,
    Topic,
    claim_due,
    enqueue,
    mark_failed,
    mark_published,
    oldest_unpublished_age,
)
from sft.data.processed import record_processed
from sft.data.roles import API, ARCHIVE, JOBS, NOTIFY, OPERATOR, RELAY, SCAN
from sft.data.scope import ScopeKind
from sft.data.tenants import get_tenant

TENANT, RESOURCE, SYSTEM = ScopeKind.TENANT, ScopeKind.RESOURCE, ScopeKind.SYSTEM

cases = Cases()


@cases.add(scopes={API: [TENANT, RESOURCE], OPERATOR: [TENANT]})
async def get_tenant_of_another_tenant(session: AsyncSession, tenants: Tenants) -> object:
    return await get_tenant(session, tenants.theirs.tenant_id)


# ---- the outbox and processed messages (#51) ----

ISOLATION_TOPIC = Topic("isolation.check", Queue.NOTIFY)

# Every role but the relay, in every scope it opens: none may read or mark outbox rows.
NOT_THE_RELAY = {
    API: [TENANT],
    OPERATOR: [TENANT],
    SCAN: [TENANT],
    NOTIFY: [TENANT],
    JOBS: [SYSTEM, TENANT],
    ARCHIVE: [SYSTEM],
}


@cases.add(scopes={API: [TENANT], OPERATOR: [TENANT], SCAN: [TENANT], JOBS: [TENANT]})
async def enqueue_names_no_other_tenant(session: AsyncSession, tenants: Tenants) -> object:
    # The tenant is the scope's, whatever IDs the payload carries.
    return await enqueue(session, ISOLATION_TOPIC, {"file_id": tenants.theirs.rows["outbox"]})


@cases.add(scopes={SCAN: [TENANT], NOTIFY: [TENANT]})
async def record_another_tenants_message(session: AsyncSession, tenants: Tenants) -> object:
    message_id = str(tenants.theirs.rows["processed_message"])
    return await record_processed(session, consumer="isolation", message_id=message_id)


@cases.add(scopes={SCAN: [TENANT], NOTIFY: [TENANT]})
async def read_processed_messages(session: AsyncSession, tenants: Tenants) -> object:
    query = select(ProcessedMessage.message_id).where(in_scope(ProcessedMessage, session))
    return (await session.scalars(query)).all()


@cases.add(scopes=NOT_THE_RELAY)
async def claim_another_tenants_messages(session: AsyncSession, tenants: Tenants) -> object:
    return await claim_due(session, 10)


@cases.add(scopes=NOT_THE_RELAY)
async def mark_another_tenants_message_published(session: AsyncSession, tenants: Tenants) -> object:
    await mark_published(session, [tenants.theirs.rows["outbox"]])
    return None


@cases.add(scopes=NOT_THE_RELAY)
async def mark_another_tenants_message_failed(session: AsyncSession, tenants: Tenants) -> object:
    await mark_failed(session, tenants.theirs.rows["outbox"], error="isolation", retry_in=1)
    return None


@cases.add(scopes={**NOT_THE_RELAY, RELAY: [SYSTEM]})
async def outbox_age(session: AsyncSession, tenants: Tenants) -> object:
    return await oldest_unpublished_age(session)


# The relay reads across tenants by design: its claim, in system scope, must change no one's rows.
@cases.add(scopes={RELAY: [SYSTEM]})
async def relay_claims_without_changing_anything(session: AsyncSession, tenants: Tenants) -> object:
    return await claim_due(session, 10)


test_isolation = cases.test()
