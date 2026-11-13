"""The isolation suite's cases for the operator's idempotency keys (#160) and admin recoveries
(#239). The harness is tests/isolation.py; the cases of the earlier features are in
tests/test_isolation.py.

- An operator's key is written and found in a tenant's scope, and found across tenants only in
  platform scope, by design (revision 0036's `operator_find`), as `sft_operator`.
- A recovery, its reset's identities and its records stay in their tenant: the operator, the
  notification worker and the daily job reach another tenant's in no tenant scope; the job's find
  step reads across tenants in system scope, by design, and changes nothing.
- A tenant's recovery contact (#274) is read in that tenant's scope only.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from isolation import Cases, Tenants
from sft.data import admin_recoveries, audit, idempotency, identities
from sft.data import tenants as tenants_data
from sft.data.audit import Actor, ActorType, Target
from sft.data.models import AdminRecoveryKind
from sft.data.roles import JOBS, NOTIFY, OPERATOR
from sft.data.scope import ScopeKind

PLATFORM, SYSTEM, TENANT = ScopeKind.PLATFORM, ScopeKind.SYSTEM, ScopeKind.TENANT
LATER = datetime.now(UTC) + timedelta(days=30)

cases = Cases()


@cases.add(scopes={OPERATOR: [TENANT]})
async def find_another_tenants_operator_key(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs
    owner = theirs.rows["operator_key_owner"]
    return await idempotency.find(session, idempotency.OPERATOR, owner, theirs.marker)


@cases.add(scopes={OPERATOR: [TENANT]})
async def write_over_another_tenants_operator_key(
    session: AsyncSession, tenants: Tenants
) -> object:
    theirs = tenants.theirs
    saved = await idempotency.save_operator(
        session,
        theirs.rows["operator_key_owner"],
        theirs.marker,
        fingerprint=bytes(32),
        status=201,
        resource_type="tenant",
        resource_id=tenants.mine.tenant_id,
    )
    taken = await idempotency.lock_operator(session, theirs.rows["operator_key_owner"], "x")
    return [saved, taken]


@cases.add(scopes={OPERATOR: [PLATFORM]}, across=[PLATFORM])
async def find_an_operator_key_across_tenants(session: AsyncSession, tenants: Tenants) -> object:
    # By design: the operator finds its key before the tenant it made is known.
    theirs = tenants.theirs
    return await idempotency.find_operator(
        session, theirs.rows["operator_key_owner"], theirs.marker
    )


@cases.add(scopes={OPERATOR: [TENANT], NOTIFY: [TENANT], JOBS: [TENANT]})
async def read_another_tenants_admin_recovery(session: AsyncSession, tenants: Tenants) -> object:
    return await admin_recoveries.get_recovery(session, tenants.theirs.rows["admin_recovery"])


@cases.add(scopes={OPERATOR: [TENANT]})
async def recover_another_tenants_user(session: AsyncSession, tenants: Tenants) -> object:
    theirs = tenants.theirs
    removed = await identities.delete_pool_identities(session, theirs.rows["user"])
    critical = await audit.latest_critical_event(
        session, action="user.sign_in_reset", target=Target("user", theirs.rows["user"])
    )
    recovery = await admin_recoveries.insert_recovery(
        session,
        recovery_id=uuid.uuid4(),
        user_id=theirs.rows["user"],
        kind=AdminRecoveryKind.SIGN_IN_RESET,
        confirmed_via="isolation",
        operator_name="isolation",
        sign_in_reset_id=uuid.uuid4(),
        lasts=None,
    )
    return [removed, critical, recovery]


@cases.add(scopes={OPERATOR: [TENANT]})
async def read_another_tenants_recovery_contact(session: AsyncSession, tenants: Tenants) -> object:
    # #274: read in the tenant's own scope only; the harness's contact holds their marker.
    return await tenants_data.recovery_contact(session, tenants.theirs.tenant_id)


@cases.add(scopes={JOBS: [TENANT]})
async def end_another_tenants_temporary_sign_in(session: AsyncSession, tenants: Tenants) -> object:
    ended = await admin_recoveries.end_temporary(session, before=LATER)
    # As the job does: the change's event in its transaction, which the audit trigger requires.
    await audit.record(
        session, action="user.temporary_sign_in_ended", actor=Actor(ActorType.SYSTEM)
    )
    return ended


@cases.add(scopes={JOBS: [SYSTEM]})
async def find_ended_temporary_sign_ins(session: AsyncSession, tenants: Tenants) -> object:
    # Across tenants by design: the job's find step, which must change nothing.
    return await admin_recoveries.tenants_with_ended(session, before=LATER)


test_isolation_operator_recovery = cases.test()
