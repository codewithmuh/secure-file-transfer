"""The isolation suite's cases for the operator API's scheduled work (#239): the break-glass
records and the SSO drift check's read. The harness is tests/isolation.py; the cases of the earlier
features are in tests/test_isolation.py.

- The drift check reads every tenant's `idp_connections` row in platform scope by design
  (revision 0038's `sso_drift_read`), as `sft_operator` only, and changes nothing.
- A break-glass record is a platform row: it holds no tenant row, and no tenant scope reaches it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from isolation import Cases, Tenants
from sft.data import break_glass_records, sso_drift
from sft.data.break_glass_records import RecordedGrant
from sft.data.roles import OPERATOR
from sft.data.scope import ScopeKind

PLATFORM, TENANT = ScopeKind.PLATFORM, ScopeKind.TENANT

cases = Cases()


@cases.add(scopes={OPERATOR: [PLATFORM]}, across=[PLATFORM])
async def read_every_tenants_recorded_sso_provider(
    session: AsyncSession, tenants: Tenants
) -> object:
    return await sso_drift.recorded_providers(session)


@cases.add(scopes={OPERATOR: [PLATFORM]})
async def break_glass_records_hold_no_tenant_rows(
    session: AsyncSession, tenants: Tenants
) -> object:
    starts = datetime.now(UTC) - timedelta(minutes=5)
    request_id = f"isolation-{uuid.uuid4()}"
    inserted = await break_glass_records.insert_recorded(
        session,
        RecordedGrant(
            assignment_request_id=request_id,
            requester="isolation",
            approver="isolation",
            incident_id="isolation",
            reason="isolation",
            tenant_ids=[],
            starts_at=starts,
            ends_at=starts + timedelta(hours=1),
            duration_minutes=60,
            recorded_by="tool",
            review_due_at=starts + timedelta(days=2),
            expired=False,
        ),
    )
    return [
        inserted is not None,
        await break_glass_records.find_by_assignment(session, request_id) is not None,
        sorted(await break_glass_records.recorded_assignments(session, {request_id})),
    ]


test_isolation_operator_jobs = cases.test()
