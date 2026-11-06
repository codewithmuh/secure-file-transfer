"""The tenant's policy: `getTenantPolicy` and `updateTenantPolicy` (FR-23, FR-3, FR-13, FR-18;
data model 2.1).

- **Reading** (`tenant_policy.read`): every member and admin, and an API key with
  `transfers:read` or `upload_requests:read`, so the web app can show the longest expiry before a
  transfer is made (authn and authz 6.3).
- **Changing** (`tenant_policy.update`): a tenant admin acting as one, so a local admin needs a
  passkey sign-in, and a sign-in in the last 15 minutes (step-up, authn and authz 3.3). Fields left
  out stay as they are. Every change writes `tenant_policy.updated` with the fields changed and
  their new values, all enums, numbers and durations, in the same transaction (FR-27).

What a change affects (FR-23): a shorter `max_expiry` applies to new transfers, and to a draft
when it is sent (`expiry_out_of_range`), never to a transfer already submitted. A new
`unscannable_policy` applies to files scanned after it (data model 3.1). A new
`received_file_retention_days` applies to files received from then on (FR-13).

The domain rules (FR-24) arrive in M5. Until then the policy shows no allowed or blocked domains,
and a change that sets any is refused with `422 validation_failed`, rather than stored and not
enforced.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from sft.core.errors import FieldError, Unprocessable, json_pointer
from sft.data import audit, tenants
from sft.data.audit import Origin, Target
from sft.data.database import Database
from sft.data.models import UnscannablePolicy
from sft.data.tenants import Policy
from sft.service.caller import Caller
from sft.service.permissions import authorize
from sft.service.transfers import MAX_EXPIRY, MIN_EXPIRY, tenant_scope

TENANT_POLICY: Final = "tenant_policy"


class Locale(StrEnum):
    EN = "en"
    JA = "ja"


@dataclass(frozen=True, slots=True)
class PolicyChange:
    """The fields of `TenantPolicyUpdate` that were sent; None leaves a field as it is."""

    max_expiry: timedelta | None = None
    unscannable_policy: UnscannablePolicy | None = None
    received_file_retention_days: int | None = None
    default_locale: str | None = None
    allowed_domains: Sequence[str] | None = None
    blocked_domains: Sequence[str] | None = None


def _invalid(field: str, detail: str) -> Unprocessable:
    return Unprocessable(
        "validation_failed", detail, errors=[FieldError(detail, pointer=json_pointer(field))]
    )


async def get_tenant_policy(database: Database, caller: Caller, *, now: datetime) -> Policy:
    """`getTenantPolicy`."""
    authorize(caller, "getTenantPolicy", now=now)
    async with database.transaction(tenant_scope(caller)) as session:
        return await tenants.get_policy(session)


async def update_tenant_policy(
    database: Database, caller: Caller, change: PolicyChange, *, origin: Origin, now: datetime
) -> Policy:
    """`updateTenantPolicy`: change the fields sent, audited (module docstring)."""
    authorize(caller, "updateTenantPolicy", now=now)
    if change.max_expiry is not None and not MIN_EXPIRY <= change.max_expiry <= MAX_EXPIRY:
        raise _invalid("max_expiry", "max_expiry is between 1 hour and 30 days.")
    for name in ("allowed_domains", "blocked_domains"):
        if getattr(change, name):
            raise _invalid(name, "Domain rules arrive with FR-24; none can be set yet.")
    scope = tenant_scope(caller)
    async with database.transaction(scope) as session:
        policy = await tenants.update_policy(
            session,
            max_expiry=change.max_expiry,
            unscannable_policy=change.unscannable_policy,
            received_file_retention_days=change.received_file_retention_days,
            default_locale=change.default_locale,
        )
        details: dict[str, audit.Detail] = {}
        if change.max_expiry is not None:
            details["max_expiry_seconds"] = int(change.max_expiry.total_seconds())
        if change.unscannable_policy is not None:
            details["unscannable_policy"] = change.unscannable_policy
        if change.received_file_retention_days is not None:
            details["received_file_retention_days"] = change.received_file_retention_days
        if change.default_locale is not None:
            details["default_locale"] = Locale(change.default_locale)
        assert scope.tenant_id is not None  # noqa: S101 - tenant_scope gives a tenant scope
        await audit.record(
            session,
            action="tenant_policy.updated",
            actor=caller.actor(),
            target=Target(TENANT_POLICY, scope.tenant_id),
            origin=origin,
            details=details,
        )
        return policy
