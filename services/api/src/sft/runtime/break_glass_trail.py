"""CloudTrail's `BreakGlass` assignments, for the reconciliation job (#239; authn and authz 8.3).

The adapter behind `sft.service.break_glass_records.AssignmentTrail`. Identity Center lives in the
management account, so its events are in that account's trail: the operator API assumes a
read-only role there (`BREAK_GLASS_TRAIL_ROLE_ARN`, which may call `cloudtrail:LookupEvents` and
`identitystore:DescribeUser`, nothing else) and reads, from the Identity Center home Region:

- `CreateAccountAssignment` events that gave this environment's account the `BreakGlass`
  permission set (`BREAK_GLASS_PERMISSION_SET_ARN`) and didn't fail: the assignment request ID,
  the approver (the role session name of the `BreakGlassApprover` that called) and the time;
- the `CreateSchedule` events of the one-time removal schedules the break-glass tool makes, named
  `sft-break-glass-<incident ID>`, whose description is JSON naming the assignment request ID, the
  reason and the tenants (authn and authz 8.3). A schedule whose description isn't that JSON leaves
  the record with an unknown incident and reason, never without the record;
- the requester's Identity Center user name, from the assignment's principal ID.

boto3 is synchronous, so the calls run in a thread (`asyncio.to_thread`), as the other AWS adapters
do. Everything here is pending the AWS run; the parsing is unit-tested on recorded event shapes.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any, Final
from uuid import UUID

from sft.service.break_glass_records import TrailAssignment

ASSIGNMENT_EVENT: Final = "CreateAccountAssignment"
SCHEDULE_EVENT: Final = "CreateSchedule"
SCHEDULE_PREFIX: Final = "sft-break-glass-"
_SESSION_NAME = re.compile(r"assumed-role/[^/]+/(?P<name>[^/]+)$")
_AT = re.compile(r"^at\((?P<when>[0-9T:\-]+)\)$")


def _event(raw: Mapping[str, Any]) -> dict[str, Any]:
    """The event's own JSON, which LookupEvents returns as a string."""
    try:
        parsed = json.loads(str(raw.get("CloudTrailEvent") or "{}"))
    except ValueError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _schedules(events: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Each removal schedule's facts, by the assignment request ID its description names."""
    found: dict[str, dict[str, Any]] = {}
    for raw in events:
        event = _event(raw)
        params = event.get("requestParameters") or {}
        name = str(params.get("name") or "")
        if event.get("errorCode") or not name.startswith(SCHEDULE_PREFIX):
            continue
        try:
            described = json.loads(str(params.get("description") or ""))
        except ValueError:
            continue
        if not isinstance(described, dict) or not described.get("assignment_request_id"):
            continue
        tenant_ids = []
        for value in described.get("tenant_ids") or []:
            try:
                tenant_ids.append(UUID(str(value)))
            except ValueError:
                continue
        ends_at = None
        expression = _AT.match(str(params.get("scheduleExpression") or ""))
        if expression and str(params.get("scheduleExpressionTimezone") or "UTC") == "UTC":
            ends_at = _time(expression["when"] + "+00:00")
        found[str(described["assignment_request_id"])] = {
            "incident_id": name.removeprefix(SCHEDULE_PREFIX) or None,
            "reason": str(described.get("reason") or "") or None,
            "tenant_ids": tuple(tenant_ids),
            "ends_at": ends_at,
        }
    return found


def assignments_from_events(
    assignment_events: Iterable[Mapping[str, Any]],
    schedule_events: Iterable[Mapping[str, Any]],
    *,
    account_id: str,
    permission_set_arn: str,
    user_names: Mapping[str, str],
) -> list[TrailAssignment]:
    """The `BreakGlass` assignments to `account_id` in these events, with their schedules' facts.
    `user_names` maps Identity Center user IDs to user names; an unknown one stays the ID."""
    schedules = _schedules(schedule_events)
    found: dict[str, TrailAssignment] = {}
    for raw in assignment_events:
        event = _event(raw)
        params = event.get("requestParameters") or {}
        status = (event.get("responseElements") or {}).get("accountAssignmentCreationStatus") or {}
        request_id = status.get("requestId")
        if (
            event.get("errorCode")
            or params.get("permissionSetArn") != permission_set_arn
            or str(params.get("targetId")) != account_id
            or params.get("principalType") != "USER"
            or not request_id
        ):
            continue
        starts_at = _time(event.get("eventTime"))
        session = _SESSION_NAME.search(str((event.get("userIdentity") or {}).get("arn") or ""))
        if starts_at is None or session is None:
            continue
        principal = str(params.get("principalId") or "")
        facts = schedules.get(str(request_id), {})
        found[str(request_id)] = TrailAssignment(
            assignment_request_id=str(request_id),
            requester=user_names.get(principal, principal),
            approver=session["name"],
            starts_at=starts_at,
            ends_at=facts.get("ends_at"),
            incident_id=facts.get("incident_id"),
            reason=facts.get("reason"),
            tenant_ids=facts.get("tenant_ids", ()),
        )
    return list(found.values())


class CloudTrailAssignments:
    """The AWS side, through a role in the management account; credentials from the pod's role."""

    def __init__(
        self,
        *,
        role_arn: str,
        region: str,
        account_id: str,
        permission_set_arn: str,
        identity_store_id: str,
    ) -> None:
        self.role_arn = role_arn
        self.region = region
        self.account_id = account_id
        self.permission_set_arn = permission_set_arn
        self.identity_store_id = identity_store_id

    async def break_glass_assignments(self, *, since: datetime) -> Sequence[TrailAssignment]:
        call = contextvars.copy_context().run
        return await asyncio.to_thread(call, self._read, since)

    def _read(self, since: datetime) -> list[TrailAssignment]:  # pragma: no cover - AWS
        import boto3

        from sft.core.telemetry import trace_aws_client

        credentials = boto3.client("sts", region_name=self.region).assume_role(
            RoleArn=self.role_arn, RoleSessionName="sft-break-glass-reconciliation"
        )["Credentials"]
        session = boto3.session.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=self.region,
        )
        trail: Any = session.client("cloudtrail")
        store: Any = session.client("identitystore")
        trace_aws_client(trail)
        trace_aws_client(store)

        def lookup(name: str) -> list[Mapping[str, Any]]:
            pages = trail.get_paginator("lookup_events").paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": name}],
                StartTime=since,
            )
            return [event for page in pages for event in page.get("Events", [])]

        assignments, schedules = lookup(ASSIGNMENT_EVENT), lookup(SCHEDULE_EVENT)
        names: dict[str, str] = {}
        for raw in assignments:
            principal = str((_event(raw).get("requestParameters") or {}).get("principalId") or "")
            if principal and principal not in names:
                user = store.describe_user(IdentityStoreId=self.identity_store_id, UserId=principal)
                names[principal] = str(user.get("UserName") or principal)
        return assignments_from_events(
            assignments,
            schedules,
            account_id=self.account_id,
            permission_set_arn=self.permission_set_arn,
            user_names=names,
        )


__all__ = ["CloudTrailAssignments", "assignments_from_events"]
