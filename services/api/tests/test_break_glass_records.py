"""The record of Identity Center break-glass grants (#239; FR-35; authn and authz 8.3):
`recordBreakGlassGrant` by the break-glass tool, and the reconciliation job that records from
CloudTrail what the tool didn't.

The acceptance criteria: the operation is implemented to the contract and audited (a
security-critical platform record and one in each named tenant's log); a retry of the same
assignment is answered with the first record; the job writes a missing record as
`reconciliation` and counts one still missing an hour after the grant, which alerts (promtool
tests in deploy/alerts/tests/break-glass-records.test.yaml). CloudTrail is a fake here: the AWS
side is pending the AWS run.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry, Counter

from member_fixtures import seed_tenant
from operators import FakeSts
from pg import ScratchDatabase
from sft.api.operator import jobs
from sft.api.operator.app import create_operator_app
from sft.core.settings import OperatorSettings
from sft.data.database import Database
from sft.runtime.break_glass_trail import assignments_from_events
from sft.service import break_glass_records
from sft.service.break_glass_records import (
    ReconcileResult,
    TrailAssignment,
    reconcile,
    review_due,
)
from test_break_glass import as_break_glass, events_of, token_as
from test_operator_api import bearer, settings_for

ACCOUNT_ID = "111111111111"
PERMISSION_SET = "arn:aws:sso:::permissionSet/ssoins-0123456789abcdef/ps-0123456789abcdef"


@pytest.fixture
def operator_app(migrated_db: ScratchDatabase) -> Iterator[TestClient]:
    with TestClient(create_operator_app(settings_for(migrated_db), sts=FakeSts())) as client:
        yield client


def grant(tenant_ids: Sequence[uuid.UUID], **fields: Any) -> dict[str, Any]:
    starts = datetime.now(UTC) - timedelta(minutes=5)
    return {
        "assignment_request_id": f"req-{uuid.uuid4()}",
        "requester": "alice@example.test",
        "approver": "bob@example.test",
        "incident_id": "INC-7",
        "reason": "Database repair during an outage",
        "tenant_ids": [str(t) for t in tenant_ids],
        "starts_at": starts.isoformat(),
        "ends_at": (starts + timedelta(hours=1)).isoformat(),
        **fields,
    }


def post(client: TestClient, token: str, body: dict[str, Any]) -> Any:
    return client.post("/v1/operator/break-glass-grants", json=body, headers=bearer(token))


def test_the_tool_records_a_grant_once_with_its_records(
    migrated_db: ScratchDatabase, operator_app: TestClient
) -> None:
    tenant = seed_tenant(migrated_db)
    token = token_as(operator_app, "carol@example.test")
    body = grant([tenant.id])
    first = post(operator_app, token, body)
    assert first.status_code == 201, first.text
    recorded = first.json()
    assert recorded["recorded_by"] == "tool"
    assert recorded["assignment_request_id"] == body["assignment_request_id"]
    assert recorded["tenant_ids"] == [str(tenant.id)]
    assert recorded["review_url"] is None
    starts = datetime.fromisoformat(body["starts_at"])
    assert datetime.fromisoformat(recorded["review_due_at"]) == review_due(starts)
    # A security-critical platform record, and one in the tenant's log.
    assert events_of(migrated_db, recorded["id"]) == [
        ("break_glass.recorded", True, True),
        ("break_glass.recorded", False, True),
    ]
    [(details,)] = migrated_db.sql(
        "SELECT details FROM audit_events WHERE target_id = :g AND tenant_id IS NULL",
        g=uuid.UUID(recorded["id"]),
    )
    assert details["recorded_by"] == "tool"
    assert details["operator_name"] == "carol@example.test"
    assert details["self_approved"] is False
    # The requester, approver, incident and reason stay in the row, never in an event.
    assert "alice" not in json.dumps(details)
    assert "INC-7" not in json.dumps(details)

    again = post(operator_app, token, body)
    assert again.status_code == 200
    assert again.json() == recorded
    assert len(events_of(migrated_db, recorded["id"])) == 2
    assert migrated_db.sql(
        "SELECT state, self_approved FROM break_glass_grants WHERE id = :g",
        g=uuid.UUID(recorded["id"]),
    ) == [("active", False)]


def test_a_recorded_grant_never_opens_the_database_to_sft_breakglass(
    migrated_db: ScratchDatabase, operator_app: TestClient
) -> None:
    tenant = seed_tenant(migrated_db)
    token = token_as(operator_app, "carol@example.test")
    recorded = post(operator_app, token, grant([tenant.id])).json()
    seen = as_break_glass(migrated_db, recorded["id"], "SELECT tenant_id FROM users")
    assert seen == []


def test_a_grant_is_checked(migrated_db: ScratchDatabase, operator_app: TestClient) -> None:
    tenant = seed_tenant(migrated_db)
    token = token_as(operator_app, "carol@example.test")
    starts = datetime.now(UTC)
    too_long = grant(
        [tenant.id],
        starts_at=starts.isoformat(),
        ends_at=(starts + timedelta(minutes=61)).isoformat(),
    )
    backwards = grant(
        [tenant.id],
        starts_at=starts.isoformat(),
        ends_at=(starts - timedelta(minutes=1)).isoformat(),
    )
    naive = grant([tenant.id], starts_at=starts.replace(tzinfo=None).isoformat())
    for body in (too_long, backwards, naive, grant([tenant.id], requester="")):
        response = post(operator_app, token, body)
        assert response.status_code == 422, body
    unknown = post(operator_app, token, grant([uuid.uuid4()]))
    assert (unknown.status_code, unknown.json()["code"]) == (422, "validation_failed")
    assert unknown.json()["errors"][0]["pointer"] == "#/tenant_ids/0"


def test_a_self_approved_grant_is_marked_and_a_past_one_is_expired(
    migrated_db: ScratchDatabase, operator_app: TestClient
) -> None:
    tenant = seed_tenant(migrated_db)
    token = token_as(operator_app, "carol@example.test")
    alone = post(operator_app, token, grant([tenant.id], approver="alice@example.test")).json()
    starts = datetime.now(UTC) - timedelta(hours=3)
    past = post(
        operator_app,
        token,
        grant(
            [tenant.id],
            starts_at=starts.isoformat(),
            ends_at=(starts + timedelta(minutes=30)).isoformat(),
        ),
    ).json()
    rows = {
        row[0]: row[1:]
        for row in migrated_db.sql(
            "SELECT id, state, self_approved, duration_minutes, ended_at = ends_at "
            "FROM break_glass_grants WHERE id IN (:a, :b)",
            a=uuid.UUID(alone["id"]),
            b=uuid.UUID(past["id"]),
        )
    }
    assert rows[uuid.UUID(alone["id"])] == ("active", True, 60, None)
    assert rows[uuid.UUID(past["id"])] == ("expired", False, 30, True)


def test_review_is_due_two_business_days_later() -> None:
    friday = datetime(2026, 11, 6, 9, 30, tzinfo=UTC)
    assert review_due(friday) == datetime(2026, 11, 10, 9, 30, tzinfo=UTC)  # Tuesday
    monday = datetime(2026, 11, 9, 9, 30, tzinfo=UTC)
    assert review_due(monday) == datetime(2026, 11, 11, 9, 30, tzinfo=UTC)
    saturday = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
    assert review_due(saturday) == datetime(2026, 11, 10, 9, 30, tzinfo=UTC)


# ---- the reconciliation ----


class FakeTrail:
    def __init__(self, assignments: Sequence[TrailAssignment]) -> None:
        self.assignments = list(assignments)
        self.since: list[datetime] = []

    async def break_glass_assignments(self, *, since: datetime) -> Sequence[TrailAssignment]:
        self.since.append(since)
        return self.assignments


def assignment(starts_ago: timedelta, **fields: Any) -> TrailAssignment:
    values: dict[str, Any] = {
        "assignment_request_id": f"req-{uuid.uuid4()}",
        "requester": "alice@example.test",
        "approver": "bob@example.test",
        "starts_at": datetime.now(UTC) - starts_ago,
        **fields,
    }
    return TrailAssignment(**values)


@pytest.mark.anyio
async def test_the_job_records_what_the_tool_didnt(
    migrated_db: ScratchDatabase, operator_app: TestClient, operator_db: Database
) -> None:
    tenant = seed_tenant(migrated_db)
    token = token_as(operator_app, "carol@example.test")
    by_tool = grant([tenant.id])
    post(operator_app, token, by_tool)
    known = assignment(
        timedelta(minutes=20),
        assignment_request_id=by_tool["assignment_request_id"],
        tenant_ids=(tenant.id,),
    )
    missing = assignment(
        timedelta(minutes=20),
        incident_id="INC-8",
        reason="Restore",
        tenant_ids=(tenant.id, uuid.uuid4()),  # one tenant that doesn't exist: dropped
        ends_at=datetime.now(UTC) + timedelta(hours=5),  # past the hour: the hour's end
    )
    bare = assignment(timedelta(hours=3))  # no removal schedule found: unknown incident
    broken = assignment(timedelta(hours=2), requester=" ")  # can't be recorded
    fresh_broken = assignment(timedelta(minutes=5), approver="")
    trail = FakeTrail([known, missing, bare, broken, fresh_broken])

    result = await reconcile(operator_db, trail)
    assert trail.since[0] <= datetime.now(UTC) - timedelta(hours=23)
    assert result.seen == 5
    assert result.reconciled == 2
    assert set(result.failed) == {
        broken.assignment_request_id,
        fresh_broken.assignment_request_id,
    }
    assert result.unrecorded == 1  # only the one that started more than an hour ago
    assert result.tenant_records_missed == 0

    rows = migrated_db.sql(
        "SELECT assignment_request_id, recorded_by, incident_id, tenant_ids, state, "
        "ends_at - starts_at FROM break_glass_grants WHERE assignment_request_id IN (:a, :b)",
        a=missing.assignment_request_id,
        b=bare.assignment_request_id,
    )
    found = {row[0]: row[1:] for row in rows}
    assert found[missing.assignment_request_id] == (
        "reconciliation",
        "INC-8",
        [tenant.id],
        "active",
        timedelta(hours=1),
    )
    assert found[bare.assignment_request_id][:4] == (
        "reconciliation",
        break_glass_records.UNKNOWN_INCIDENT,
        [],
        "expired",
    )
    [(grant_id,)] = migrated_db.sql(
        "SELECT id FROM break_glass_grants WHERE assignment_request_id = :a",
        a=missing.assignment_request_id,
    )
    assert events_of(migrated_db, str(grant_id)) == [
        ("break_glass.recorded", True, True),
        ("break_glass.recorded", False, True),
    ]
    [(details,)] = migrated_db.sql(
        "SELECT details FROM audit_events WHERE target_id = :g AND tenant_id IS NULL",
        g=grant_id,
    )
    assert details["job"] == "break_glass_reconciliation"
    assert details["recorded_by"] == "reconciliation"
    assert details["tenants_dropped"] == 1

    again = await reconcile(operator_db, trail)
    assert (again.reconciled, again.unrecorded) == (0, 1)


def test_cloudtrail_events_become_assignments() -> None:
    request_id = "e1b2c3d4-0000-4000-8000-000000000001"
    tenant = uuid.uuid4()

    def event(body: dict[str, Any]) -> dict[str, Any]:
        return {"CloudTrailEvent": json.dumps(body)}

    def assigned(**overrides: Any) -> dict[str, Any]:
        body: dict[str, Any] = {
            "eventTime": "2026-11-09T01:02:03Z",
            "userIdentity": {
                "arn": "arn:aws:sts::999999999999:assumed-role/"
                "AWSReservedSSO_BreakGlassApprover_0123456789abcdef/bob@example.test"
            },
            "requestParameters": {
                "targetId": ACCOUNT_ID,
                "targetType": "AWS_ACCOUNT",
                "permissionSetArn": PERMISSION_SET,
                "principalType": "USER",
                "principalId": "user-1",
            },
            "responseElements": {"accountAssignmentCreationStatus": {"requestId": request_id}},
        }
        body.update(overrides)
        return event(body)

    schedule = event(
        {
            "requestParameters": {
                "name": "sft-break-glass-INC-9",
                "description": json.dumps(
                    {
                        "assignment_request_id": request_id,
                        "reason": "Repair",
                        "tenant_ids": [str(tenant), "not-a-uuid"],
                    }
                ),
                "scheduleExpression": "at(2026-11-09T02:02:03)",
                "scheduleExpressionTimezone": "UTC",
            }
        }
    )
    other_account = assigned(
        requestParameters={
            "targetId": "222222222222",
            "permissionSetArn": PERMISSION_SET,
            "principalType": "USER",
            "principalId": "user-1",
        }
    )
    failed = assigned(errorCode="AccessDenied")
    found = assignments_from_events(
        [assigned(), other_account, failed, {"CloudTrailEvent": "not json"}],
        [schedule, event({"requestParameters": {"name": "someone-else"}})],
        account_id=ACCOUNT_ID,
        permission_set_arn=PERMISSION_SET,
        user_names={"user-1": "alice@example.test"},
    )
    assert found == [
        TrailAssignment(
            assignment_request_id=request_id,
            requester="alice@example.test",
            approver="bob@example.test",
            starts_at=datetime(2026, 11, 9, 1, 2, 3, tzinfo=UTC),
            ends_at=datetime(2026, 11, 9, 2, 2, 3, tzinfo=UTC),
            incident_id="INC-9",
            reason="Repair",
            tenant_ids=(tenant,),
        )
    ]


def test_the_metrics_follow_the_job() -> None:
    registry = CollectorRegistry()
    missed = Counter("missed_total", "test", registry=registry)
    metrics = jobs.RecordMetrics.create(registry, missed)
    assert registry.get_sample_value("sft_break_glass_unrecorded_assignments") == 0
    metrics.observe(ReconcileResult(seen=3, reconciled=2, unrecorded=1, tenant_records_missed=1))
    assert registry.get_sample_value("sft_break_glass_records_reconciled_total") == 2
    assert registry.get_sample_value("sft_break_glass_unrecorded_assignments") == 1
    assert registry.get_sample_value("missed_total") == 1
    stamp = registry.get_sample_value(
        "sft_break_glass_reconciliation_last_success_timestamp_seconds"
    )
    assert stamp is not None
    assert stamp > 0


@pytest.mark.anyio
async def test_the_operator_api_runs_the_job_where_the_environment_has_a_trail(
    migrated_db: ScratchDatabase, operator_db: Database
) -> None:
    settings = settings_for(migrated_db)
    registry = CollectorRegistry()
    missed = Counter("missed_total", "test", registry=registry)
    assert jobs.start(settings, operator_db, registry, missed) == []  # no trail, no drift pools
    trail = FakeTrail([])
    tasks = jobs.start(settings, operator_db, registry, missed, trail=trail)
    try:
        for _ in range(100):
            if registry.get_sample_value(
                "sft_break_glass_reconciliation_last_success_timestamp_seconds"
            ):
                break
            await asyncio.sleep(0.05)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    assert trail.since


def test_the_trail_settings_go_together(migrated_db: ScratchDatabase) -> None:
    fields = settings_for(migrated_db).model_dump()
    with pytest.raises(ValueError, match="go together"):
        OperatorSettings(
            **{**fields, "break_glass_trail_role_arn": "arn:aws:iam::999999999999:role/trail"}
        )
