"""DLP approvals (#220; FR-43, FR-44, FR-54; architecture 4.6; data model 2.7, 3.2, 3.6; authn and
authz 3.3, 5.3, 6.3; threat model T-100, T-104, T-106): `confirmTransfer`'s approval path, the
approval queue and request page, `approveTransfer` and `rejectTransfer`, the withdrawals, the
expiry job, the emails, the approver designation and the audit trail.

Real PostgreSQL through the routes as `sft_api`, the notification worker as `sft_notify` and the
expiry job as `sft_jobs`. Tenants have the default policy, with "My Numbers" changed to require
approval; the admin and the target are approvers, the member (the sender) isn't, unless a test
says so. Recipients are at `example.test`, which the tenant knows, so only the My Number rule
matches.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2 as httpx
import pytest
from prometheus_client import CollectorRegistry

from member_fixtures import Tenant, client, seed_tenant, session_caller
from notify_fixtures import Sent, drain, elapse, notifier
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.models import Role
from sft.data.roles import JOBS, NOTIFY
from sft.service import lifecycle
from sft.service.caller import AuthMethod, Caller, CallerKind
from sft.service.lifecycle import JobMetrics, Jobs
from transfer_fixtures import actions, outbox_topics, seed_file, seed_transfer, transfer_row

pytestmark = pytest.mark.anyio

KNOWN = "aiko@example.test"
JUSTIFICATION = "Quarterly payroll for the auditor, zebra-justification"
COMMENT = "Too many identifiers, zebra-comment"
FILE_NAME = "payroll-2026.xlsx"


@dataclass
class World:
    db: ScratchDatabase
    tenant: Tenant
    http: httpx.AsyncClient
    current: list[Caller | None]

    def act_as(self, caller: Caller | None) -> None:
        self.current[0] = caller

    @property
    def sender(self) -> Caller:
        return session_caller(self.tenant.id, self.tenant.member, Role.MEMBER)

    @property
    def approver(self) -> Caller:
        return session_caller(self.tenant.id, self.tenant.target, Role.MEMBER)

    @property
    def admin(self) -> Caller:
        return session_caller(self.tenant.id, self.tenant.admin, Role.ADMIN)

    def key(self, *scopes: str) -> Caller:
        return Caller(
            CallerKind.API_KEY,
            tenant_id=self.tenant.id,
            user_id=self.tenant.member,
            credential_id=uuid.uuid4(),
            scopes=frozenset(scopes),
        )

    def approvers(self, *user_ids: uuid.UUID) -> None:
        """Exactly these users have the designation."""
        self.db.sql(
            "UPDATE users SET dlp_approver = (id = ANY(:ids)) WHERE tenant_id = :t",
            ids=list(user_ids),
            t=self.tenant.id,
        )

    def needing_approval(self, owner: uuid.UUID | None = None) -> uuid.UUID:
        """A draft with a file that has a My Number, ready to send."""
        transfer_id, _ = seed_transfer(
            self.db, self.tenant.id, owner or self.tenant.member, recipients=(KNOWN,)
        )
        self.file(transfer_id)
        return transfer_id

    def file(self, transfer_id: uuid.UUID) -> uuid.UUID:
        file_id = seed_file(
            self.db, self.tenant.id, transfer_id, state="clean", inspection_state="inspected"
        )
        self.db.sql(
            "UPDATE files SET display_name_ct = '\\x00'::bytea || convert_to(:name, 'UTF8') "
            "WHERE id = :id",
            name=FILE_NAME,
            id=file_id,
        )
        self.db.sql(
            "INSERT INTO dlp_findings (id, tenant_id, file_id, detector, count_low, count_medium, "
            "count_high) VALUES (:id, :t, :f, 'jp_my_number', 0, 0, 1)",
            id=uuid.uuid4(),
            t=self.tenant.id,
            f=file_id,
        )
        return file_id

    async def call(
        self, caller: Caller, method: str, path: str, body: object = None
    ) -> httpx.Response:
        self.act_as(caller)
        return await self.http.request(method, path, json=body)

    async def awaiting(self, owner: uuid.UUID | None = None) -> tuple[uuid.UUID, str]:
        """A transfer awaiting confirmation of a required approval, and its decision."""
        transfer_id = self.needing_approval(owner)
        sent = await self.call(self.sender, "POST", f"/v1/transfers/{transfer_id}/send")
        assert sent.status_code == 200, sent.text
        body = sent.json()
        assert (body["state"], body["dlp"]["outcome"]) == (
            "awaiting_confirmation",
            "require_approval",
        )
        return transfer_id, self.decision_of(transfer_id)

    def decision_of(self, transfer_id: uuid.UUID) -> str:
        [(decision,)] = self.db.sql(
            "SELECT dlp_decision_id FROM transfers WHERE id = :id", id=transfer_id
        )
        return str(decision)

    async def confirm(
        self,
        transfer_id: uuid.UUID,
        decision_id: str,
        justification: str | None = JUSTIFICATION,
        *,
        caller: Caller | None = None,
    ) -> httpx.Response:
        body: dict[str, object] = {"decision_id": decision_id}
        if justification is not None:
            body["justification"] = justification
        return await self.call(
            caller or self.sender, "POST", f"/v1/transfers/{transfer_id}/confirm", body
        )

    async def pending(self, owner: uuid.UUID | None = None) -> tuple[uuid.UUID, str]:
        """A transfer pending approval, and its request."""
        transfer_id, decision = await self.awaiting(owner)
        confirmed = await self.confirm(transfer_id, decision)
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json()["state"] == "pending_approval"
        return transfer_id, str(confirmed.json()["dlp"]["approval_request_id"])

    async def approve(
        self, request_id: str, caller: Caller | None = None, comment: str | None = None
    ) -> httpx.Response:
        body = {} if comment is None else {"comment": comment}
        path = f"/v1/dlp/approval-requests/{request_id}/approve"
        return await self.call(caller or self.approver, "POST", path, body)

    async def reject(
        self, request_id: str, caller: Caller | None = None, comment: str | None = COMMENT
    ) -> httpx.Response:
        body = {} if comment is None else {"comment": comment}
        path = f"/v1/dlp/approval-requests/{request_id}/reject"
        return await self.call(caller or self.approver, "POST", path, body)

    def request_states(self, transfer_id: uuid.UUID) -> list[object]:
        return [
            state
            for (state,) in self.db.sql(
                "SELECT state FROM dlp_approval_requests WHERE transfer_id = :id "
                "ORDER BY created_at, id",
                id=transfer_id,
            )
        ]

    def details(self, target: object, action: str) -> list[dict[str, Any]]:
        return [
            dict(details)  # type: ignore[call-overload]
            for (details,) in self.db.sql(
                "SELECT details FROM audit_events WHERE target_id = :id AND action = :a "
                "ORDER BY occurred_at, id",
                id=uuid.UUID(str(target)),
                a=action,
            )
        ]

    def address(self, user_id: uuid.UUID) -> str:
        [(email,)] = self.db.sql("SELECT email FROM users WHERE id = :id", id=user_id)
        return str(email)


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    current: list[Caller | None] = [None]
    tenant = seed_tenant(migrated_db)
    async with client(migrated_db, lambda: current[0]) as http:
        world = World(migrated_db, tenant, http, current)
        world.approvers(tenant.admin, tenant.target)
        [(rule,)] = migrated_db.sql(
            "SELECT id FROM dlp_rules WHERE tenant_id = :t AND name = 'My Numbers' "
            "AND retired_at IS NULL",
            t=tenant.id,
        )
        changed = await world.call(
            world.admin, "PATCH", f"/v1/dlp/rules/{rule}", {"action": "require_approval"}
        )
        assert changed.status_code == 200, changed.text
        yield world


async def emails(db: ScratchDatabase, tenant_id: uuid.UUID) -> Sent:
    """Every email the notification worker sends for the tenant's pending messages."""
    sent = Sent()
    database = Database.connect(db.url(NOTIFY), pool_size=1)
    try:
        await drain(notifier(database, sent), db, tenant_id)
    finally:
        await database.dispose()
    return sent


async def run_expiry(db: ScratchDatabase, at: datetime) -> dict[str, int]:
    database = Database.connect(db.url(JOBS), pool_size=1)
    try:
        jobs = Jobs(database, JobMetrics.create(CollectorRegistry()), lambda: at)
        await lifecycle.RUNS[lifecycle.Job.EXPIRY](jobs)
        return jobs.report
    finally:
        await database.dispose()


def every_record(db: ScratchDatabase, tenant_id: uuid.UUID) -> str:
    return json.dumps(
        db.sql(
            "SELECT action, details, target_type FROM audit_events WHERE tenant_id = :t",
            t=tenant_id,
        ),
        default=str,
    )


# ---- the acceptance criteria of #220 ----


async def test_an_approver_who_isnt_the_sender_approves_and_the_recipients_are_emailed(
    w: World,
) -> None:
    transfer_id, decision = await w.awaiting()
    await emails(w.db, w.tenant.id)  # the sender's dlp_confirmation_needed

    missing = await w.confirm(transfer_id, decision, None)
    assert (missing.status_code, missing.json()["code"]) == (422, "justification_required")
    assert missing.json()["errors"][0]["pointer"] == "#/justification"
    confirmed = await w.confirm(transfer_id, decision)
    assert confirmed.status_code == 200, confirmed.text
    body = confirmed.json()
    assert (body["state"], body["dlp"]["outcome"]) == ("pending_approval", "require_approval")
    request_id = body["dlp"]["approval_request_id"]
    assert w.request_states(transfer_id) == ["pending"]
    # A retry of the same confirmation returns the transfer and asks nobody again.
    again = await w.confirm(transfer_id, decision)
    assert (again.status_code, again.json()["state"]) == (200, "pending_approval")
    assert w.request_states(transfer_id) == ["pending"]

    # Each approver but the sender is emailed, with no file name and no approve link.
    sent = await emails(w.db, w.tenant.id)
    asked = sent.of_type("dlp_approval_requested")
    assert {e.to for e in asked} == {w.address(w.tenant.admin), w.address(w.tenant.target)}
    for email in asked:
        assert "/approve" not in email.text
        assert JUSTIFICATION not in email.text
    assert sent.to(KNOWN) == []

    # The sender's view of the decision shows the request in brief.
    shown = await w.call(w.sender, "GET", f"/v1/transfers/{transfer_id}/dlp")
    summary = shown.json()["approval_request"]
    assert (summary["id"], summary["state"], summary["approvals"]) == (request_id, "pending", 0)
    assert (summary["approvals_required"], summary["rule_names"]) == (1, ["My Numbers"])
    assert summary["requested_by"] == str(w.tenant.member)

    # The approver's queue and the request page.
    queue = await w.call(w.approver, "GET", "/v1/dlp/approval-requests")
    assert [i["id"] for i in queue.json()["items"]] == [request_id]
    page = await w.call(w.approver, "GET", f"/v1/dlp/approval-requests/{request_id}")
    assert page.status_code == 200, page.text
    request = page.json()
    assert (request["justification"], request["can_decide"]) == (JUSTIFICATION, True)
    assert request["transfer"]["created_by"] == str(w.tenant.member)
    [recipient] = request["transfer"]["recipients"]
    assert (recipient["email"], recipient["trusted"], recipient["new_domain"]) == (
        KNOWN,
        False,
        False,
    )
    [file] = request["transfer"]["files"]
    assert (file["display_name"], file["size"]) == (FILE_NAME, 10)
    assert all(file["display_name"] not in email.text for email in asked)
    assert file["inspection"]["detectors"] == ["jp_my_number"]
    assert [r["name"] for r in request["matched_rules"]] == ["My Numbers"]
    assert request["decisions"] == []
    # An approver reads the findings of a transfer with a request (authn and authz 6.3).
    findings = await w.call(w.approver, "GET", f"/v1/transfers/{transfer_id}/dlp")
    assert findings.status_code == 200, findings.text

    approved = await w.approve(request_id, comment="Fine for the auditor")
    assert approved.status_code == 200, approved.text
    assert (approved.json()["state"], approved.json()["approvals"]) == ("approved", 1)
    assert approved.json()["can_decide"] is False
    assert transfer_row(w.db, transfer_id)["state"] == "sent"
    assert w.db.sql(
        "SELECT delivery_state FROM transfer_recipients WHERE transfer_id = :id", id=transfer_id
    ) == [("queued",)]
    # Approving again returns it unchanged.
    repeat = await w.approve(request_id, comment="Fine for the auditor")
    assert (repeat.status_code, repeat.json()["state"]) == (200, "approved")
    assert w.db.sql(
        "SELECT count(*) FROM dlp_approval_decisions WHERE approval_request_id = :id",
        id=request_id,
    ) == [(1,)]
    assert actions(w.db, transfer_id).count("transfer.sent") == 1

    sent = await emails(w.db, w.tenant.id)
    assert [e.email_type for e in sent.to(KNOWN)] == ["transfer_link"]
    [decided] = sent.to(w.address(w.tenant.member))
    assert decided.email_type == "dlp_approval_decided"
    assert "Fine for the auditor" not in decided.text

    # An approver who has decided still reads the decision; the sender reads the request.
    after = await w.call(w.approver, "GET", f"/v1/transfers/{transfer_id}/dlp")
    assert after.json()["approval_request"]["state"] == "approved"
    own = await w.call(w.sender, "GET", f"/v1/dlp/approval-requests/{request_id}")
    assert own.json()["decisions"][0]["comment"] == "Fine for the auditor"
    assert own.json()["decisions"][0]["approver_id"] == str(w.tenant.target)
    transfer = await w.call(w.sender, "GET", f"/v1/transfers/{transfer_id}")
    assert transfer.json()["dlp"]["approval_request_id"] == request_id


async def test_a_rejection_holds_the_transfer_and_emails_the_sender(w: World) -> None:
    transfer_id, request_id = await w.pending()
    await emails(w.db, w.tenant.id)

    bare = await w.reject(request_id, comment=None)
    assert (bare.status_code, bare.json()["code"]) == (422, "validation_failed")
    rejected = await w.reject(request_id)
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["state"] == "rejected"
    assert rejected.json()["decisions"][0]["comment"] == COMMENT
    row = transfer_row(w.db, transfer_id)
    assert (row["state"], row["hold_reason"]) == ("held", "approval_rejected")
    assert (await w.reject(request_id)).status_code == 200  # the same rejection again
    approve_after = await w.approve(request_id)
    assert (approve_after.status_code, approve_after.json()["code"]) == (409, "invalid_state")

    sent = await emails(w.db, w.tenant.id)
    [decided] = sent.to(w.address(w.tenant.member))
    assert decided.email_type == "dlp_approval_decided"
    assert COMMENT not in decided.text
    assert sent.to(KNOWN) == []

    # The decision stands: confirming again is refused, and only a removal decides again.
    again = await w.confirm(transfer_id, w.decision_of(transfer_id))
    assert (again.status_code, again.json()["code"]) == (409, "invalid_state")
    own = await w.call(w.sender, "GET", f"/v1/transfers/{transfer_id}/dlp")
    assert own.json()["approval_request"]["state"] == "rejected"


async def test_an_expired_request_returns_the_transfer_and_a_fourth_request_is_refused(
    w: World,
) -> None:
    transfer_id, decision = await w.awaiting()
    later = datetime.now(UTC) + timedelta(hours=73)  # past the default 72-hour timeout
    for number in range(1, 4):
        confirmed = await w.confirm(transfer_id, decision)
        assert confirmed.status_code == 200, confirmed.text
        request_id = confirmed.json()["dlp"]["approval_request_id"]
        await emails(w.db, w.tenant.id)
        report = await run_expiry(w.db, later)
        assert report["approval_requests_expired"] >= 1  # other tests' tenants' too
        assert transfer_row(w.db, transfer_id)["state"] == "awaiting_confirmation"
        assert w.request_states(transfer_id) == ["expired"] * number
        [expired] = w.details(request_id, "dlp_approval.expired")
        assert (expired["reason"], expired["returned"]) == ("approval_timeout", True)
        sent = await emails(w.db, w.tenant.id)
        assert [e.email_type for e in sent.to(w.address(w.tenant.member))] == [
            "dlp_approval_expired"
        ]
    fourth = await w.confirm(transfer_id, decision)
    assert (fourth.status_code, fourth.json()["code"]) == (409, "approval_limit_reached")
    assert transfer_row(w.db, transfer_id)["state"] == "awaiting_confirmation"
    assert len(w.request_states(transfer_id)) == 3


async def test_a_request_expires_with_its_transfer_without_returning_it(w: World) -> None:
    transfer_id, request_id = await w.pending()
    await emails(w.db, w.tenant.id)
    [(expires_at,)] = w.db.sql("SELECT expires_at FROM transfers WHERE id = :id", id=transfer_id)
    [(request_expiry,)] = w.db.sql(
        "SELECT expires_at FROM dlp_approval_requests WHERE id = :id", id=request_id
    )
    # 72 hours is before the transfer's 7 days: the request's expiry is the earlier one.
    assert request_expiry < expires_at  # type: ignore[operator]
    await run_expiry(w.db, expires_at + timedelta(minutes=1))  # type: ignore[operator]
    assert transfer_row(w.db, transfer_id)["state"] == "expired"
    assert w.request_states(transfer_id) == ["expired"]
    [record] = w.details(request_id, "dlp_approval.expired")
    assert (record["reason"], record["returned"]) == ("transfer_expired", False)
    sent = await emails(w.db, w.tenant.id)
    assert sent.of_type("dlp_approval_expired") == []


async def test_a_second_pending_request_is_impossible(w: World) -> None:
    transfer_id, decision = await w.awaiting()
    first, second = await asyncio.gather(
        w.confirm(transfer_id, decision), w.confirm(transfer_id, decision)
    )
    assert (first.status_code, second.status_code) == (200, 200)
    assert w.request_states(transfer_id) == ["pending"]
    # The partial unique index refuses a second pending request whatever writes it.
    [(request,)] = w.db.sql(
        "SELECT confirmation_id FROM dlp_approval_requests WHERE transfer_id = :id",
        id=transfer_id,
    )
    with pytest.raises(Exception, match="dlp_approval_requests_pending_transfer_id_key"):
        w.db.sql(
            "INSERT INTO dlp_approval_requests (id, tenant_id, transfer_id, decision_id, "
            "confirmation_id, requested_by, approvals_required, expires_at) VALUES "
            "(gen_random_uuid(), :t, :x, :d, :c, :u, 1, now() + interval '1 day')",
            t=w.tenant.id,
            x=transfer_id,
            d=decision,
            c=request,
            u=w.tenant.member,
        )


async def test_no_self_approval_even_for_an_api_keys_transfer(w: World) -> None:
    # The sender is an approver too: still not of their own transfer (T-100).
    w.approvers(w.tenant.admin, w.tenant.target, w.tenant.member)
    _, request_id = await w.pending()
    own = await w.approve(request_id, caller=w.sender)
    assert (own.status_code, own.json()["code"]) == (403, "self_approval_forbidden")
    reject_own = await w.reject(request_id, caller=w.sender)
    assert (reject_own.status_code, reject_own.json()["code"]) == (403, "self_approval_forbidden")
    page = await w.call(w.sender, "GET", f"/v1/dlp/approval-requests/{request_id}")
    assert page.json()["can_decide"] is False
    queue = await w.call(w.sender, "GET", "/v1/dlp/approval-requests?scope=queue")
    assert queue.json()["items"] == []

    # A transfer an API key made and sent: its owner is the sender, so can't approve it.
    key = w.key("transfers:write", "transfers:read")
    made = await w.call(key, "POST", "/v1/transfers", {"recipients": [{"email": KNOWN}]})
    assert made.status_code == 201, made.text
    transfer_id = uuid.UUID(made.json()["id"])
    w.file(transfer_id)
    sent = await w.call(key, "POST", f"/v1/transfers/{transfer_id}/send")
    assert sent.json()["state"] == "awaiting_confirmation"
    confirmed = await w.confirm(transfer_id, w.decision_of(transfer_id))
    assert confirmed.status_code == 200, confirmed.text
    key_request = confirmed.json()["dlp"]["approval_request_id"]
    by_owner = await w.approve(key_request, caller=w.sender)
    assert (by_owner.status_code, by_owner.json()["code"]) == (403, "self_approval_forbidden")
    assert transfer_row(w.db, transfer_id)["state"] == "pending_approval"
    assert (await w.approve(key_request)).status_code == 200


async def test_api_keys_get_403_on_every_approval_operation(w: World) -> None:
    transfer_id, decision = await w.awaiting()
    key = w.key("transfers:read", "transfers:write", "audit:read")
    refused = await w.confirm(transfer_id, decision, caller=key)
    assert (refused.status_code, refused.json()["code"]) == (403, "permission_denied")
    _, request_id = await w.pending()
    base = f"/v1/dlp/approval-requests/{request_id}"
    for method, path, body in (
        ("GET", "/v1/dlp/approval-requests", None),
        ("GET", base, None),
        ("POST", f"{base}/approve", {}),
        ("POST", f"{base}/reject", {"comment": "No"}),
    ):
        response = await w.call(key, method, path, body)
        assert (response.status_code, response.json()["code"]) == (403, "permission_denied"), path


async def test_who_may_decide(w: World, migrated_db: ScratchDatabase) -> None:
    _, request_id = await w.pending()
    # Approving needs a sign-in in the last 15 minutes; rejecting doesn't.
    stale = session_caller(
        w.tenant.id, w.tenant.target, Role.MEMBER, signed_in=timedelta(minutes=16)
    )
    old = await w.approve(request_id, caller=stale)
    assert (old.status_code, old.json()["code"]) == (401, "reauthentication_required")
    # A member who isn't an approver: 403; another tenant's approver: 404.
    w.approvers(w.tenant.admin)
    target = await w.approve(request_id)
    assert (target.status_code, target.json()["code"]) == (403, "permission_denied")
    other = seed_tenant(migrated_db)
    migrated_db.sql("UPDATE users SET dlp_approver = true WHERE id = :id", id=other.admin)
    outsider = session_caller(other.id, other.admin, Role.ADMIN)
    assert (await w.approve(request_id, caller=outsider)).status_code == 404
    assert (await w.reject(request_id, caller=outsider)).status_code == 404
    page = await w.call(outsider, "GET", f"/v1/dlp/approval-requests/{request_id}")
    assert page.status_code == 404
    # An admin with the designation (not an admin right: a TOTP sign-in will do) approves.
    totp = session_caller(w.tenant.id, w.tenant.admin, Role.ADMIN, AuthMethod.PASSWORD_TOTP)
    assert (await w.approve(request_id, caller=totp)).status_code == 200


async def test_only_the_sender_as_approver_refuses_and_tells_the_admins(w: World) -> None:
    transfer_id, decision = await w.awaiting()
    await emails(w.db, w.tenant.id)
    w.approvers(w.tenant.member)  # designations changed since the rule was made
    refused = await w.confirm(transfer_id, decision)
    assert (refused.status_code, refused.json()["code"]) == (409, "no_eligible_approver")
    # Nothing changed but the admins' notice and the refusal's record.
    assert transfer_row(w.db, transfer_id)["state"] == "awaiting_confirmation"
    assert w.request_states(transfer_id) == []
    assert w.db.sql(
        "SELECT count(*) FROM dlp_confirmations WHERE transfer_id = :id", id=transfer_id
    ) == [(0,)]
    assert outbox_topics(w.db, "transfer_id", transfer_id)[-1] == (
        "dlp_approval.no_eligible_approver"
    )
    [(outcome, details)] = w.db.sql(
        "SELECT outcome, details FROM audit_events WHERE target_id = :id "
        "AND action = 'dlp_approval.requested'",
        id=transfer_id,
    )
    assert outcome == "failure"
    assert details["reason"] == "no_eligible_approver"  # type: ignore[index]
    sent = await emails(w.db, w.tenant.id)
    assert [e.to for e in sent.of_type("dlp_no_eligible_approver")] == [w.address(w.tenant.admin)]


@pytest.mark.parametrize("how", ["remove", "revoke", "cancel"])
async def test_removing_a_file_revoking_or_cancelling_withdraws_the_request(
    w: World, how: str
) -> None:
    transfer_id, request_id = await w.pending()
    if how == "remove":
        extra = w.file(transfer_id)
        response = await w.call(w.sender, "DELETE", f"/v1/files/{extra}")
        assert response.status_code == 204, response.text
        # A new decision on the files left: approval again, under a new decision.
        assert transfer_row(w.db, transfer_id)["state"] == "awaiting_confirmation"
    else:
        response = await w.call(w.sender, "POST", f"/v1/transfers/{transfer_id}/{how}")
        assert response.status_code == 200, response.text
    assert w.request_states(transfer_id) == ["withdrawn"]
    [record] = w.details(request_id, "dlp_approval.withdrawn")
    reason = {"remove": "file_removed", "revoke": "revoked", "cancel": "cancelled"}[how]
    assert (record["reason"], record["transfer_id"]) == (reason, str(transfer_id))
    refused = await w.approve(request_id)
    assert (refused.status_code, refused.json()["code"]) == (
        409,
        "invalid_state" if how != "revoke" else "transfer_revoked",
    )


async def test_every_step_is_audited_without_the_text(w: World) -> None:
    transfer_id, request_id = await w.pending()
    assert (await w.approve(request_id, comment=COMMENT)).status_code == 200
    rejected_transfer, rejected_request = await w.pending()
    assert (await w.reject(rejected_request)).status_code == 200
    withdrawn_transfer, withdrawn_request = await w.pending()
    revoke = f"/v1/transfers/{withdrawn_transfer}/revoke"
    assert (await w.call(w.sender, "POST", revoke)).status_code == 200

    assert actions(w.db, uuid.UUID(request_id)) == [
        "dlp_approval.requested",
        "dlp_approval.approved",
    ]
    assert actions(w.db, uuid.UUID(rejected_request)) == [
        "dlp_approval.requested",
        "dlp_approval.rejected",
    ]
    assert actions(w.db, uuid.UUID(withdrawn_request)) == [
        "dlp_approval.requested",
        "dlp_approval.withdrawn",
    ]
    [approved] = w.details(request_id, "dlp_approval.approved")
    assert (approved["approvals"], approved["complete"], approved["comment_given"]) == (
        1,
        True,
        True,
    )
    assert "transfer.held" in actions(w.db, rejected_transfer)
    [confirmed] = w.details(transfer_id, "transfer.confirmed")
    assert confirmed["justification_given"] is True
    assert confirmed["approval_request_id"] == request_id
    records = every_record(w.db, w.tenant.id)
    assert "zebra" not in records  # neither the justification nor a comment
    # The text is stored sealed, not in any other column.
    assert w.db.sql(
        "SELECT count(*) FROM dlp_approval_decisions WHERE tenant_id = :t "
        "AND comment_ct IS NOT NULL",
        t=w.tenant.id,
    ) == [(2,)]


async def test_the_approver_designation_is_audited_and_emailed_to_admins(w: World) -> None:
    await emails(w.db, w.tenant.id)
    path = f"/v1/users/{w.tenant.member}"
    changed = await w.call(w.admin, "PATCH", path, {"dlp_approver": True})
    assert changed.status_code == 200, changed.text
    assert changed.json()["dlp_approver"] is True
    assert actions(w.db, w.tenant.member)[-1] == "user.dlp_approver_changed"
    await emails(w.db, w.tenant.id)  # the change joins the coalesced notice (#230)
    elapse(w.db, w.tenant.id, timedelta(minutes=10))
    sent = await emails(w.db, w.tenant.id)
    [notice] = sent.of_type("dlp_policy_changed")
    assert notice.to == w.address(w.tenant.admin)
    # Setting the value it has changes nothing and tells nobody.
    assert (await w.call(w.admin, "PATCH", path, {"dlp_approver": True})).status_code == 200
    assert (await emails(w.db, w.tenant.id)).emails == []
    # An admin may name themselves; they still never approve their own transfers.
    me = f"/v1/users/{w.tenant.admin}"
    assert (await w.call(w.admin, "PATCH", me, {"dlp_approver": True})).status_code == 200


async def test_a_rule_needing_approval_needs_more_approvers_than_it_asks_for(w: World) -> None:
    w.approvers(w.tenant.admin)
    made = await w.call(
        w.admin,
        "POST",
        "/v1/dlp/rules",
        {
            "name": "Approval for cards",
            "direction": "sent",
            "condition": "content",
            "detectors": ["payment_card"],
            "action": "require_approval",
        },
    )
    assert (made.status_code, made.json()["code"]) == (422, "approvers_insufficient")


async def test_the_list_scopes_filters_and_pages(w: World) -> None:
    _, first = await w.pending()
    _, second = await w.pending()
    _, third = await w.pending()
    assert (await w.reject(third)).status_code == 200

    # A member who isn't an approver: their own by default, never the queue or the tenant.
    own = await w.call(w.sender, "GET", "/v1/dlp/approval-requests")
    assert [i["id"] for i in own.json()["items"]] == [third, second, first]
    queue = await w.call(w.sender, "GET", "/v1/dlp/approval-requests?scope=queue")
    assert (queue.status_code, queue.json()["code"]) == (403, "permission_denied")
    tenant = await w.call(w.sender, "GET", "/v1/dlp/approval-requests?scope=tenant")
    assert (tenant.status_code, tenant.json()["code"]) == (403, "permission_denied")
    totp = session_caller(w.tenant.id, w.tenant.admin, Role.ADMIN, AuthMethod.PASSWORD_TOTP)
    by_totp = await w.call(totp, "GET", "/v1/dlp/approval-requests?scope=tenant")
    assert (by_totp.status_code, by_totp.json()["code"]) == (403, "passkey_required")

    # The approver's queue: pending only, newest first, a page at a time.
    page = await w.call(w.approver, "GET", "/v1/dlp/approval-requests?limit=1")
    assert [i["id"] for i in page.json()["items"]] == [second]
    cursor = page.json()["next_cursor"]
    rest = await w.call(w.approver, "GET", f"/v1/dlp/approval-requests?limit=1&cursor={cursor}")
    assert ([i["id"] for i in rest.json()["items"]], rest.json()["next_cursor"]) == ([first], None)
    bad = await w.call(w.approver, "GET", "/v1/dlp/approval-requests?cursor=%21%21")
    assert bad.status_code == 400
    # The admin's view of the tenant, filtered by state.
    everything = await w.call(w.admin, "GET", "/v1/dlp/approval-requests?scope=tenant")
    assert len(everything.json()["items"]) == 3
    rejected = await w.call(w.admin, "GET", "/v1/dlp/approval-requests?scope=tenant&state=rejected")
    assert [(i["id"], i["state"]) for i in rejected.json()["items"]] == [(third, "rejected")]
    # Another member who is neither sender nor approver sees nothing of the sender's requests.
    w.approvers(w.tenant.admin)
    other = await w.call(w.approver, "GET", "/v1/dlp/approval-requests")
    assert other.json()["items"] == []
    hidden = await w.call(w.approver, "GET", f"/v1/dlp/approval-requests/{first}")
    assert hidden.status_code == 404
