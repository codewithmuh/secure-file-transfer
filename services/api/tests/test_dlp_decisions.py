"""The DLP decision of a transfer (#219; architecture 4.6; data model 2.7, 3.2; FR-41, FR-42,
FR-45, FR-46, FR-48): the decision in the evaluation, `getTransferDlp`, `confirmTransfer`, the
emails, the audit events and the daily cleanup.

Real PostgreSQL through the routes as `sft_api`, the scan worker as `sft_scan` (with the fake
inspector answering as the real one, scan_fixtures.py), the notification worker as `sft_notify`
and the cleanup as `sft_jobs`. Tenants have the default policy (detectors 6) and have sent to
`example.test` before (member_fixtures.py); policy changes go through the admin's API.
"""

from __future__ import annotations

import json
import random
import uuid
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2 as httpx
import pytest
import sqlalchemy.exc
from prometheus_client import CollectorRegistry

from dlp_corpus.generate import my_number
from dlp_fixtures import xlsx
from member_fixtures import Tenant, client, seed_tenant, session_caller
from notify_fixtures import Sent, drain, notifier
from pg import ScratchDatabase
from scan_fixtures import FakeClamd, FakeInspector, FakeScanObjects
from sft.core.ids import uuid7
from sft.data.audit import Actor
from sft.data.database import Database
from sft.data.models import ActorType, Role
from sft.data.outbox import OutboxMessage, Queue
from sft.data.roles import JOBS, NOTIFY, SCAN
from sft.data.scope import Scope
from sft.service import lifecycle
from sft.service.caller import Caller, CallerKind
from sft.service.dlp_decision import KNOWN_FOR, MissingPolicyError
from sft.service.evaluation import Outcome, evaluate
from sft.service.lifecycle import JobMetrics, Jobs
from sft.workers.consumer import Delivery
from sft.workers.consumer import Outcome as Processed
from sft.workers.scan import Engines, Leases, ScanMetrics, SmallScanConsumer
from transfer_fixtures import actions, outbox_topics, seed_file, seed_transfer, transfer_row

pytestmark = pytest.mark.anyio

NEW = "chika@partner.example"
"""A recipient at a domain the tenant has never sent to, and doesn't trust."""
KNOWN = "aiko@example.test"


@dataclass
class World:
    db: ScratchDatabase
    tenant: Tenant
    http: httpx.AsyncClient
    current: list[Caller | None]

    def act_as(self, caller: Caller | None) -> None:
        self.current[0] = caller

    @property
    def owner(self) -> Caller:
        return session_caller(self.tenant.id, self.tenant.member, Role.MEMBER)

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

    def draft(self, *recipients: str) -> uuid.UUID:
        transfer_id, _ = seed_transfer(
            self.db, self.tenant.id, self.tenant.member, recipients=recipients or (KNOWN,)
        )
        return transfer_id

    def file(
        self,
        transfer_id: uuid.UUID,
        *,
        high: dict[str, int] | None = None,
        low: dict[str, int] | None = None,
        reasons: Sequence[str] = (),
    ) -> uuid.UUID:
        """A clean file, inspected (or `partial` with `reasons`), with these findings."""
        file_id = seed_file(
            self.db,
            self.tenant.id,
            transfer_id,
            state="clean",
            inspection_state="partial" if reasons else "inspected",
        )
        if reasons:
            self.db.sql(
                "UPDATE files SET inspection_reasons = :r WHERE id = :id",
                r=list(reasons),
                id=file_id,
            )
        for detector in {*(high or {}), *(low or {})}:
            self.db.sql(
                "INSERT INTO dlp_findings (id, tenant_id, file_id, detector, count_low, "
                "count_medium, count_high) VALUES (:id, :t, :f, :d, :low, 0, :high)",
                id=uuid.uuid4(),
                t=self.tenant.id,
                f=file_id,
                d=detector,
                low=(low or {}).get(detector, 0),
                high=(high or {}).get(detector, 0),
            )
        return file_id

    async def send(self, transfer_id: uuid.UUID) -> dict[str, Any]:
        self.act_as(self.owner)
        response = await self.http.post(f"/v1/transfers/{transfer_id}/send")
        assert response.status_code == 200, response.text
        return dict(response.json())

    async def dlp(self, transfer_id: uuid.UUID, language: str = "en") -> dict[str, Any]:
        self.act_as(self.owner)
        response = await self.http.get(
            f"/v1/transfers/{transfer_id}/dlp", headers={"accept-language": language}
        )
        assert response.status_code == 200, response.text
        return dict(response.json())

    async def confirm(
        self,
        transfer_id: uuid.UUID,
        decision_id: object,
        justification: str | None = None,
        *,
        caller: Caller | None = None,
    ) -> httpx.Response:
        self.act_as(caller or self.owner)
        body: dict[str, object] = {"decision_id": str(decision_id)}
        if justification is not None:
            body["justification"] = justification
        return await self.http.post(f"/v1/transfers/{transfer_id}/confirm", json=body)

    async def remove(self, file_id: uuid.UUID) -> None:
        self.act_as(self.owner)
        response = await self.http.delete(f"/v1/files/{file_id}")
        assert response.status_code == 204, response.text

    def rule(self, name: str) -> uuid.UUID:
        [(rule_id,)] = self.db.sql(
            "SELECT id FROM dlp_rules WHERE tenant_id = :t AND name = :n AND retired_at IS NULL",
            t=self.tenant.id,
            n=name,
        )
        return rule_id  # type: ignore[return-value]

    async def change_rule(self, rule_name: str, /, **change: object) -> dict[str, Any]:
        self.act_as(self.admin)
        response = await self.http.patch(f"/v1/dlp/rules/{self.rule(rule_name)}", json=change)
        assert response.status_code == 200, response.text
        return dict(response.json())

    async def add_rule(self, **rule: object) -> None:
        self.act_as(self.admin)
        response = await self.http.post("/v1/dlp/rules", json={"direction": "sent", **rule})
        assert response.status_code == 201, response.text

    async def change_policy(self, **change: object) -> None:
        self.act_as(self.admin)
        response = await self.http.patch("/v1/dlp/policy", json=change)
        assert response.status_code == 200, response.text

    def decisions(self, transfer_id: uuid.UUID) -> list[tuple[object, ...]]:
        return self.db.sql(
            "SELECT id, outcome, policy_version FROM dlp_decisions WHERE transfer_id = :id "
            "ORDER BY decided_at, id",
            id=transfer_id,
        )

    def delivery_states(self, transfer_id: uuid.UUID) -> list[object]:
        return [
            state
            for (state,) in self.db.sql(
                "SELECT delivery_state FROM transfer_recipients WHERE transfer_id = :id",
                id=transfer_id,
            )
        ]

    def details(self, target: uuid.UUID, action: str) -> list[dict[str, Any]]:
        return [
            dict(details)  # type: ignore[call-overload]
            for (details,) in self.db.sql(
                "SELECT details FROM audit_events WHERE target_id = :id AND action = :a "
                "ORDER BY occurred_at, id",
                id=target,
                a=action,
            )
        ]


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    current: list[Caller | None] = [None]
    tenant = seed_tenant(migrated_db)
    async with client(migrated_db, lambda: current[0]) as http:
        yield World(migrated_db, tenant, http, current)


async def emails(db: ScratchDatabase, tenant_id: uuid.UUID) -> Sent:
    """Every email the notification worker sends for the tenant's pending messages."""
    sent = Sent()
    database = Database.connect(db.url(NOTIFY), pool_size=1)
    try:
        await drain(notifier(database, sent), db, tenant_id)
    finally:
        await database.dispose()
    return sent


def address_of(db: ScratchDatabase, user_id: uuid.UUID) -> str:
    [(email,)] = db.sql("SELECT email FROM users WHERE id = :id", id=user_id)
    return str(email)


def every_audit_row(db: ScratchDatabase, tenant_id: uuid.UUID) -> str:
    return json.dumps(
        db.sql("SELECT action, details FROM audit_events WHERE tenant_id = :t", t=tenant_id),
        default=str,
        ensure_ascii=False,
    )


# ---- the acceptance criteria of #219 ----


async def test_a_my_number_spreadsheet_to_an_untrusted_domain_warns_and_the_member_confirms(
    w: World,
) -> None:
    rng = random.Random(219)  # noqa: S311 - test data, not a secret
    numbers = [my_number(rng) for _ in range(3)]
    sheet = xlsx({"社員": [["氏名", "マイナンバー"], *[["山田", n] for n in numbers]]})
    transfer_id = w.draft(NEW)
    file_id = seed_file(w.db, w.tenant.id, transfer_id, state="scanning", size=len(sheet))
    objects, clamd, inspector = FakeScanObjects(), FakeClamd(), FakeInspector(mode="detect")
    objects.put(f"tenants/{w.tenant.id}/files/{file_id}", "version-1", sheet)
    await clamd.start()
    await inspector.start()
    database = Database.connect(w.db.url(SCAN), pool_size=2)
    try:
        assert (await w.send(transfer_id))["state"] == "submitted"
        engines = Engines("127.0.0.1", clamd.port, "127.0.0.1", inspector.port, connect_timeout=2)
        consumer = SmallScanConsumer(
            database,
            objects,
            engines,
            ScanMetrics.create(CollectorRegistry()),
            Leases(None, Queue.SCAN_SMALL, 4, lambda: 0.0),
        )
        delivery = Delivery(OutboxMessage(uuid7(), "file.scan", w.tenant.id, {"file_id": file_id}))
        assert await consumer.process(delivery) is Processed.PROCESSED
    finally:
        await database.dispose()
        await clamd.stop()
        await inspector.stop()

    # The scan worker's evaluation decided: a warning. Nothing reaches the recipient yet.
    assert transfer_row(w.db, transfer_id)["state"] == "awaiting_confirmation"
    assert outbox_topics(w.db, "transfer_id", transfer_id) == ["transfer.awaiting_confirmation"]
    assert w.delivery_states(transfer_id) == ["pending"]
    sent = await emails(w.db, w.tenant.id)
    member = address_of(w.db, w.tenant.member)
    assert [e.email_type for e in sent.to(member)] == ["dlp_confirmation_needed"]
    assert sent.to(NEW) == []
    assert numbers[0] not in sent.to(member)[0].text

    shown = await w.dlp(transfer_id)
    decision = shown["decision"]
    assert (shown["state"], decision["outcome"], decision["mode"]) == (
        "awaiting_confirmation",
        "warn",
        "enforce",
    )
    assert (decision["untrusted_recipients"], decision["new_domains"]) == (1, 1)
    rules = {r["name"]: r for r in decision["matched_rules"]}
    assert set(rules) == {"My Numbers", "New recipient domain"}
    assert rules["My Numbers"]["condition"] == "content"
    assert rules["My Numbers"]["matched_count"] == 3
    assert rules["My Numbers"]["threshold"] == 1
    assert (
        rules["New recipient domain"]["matched_count"],
        rules["New recipient domain"]["threshold"],
    ) == (
        1,
        None,
    )
    [recipient] = shown["recipients"]
    assert (recipient["email"], recipient["trusted"], recipient["new_domain"]) == (NEW, False, True)
    [file] = shown["files"]
    [found] = [f for f in file["findings"] if f["detector"] == "jp_my_number"]
    assert found["detector_name"] == "My Number (Individual Number)"
    assert (found["count_high"], found["details_visible"]) == (3, False)
    assert "locations" not in found
    assert "previews" not in found
    assert (shown["message_findings"], shown["approval_request"]) == ([], None)
    japanese = await w.dlp(transfer_id, "ja")
    assert "マイナンバー・個人番号" in {
        f["detector_name"] for f in japanese["files"][0]["findings"]
    }
    for number in numbers:
        assert number not in json.dumps(shown)

    confirmed = await w.confirm(transfer_id, decision["id"], "Payroll for the auditor")
    assert confirmed.status_code == 200, confirmed.text
    assert (confirmed.json()["state"], confirmed.json()["dlp"]["outcome"]) == ("sent", "warn")
    assert w.delivery_states(transfer_id) == ["queued"]
    assert w.db.sql(
        "SELECT domain FROM dlp_known_domains WHERE tenant_id = :t AND domain = 'partner.example'",
        t=w.tenant.id,
    ) == [("partner.example",)]
    [(justification,)] = w.db.sql(
        "SELECT justification_ct FROM dlp_confirmations WHERE transfer_id = :id", id=transfer_id
    )
    assert justification == b"\x00Payroll for the auditor"  # sealed (M2's stand-in)
    sent = await emails(w.db, w.tenant.id)
    assert [e.email_type for e in sent.to(NEW)] == ["transfer_link"]

    # Every step is on record, with IDs, enums and counts only.
    assert actions(w.db, transfer_id) == [
        "transfer.submitted",
        "dlp.decided",
        "transfer.awaiting_confirmation",
        "email.sent",  # dlp_confirmation_needed, to the member
        "transfer.confirmed",
        "transfer.sent",
    ]
    [decided] = w.details(transfer_id, "dlp.decided")
    assert decided["decision_id"] == decision["id"]
    assert (decided["outcome"], decided["mode"], decided["enforced"]) == ("warn", "enforce", True)
    assert (decided["matched_rules"], decided["untrusted_recipients"], decided["new_domains"]) == (
        2,
        1,
        1,
    )
    assert decided["policy_version"] == 1
    assert decided["system_actor"] == "scan_worker"
    matched = w.db.sql(
        "SELECT target_id, details->>'matched_count' FROM audit_events "
        "WHERE action = 'dlp.rule_matched' AND tenant_id = :t ORDER BY 2",
        t=w.tenant.id,
    )
    assert matched == [
        (w.rule("New recipient domain"), "1"),
        (w.rule("My Numbers"), "3"),
    ]
    [confirmation] = w.details(transfer_id, "transfer.confirmed")
    assert confirmation["justification_given"] is True
    assert confirmation["decision_id"] == decision["id"]
    audit_text = every_audit_row(w.db, w.tenant.id)
    for secret in ("Payroll", "partner.example", NEW, *numbers):
        assert secret not in audit_text


async def test_a_block_rule_holds_the_transfer_and_removing_the_file_sends_the_rest(
    w: World,
) -> None:
    await w.change_rule("My Numbers", action="block")
    transfer_id = w.draft(KNOWN)
    plain = w.file(transfer_id)
    flagged = w.file(transfer_id, high={"jp_my_number": 2})
    body = await w.send(transfer_id)
    assert (body["state"], body["hold_reason"], body["dlp"]["outcome"]) == (
        "held",
        "dlp_blocked",
        "block",
    )
    assert outbox_topics(w.db, "transfer_id", transfer_id) == ["transfer.held"]
    sent = await emails(w.db, w.tenant.id)
    assert [e.email_type for e in sent.to(address_of(w.db, w.tenant.member))] == ["transfer_held"]
    assert sent.to(KNOWN) == []
    shown = await w.dlp(transfer_id)
    [rule] = shown["decision"]["matched_rules"]
    assert (rule["name"], rule["action"], rule["revision"]) == ("My Numbers", "block", 2)

    await w.remove(flagged)
    row = transfer_row(w.db, transfer_id)
    assert (row["state"], row["hold_reason"]) == ("sent", None)
    assert [outcome for _, outcome, _ in w.decisions(transfer_id)] == ["block", "none"]
    assert w.delivery_states(transfer_id) == ["queued"]
    counters = w.db.sql("SELECT file_id FROM download_counters WHERE tenant_id = :t", t=w.tenant.id)
    assert counters == [(plain,)]
    assert (await w.dlp(transfer_id))["decision"]["outcome"] == "none"


async def test_a_policy_change_leaves_a_decision_alone_and_a_removal_decides_again(
    w: World,
) -> None:
    confirmed = w.draft(KNOWN)
    w.file(confirmed, high={"jp_my_number": 1})
    reopened = w.draft(KNOWN)
    w.file(reopened, high={"jp_my_number": 1})
    spare = w.file(reopened)
    for transfer_id in (confirmed, reopened):
        assert (await w.send(transfer_id))["state"] == "awaiting_confirmation"
    [(first, _, version)] = w.decisions(confirmed)
    assert version == 1

    # The admin makes My Numbers block, and renames the rule: version 2, rule revision 2.
    await w.change_rule("My Numbers", action="block", name="My Numbers blocked")
    for transfer_id in (confirmed, reopened):
        assert transfer_row(w.db, transfer_id)["state"] == "awaiting_confirmation"
    shown = await w.dlp(confirmed)
    [rule] = shown["decision"]["matched_rules"]
    assert (rule["name"], rule["action"], rule["revision"]) == ("My Numbers", "warn", 1)
    assert shown["decision"]["policy_version"] == 1
    response = await w.confirm(confirmed, first)
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "sent"

    # A file removal is a change to the counted files: a new decision, under the new policy.
    [(old, _, _)] = w.decisions(reopened)
    await w.remove(spare)
    row = transfer_row(w.db, reopened)
    assert (row["state"], row["hold_reason"]) == ("held", "dlp_blocked")
    [_, (new, outcome, version)] = w.decisions(reopened)
    assert (outcome, version) == ("block", 2)
    stale = await w.confirm(reopened, old)
    assert stale.status_code == 409
    assert stale.json()["code"] == "dlp_decision_changed"
    [rule] = (await w.dlp(reopened))["decision"]["matched_rules"]
    assert (rule["name"], rule["revision"]) == ("My Numbers blocked", 2)
    assert new != old


async def test_my_numbers_split_over_two_files_add_up(w: World) -> None:
    # FR-48: a threshold of 5, each file under it, together over it. Low-confidence matches don't
    # count for a rule at `high`.
    await w.change_rule("My Numbers", threshold=5)
    alone = w.draft(KNOWN)
    w.file(alone, high={"jp_my_number": 3}, low={"jp_my_number": 9})
    split = w.draft(KNOWN)
    w.file(split, high={"jp_my_number": 3})
    w.file(split, high={"jp_my_number": 3})
    assert (await w.send(alone))["state"] == "sent"
    assert (await w.send(split))["state"] == "awaiting_confirmation"
    [rule] = (await w.dlp(split))["decision"]["matched_rules"]
    assert (rule["name"], rule["matched_count"], rule["threshold"]) == ("My Numbers", 6, 5)


async def test_the_same_findings_warn_for_a_trusted_partner_and_block_an_untrusted_domain(
    w: World,
) -> None:
    # FR-45: the partner is trusted, a subdomain of it too; a rule for untrusted recipients
    # blocks what only warns for the partner.
    await w.change_policy(trusted_domains=["partner.example"])
    await w.add_rule(
        name="My Numbers to untrusted recipients",
        condition="content",
        detectors=["jp_my_number"],
        min_confidence="high",
        recipient_scope="untrusted",
        action="block",
    )
    outcomes = {}
    for address in ("a@partner.example", "a@Sales.Partner.Example", "a@elsewhere.example"):
        transfer_id = w.draft(address)
        w.file(transfer_id, high={"jp_my_number": 1})
        body = await w.send(transfer_id)
        shown = await w.dlp(transfer_id)
        outcomes[address] = (
            body["state"],
            shown["decision"]["untrusted_recipients"],
            shown["recipients"][0]["trusted"],
            sorted(r["name"] for r in shown["decision"]["matched_rules"]),
        )
    names = ["My Numbers", "New recipient domain"]
    assert outcomes == {
        "a@partner.example": ("awaiting_confirmation", 0, True, names),
        "a@Sales.Partner.Example": ("awaiting_confirmation", 0, True, names),
        "a@elsewhere.example": (
            "held",
            1,
            False,
            sorted([*names, "My Numbers to untrusted recipients"]),
        ),
    }


async def test_confirm_refusals_and_a_repeated_confirm(w: World) -> None:
    transfer_id = w.draft(KNOWN)
    first_file = w.file(transfer_id, high={"jp_my_number": 1})
    w.file(transfer_id, high={"jp_my_number": 1})
    await w.send(transfer_id)
    [(old, _, _)] = w.decisions(transfer_id)
    await w.remove(first_file)  # a removal in another tab: a new decision, still a warning
    [_, (current, outcome, _)] = w.decisions(transfer_id)
    assert outcome == "warn"

    stale = await w.confirm(transfer_id, old)
    assert (stale.status_code, stale.json()["code"]) == (409, "dlp_decision_changed")
    # People only: a key, whatever its scopes, gets 403 (authn and authz 5.3).
    key = await w.confirm(transfer_id, current, caller=w.key("transfers:read", "transfers:write"))
    assert (key.status_code, key.json()["code"]) == (403, "permission_denied")
    # Only the owner: an admin acting as one sees the transfer, so 403; another member, 404.
    admin = await w.confirm(transfer_id, current, caller=w.admin)
    assert (admin.status_code, admin.json()["code"]) == (403, "permission_denied")
    other = session_caller(w.tenant.id, w.tenant.target, Role.MEMBER)
    assert (await w.confirm(transfer_id, current, caller=other)).status_code == 404
    assert transfer_row(w.db, transfer_id)["state"] == "awaiting_confirmation"

    done = await w.confirm(transfer_id, current)
    assert done.status_code == 200, done.text
    again = await w.confirm(transfer_id, current)
    assert again.status_code == 200, again.text
    assert again.json()["sent_at"] == done.json()["sent_at"]
    assert again.json()["state"] == "sent"
    assert w.db.sql(
        "SELECT count(*) FROM dlp_confirmations WHERE transfer_id = :id", id=transfer_id
    ) == [(1,)]
    assert actions(w.db, transfer_id).count("transfer.sent") == 1
    # Without a justification, the record says so.
    [confirmation] = w.details(transfer_id, "transfer.confirmed")
    assert confirmation["justification_given"] is False
    # A sent transfer under another decision, or a held one, can't be confirmed.
    assert (await w.confirm(transfer_id, old)).json()["code"] == "dlp_decision_changed"


async def test_a_decision_that_needs_approval_asks_for_it_on_confirmation(w: World) -> None:
    # #220 (tests/test_dlp_approvals.py) brings the approval requests: a confirmation with a
    # justification asks the approvers, and nothing reaches the recipient.
    w.db.sql(
        "UPDATE users SET dlp_approver = true WHERE tenant_id = :t AND id <> :member",
        t=w.tenant.id,
        member=w.tenant.member,
    )
    await w.change_rule("My Numbers", action="require_approval")
    transfer_id = w.draft(KNOWN)
    w.file(transfer_id, high={"jp_my_number": 1})
    body = await w.send(transfer_id)
    assert (body["state"], body["dlp"]["outcome"]) == ("awaiting_confirmation", "require_approval")
    [(decision, _, _)] = w.decisions(transfer_id)
    asked = await w.confirm(transfer_id, decision, "Needed by the auditor")
    assert asked.status_code == 200, asked.text
    assert asked.json()["state"] == "pending_approval"
    assert asked.json()["dlp"]["approval_request_id"] is not None
    assert w.delivery_states(transfer_id) == ["pending"]


@pytest.mark.parametrize(
    ("action", "state"),
    [
        (None, "sent"),
        ("allow_and_record", "sent"),
        ("warn", "awaiting_confirmation"),
        ("require_approval", "awaiting_confirmation"),
        ("block", "held"),
    ],
)
async def test_no_recipient_email_is_written_before_the_decision_allows_it(
    w: World, action: str | None, state: str
) -> None:
    if action == "require_approval":
        w.db.sql("UPDATE users SET dlp_approver = true WHERE tenant_id = :t", t=w.tenant.id)
    if action is not None:
        await w.change_rule("My Numbers", action=action)
    transfer_id = w.draft(KNOWN)
    w.file(transfer_id, high={"jp_my_number": 1} if action else None)
    body = await w.send(transfer_id)
    assert body["state"] == state
    assert body["dlp"]["outcome"] == (action or "none")
    allowed = state == "sent"
    assert ("transfer.sent" in outbox_topics(w.db, "transfer_id", transfer_id)) is allowed
    assert w.delivery_states(transfer_id) == (["queued"] if allowed else ["pending"])
    counters = w.db.sql(
        "SELECT count(*) FROM download_counters WHERE tenant_id = :t", t=w.tenant.id
    )
    assert counters == [(1 if allowed else 0,)]
    sent = await emails(w.db, w.tenant.id)
    assert [e.email_type for e in sent.to(KNOWN)] == (["transfer_link"] if allowed else [])


# ---- the decision's edges ----


async def test_get_transfer_dlp_before_a_decision_and_for_each_caller(w: World) -> None:
    transfer_id = w.draft(NEW, KNOWN)
    file_id = seed_file(w.db, w.tenant.id, transfer_id, state="scanning")
    shown = await w.dlp(transfer_id)
    assert shown["decision"] is None
    assert {(r["email"], r["new_domain"]) for r in shown["recipients"]} == {
        (NEW, True),
        (KNOWN, False),
    }
    assert [(f["file_id"], f["inspection"]["state"]) for f in shown["files"]] == [
        (str(file_id), "pending")
    ]
    w.act_as(w.admin)  # an admin acting as one: counts only, as everyone until DLP-8
    assert (await w.http.get(f"/v1/transfers/{transfer_id}/dlp")).status_code == 200
    w.act_as(w.key("transfers:read"))
    assert (await w.http.get(f"/v1/transfers/{transfer_id}/dlp")).status_code == 200
    w.act_as(w.key("upload_requests:read"))
    assert (await w.http.get(f"/v1/transfers/{transfer_id}/dlp")).status_code == 404
    w.act_as(session_caller(w.tenant.id, w.tenant.target, Role.MEMBER))
    assert (await w.http.get(f"/v1/transfers/{transfer_id}/dlp")).status_code == 404
    w.act_as(w.owner)
    listed = (await w.http.get("/v1/transfers")).json()["items"]
    assert [i["dlp_outcome"] for i in listed if i["id"] == str(transfer_id)] == [None]


async def test_not_inspected_counts_files_and_allow_and_record_sends(w: World) -> None:
    # `encrypted` warns, `no_text` only records (detectors 6); a rule's count is its files.
    recorded = w.draft(KNOWN)
    w.file(recorded, reasons=["no_text"])
    warned = w.draft(KNOWN)
    w.file(warned, reasons=["encrypted"])
    w.file(warned, reasons=["parse_error", "no_text"])
    body = await w.send(recorded)
    assert (body["state"], body["dlp"]["outcome"]) == ("sent", "allow_and_record")
    body = await w.send(warned)
    assert (body["state"], body["dlp"]["outcome"]) == ("awaiting_confirmation", "warn")
    rules = {r["name"]: r for r in (await w.dlp(warned))["decision"]["matched_rules"]}
    assert rules["Files that couldn't be fully inspected"]["matched_count"] == 2
    assert rules["Files that couldn't be fully inspected"]["threshold"] is None
    assert rules["Images and files without text"]["matched_count"] == 1
    listed = (await w.http.get("/v1/transfers")).json()["items"]
    assert {i["id"]: i["dlp_outcome"] for i in listed}[str(warned)] == "warn"


async def test_removing_the_last_file_while_awaiting_confirmation_returns_to_draft(
    w: World,
) -> None:
    transfer_id = w.draft(KNOWN)
    file_id = w.file(transfer_id, high={"jp_my_number": 1})
    await w.send(transfer_id)
    await w.remove(file_id)
    row = transfer_row(w.db, transfer_id)
    assert (row["state"], row["expires_at"]) == ("draft", None)
    assert (await w.dlp(transfer_id))["decision"] is None
    w.act_as(w.owner)
    assert (await w.http.get(f"/v1/transfers/{transfer_id}")).json()["dlp"] is None


async def test_a_repeated_evaluation_never_makes_a_second_decision(w: World) -> None:
    # A scan worker's retry runs the evaluation again: a decision stands for the files it saw.
    await w.change_rule("Payment cards", action="block")
    held = w.draft(KNOWN)
    w.file(held, high={"payment_card": 1})
    waiting = w.draft(KNOWN)
    w.file(waiting, high={"jp_my_number": 1})
    await w.send(held)
    await w.send(waiting)
    database = Database.connect(w.db.url(SCAN), pool_size=1)
    try:
        for transfer_id in (held, waiting):
            async with database.transaction(Scope.tenant(w.tenant.id)) as session:
                outcome = await evaluate(
                    session, transfer_id, actor=Actor(ActorType.SYSTEM), now=datetime.now(UTC)
                )
            assert outcome is Outcome.UNCHANGED
    finally:
        await database.dispose()
    assert len(w.decisions(held)) == len(w.decisions(waiting)) == 1
    assert outbox_topics(w.db, "transfer_id", held) == ["transfer.held"]


async def test_monitor_mode_records_the_decision_and_sends(w: World) -> None:
    # Monitor mode is #221's to switch on (the policy API refuses it); the evaluation honours it.
    w.db.sql("UPDATE dlp_policies SET mode = 'monitor' WHERE tenant_id = :t", t=w.tenant.id)
    transfer_id = w.draft(NEW)
    w.file(transfer_id, high={"jp_my_number": 1})
    body = await w.send(transfer_id)
    assert body["state"] == "sent"
    assert body["dlp"] == {
        "outcome": "warn",
        "mode": "monitor",
        "enforced": False,
        "approval_request_id": None,
    }


async def test_a_tenant_without_a_policy_sends_nothing(w: World) -> None:
    # Every tenant has one (revision 0024, createTenant); without, nothing is sent undecided.
    w.db.sql("DELETE FROM dlp_rules WHERE tenant_id = :t", t=w.tenant.id)
    w.db.sql("DELETE FROM dlp_policies WHERE tenant_id = :t", t=w.tenant.id)
    transfer_id = w.draft(KNOWN)
    w.file(transfer_id)
    w.act_as(w.owner)
    with pytest.raises(MissingPolicyError):
        await w.http.post(f"/v1/transfers/{transfer_id}/send")
    assert transfer_row(w.db, transfer_id)["state"] == "draft"


# ---- the daily cleanup (data model 6) ----


async def test_the_cleanup_keeps_an_applied_rule_revision_and_forgets_old_domains(
    w: World,
) -> None:
    transfer_id = w.draft(KNOWN)
    w.file(transfer_id, high={"jp_my_number": 1})
    await w.send(transfer_id)
    my_numbers, cards = w.rule("My Numbers"), w.rule("Payment cards")
    await w.change_rule("My Numbers", threshold=2)  # revision 1, which the decision applied
    await w.change_rule("Payment cards", threshold=2)  # revision 1, which nothing applied
    for domain, days in (("stale.example", 366), ("recent.example", 364)):
        w.db.sql(
            "INSERT INTO dlp_known_domains (tenant_id, domain, first_sent_at, last_sent_at) "
            "VALUES (:t, :d, now() - make_interval(days => :n), now() - make_interval(days => :n))",
            t=w.tenant.id,
            d=domain,
            n=days,
        )
    database = Database.connect(w.db.url(JOBS), pool_size=1)
    try:
        jobs = Jobs(database, JobMetrics.create(CollectorRegistry()), lambda: datetime.now(UTC))
        report = await lifecycle.clean_up(jobs)
    finally:
        await database.dispose()

    revisions = w.db.sql(
        "SELECT id, revision FROM dlp_rules WHERE id IN (:a, :b) ORDER BY id, revision",
        a=my_numbers,
        b=cards,
    )
    assert set(revisions) == {(my_numbers, 1), (my_numbers, 2), (cards, 2)}
    # The decision's key keeps the revision even from the owner.
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        w.db.sql("DELETE FROM dlp_rules WHERE id = :id AND revision = 1", id=my_numbers)
    domains = w.db.sql(
        "SELECT domain FROM dlp_known_domains WHERE tenant_id = :t ORDER BY 1", t=w.tenant.id
    )
    assert domains == [("example.test",), ("recent.example",)]
    assert report["dlp_known_domains_deleted"] == 1
    [details] = [
        d
        for (d,) in w.db.sql(
            "SELECT details FROM audit_events WHERE action = 'retention.rows_deleted' "
            "AND tenant_id = :t AND details->>'table' = 'dlp_known_domains'",
            t=w.tenant.id,
        )
    ]
    assert details["rows"] == 1  # type: ignore[index]
    assert "stale" not in json.dumps(details)


def test_known_domains_expire_after_365_days() -> None:
    assert timedelta(days=365) == KNOWN_FOR
