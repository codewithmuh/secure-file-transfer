"""DLP-6's Should requirements (#221; FR-39, FR-44, FR-49, FR-50, FR-52, FR-56; #164): patterns
and their save-time checks, a pattern's budget stops, `testDlpDetectors`, two approvers, the
sender's 24 hours, the message's findings and monitor mode, end to end through the routes.

Received files (FR-51) are tests/test_dlp_received.py. The new-domain condition (FR-46) moved to
#219 and has its end-to-end tests in tests/test_dlp_decisions.py.
"""

from __future__ import annotations

import json
import random
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest

from dlp_corpus.generate import my_number
from member_fixtures import client, seed_tenant, seed_user, session_caller
from pg import ScratchDatabase
from sft.data.database import Database
from sft.data.models import FileState, InspectionState, Role
from sft.data.roles import SCAN
from sft.data.scope import Scope
from sft.service import scans
from sft.service.caller import Caller
from sft.service.scans import InspectionResult, ScanResult
from test_dlp_decisions import KNOWN, NEW, World
from transfer_fixtures import seed_file, transfer_row

pytestmark = pytest.mark.anyio

CANARY = "zebra-canary-221"
"""A word in sample text and messages that must never reach a log, an audit record or an email."""


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    current: list[Caller | None] = [None]
    tenant = seed_tenant(migrated_db)
    async with client(migrated_db, lambda: current[0]) as http:
        yield World(migrated_db, tenant, http, current)


async def admin_call(w: World, method: str, path: str, body: object = None) -> Any:
    w.act_as(w.admin)
    return await w.http.request(method, path, json=body)


def every_audit_row(w: World) -> str:
    return json.dumps(
        w.db.sql("SELECT action, details FROM audit_events WHERE tenant_id = :t", t=w.tenant.id),
        default=str,
        ensure_ascii=False,
    )


# ---- FR-39: patterns and their save-time checks ----


@pytest.mark.parametrize(
    ("pattern", "detail"),
    [
        ("ORD-(", "doesn't compile"),
        ("x*", "empty string"),
        ("\\b", "empty string"),
        ("(?:[a-z]{1,5}\\d{1,5}){40}", "1,000 RE2 instructions"),
    ],
)
async def test_a_pattern_that_breaks_a_rule_is_refused_with_a_pointer(
    w: World, pattern: str, detail: str
) -> None:
    refused = await admin_call(
        w, "POST", "/v1/dlp/detectors", {"name": "Orders", "kind": "pattern", "pattern": pattern}
    )
    assert refused.status_code == 422, refused.text
    body = refused.json()
    assert body["code"] == "validation_failed"
    assert body["errors"][0]["pointer"] == "#/pattern"
    assert detail in body["errors"][0]["detail"]
    assert pattern not in body["errors"][0]["detail"]  # the reason, never the expression
    assert (
        w.db.sql(
            "SELECT id FROM dlp_detectors WHERE kind = 'pattern' AND tenant_id = :t", t=w.tenant.id
        )
        == []
    )


async def test_a_pattern_is_saved_shown_changed_and_limited_to_20(w: World) -> None:
    made = await admin_call(
        w,
        "POST",
        "/v1/dlp/detectors",
        {
            "name": "Order numbers",
            "kind": "pattern",
            "pattern": "ORD-\\d{4}-\\d{6}",
            "context_keywords": ["注文番号", "order"],
            "min_length": 8,
        },
    )
    assert made.status_code == 201, made.text
    detector = made.json()
    assert (detector["kind"], detector["pattern"], detector["case_insensitive"]) == (
        "pattern",
        "ORD-\\d{4}-\\d{6}",
        True,
    )
    assert (detector["context_keywords"], detector["min_length"]) == (["注文番号", "order"], 8)
    shown = (await admin_call(w, "GET", f"/v1/dlp/detectors/{detector['id']}")).json()
    assert (shown["budget_exceeded_files"], shown["budget_exceeded_last_at"]) == (0, None)
    changed = await admin_call(
        w, "PATCH", f"/v1/dlp/detectors/{detector['id']}", {"case_insensitive": False}
    )
    assert changed.status_code == 200, changed.text
    assert (changed.json()["revision"], changed.json()["case_insensitive"]) == (2, False)
    wrong_kind = await admin_call(
        w, "PATCH", f"/v1/dlp/detectors/{detector['id']}", {"keywords": ["vega"]}
    )
    assert (wrong_kind.status_code, wrong_kind.json()["errors"][0]["pointer"]) == (
        422,
        "#/keywords",
    )
    # 19 more make 20; the 21st is refused.
    for index in range(19):
        more = await admin_call(
            w,
            "POST",
            "/v1/dlp/detectors",
            {"name": f"P{index}", "kind": "pattern", "pattern": f"Q{index}-\\d{{3}}"},
        )
        assert more.status_code == 201, more.text
    over = await admin_call(
        w, "POST", "/v1/dlp/detectors", {"name": "P21", "kind": "pattern", "pattern": "Z-\\d"}
    )
    assert (over.status_code, over.json()["code"]) == (422, "validation_failed")
    assert "20 patterns" in over.json()["detail"]


async def test_a_pattern_past_its_budget_is_counted_by_id_and_shown(w: World) -> None:
    # #164: the inspector names the patterns it stopped; the scan worker counts them, once per
    # file, with dlp.pattern_budget_exceeded holding IDs only.
    made = await admin_call(
        w,
        "POST",
        "/v1/dlp/detectors",
        {"name": "Broad", "kind": "pattern", "pattern": "(?:.{0,30}\\d){1,2}q"},
    )
    assert made.status_code == 201, made.text
    detector_id = uuid.UUID(made.json()["id"].removeprefix("custom:"))
    database = Database.connect(w.db.url(SCAN), pool_size=1)
    try:
        for _ in range(2):
            transfer_id = w.draft(KNOWN)
            file_id = seed_file(w.db, w.tenant.id, transfer_id, state="scanning")
            async with database.transaction(Scope.tenant(w.tenant.id)) as session:
                assert await scans.record(
                    session,
                    file_id,
                    transfer_id,
                    ScanResult(FileState.CLEAN),
                    InspectionResult(
                        InspectionState.INSPECTED,
                        engine_version="test.1",
                        budget_exceeded=(f"custom:{detector_id}", "custom:not-a-uuid"),
                    ),
                    attempts=1,
                )
    finally:
        await database.dispose()
    shown = (await admin_call(w, "GET", f"/v1/dlp/detectors/custom:{detector_id}")).json()
    assert shown["budget_exceeded_files"] == 2
    assert shown["budget_exceeded_last_at"] is not None
    events = w.db.sql(
        "SELECT details FROM audit_events WHERE action = 'dlp.pattern_budget_exceeded' "
        "AND tenant_id = :t",
        t=w.tenant.id,
    )
    assert len(events) == 2
    for (details,) in events:
        assert details["patterns"] == 1  # type: ignore[index]
        assert details["detector_a"] == str(detector_id)  # type: ignore[index]
        assert set(details) == {"system_actor", "patterns", "detector_a"}  # type: ignore[arg-type]


# ---- FR-56: testDlpDetectors ----


async def test_a_draft_and_existing_detectors_are_tried_and_nothing_of_the_text_is_kept(
    w: World,
) -> None:
    number = my_number(random.Random(56))  # noqa: S311 - test data
    text = (
        f"Project Vega kickoff {CANARY}\n"
        f"マイナンバー {number}\n"
        "注文番号 ORD-2026-000123 and ORD-2026-000124\n"
    )
    made = await admin_call(
        w,
        "POST",
        "/v1/dlp/detectors",
        {"name": "Projects", "kind": "keywords", "keywords": ["project vega"]},
    )
    keywords_id = made.json()["id"]
    tried = await admin_call(
        w,
        "POST",
        "/v1/dlp/detector-tests",
        {
            "text": text,
            "detectors": [keywords_id, "jp_my_number"],
            "draft": {
                "name": "Orders",
                "kind": "pattern",
                "pattern": "ORD-\\d{4}-\\d{6}",
                "context_keywords": ["注文番号"],
            },
        },
    )
    assert tried.status_code == 200, tried.text
    body = tried.json()
    found = [(m["detector"], m["line"], m["confidence"]) for m in body["matches"]]
    assert (keywords_id, 1, "high") in found
    assert ("jp_my_number", 2, "high") in found
    assert found.count(("draft", 3, "high")) == 2
    assert body["truncated"] is False
    assert number not in tried.text
    assert "ORD-2026-000123" not in tried.text
    for match in body["matches"]:
        if match["detector"] == "draft":
            assert match["preview"].startswith("****")
    # Only what was asked for: no email address or other built-in detector ran into the result.
    assert {m["detector"] for m in body["matches"]} == {keywords_id, "jp_my_number", "draft"}
    records = every_audit_row(w)
    assert CANARY not in records
    assert number not in records
    [(details,)] = w.db.sql(
        "SELECT details FROM audit_events WHERE action = 'dlp.detector_tested' AND tenant_id = :t",
        t=w.tenant.id,
    )
    assert details["builtin_jp_my_number"] is True  # type: ignore[index]
    assert details["detector_a"] == keywords_id.removeprefix("custom:")  # type: ignore[index]
    assert details["draft_kind"] == "pattern"  # type: ignore[index]
    assert (
        w.db.sql(
            "SELECT id FROM dlp_detectors WHERE kind = 'pattern' AND tenant_id = :t", t=w.tenant.id
        )
        == []
    )


async def test_detector_tests_refuse_long_text_bad_drafts_and_unknown_ids(w: World) -> None:
    too_long = await admin_call(w, "POST", "/v1/dlp/detector-tests", {"text": "a" * 16_385})
    assert (too_long.status_code, too_long.json()["code"]) == (413, "request_too_large")
    bad = await admin_call(
        w,
        "POST",
        "/v1/dlp/detector-tests",
        {"text": "ok", "draft": {"name": "x", "kind": "pattern", "pattern": "a**("}},
    )
    assert (bad.status_code, bad.json()["errors"][0]["pointer"]) == (422, "#/draft/pattern")
    unknown = await admin_call(
        w,
        "POST",
        "/v1/dlp/detector-tests",
        {"text": "ok", "detectors": ["jp_my_number", f"custom:{uuid.uuid4()}"]},
    )
    assert (unknown.status_code, unknown.json()["errors"][0]["pointer"]) == (
        422,
        "#/detectors/1",
    )
    everything = await admin_call(
        w, "POST", "/v1/dlp/detector-tests", {"text": "mail a@example.com 社外秘"}
    )
    assert {m["detector"] for m in everything.json()["matches"]} == {
        "email_address",
        "confidentiality_label",
    }
    w.act_as(w.owner)
    member = await w.http.post("/v1/dlp/detector-tests", json={"text": "ok"})
    assert member.status_code == 403


# ---- FR-44: two approvers ----


async def test_a_rule_needing_two_approvers_waits_for_two_different_ones(w: World) -> None:
    third = seed_user(w.db, w.tenant.id)
    w.db.sql(
        "UPDATE users SET dlp_approver = (id = ANY(:ids)) WHERE tenant_id = :t",
        ids=[w.tenant.admin, w.tenant.target],
        t=w.tenant.id,
    )
    # Two approvers aren't enough for a two-approver rule: the sender may be one of them.
    refused = await admin_call(
        w,
        "PATCH",
        f"/v1/dlp/rules/{w.rule('My Numbers')}",
        {"action": "require_approval", "approvals_required": 2},
    )
    assert (refused.status_code, refused.json()["code"]) == (422, "approvers_insufficient")
    w.db.sql("UPDATE users SET dlp_approver = true WHERE id = :id", id=third)
    await w.change_rule("My Numbers", action="require_approval", approvals_required=2)
    not_alone = await admin_call(
        w, "PATCH", f"/v1/dlp/rules/{w.rule('Payment cards')}", {"approvals_required": 2}
    )
    assert not_alone.json()["errors"][0]["pointer"] == "#/approvals_required"

    transfer_id = w.draft(KNOWN)
    w.file(transfer_id, high={"jp_my_number": 1})
    body = await w.send(transfer_id)
    assert body["dlp"]["outcome"] == "require_approval"
    confirmed = await w.confirm(transfer_id, w.decisions(transfer_id)[0][0], "Payroll run")
    assert confirmed.status_code == 200, confirmed.text
    request_id = confirmed.json()["dlp"]["approval_request_id"]
    path = f"/v1/dlp/approval-requests/{request_id}/approve"

    w.act_as(session_caller(w.tenant.id, w.tenant.target, Role.MEMBER))
    first = await w.http.post(path, json={})
    assert first.status_code == 200, first.text
    assert (first.json()["state"], first.json()["approvals"]) == ("pending", 1)
    again = await w.http.post(path, json={})  # the same approver counts once
    assert again.json()["approvals"] == 1
    assert transfer_row(w.db, transfer_id)["state"] == "pending_approval"

    w.act_as(session_caller(w.tenant.id, third, Role.MEMBER))
    second = await w.http.post(path, json={})
    assert second.status_code == 200, second.text
    assert (second.json()["state"], second.json()["approvals"]) == ("approved", 2)
    assert transfer_row(w.db, transfer_id)["state"] == "sent"


# ---- FR-49: the sender's 24 hours ----


async def test_the_senders_last_24_hours_add_up_across_transfers(w: World) -> None:
    await w.change_rule("My Numbers", threshold=5, include_sender_24h=True)
    old = w.draft(KNOWN)
    w.file(old, high={"jp_my_number": 4})
    assert (await w.send(old))["state"] == "sent"
    first = w.draft(KNOWN)
    w.file(first, high={"jp_my_number": 3})
    # 4 + 3 = 7: the window counts the transfer sent before.
    assert (await w.send(first))["state"] == "awaiting_confirmation"
    [rule] = (await w.dlp(first))["decision"]["matched_rules"]
    assert (rule["name"], rule["matched_count"]) == ("My Numbers", 7)

    # A day later the old one is out of the window, and another member's transfers never count.
    w.db.sql("UPDATE transfers SET sent_at = now() - interval '25 hours' WHERE id = :id", id=old)
    other_owner = w.tenant.target
    theirs = w.draft(KNOWN)
    w.db.sql("UPDATE transfers SET created_by = :u WHERE id = :id", u=other_owner, id=theirs)
    w.file(theirs, high={"jp_my_number": 4})
    w.act_as(session_caller(w.tenant.id, other_owner, Role.MEMBER))
    assert (await w.http.post(f"/v1/transfers/{theirs}/send")).json()["state"] == "sent"
    later = w.draft(KNOWN)
    w.file(later, high={"jp_my_number": 3})
    assert (await w.send(later))["state"] == "sent"

    refused = await admin_call(
        w,
        "PATCH",
        f"/v1/dlp/rules/{w.rule('New recipient domain')}",
        {"include_sender_24h": True},
    )
    assert refused.json()["errors"][0]["pointer"] == "#/include_sender_24h"


# ---- FR-50: the message ----


async def test_the_message_is_inspected_at_creation_and_counts_in_the_decision(w: World) -> None:
    number = my_number(random.Random(50))  # noqa: S311 - test data
    w.act_as(w.owner)
    created = await w.http.post(
        "/v1/transfers",
        json={
            "recipients": [{"email": KNOWN}],
            "message": f"Payroll {CANARY}: マイナンバー {number}",
        },
    )
    assert created.status_code == 201, created.text
    transfer_id = uuid.UUID(created.json()["id"])
    rows = w.db.sql(
        "SELECT detector, count_high, file_id FROM dlp_findings WHERE transfer_id = :id",
        id=transfer_id,
    )
    assert ("jp_my_number", 1, None) in rows
    assert {file_id for _, _, file_id in rows} == {None}
    w.file(transfer_id)  # a file with nothing in it
    body = await w.send(transfer_id)
    assert (body["state"], body["dlp"]["outcome"]) == ("awaiting_confirmation", "warn")
    shown = await w.dlp(transfer_id)
    [finding] = shown["message_findings"]
    assert (finding["detector"], finding["count_high"]) == ("jp_my_number", 1)
    assert "My Numbers" in [r["name"] for r in shown["decision"]["matched_rules"]]
    records = every_audit_row(w)
    assert number not in records
    assert CANARY not in records
    [(details,)] = w.db.sql(
        "SELECT details FROM audit_events WHERE action = 'transfer.created' AND target_id = :id",
        id=transfer_id,
    )
    assert details["message_findings"] == 1  # type: ignore[index]


# ---- FR-52: monitor mode ----


async def test_monitor_mode_records_and_sends_and_enforce_holds_the_next_one(w: World) -> None:
    await w.change_rule("My Numbers", action="block")
    await w.change_policy(mode="monitor")
    watched = w.draft(NEW)
    w.file(watched, high={"jp_my_number": 1})
    body = await w.send(watched)
    assert body["state"] == "sent"
    assert body["dlp"] == {
        "outcome": "block",
        "mode": "monitor",
        "enforced": False,
        "approval_request_id": None,
    }
    [(_, outcome, _)] = w.decisions(watched)
    assert outcome == "block"

    await w.change_policy(mode="enforce")
    held = w.draft(NEW)
    w.file(held, high={"jp_my_number": 1})
    body = await w.send(held)
    assert (body["state"], body["hold_reason"], body["dlp"]["enforced"]) == (
        "held",
        "dlp_blocked",
        True,
    )
    events = w.db.sql(
        "SELECT details->>'mode' FROM audit_events WHERE action = 'dlp_policy.updated' "
        "AND tenant_id = :t ORDER BY occurred_at",
        t=w.tenant.id,
    )
    assert events == [("monitor",), ("enforce",)]


# ---- the rule checks of #221 ----


async def test_rules_for_received_files_only_allow_or_block_on_content_or_inspection(
    w: World,
) -> None:
    base = {"name": "Received", "direction": "received", "condition": "content"}
    for change, pointer in (
        ({"detectors": ["jp_my_number"], "action": "warn"}, "#/action"),
        ({"condition": "new_domain", "action": "block"}, "#/condition"),
        (
            {"detectors": ["jp_my_number"], "action": "block", "recipient_scope": "untrusted"},
            "#/recipient_scope",
        ),
        (
            {"detectors": ["jp_my_number"], "action": "block", "include_sender_24h": True},
            "#/include_sender_24h",
        ),
    ):
        refused = await admin_call(w, "POST", "/v1/dlp/rules", {**base, **change})
        assert refused.status_code == 422, refused.text
        assert refused.json()["errors"][0]["pointer"] == pointer
    made = await admin_call(
        w,
        "POST",
        "/v1/dlp/rules",
        {**base, "detectors": ["jp_my_number"], "action": "block"},
    )
    assert made.status_code == 201, made.text
    assert made.json()["direction"] == "received"
