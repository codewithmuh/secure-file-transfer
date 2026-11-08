"""DLP reports (#222, DLP-7; FR-55, FR-29): `listDlpDecisions` and `getDlpReport` against the
audit log of a seeded month, the export of the same decisions, and who may read them.

The month is made through the routes as a member and an admin would make it (test_dlp_decisions.py's
world): sends that the decision warns, sends, holds or asks approval for, a policy change and an
approval. Every total of the report is then counted again, independently, from `audit_events`.
"""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from member_fixtures import client, seed_tenant, session_caller
from pg import ScratchDatabase
from sft.data.models import Role
from sft.service.caller import Caller
from test_dlp_decisions import KNOWN, NEW, World

pytestmark = pytest.mark.anyio


@pytest.fixture
async def w(migrated_db: ScratchDatabase) -> AsyncIterator[World]:
    current: list[Caller | None] = [None]
    tenant = seed_tenant(migrated_db)
    async with client(migrated_db, lambda: current[0]) as http:
        yield World(migrated_db, tenant, http, current)


async def read(w: World, path: str, caller: Caller | None = None, **params: Any) -> Any:
    w.act_as(caller or w.admin)
    return await w.http.get(path, params=params)


async def seed_month(w: World) -> dict[str, uuid.UUID]:
    """A month of decisions: none, warn (content, new domain, not inspected), block, and an
    approved request, with one policy change before the block."""
    made: dict[str, uuid.UUID] = {}
    made["plain"] = w.draft(KNOWN)
    w.file(made["plain"])
    made["number"] = w.draft(KNOWN)
    w.file(made["number"], high={"jp_my_number": 2})
    made["new"] = w.draft(NEW)
    w.file(made["new"])
    made["encrypted"] = w.draft(KNOWN)
    w.file(made["encrypted"], reasons=["encrypted"])
    for name in ("plain", "number", "new", "encrypted"):
        await w.send(made[name])
    await w.change_rule("My Numbers", action="block")
    made["blocked"] = w.draft(KNOWN)
    w.file(made["blocked"], high={"jp_my_number": 1})
    await w.send(made["blocked"])

    # An approval: Payment cards needs one, the target approves.
    w.db.sql(
        "UPDATE users SET dlp_approver = (id = ANY(:ids)) WHERE tenant_id = :t",
        ids=[w.tenant.admin, w.tenant.target],
        t=w.tenant.id,
    )
    await w.change_rule("Payment cards", action="require_approval")
    made["card"] = w.draft(KNOWN)
    w.file(made["card"], high={"payment_card": 1})
    await w.send(made["card"])
    [(decision, _, _)] = w.decisions(made["card"])
    confirmed = await w.confirm(made["card"], decision, "Card list for the processor")
    request_id = confirmed.json()["dlp"]["approval_request_id"]
    w.act_as(session_caller(w.tenant.id, w.tenant.target, Role.MEMBER))
    approved = await w.http.post(f"/v1/dlp/approval-requests/{request_id}/approve", json={})
    assert approved.status_code == 200, approved.text
    return made


def audit_counts(w: World, action: str, key: str) -> Counter[str]:
    return Counter(
        str(value)
        for (value,) in w.db.sql(
            "SELECT details->>:key FROM audit_events WHERE tenant_id = :t AND action = :a",
            key=key,
            t=w.tenant.id,
            a=action,
        )
    )


def pairs(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {row["key"]: row["count"] for row in rows}


async def test_the_reports_totals_match_the_audit_log_and_viewing_it_is_audited(w: World) -> None:
    made = await seed_month(w)
    shown = await read(w, "/v1/dlp/report")
    assert shown.status_code == 200, shown.text
    report = shown.json()

    # Decisions by outcome, from dlp.decided.
    assert pairs(report["decisions_by_outcome"]) == dict(audit_counts(w, "dlp.decided", "outcome"))
    assert pairs(report["decisions_by_outcome"]) == {
        "none": 1,
        "warn": 3,
        "block": 1,
        "require_approval": 1,
    }
    [today] = report["decisions_by_day"]
    assert today["date"] == datetime.now(UTC).date().isoformat()
    assert pairs(today["by_outcome"]) == pairs(report["decisions_by_outcome"])
    # Matches by rule, from dlp.rule_matched (each names its rule as the target).
    by_rule = Counter(
        str(target)
        for (target,) in w.db.sql(
            "SELECT target_id FROM audit_events WHERE tenant_id = :t "
            "AND action = 'dlp.rule_matched'",
            t=w.tenant.id,
        )
    )
    assert pairs(report["matches_by_rule"]) == dict(by_rule)
    # Policy changes, from the policy events: the two rule changes.
    changes = w.db.sql(
        "SELECT count(*) FROM audit_events WHERE tenant_id = :t AND (action LIKE 'dlp_rule.%' "
        "OR action LIKE 'dlp_detector.%' OR action = 'dlp_policy.updated')",
        t=w.tenant.id,
    )
    assert [(report["policy_changes"],)] == changes
    assert report["policy_changes"] == 2
    # Approvals by approver, from dlp_approval.approved.
    [approver] = report["approvals_by_approver"]
    assert (approver["approver_id"], approver["approved"], approver["rejected"]) == (
        str(w.tenant.target),
        1,
        0,
    )
    assert approver["median_seconds_to_decide"] >= 0
    assert audit_counts(w, "dlp_approval.approved", "complete") == Counter({"true": 1})
    # Senders, recipient domains, detectors and files not fully inspected.
    assert pairs(report["decisions_by_sender"]) == {str(w.tenant.member): 6}
    domains = pairs(report["decisions_by_recipient_domain"])
    assert (domains["example.test"], domains["partner.example"]) == (5, 1)
    detectors = pairs(report["matches_by_detector"])
    assert (detectors["jp_my_number"], detectors["payment_card"]) == (2, 1)
    assert pairs(report["not_inspected_by_reason"]) == {"encrypted": 1}

    [(details,)] = w.db.sql(
        "SELECT details FROM audit_events WHERE tenant_id = :t AND action = 'dlp.report_viewed'",
        t=w.tenant.id,
    )
    assert set(details) == {"from", "to"}  # type: ignore[arg-type]
    assert made  # the month's transfers


async def test_exporting_the_decisions_returns_the_reports_count(w: World) -> None:
    await seed_month(w)
    report = (await read(w, "/v1/dlp/report")).json()
    w.act_as(w.admin)
    exported = await w.http.post(
        "/v1/audit/exports",
        json={"format": "json", "filter": {"actions": ["dlp.decided"]}},
    )
    assert exported.status_code == 200, exported.text
    assert len(exported.json()) == sum(row["count"] for row in report["decisions_by_outcome"])


async def test_the_decisions_list_filters_and_pages(w: World) -> None:
    made = await seed_month(w)
    everything = (await read(w, "/v1/dlp/decisions", limit=100)).json()
    assert len(everything["items"]) == 6
    assert everything["next_cursor"] is None
    ids = [item["id"] for item in everything["items"]]
    assert ids == sorted(ids, reverse=True)  # newest first

    warned = (await read(w, "/v1/dlp/decisions", outcome=["warn", "block"])).json()
    assert {item["outcome"] for item in warned["items"]} == {"warn", "block"}
    assert len(warned["items"]) == 4
    rule = w.rule("My Numbers")
    by_rule = (await read(w, "/v1/dlp/decisions", rule_id=str(rule))).json()["items"]
    assert {item["transfer_id"] for item in by_rule} == {
        str(made["number"]),
        str(made["blocked"]),
    }
    [matched] = [m for m in by_rule[0]["matched_rules"] if m["rule_id"] == str(rule)]
    assert matched["name"] == "My Numbers"
    theirs = (await read(w, "/v1/dlp/decisions", sender_id=str(w.tenant.target))).json()
    assert theirs["items"] == []

    first = (await read(w, "/v1/dlp/decisions", limit=4)).json()
    assert len(first["items"]) == 4
    second = (await read(w, "/v1/dlp/decisions", limit=4, cursor=first["next_cursor"])).json()
    assert [i["id"] for i in first["items"] + second["items"]] == ids
    assert second["next_cursor"] is None
    bad = await read(w, "/v1/dlp/decisions", cursor="!!")
    assert (bad.status_code, bad.json()["code"]) == (400, "invalid_cursor")
    later = datetime.now(UTC) + timedelta(days=1)
    empty = await read(w, "/v1/dlp/decisions", **{"from": later.isoformat()})
    assert empty.status_code == 422  # `from` after the default `to` (now)


async def test_who_may_read_the_report_and_its_range(
    w: World, migrated_db: ScratchDatabase
) -> None:
    await seed_month(w)
    now = datetime.now(UTC)
    too_long = await read(
        w,
        "/v1/dlp/report",
        **{"from": (now - timedelta(days=93)).isoformat(), "to": now.isoformat()},
    )
    assert (too_long.status_code, too_long.json()["code"]) == (422, "validation_failed")
    within = await read(
        w,
        "/v1/dlp/report",
        **{"from": (now - timedelta(days=92)).isoformat(), "to": now.isoformat()},
    )
    assert within.status_code == 200, within.text

    assert (await read(w, "/v1/dlp/report", w.owner)).status_code == 403
    assert (await read(w, "/v1/dlp/decisions", w.owner)).status_code == 403
    assert (await read(w, "/v1/dlp/report", w.key("audit:read"))).status_code == 200
    assert (await read(w, "/v1/dlp/decisions", w.key("audit:read"))).status_code == 200
    assert (await read(w, "/v1/dlp/report", w.key("transfers:read"))).status_code == 403

    other = seed_tenant(migrated_db)
    theirs = session_caller(other.id, other.admin, Role.ADMIN)
    their_report = (await read(w, "/v1/dlp/report", theirs)).json()
    assert their_report["decisions_by_outcome"] == []
    assert (await read(w, "/v1/dlp/decisions", theirs)).json()["items"] == []
