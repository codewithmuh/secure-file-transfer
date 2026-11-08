"""The DLP policy, rules and keyword lists end to end against PostgreSQL (#218; FR-38, FR-40,
FR-41, FR-45, FR-54; data model 2.7; detectors 5, 6).

The authorization matrix covers who may call each operation; the isolation suite each data
function. Here: the default policy, versions and `expected_version`, revisions, the checks #218
makes, the audit events, the admins' notices and the policy-change limit.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from member_fixtures import RecordingLimiter, client, seed_tenant, seed_user, session_caller
from pg import ScratchDatabase
from sft.core.errors import RateLimited
from sft.data.models import Role
from sft.dlp.detect import BUILTIN_DETECTORS
from sft.service.dlp_policy import engine_version
from sft.service.email.catalog import PolicyChange
from sft.service.rate_limits.limits import KeyType, KeyValue, Limit

pytestmark = pytest.mark.anyio

DEFAULT_RULES = [
    ("Credentials and private keys", "content", ["cloud_credential", "private_key"], "medium", 1),
    ("My Numbers", "content", ["jp_my_number"], "high", 1),
    ("Payment cards", "content", ["payment_card"], "high", 1),
    (
        "Personal data in bulk",
        "content",
        [
            "phone_number",
            "email_address",
            "jp_bank_account",
            "iban",
            "jp_passport",
            "passport_mrz",
            "jp_drivers_licence",
        ],
        "medium",
        50,
    ),
    ("Files that couldn't be fully inspected", "not_inspected", [], "medium", 1),
    ("Images and files without text", "not_inspected", [], "medium", 1),
    (
        "Corporate Numbers and confidentiality labels",
        "content",
        ["jp_corporate_number", "confidentiality_label"],
        "medium",
        1,
    ),
    ("New recipient domain", "new_domain", [], "medium", 1),
]
ACTIONS = ["warn", "warn", "warn", "warn", "warn", "allow_and_record", "allow_and_record", "warn"]


class PolicyChangesUsedUp(RecordingLimiter):
    """Refuses group K's policy changes only: the tenant used its 100 of the day."""

    async def check(
        self, limits: Sequence[Limit], keys: Mapping[KeyType, KeyValue], *, cost: int = 1
    ) -> None:
        await super().check(limits, keys, cost=cost)
        if any(limit.id == "K.policy_changes" for limit in limits):
            raise RateLimited(retry_after=60)


def topics(db: ScratchDatabase, tenant_id: uuid.UUID) -> list[str]:
    rows = db.sql(
        "SELECT topic FROM outbox WHERE tenant_id = :t AND topic LIKE 'dlp_policy.%' "
        "ORDER BY created_at, id",
        t=tenant_id,
    )
    return [str(topic) for (topic,) in rows]


def dlp_events(db: ScratchDatabase, tenant_id: uuid.UUID) -> list[tuple[Any, ...]]:
    return db.sql(
        "SELECT action, target_type, target_id, details FROM audit_events "
        "WHERE tenant_id = :t AND action LIKE 'dlp%' ORDER BY occurred_at, id",
        t=tenant_id,
    )


def version(db: ScratchDatabase, tenant_id: uuid.UUID) -> int:
    [(found,)] = db.sql("SELECT version FROM dlp_policies WHERE tenant_id = :t", t=tenant_id)
    return int(found)  # type: ignore[call-overload]


async def test_the_default_policy_is_detectors_6_at_version_1(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        policy = (await http.get("/v1/dlp/policy")).json()
        rules = (await http.get("/v1/dlp/rules")).json()
    assert {k: v for k, v in policy.items() if k != "updated_at"} == {
        "mode": "enforce",
        "version": 1,
        "trusted_domains": [],
        "approval_timeout": "P3D",
        "active_approvers": 0,
        "updated_by": None,
    }
    assert rules["policy_version"] == 1
    found = [
        (r["name"], r["condition"], r["detectors"], r["min_confidence"], r["threshold"])
        for r in rules["items"]
    ]
    assert found == DEFAULT_RULES
    assert [r["action"] for r in rules["items"]] == ACTIONS
    assert [r["reasons"] for r in rules["items"]][4:6] == [
        ["encrypted", "too_large", "limit_exceeded", "parse_error"],
        ["unsupported_type", "no_text"],
    ]
    for rule in rules["items"]:
        assert rule["revision"] == 1
        assert rule["enabled"] is True
        assert (rule["direction"], rule["recipient_scope"]) == ("sent", "any")
        assert rule["created_by"] == str(tenant.admin)
        assert set(rule["detectors"]) <= BUILTIN_DETECTORS


async def test_a_japanese_tenant_gets_the_rules_named_in_japanese(
    migrated_db: ScratchDatabase,
) -> None:
    tenant_id = uuid.uuid4()
    migrated_db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, 'T', 'active')", id=tenant_id
    )
    admin = seed_user(migrated_db, tenant_id, role="admin")
    migrated_db.sql("SELECT dlp_default_policy(:t, :a, 'ja')", t=tenant_id, a=admin)
    names = migrated_db.sql(
        "SELECT name FROM dlp_rules WHERE tenant_id = :t ORDER BY id", t=tenant_id
    )
    assert names[1] == ("マイナンバー",)
    assert names[-1] == ("新しい宛先ドメイン",)
    # Called again, for a tenant that has its policy, it writes nothing.
    migrated_db.sql("SELECT dlp_default_policy(:t, :a, 'en')", t=tenant_id, a=admin)
    assert len(migrated_db.sql("SELECT 1 FROM dlp_rules WHERE tenant_id = :t", t=tenant_id)) == 8


async def test_every_write_raises_the_version_once_is_audited_and_noticed(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    second_admin = seed_user(migrated_db, tenant.id, role="admin")
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    limiter = RecordingLimiter()
    secret_term, secret_domain = "orion-codename", "secret-partner.example"
    async with client(migrated_db, lambda: admin, limiter) as http:
        policy = await http.patch(
            "/v1/dlp/policy",
            json={
                "expected_version": 1,
                "trusted_domains": [secret_domain.upper(), "パートナー.example"],
                "approval_timeout": "PT24H",
            },
        )
        assert policy.status_code == 200, policy.text
        assert policy.json()["version"] == 2
        assert policy.json()["trusted_domains"] == [secret_domain, "xn--fdket6oc.example"]
        assert policy.json()["approval_timeout"] == "P1D"
        assert policy.json()["updated_by"] == str(tenant.admin)
        detector = await http.post(
            "/v1/dlp/detectors",
            json={
                "expected_version": 2,
                "name": "Codenames",
                "kind": "keywords",
                "keywords": [secret_term, "機密プロジェクト"],
            },
        )
        assert detector.status_code == 201, detector.text
        body = detector.json()
        assert body["id"].startswith("custom:")
        assert (body["kind"], body["revision"], body["enabled"]) == ("keywords", 1, True)
        assert body["keywords"] == [secret_term, "機密プロジェクト"]
        assert detector.headers["location"] == f"/v1/dlp/detectors/{body['id']}"
        rule = await http.post(
            "/v1/dlp/rules",
            json={
                "expected_version": 3,
                "name": "Codenames out",
                "direction": "sent",
                "condition": "content",
                "detectors": [body["id"], "jp_my_number"],
                "threshold": 4321,
                "recipient_scope": "untrusted",
                "action": "block",
            },
        )
        assert rule.status_code == 201, rule.text
        rule_id = rule.json()["id"]
        changed = await http.patch(
            f"/v1/dlp/rules/{rule_id}", json={"expected_version": 4, "threshold": 9876}
        )
        assert changed.status_code == 200, changed.text
        assert (changed.json()["revision"], changed.json()["threshold"]) == (2, 9876)
        renamed = await http.patch(
            f"/v1/dlp/detectors/{body['id']}", json={"keywords": [secret_term, "別の名前"]}
        )
        assert (renamed.status_code, renamed.json()["revision"]) == (200, 2)
        assert (await http.delete(f"/v1/dlp/rules/{rule_id}")).status_code == 204
        assert (await http.delete(f"/v1/dlp/detectors/{body['id']}")).status_code == 204
        after = (await http.get("/v1/dlp/policy")).json()
    assert after["version"] == 8  # seven writes, one each
    assert version(migrated_db, tenant.id) == 8
    events = dlp_events(migrated_db, tenant.id)
    assert [e[0] for e in events] == [
        "dlp_policy.updated",
        "dlp_detector.created",
        "dlp_rule.created",
        "dlp_rule.changed",
        "dlp_detector.changed",
        "dlp_rule.deleted",
        "dlp_detector.deleted",
    ]
    assert [e[3]["policy_version"] for e in events] == list(range(2, 9))
    assert events[0][3]["trusted_domains"] == 2
    assert events[0][3]["approval_timeout_seconds"] == 86400
    assert events[3][3]["changed_threshold"] is True
    # Never a keyword, a threshold, a domain or a name (FR-54).
    text = json.dumps([e[3] for e in events], ensure_ascii=False)
    for secret in (secret_term, "機密", secret_domain, "xn--", "4321", "9876", "Codenames"):
        assert secret not in text
    expected_topics = [
        "trusted_domains_changed",
        "approval_timeout_changed",
        "detector_added",
        "rule_added",
        "rule_changed",
        "detector_changed",
        "rule_removed",
        "detector_removed",
    ]
    assert topics(migrated_db, tenant.id) == [f"dlp_policy.changed.{t}" for t in expected_topics]
    charged = [ids for ids, _ in limiter.checks if ids == ("K.policy_changes",)]
    assert len(charged) == 7
    assert second_admin  # every active admin is emailed: tests/test_notify.py


async def test_two_admins_with_the_same_version_the_second_gets_a_conflict(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    other = seed_user(migrated_db, tenant.id, role="admin")
    first = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    second = session_caller(tenant.id, other, Role.ADMIN)
    body = {"expected_version": 1, "trusted_domains": ["a.example"]}
    async with client(migrated_db, lambda: first) as http:
        assert (await http.patch("/v1/dlp/policy", json=body)).status_code == 200
    async with client(migrated_db, lambda: second) as http:
        stale = await http.patch("/v1/dlp/policy", json={**body, "trusted_domains": ["b.example"]})
        rule = await http.post(
            "/v1/dlp/rules",
            json={
                "expected_version": 1,
                "name": "x",
                "direction": "sent",
                "condition": "new_domain",
                "action": "warn",
            },
        )
    assert (stale.status_code, stale.json()["code"]) == (409, "dlp_policy_conflict")
    assert (rule.status_code, rule.json()["code"]) == (409, "dlp_policy_conflict")
    assert version(migrated_db, tenant.id) == 2


async def test_a_rule_change_writes_a_revision_and_retires_the_old(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        rules = (await http.get("/v1/dlp/rules")).json()["items"]
        my_numbers = rules[1]
        same = await http.patch(
            f"/v1/dlp/rules/{my_numbers['id']}", json={"name": my_numbers["name"]}
        )
        assert same.json() == my_numbers  # nothing changed: no revision, no version
        changed = await http.patch(
            f"/v1/dlp/rules/{my_numbers['id']}",
            json={"recipient_scope": "untrusted", "enabled": False},
        )
        assert changed.status_code == 200, changed.text
        got = (await http.get(f"/v1/dlp/rules/{my_numbers['id']}")).json()
        listed = (await http.get("/v1/dlp/rules")).json()
        gone = await http.delete(f"/v1/dlp/rules/{my_numbers['id']}")
        again = await http.delete(f"/v1/dlp/rules/{my_numbers['id']}")
        missing = await http.get(f"/v1/dlp/rules/{my_numbers['id']}")
    assert got == changed.json()
    assert (got["revision"], got["recipient_scope"], got["enabled"]) == (2, "untrusted", False)
    assert listed["policy_version"] == 2
    assert [r["id"] for r in listed["items"]] == [r["id"] for r in rules]
    assert gone.status_code == 204
    assert (again.status_code, missing.status_code) == (404, 404)
    rows = migrated_db.sql(
        "SELECT revision, retired_at IS NOT NULL, recipient_scope FROM dlp_rules "
        "WHERE id = :id ORDER BY revision",
        id=my_numbers["id"],
    )
    assert rows == [(1, True, "any"), (2, True, "untrusted")]


async def test_a_detector_a_live_rule_uses_and_a_built_in_one_cant_be_deleted(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        detector = (
            await http.post(
                "/v1/dlp/detectors",
                json={"name": "Projects", "kind": "keywords", "keywords": ["vega"]},
            )
        ).json()
        rule = (
            await http.post(
                "/v1/dlp/rules",
                json={
                    "name": "Projects",
                    "direction": "sent",
                    "condition": "content",
                    "detectors": [detector["id"]],
                    "action": "warn",
                },
            )
        ).json()
        in_use = await http.delete(f"/v1/dlp/detectors/{detector['id']}")
        built_in = await http.delete("/v1/dlp/detectors/jp_my_number")
        change_built_in = await http.patch("/v1/dlp/detectors/jp_my_number", json={"name": "x"})
        unknown = await http.get("/v1/dlp/detectors/not_a_detector")
        await http.patch(f"/v1/dlp/rules/{rule['id']}", json={"detectors": ["jp_my_number"]})
        free = await http.delete(f"/v1/dlp/detectors/{detector['id']}")
    assert (in_use.status_code, in_use.json()["code"]) == (409, "detector_in_use")
    assert (built_in.status_code, built_in.json()["code"]) == (409, "invalid_state")
    assert (change_built_in.status_code, change_built_in.json()["code"]) == (409, "invalid_state")
    assert unknown.status_code == 404
    assert free.status_code == 204


@pytest.mark.parametrize(
    ("path", "body", "pointer"),
    [
        ("/v1/dlp/policy", {"trusted_domains": ["com"]}, "#/trusted_domains/0"),
        ("/v1/dlp/policy", {"trusted_domains": ["bad_domain.example"]}, "#/trusted_domains/0"),
        ("/v1/dlp/policy", {"approval_timeout": "PT30M"}, "#/approval_timeout"),
        # #221: a rule for received files tests content or inspection only.
        ("/v1/dlp/rules", {"direction": "received", "action": "block"}, "#/condition"),
        ("/v1/dlp/rules", {"include_sender_24h": True}, "#/include_sender_24h"),
        ("/v1/dlp/rules", {"approvals_required": 2}, "#/approvals_required"),
        ("/v1/dlp/rules", {"condition": "content"}, "#/detectors"),
        ("/v1/dlp/rules", {"condition": "content", "detectors": ["jp_nothing"]}, "#/detectors/0"),
        (
            "/v1/dlp/rules",
            {"condition": "content", "detectors": [f"custom:{uuid.uuid4()}"]},
            "#/detectors/0",
        ),
        ("/v1/dlp/rules", {"condition": "not_inspected"}, "#/reasons"),
        ("/v1/dlp/detectors", {"kind": "pattern"}, "#/pattern"),
        ("/v1/dlp/detectors", {"kind": "keywords"}, "#/keywords"),
        (
            "/v1/dlp/detectors",
            {"kind": "keywords", "keywords": ["a"], "min_length": 3},
            "#/min_length",
        ),
    ],
)
async def test_what_the_policy_doesnt_accept_is_refused(
    migrated_db: ScratchDatabase, path: str, body: dict[str, object], pointer: str
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    defaults: dict[str, object] = {}
    if path.endswith("rules"):
        defaults = {"name": "r", "direction": "sent", "condition": "new_domain", "action": "warn"}
    elif path.endswith("detectors"):
        defaults = {"name": "k"}
    method = "PATCH" if path.endswith("policy") else "POST"
    async with client(migrated_db, lambda: admin) as http:
        response = await http.request(method, path, json={**defaults, **body})
    assert response.status_code == 422, response.text
    assert response.json()["code"] == "validation_failed"
    assert [e.get("pointer") for e in response.json()["errors"]] == [pointer]
    assert version(migrated_db, tenant.id) == 1


async def test_require_approval_needs_more_active_approvers_than_it_needs(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    body = {
        "name": "Approve",
        "direction": "sent",
        "condition": "new_domain",
        "action": "require_approval",
    }
    approvers = [seed_user(migrated_db, tenant.id) for _ in range(2)]
    async with client(migrated_db, lambda: admin) as http:
        migrated_db.sql("UPDATE users SET dlp_approver = true WHERE id = :id", id=approvers[0])
        alone = await http.post("/v1/dlp/rules", json=body)
        migrated_db.sql("UPDATE users SET dlp_approver = true WHERE id = :id", id=approvers[1])
        enough = await http.post("/v1/dlp/rules", json=body)
        policy = (await http.get("/v1/dlp/policy")).json()
    assert (alone.status_code, alone.json()["code"]) == (422, "approvers_insufficient")
    assert enough.status_code == 201, enough.text
    assert policy["active_approvers"] == 2


async def test_a_keyword_list_is_checked_as_the_inspector_compiles_it(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        blank = await http.post(
            "/v1/dlp/detectors", json={"name": "k", "kind": "keywords", "keywords": ["  "]}
        )
        duplicate = await http.post(
            "/v1/dlp/detectors", json={"name": "k", "kind": "keywords", "keywords": ["a", "a"]}
        )
    assert (blank.status_code, blank.json()["errors"][0]["pointer"]) == (422, "#/keywords/0")
    assert duplicate.status_code == 422


async def test_the_detectors_list_names_built_ins_in_the_callers_language(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    migrated_db.sql(
        "INSERT INTO tenant_policies (tenant_id, default_locale) VALUES (:t, 'ja')", t=tenant.id
    )
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin) as http:
        created = await http.post(
            "/v1/dlp/detectors",
            json={"name": "顧客名", "kind": "keywords", "keywords": ["株式会社サンプル"]},
        )
        english = await http.get("/v1/dlp/detectors", headers={"Accept-Language": "en-GB"})
        tenant_default = (await http.get("/v1/dlp/detectors")).json()
        one = await http.get("/v1/dlp/detectors/jp_my_number", headers={"Accept-Language": "en"})
        own = await http.get(f"/v1/dlp/detectors/{created.json()['id']}")
    listed = english.json()
    assert listed["engine_version"] == engine_version()
    built_in = [d for d in listed["items"] if d["kind"] == "built_in"]
    assert {d["id"] for d in built_in} == BUILTIN_DETECTORS
    assert built_in[0] == {
        "id": "jp_my_number",
        "kind": "built_in",
        "name": "My Number (Individual Number)",
        "description": built_in[0]["description"],
        "enabled": True,
    }
    assert listed["items"][-1]["keywords"] == ["株式会社サンプル"]
    assert tenant_default["items"][0]["name"] == "マイナンバー・個人番号"
    assert one.json()["name"] == "My Number (Individual Number)"
    assert own.json() == listed["items"][-1]


async def test_a_retry_with_the_same_key_creates_one_rule(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    body = {"name": "r", "direction": "sent", "condition": "new_domain", "action": "warn"}
    async with client(migrated_db, lambda: admin) as http:
        first = await http.post("/v1/dlp/rules", json=body, headers={"Idempotency-Key": "k-1"})
        second = await http.post("/v1/dlp/rules", json=body, headers={"Idempotency-Key": "k-1"})
        other = await http.post(
            "/v1/dlp/rules", json={**body, "name": "s"}, headers={"Idempotency-Key": "k-1"}
        )
    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()
    assert other.json()["code"] == "idempotency_conflict"
    assert version(migrated_db, tenant.id) == 2


async def test_the_daily_limit_refuses_a_change_and_writes_nothing(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    admin = session_caller(tenant.id, tenant.admin, Role.ADMIN)
    async with client(migrated_db, lambda: admin, PolicyChangesUsedUp()) as http:
        refused = await http.patch("/v1/dlp/policy", json={"trusted_domains": ["a.example"]})
    assert refused.status_code == 429
    assert version(migrated_db, tenant.id) == 1
    assert topics(migrated_db, tenant.id) == []


def test_every_change_kind_has_a_topic() -> None:
    from sft.data.outbox import DLP_POLICY_CHANGED, DLP_POLICY_CHANGES, TOPICS

    assert set(DLP_POLICY_CHANGES) == {c.value for c in PolicyChange}
    for topic in DLP_POLICY_CHANGED.values():
        assert TOPICS[topic.name] is topic
