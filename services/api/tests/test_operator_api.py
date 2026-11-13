"""The operator API over HTTP, against PostgreSQL as `sft_operator` (FR-34, issue #111).

An operator exchanges a signed STS request for a token, creates a tenant, whose first admin is
invited, and lists, reads and suspends tenants. Every call is audited; every operation but the
token exchange needs a token (the authorization matrix below); each app serves only its own
server's operations.
"""

from collections.abc import Iterator
from typing import Any
from uuid import UUID

import pytest
from fastapi import FastAPI
from prometheus_client import CollectorRegistry
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from starlette.testclient import TestClient

from operators import ACCOUNT, OPERATOR_NAME, ROLE, FakeSts, signed_headers
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.api.operator import __main__ as operator_main
from sft.api.operator.app import create_operator_app
from sft.api.server import ApiServer
from sft.core.settings import EXIT_BAD_SETTINGS, OperatorSettings
from sft.data import audit
from sft.data.access import scope_of
from sft.data.database import sync_engine
from sft.data.roles import API, OPERATOR
from sft.data.scope import ScopeKind
from sft.service import operator_tenants
from sft.service.idempotency import IdempotentRequest, OperatorKey, fingerprint
from sft.service.operator_auth import GET_CALLER_IDENTITY
from tools.contract_check import (
    CONTRACT,
    OPERATOR_SERVER,
    PUBLIC_SERVER,
    check,
    contract_operations,
    load_contract,
)

PROBLEM = "application/problem+json"
# Nothing listens there: the counter store fails open in the pod (group J), and no test needs it.
VALKEY_URL = "redis://u:p@127.0.0.1:1/0"


def settings_for(db: ScratchDatabase, role: str = OPERATOR) -> OperatorSettings:
    return OperatorSettings(
        database_url=SecretStr(db.url(role)),
        database_pool_size=1,
        valkey_url=SecretStr(VALKEY_URL),
        operator_environment="dev",
        operator_aws_account_id=ACCOUNT,
        operator_role_name=ROLE,
    )


@pytest.fixture
def client(migrated_db: ScratchDatabase) -> Iterator[TestClient]:
    app = create_operator_app(settings_for(migrated_db), sts=FakeSts())
    with TestClient(app) as test_client:
        yield test_client


def token_request() -> dict[str, Any]:
    return {"sts_request": {"headers": signed_headers(), "body": GET_CALLER_IDENTITY}}


@pytest.fixture
def token(client: TestClient) -> str:
    response = client.post("/v1/operator/token", json=token_request())
    assert response.status_code == 201, response.text
    return str(response.json()["token"])


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def new_tenant(**fields: str) -> dict[str, str]:
    return {
        "name": "Example KK",
        "first_admin_email": "Admin@Example.test",
        "recovery_contact": "+81-3-0000-0000",
        **fields,
    }


def create(client: TestClient, token: str, **fields: str) -> dict[str, Any]:
    response = client.post("/v1/operator/tenants", json=new_tenant(**fields), headers=bearer(token))
    assert response.status_code == 201, response.text
    body: dict[str, Any] = response.json()
    return body


# ---- the token exchange ----


def test_the_token_is_never_cached(client: TestClient) -> None:
    response = client.post("/v1/operator/token", json=token_request())
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert (body["aws_account_id"], body["operator_name"]) == (ACCOUNT, OPERATOR_NAME)


def test_a_refused_exchange_is_a_401_problem_that_says_nothing_more(client: TestClient) -> None:
    request = {
        "sts_request": {
            "headers": signed_headers(audience="operator-api-prod"),
            "body": GET_CALLER_IDENTITY,
        }
    }
    response = client.post("/v1/operator/token", json=request)
    assert response.status_code == 401
    assert response.headers["content-type"] == PROBLEM
    assert response.json()["code"] == "credentials_invalid"
    assert "audience" not in response.text


def test_operator_authentication_failures_are_counted(migrated_db: ScratchDatabase) -> None:
    # auth_failures_total{scheme="operator"} (#260): a refused exchange and a token that isn't
    # live count; a request without a token doesn't.
    registry = CollectorRegistry()
    app = create_operator_app(settings_for(migrated_db), sts=FakeSts(), registry=registry)

    def counted() -> float | None:
        return registry.get_sample_value("auth_failures_total", {"scheme": "operator"})

    with TestClient(app) as client:
        assert counted() == 0
        refused = {
            "sts_request": {
                "headers": signed_headers(audience="operator-api-prod"),
                "body": GET_CALLER_IDENTITY,
            }
        }
        assert client.post("/v1/operator/token", json=refused).status_code == 401
        assert client.get("/v1/operator/tenants", headers=bearer("x" * 43)).status_code == 401
        assert client.get("/v1/operator/tenants").status_code == 401
    assert counted() == 2


def test_a_body_other_than_get_caller_identity_is_a_422(client: TestClient) -> None:
    request = {"sts_request": {"headers": {}, "body": "Action=AssumeRole"}}
    response = client.post("/v1/operator/token", json=request)
    assert (response.status_code, response.json()["code"]) == (422, "validation_failed")


# ---- createTenant: the acceptance criterion ----


def test_an_operator_creates_a_tenant_and_its_first_admin_is_invited(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    response = client.post(
        "/v1/operator/tenants",
        json=new_tenant(default_locale="ja"),
        headers={**bearer(token), "Idempotency-Key": "create-example-kk"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    tenant_id, admin_id = UUID(body["tenant"]["id"]), UUID(body["first_admin"]["id"])
    assert response.headers["Location"] == f"/v1/operator/tenants/{tenant_id}"
    assert body["tenant"]["status"] == "active"
    assert body["first_admin"] | {"id": None, "created_at": None} == {
        "id": None,
        "email": "Admin@Example.test",
        "role": "admin",
        "status": "invited",
        "sso_fallback": False,
        "dlp_approver": False,
        "created_at": None,
    }
    assert "recovery_contact" not in response.text  # visible to operators only when needed

    # In the database: the tenant, its policy, the invited admin, and the invitation email's
    # outbox message, carrying the user's ID only.
    assert migrated_db.sql(
        "SELECT name, status, recovery_contact FROM tenants WHERE id = :id", id=tenant_id
    ) == [("Example KK", "active", "+81-3-0000-0000")]
    assert migrated_db.sql(
        "SELECT default_locale FROM tenant_policies WHERE tenant_id = :id", id=tenant_id
    ) == [("ja",)]
    assert migrated_db.sql(
        "SELECT tenant_id, email_normalized, role, status FROM users WHERE id = :id", id=admin_id
    ) == [(tenant_id, "admin@example.test", "admin", "invited")]
    assert migrated_db.sql(
        "SELECT topic, payload FROM outbox WHERE tenant_id = :id", id=tenant_id
    ) == [("member.invited", {"user_id": str(admin_id)})]

    # Audited in the new tenant's log, and as a platform event, naming the operator.
    events = migrated_db.sql(
        "SELECT tenant_id, action, actor_type, details->>'operator_name' FROM audit_events "
        "WHERE target_id IN (:tenant, :admin) ORDER BY tenant_id NULLS LAST, action",
        tenant=tenant_id,
        admin=admin_id,
    )
    assert events == [
        (tenant_id, "tenant.created", "operator", OPERATOR_NAME),
        (tenant_id, "user.invited", "operator", None),
        (None, "tenant.created", "operator", OPERATOR_NAME),
    ]


@pytest.mark.parametrize(
    "fields",
    [
        {"name": ""},
        {"name": "x" * 201},
        {"first_admin_email": "not an address"},
        {"first_admin_email": "a@b"},
        # The mail adapter's rule (sft.core.addresses), as inviteUser applies it.
        {"first_admin_email": "a,b@x.com"},
        {"first_admin_email": "a<b>@x.com"},
        {"first_admin_email": "a@b@x.com"},
        {"first_admin_email": "ad\u200bmin@x.com"},  # a zero-width space
        {"first_admin_email": f"{'a' * 65}@x.com"},
        {"recovery_contact": ""},
        {"default_locale": "fr"},
        {"plan": "gold"},
    ],
)
def test_a_body_that_breaks_the_schema_is_a_422_and_creates_nothing(
    fields: dict[str, str], client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    before = migrated_db.sql("SELECT count(*) FROM tenants")
    response = client.post("/v1/operator/tenants", json=new_tenant(**fields), headers=bearer(token))
    assert (response.status_code, response.json()["code"]) == (422, "validation_failed")
    assert migrated_db.sql("SELECT count(*) FROM tenants") == before


# ---- listTenants and getTenant ----


def test_tenants_are_listed_newest_first_a_page_at_a_time(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    made = [create(client, token, name=f"List {n}")["tenant"]["id"] for n in range(3)]
    # Other tests share the database, so check order and paging against the whole list, read a
    # full page at a time to its last page, which has no cursor.
    ids: list[str] = []
    cursor = None
    while True:
        params: dict[str, Any] = {"limit": 100} | ({"cursor": cursor} if cursor else {})
        page = client.get("/v1/operator/tenants", params=params, headers=bearer(token))
        assert page.status_code == 200
        ids += [t["id"] for t in page.json()["items"]]
        cursor = page.json()["next_cursor"]
        if cursor is None:
            break
    assert ids == sorted(ids, key=UUID, reverse=True)
    assert [i for i in ids if i in made] == made[::-1]
    assert len(ids) == int(str(migrated_db.sql("SELECT count(*) FROM tenants")[0][0]))
    first = client.get("/v1/operator/tenants", params={"limit": 2}, headers=bearer(token)).json()
    assert [t["id"] for t in first["items"]] == ids[:2]
    second = client.get(
        "/v1/operator/tenants",
        params={"limit": 1, "cursor": first["next_cursor"]},
        headers=bearer(token),
    ).json()
    assert [t["id"] for t in second["items"]] == ids[2:3]
    # Audited as a platform event.
    assert migrated_db.sql(
        "SELECT count(*) FROM audit_events WHERE action = 'tenant.listed' AND tenant_id IS NULL"
    )[0][0]


def test_tenants_can_be_listed_by_status(client: TestClient, token: str) -> None:
    tenant_id = create(client, token)["tenant"]["id"]
    client.post(f"/v1/operator/tenants/{tenant_id}/suspend", headers=bearer(token))
    suspended = client.get(
        "/v1/operator/tenants", params={"status": "suspended", "limit": 100}, headers=bearer(token)
    ).json()["items"]
    assert tenant_id in [t["id"] for t in suspended]
    assert {t["status"] for t in suspended} == {"suspended"}


@pytest.mark.parametrize(
    ("params", "code"),
    [
        ({"cursor": "%%%"}, "invalid_cursor"),
        ({"cursor": "AAAA"}, "invalid_cursor"),
        ({"limit": 0}, "malformed_request"),
        ({"limit": 101}, "malformed_request"),
        ({"status": "deleted"}, "malformed_request"),
    ],
)
def test_bad_list_parameters_are_a_400(
    params: dict[str, object], code: str, client: TestClient, token: str
) -> None:
    response = client.get("/v1/operator/tenants", params=params, headers=bearer(token))
    assert (response.status_code, response.json()["code"]) == (400, code)


def test_a_tenant_is_read_by_id(client: TestClient, token: str) -> None:
    created = create(client, token)["tenant"]
    response = client.get(f"/v1/operator/tenants/{created['id']}", headers=bearer(token))
    assert (response.status_code, response.json()) == (200, created)


@pytest.mark.parametrize("tenant_id", ["0190f0f0-0000-7000-8000-000000000000", "not-a-uuid"])
def test_an_unknown_tenant_is_a_404(tenant_id: str, client: TestClient, token: str) -> None:
    for response in (
        client.get(f"/v1/operator/tenants/{tenant_id}", headers=bearer(token)),
        client.post(f"/v1/operator/tenants/{tenant_id}/suspend", headers=bearer(token)),
    ):
        assert (response.status_code, response.json()["code"]) == (404, "not_found")


# ---- getTenantRecoveryContact (#274) ----


def test_an_operator_reads_the_recovery_contact_recorded_in_both_logs(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    tenant_id = UUID(create(client, token)["tenant"]["id"])
    response = client.get(
        f"/v1/operator/tenants/{tenant_id}/recovery-contact", headers=bearer(token)
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"tenant_id": str(tenant_id), "recovery_contact": "+81-3-0000-0000"}
    assert response.headers["Cache-Control"] == "no-store"
    # In the tenant's log, where its admins see it, and as a platform event; never the contact.
    events = migrated_db.sql(
        "SELECT tenant_id, actor_type, details->>'operator_name', details::text FROM audit_events "
        "WHERE action = 'tenant.recovery_contact_read' AND target_id = :id "
        "ORDER BY tenant_id NULLS LAST",
        id=tenant_id,
    )
    assert [row[:3] for row in events] == [
        (tenant_id, "operator", OPERATOR_NAME),
        (None, "operator", OPERATOR_NAME),
    ]
    assert all("0000-0000" not in row[3] for row in events)


def test_a_tenant_made_before_contacts_were_recorded_has_none(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    tenant_id = create(client, token)["tenant"]["id"]
    migrated_db.sql("UPDATE tenants SET recovery_contact = NULL WHERE id = :id", id=UUID(tenant_id))
    response = client.get(
        f"/v1/operator/tenants/{tenant_id}/recovery-contact", headers=bearer(token)
    )
    assert (response.status_code, response.json()["recovery_contact"]) == (200, None)


@pytest.mark.parametrize("tenant_id", ["0190f0f0-0000-7000-8000-000000000000", "not-a-uuid"])
def test_an_unknown_tenants_recovery_contact_is_a_404(
    tenant_id: str, client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    reads = "SELECT count(*) FROM audit_events WHERE action = 'tenant.recovery_contact_read'"
    before = migrated_db.sql(reads)
    response = client.get(
        f"/v1/operator/tenants/{tenant_id}/recovery-contact", headers=bearer(token)
    )
    assert (response.status_code, response.json()["code"]) == (404, "not_found")
    assert migrated_db.sql(reads) == before


def test_the_contact_is_not_returned_until_the_platform_record_is_written(
    client: TestClient, token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = create(client, token)["tenant"]["id"]
    original = audit.record

    async def platform_down(session: Any, **kwargs: Any) -> Any:
        if scope_of(session).kind is ScopeKind.PLATFORM:
            raise OperationalError("INSERT", {}, Exception("connection lost"))
        return await original(session, **kwargs)

    monkeypatch.setattr(operator_tenants.audit, "record", platform_down)
    url = f"/v1/operator/tenants/{tenant_id}/recovery-contact"
    response = client.get(url, headers=bearer(token))
    assert (response.status_code, response.json()["code"]) == (503, "service_unavailable")
    assert "0000-0000" not in response.text
    monkeypatch.setattr(operator_tenants.audit, "record", original)
    assert client.get(url, headers=bearer(token)).status_code == 200


# ---- suspendTenant ----


def test_a_suspension_is_audited_in_the_tenants_log_and_safe_to_retry(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    tenant_id = create(client, token)["tenant"]["id"]
    for _ in range(2):
        response = client.post(f"/v1/operator/tenants/{tenant_id}/suspend", headers=bearer(token))
        assert (response.status_code, response.json()["status"]) == (200, "suspended")
    events = migrated_db.sql(
        "SELECT tenant_id IS NULL, count(*) FROM audit_events "
        "WHERE action = 'tenant.suspended' AND target_id = :id GROUP BY 1 ORDER BY 1",
        id=UUID(tenant_id),
    )
    # One change in the tenant's log; a platform event for each call.
    assert events == [(False, 1), (True, 2)]


def test_a_suspension_ends_every_session_of_the_tenant(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    created = create(client, token)
    tenant_id, admin_id = created["tenant"]["id"], created["first_admin"]["id"]
    for _ in range(2):
        migrated_db.sql(
            "INSERT INTO member_sessions (id, tenant_id, user_id, identity_id, session_hash, "
            "auth_time, auth_method, expires_at) VALUES (gen_random_uuid(), :tenant, :user, "
            "gen_random_uuid(), sha256(convert_to(gen_random_uuid()::text, 'UTF8')), now(), "
            "'local', now() + interval '1 hour')",
            tenant=UUID(tenant_id),
            user=UUID(admin_id),
        )
    response = client.post(f"/v1/operator/tenants/{tenant_id}/suspend", headers=bearer(token))
    assert response.status_code == 200
    assert migrated_db.sql(
        "SELECT revoked_reason, count(*) FROM member_sessions WHERE tenant_id = :tenant GROUP BY 1",
        tenant=UUID(tenant_id),
    ) == [("tenant_suspended", 2)]


def test_a_platform_record_that_fails_after_the_change_is_a_503(
    client: TestClient, token: str, migrated_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    tenant_id = create(client, token)["tenant"]["id"]
    original = audit.record

    async def platform_down(session: Any, **kwargs: Any) -> Any:
        if scope_of(session).kind is ScopeKind.PLATFORM:
            raise OperationalError("INSERT", {}, Exception("connection lost"))
        return await original(session, **kwargs)

    monkeypatch.setattr(operator_tenants.audit, "record", platform_down)
    response = client.post(f"/v1/operator/tenants/{tenant_id}/suspend", headers=bearer(token))
    assert (response.status_code, response.json()["code"]) == (503, "service_unavailable")
    assert "Retry-After" in response.headers
    # The suspension stands, with its record in the tenant's log; a retry writes the platform one.
    assert migrated_db.sql("SELECT status FROM tenants WHERE id = :id", id=UUID(tenant_id)) == [
        ("suspended",)
    ]
    monkeypatch.setattr(operator_tenants.audit, "record", original)
    response = client.post(f"/v1/operator/tenants/{tenant_id}/suspend", headers=bearer(token))
    assert response.status_code == 200


def test_a_tenant_whose_platform_record_fails_is_still_created_and_counted(
    migrated_db: ScratchDatabase, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The tenant stands, with its record in its own log: a 503 would invite a retry without a key
    # that makes a second tenant and a second invitation. It answers 201, and the miss is a
    # metric that alerts.
    registry = CollectorRegistry()
    app = create_operator_app(settings_for(migrated_db), sts=FakeSts(), registry=registry)
    original = audit.record

    async def platform_down(session: Any, **kwargs: Any) -> Any:
        if scope_of(session).kind is ScopeKind.PLATFORM and kwargs["action"] == "tenant.created":
            raise OperationalError("INSERT", {}, Exception("connection lost"))
        return await original(session, **kwargs)

    with TestClient(app) as client:
        token = client.post("/v1/operator/token", json=token_request()).json()["token"]
        monkeypatch.setattr(operator_tenants.audit, "record", platform_down)
        created = create(client, token)
    tenant_id = UUID(created["tenant"]["id"])
    assert migrated_db.sql(
        "SELECT tenant_id IS NULL, count(*) FROM audit_events "
        "WHERE action = 'tenant.created' AND target_id = :id GROUP BY 1",
        id=tenant_id,
    ) == [(False, 1)]  # the tenant's own record, with the change; no platform one
    failures = registry.get_sample_value(
        "sft_operator_platform_audit_failures_total", {"action": "tenant.created"}
    )
    assert failures == 1


# ---- createTenant's Idempotency-Key (#160) ----


def keyed(client: TestClient, token: str, key: str, **fields: str) -> Any:
    return client.post(
        "/v1/operator/tenants",
        json=new_tenant(**fields),
        headers={**bearer(token), "Idempotency-Key": key},
    )


def test_a_retry_with_the_same_key_returns_the_first_tenant_and_makes_nothing(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    key = f"create-{UUID(int=0).hex[:4]}-retry"
    first = keyed(client, token, key, name="Retry KK")
    assert first.status_code == 201, first.text
    # A retry with a new operator token: the key is the operator's, not the token's.
    fresh = client.post("/v1/operator/token", json=token_request()).json()["token"]
    again = keyed(client, fresh, key, name="Retry KK")
    assert again.status_code == 201, again.text
    assert again.json() == first.json()
    assert again.headers["Location"] == first.headers["Location"]
    tenant_id = UUID(first.json()["tenant"]["id"])
    assert migrated_db.sql("SELECT count(*) FROM tenants WHERE name = 'Retry KK'") == [(1,)]
    assert migrated_db.sql("SELECT count(*) FROM users WHERE tenant_id = :t", t=tenant_id) == [(1,)]
    assert migrated_db.sql("SELECT count(*) FROM outbox WHERE tenant_id = :t", t=tenant_id) == [
        (1,)
    ]  # one invitation email
    assert migrated_db.sql(
        "SELECT count(*) FROM audit_events WHERE action = 'tenant.created' AND target_id = :t",
        t=tenant_id,
    ) == [(2,)]  # the tenant's and the platform's, once each
    # The key is kept in the new tenant's scope, for the operator, never the body.
    assert migrated_db.sql(
        "SELECT tenant_id, caller_type, resource_type, resource_id, response_status "
        "FROM idempotency_keys WHERE key = :k",
        k=key,
    ) == [(tenant_id, "operator", "tenant", tenant_id, 201)]


def test_a_key_used_for_another_request_is_a_conflict(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    key = "create-conflict"
    assert keyed(client, token, key, name="First KK").status_code == 201
    other = keyed(client, token, key, name="Second KK")
    assert (other.status_code, other.json()["code"]) == (409, "idempotency_conflict")
    assert migrated_db.sql("SELECT count(*) FROM tenants WHERE name = 'Second KK'") == [(0,)]
    # A key past its 24 hours that the daily job hasn't deleted yet is never written again.
    migrated_db.sql(
        "UPDATE idempotency_keys SET created_at = now() - interval '2 days', "
        "expires_at = now() - interval '1 day' WHERE key = :k",
        k=key,
    )
    late = keyed(client, token, key, name="First KK")
    assert (late.status_code, late.json()["code"]) == (409, "idempotency_conflict")


def test_a_key_still_in_use_is_in_progress(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    key = "create-in-progress"
    owner = OperatorKey.of(OPERATOR_NAME, IdempotentRequest(key, fingerprint("POST", "/", b"")))
    assert owner is not None
    name = owner.caller_id
    engine = sync_engine(migrated_db.admin)
    try:
        with engine.connect() as held:
            # Another request with the key holds its lock (a session lock stands in for its
            # transaction's).
            held.execute(
                text("SELECT pg_advisory_lock(hashtextextended(:n, 0))"),
                {"n": f"idempotency/operator/{name}/{key}"},
            )
            busy = keyed(client, token, key, name="Busy KK")
            held.execute(text("SELECT pg_advisory_unlock_all()"))
    finally:
        engine.dispose()
    assert (busy.status_code, busy.json()["code"]) == (409, "idempotency_in_progress")
    assert migrated_db.sql("SELECT count(*) FROM tenants WHERE name = 'Busy KK'") == [(0,)]
    assert keyed(client, token, key, name="Busy KK").status_code == 201


# ---- the authorization matrix (authn-authz 6.3: the Operator column) ----

CONTRACT_DOCUMENT = load_contract(CONTRACT)
OPERATOR_OPERATIONS = [
    op for op in contract_operations(CONTRACT_DOCUMENT) if op.server == OPERATOR_SERVER
]
SAMPLE_ID = "0190f0f0-0000-7000-8000-000000000000"


def request_of(method: str, path: str) -> tuple[str, str]:
    filled = path.replace("{tenant_id}", SAMPLE_ID).replace("{break_glass_request_id}", SAMPLE_ID)
    return method.upper(), "/v1" + filled


def implemented_operations() -> list[tuple[str, str, str]]:
    app = create_operator_app()
    ids = {
        operation["operationId"]
        for item in app.openapi()["paths"].values()
        for operation in item.values()
        if isinstance(operation, dict) and "operationId" in operation
    }
    return [
        (op.operation_id, op.method, op.path)
        for op in OPERATOR_OPERATIONS
        if op.operation_id in ids
    ]


MATRIX = implemented_operations()


def test_the_matrix_covers_every_operation_the_operator_app_serves() -> None:
    assert {op_id for op_id, _, _ in MATRIX} == {
        "createOperatorToken",
        "createTenant",
        "listTenants",
        "getTenant",
        "suspendTenant",
        # #231 and #232: tests/test_sso.py and tests/test_break_glass.py run them end to end.
        "configureTenantSso",
        "requestBreakGlass",
        "listBreakGlassRequests",
        "approveBreakGlass",
        "endBreakGlass",
        # #239: tests/test_break_glass_records.py runs it end to end.
        "recordBreakGlassGrant",
        # #239: tests/test_admin_recovery.py runs it end to end.
        "recoverTenantAdmin",
        # #274: run above.
        "getTenantRecoveryContact",
    }


@pytest.mark.parametrize(("operation_id", "method", "path"), MATRIX, ids=[m[0] for m in MATRIX])
@pytest.mark.parametrize(
    "credential", ["none", "unknown token", "expired token", "a member's cookie", "basic"]
)
def test_every_operator_operation_but_the_exchange_needs_a_live_operator_token(
    operation_id: str,
    method: str,
    path: str,
    credential: str,
    client: TestClient,
    token: str,
    migrated_db: ScratchDatabase,
) -> None:
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    if credential == "unknown token":
        headers = bearer("x" * 43)
    elif credential == "expired token":
        migrated_db.sql(
            "UPDATE operator_sessions SET expires_at = now() - interval '1 second' "
            "WHERE token_hash = sha256(convert_to(:token, 'UTF8'))",
            token=token,
        )
        headers = bearer(token)
    elif credential == "a member's cookie":
        cookies = {"__Host-sft_session": "member-session"}
    elif credential == "basic":
        headers = {"Authorization": "Basic b3BlcmF0b3I6eA=="}
    verb, url = request_of(method, path)
    body = token_request() if operation_id == "createOperatorToken" else new_tenant()
    client.cookies.update(cookies)
    response = client.request(verb, url, headers=headers, json=body if verb == "POST" else None)
    client.cookies.clear()
    if operation_id == "createOperatorToken":
        assert response.status_code == 201  # public: the signed request is the credential
    else:
        assert response.status_code == 401, response.text
        assert response.headers["WWW-Authenticate"].startswith("Bearer")


# ---- each app serves only its own server's operations ----


@pytest.mark.parametrize(("operation_id", "method", "path"), MATRIX, ids=[m[0] for m in MATRIX])
def test_the_member_app_serves_no_operator_route(operation_id: str, method: str, path: str) -> None:
    verb, url = request_of(method, path)
    assert TestClient(create_app()).request(verb, url).status_code == 404


@pytest.mark.parametrize(
    "url", ["/v1/users", "/v1/transfers", "/healthz", "/metrics", "/openapi.json"]
)
def test_the_operator_app_serves_no_member_route_and_no_probes(url: str) -> None:
    assert TestClient(create_operator_app()).get(url).status_code == 404


def test_the_contract_check_fails_an_operator_operation_on_the_member_app() -> None:
    report = check({PUBLIC_SERVER: create_operator_app()}, CONTRACT_DOCUMENT)
    assert any(
        "createTenant" in problem and OPERATOR_SERVER in problem for problem in report.problems
    )


def test_the_contract_check_fails_a_member_operation_on_the_operator_app() -> None:
    app = create_operator_app()

    @app.get("/v1/users", operation_id="listUsers")
    def list_users() -> None:
        raise NotImplementedError

    report = check({OPERATOR_SERVER: app}, CONTRACT_DOCUMENT)
    assert any("listUsers" in problem and PUBLIC_SERVER in problem for problem in report.problems)


def test_the_service_apps_pass_the_contract_check() -> None:
    assert check(
        {PUBLIC_SERVER: create_app(), OPERATOR_SERVER: create_operator_app()}, CONTRACT_DOCUMENT
    ).ok


# ---- startup ----


def test_the_operator_app_logs_in_only_as_sft_operator(migrated_db: ScratchDatabase) -> None:
    with pytest.raises(ValueError, match="sft_operator"):
        create_operator_app(settings_for(migrated_db, API))


def test_without_settings_there_is_no_database() -> None:
    client = TestClient(create_operator_app(), raise_server_exceptions=False)
    response = client.get("/v1/operator/tenants", headers=bearer("x" * 43))
    assert (response.status_code, response.json()["code"]) == (500, "internal_error")


def test_the_default_sts_endpoint_is_the_regional_one(migrated_db: ScratchDatabase) -> None:
    settings = settings_for(migrated_db)
    assert settings.sts_endpoint == "https://sts.ap-northeast-1.amazonaws.com"
    assert settings.operator_audience == "operator-api-dev"
    app: FastAPI = create_operator_app(settings)
    with TestClient(app):
        assert app.state.sts.host == "sts.ap-northeast-1.amazonaws.com"


@pytest.mark.parametrize(
    "field",
    [
        {"operator_role_name": "AWSReservedSSO_BreakGlass_0123456789abcdef"},
        {"operator_role_name": "Operator"},
        {"operator_aws_account_id": "12345"},
        {"operator_environment": "test"},
        {"operator_sts_endpoint_url": "sts.example/path"},
    ],
)
def test_the_operator_settings_name_only_this_environments_operator_role(
    field: dict[str, str], migrated_db: ScratchDatabase
) -> None:
    values = settings_for(migrated_db).model_dump() | field
    with pytest.raises(ValueError, match="validation error"):
        OperatorSettings(**values)


def test_the_entry_point_exits_2_on_bad_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPERATOR_AWS_ACCOUNT_ID", raising=False)
    assert operator_main.main() == EXIT_BAD_SETTINGS


def test_the_entry_point_serves_the_operator_app(
    monkeypatch: pytest.MonkeyPatch, migrated_db: ScratchDatabase
) -> None:
    served: list[ApiServer] = []

    async def run(self: ApiServer, *, handle_signals: bool = True) -> int:
        served.append(self)
        return 0

    for name, value in {
        "DATABASE_URL": migrated_db.url(OPERATOR),
        "VALKEY_URL": VALKEY_URL,
        "OPERATOR_ENVIRONMENT": "dev",
        "OPERATOR_AWS_ACCOUNT_ID": ACCOUNT,
        "OPERATOR_ROLE_NAME": ROLE,
    }.items():
        monkeypatch.setenv(name, value)
    built: list[object] = []
    make = operator_main.create_operator_app

    def recording(settings: OperatorSettings, **kwargs: Any) -> FastAPI:
        built.append(kwargs.get("registry"))
        return make(settings, **kwargs)

    monkeypatch.setattr(ApiServer, "run", run)
    monkeypatch.setattr(operator_main, "create_operator_app", recording)
    assert operator_main.main() == 0
    assert isinstance(served[0].settings, OperatorSettings)
    # Its metrics go to the registry the server's /metrics serves.
    assert built == [served[0].metrics.registry]


def test_a_new_tenant_starts_with_the_default_dlp_policy_at_version_1(
    client: TestClient, token: str, migrated_db: ScratchDatabase
) -> None:
    # #218, detectors 6: written as sft_operator in the transaction that makes the tenant, its
    # rules made by the first admin and named in the tenant's language.
    response = client.post("/v1/operator/tenants", json=new_tenant(), headers=bearer(token))
    assert response.status_code == 201, response.text
    tenant_id = UUID(response.json()["tenant"]["id"])
    admin_id = UUID(response.json()["first_admin"]["id"])
    assert migrated_db.sql(
        "SELECT version, mode, updated_by FROM dlp_policies WHERE tenant_id = :id", id=tenant_id
    ) == [(1, "enforce", None)]
    rules = migrated_db.sql(
        "SELECT name, revision, created_by FROM dlp_rules WHERE tenant_id = :id ORDER BY id",
        id=tenant_id,
    )
    assert len(rules) == 8
    assert rules[0] == ("Credentials and private keys", 1, admin_id)
    assert rules[-1] == ("New recipient domain", 1, admin_id)
