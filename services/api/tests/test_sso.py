# ruff: noqa: F811 - `harness`, the sign-in tests' fixture, is imported and then requested
"""Tenant single sign-on (#231; FR-26; authn and authz 2.4, 2.5): the admin's settings and
domains, the operator's record, sign-in through a tenant's provider with members bound or created
just in time, `sso_required`, and proven domains as trusted DLP recipients.

The acceptance criteria: a member of an SSO tenant signs in through the customer's identity
provider and lands in the right tenant and role (here through the stand-in pool that signs real
ID tokens; locally Keycloak brokers to a second realm, docs/local-development.md); an unverified
domain can't route sign-in; the authorization matrix and the isolation suite cover the new
operations (tests/test_authorization_matrix.py, tests/test_isolation.py).
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest
from fastapi.testclient import TestClient

from member_fixtures import Tenant, app_for, seed_tenant, session_caller
from operators import FakeSts
from pg import ScratchDatabase
from sft.api.caller import SESSION_COOKIE
from sft.api.operator.app import create_operator_app
from sft.data.database import Database
from sft.data.dlp_decisions import decision_policy
from sft.data.models import Role
from sft.data.roles import API, SCAN
from sft.data.scope import Scope
from sft.service import sso
from sft.service.caller import AuthMethod, Caller
from sft.service.oidc import groups_of
from test_operator_api import bearer, settings_for, token_request
from test_signin import Harness, harness, role  # noqa: F401 - the sign-in harness and its role

pytestmark = pytest.mark.anyio

# ---- the admin's operations ----


@asynccontextmanager
async def admin_client(
    db: ScratchDatabase, caller: Caller, records: dict[str, list[str]] | None = None
) -> AsyncIterator[httpx.AsyncClient]:
    database = Database.connect(db.url(API), pool_size=2)
    app = app_for(database, lambda: caller)
    app.state.txt_resolver = sso.StaticTxtResolver(records or {})
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://api.test") as http:
            yield http
    finally:
        await database.dispose()


def admin(tenant: Tenant) -> Caller:
    return session_caller(tenant.id, tenant.admin, Role.ADMIN)


def actions(db: ScratchDatabase, tenant_id: uuid.UUID) -> list[str]:
    return [
        str(a)
        for (a,) in db.sql(
            "SELECT action FROM audit_events WHERE tenant_id = :t ORDER BY occurred_at, id",
            t=tenant_id,
        )
    ]


async def test_an_admin_claims_proves_and_removes_a_domain(migrated_db: ScratchDatabase) -> None:
    tenant = seed_tenant(migrated_db)
    domain = unique_domain()
    async with admin_client(migrated_db, admin(tenant)) as http:
        claimed = await http.post("/v1/tenant/sso/domains", json={"domain": domain.upper() + "."})
        assert claimed.status_code == 201, claimed.text
        body = claimed.json()
        assert body["domain"] == domain
        assert body["status"] == "pending"
        assert body["txt_record_name"] == f"_sft-verification.{domain}"
        assert body["txt_record_value"].startswith("sft-domain-verification=")
        # Claiming it again returns the same claim.
        again = await http.post("/v1/tenant/sso/domains", json={"domain": domain})
        assert (again.status_code, again.json()["id"]) == (200, body["id"])
        # The record isn't there yet.
        missing = await http.post(f"/v1/tenant/sso/domains/{body['id']}/verify")
        assert (missing.status_code, missing.json()["code"]) == (422, "validation_failed")
        assert "_sft-verification." in missing.json()["detail"]
    records = {body["txt_record_name"]: ["v=spf1 -all", body["txt_record_value"]]}
    async with admin_client(migrated_db, admin(tenant), records) as http:
        proven = await http.post(f"/v1/tenant/sso/domains/{body['id']}/verify")
        assert proven.status_code == 200, proven.text
        assert proven.json()["status"] == "verified"
        view = (await http.get("/v1/tenant/sso")).json()
        assert view["connection"] is None
        assert [d["domain"] for d in view["domains"]] == [domain]
        removed = await http.delete(f"/v1/tenant/sso/domains/{body['id']}")
        assert removed.status_code == 204
        gone = await http.delete(f"/v1/tenant/sso/domains/{body['id']}")
        assert gone.status_code == 404
    assert [a for a in actions(migrated_db, tenant.id) if a.startswith("sso_domain.")] == [
        "sso_domain.claimed",
        "sso_domain.verified",
        "sso_domain.deleted",
    ]
    # No audit event holds the domain's text (data model 2.5).
    assert not migrated_db.sql(
        "SELECT 1 FROM audit_events WHERE tenant_id = :t AND details::text LIKE '%' || :d || '%'",
        t=tenant.id,
        d=domain,
    )


async def test_a_domain_another_tenant_proved_first_is_taken(migrated_db: ScratchDatabase) -> None:
    first, second = seed_tenant(migrated_db), seed_tenant(migrated_db)
    shared = unique_domain("shared")
    claims = {}
    for tenant in (first, second):
        async with admin_client(migrated_db, admin(tenant)) as http:
            claims[tenant.id] = (
                await http.post("/v1/tenant/sso/domains", json={"domain": shared})
            ).json()
    records = {f"_sft-verification.{shared}": [c["txt_record_value"] for c in claims.values()]}
    async with admin_client(migrated_db, admin(first), records) as http:
        ok = await http.post(f"/v1/tenant/sso/domains/{claims[first.id]['id']}/verify")
        assert ok.status_code == 200
    async with admin_client(migrated_db, admin(second), records) as http:
        taken = await http.post(f"/v1/tenant/sso/domains/{claims[second.id]['id']}/verify")
        assert (taken.status_code, taken.json()["code"]) == (409, "invalid_state")
        assert taken.json()["current_state"] == "pending"
        # And another tenant's claim is never reachable by ID.
        other = await http.post(f"/v1/tenant/sso/domains/{claims[first.id]['id']}/verify")
        assert other.status_code == 404


async def test_the_settings_need_a_provider_and_mfa_before_requiring_sso(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    async with admin_client(migrated_db, admin(tenant)) as http:
        refused = await http.patch("/v1/tenant/sso", json={"sso_required": True})
        assert (refused.status_code, refused.json()["code"]) == (422, "validation_failed")
        changed = await http.patch(
            "/v1/tenant/sso",
            json={
                "confirm_idp_mfa": True,
                "jit_provisioning": False,
                "group_roles": [
                    {"group": "sft-admins", "role": "admin"},
                    {"group": "staff", "role": "member"},
                ],
            },
        )
        assert changed.status_code == 200, changed.text
        view = changed.json()
        assert view["sso_mfa_confirmed_by"] == str(tenant.admin)
        assert view["jit_provisioning"] is False
        assert {g["group"] for g in view["group_roles"]} == {"sft-admins", "staff"}
        duplicate = await http.patch(
            "/v1/tenant/sso",
            json={
                "group_roles": [{"group": "a", "role": "admin"}, {"group": "a", "role": "member"}]
            },
        )
        assert duplicate.status_code == 422
        assert (await http.patch("/v1/tenant/sso", json={})).status_code == 422
    [(details,)] = migrated_db.sql(
        "SELECT details FROM audit_events WHERE tenant_id = :t AND action = 'tenant_sso.updated'",
        t=tenant.id,
    )
    assert details == {
        "idp_mfa_confirmed": True,
        "jit_provisioning": False,
        "group_roles_before": 0,
        "group_roles_count": 2,
        "group_roles_admin": 1,
    }


async def test_the_sso_writes_need_a_recent_sign_in(migrated_db: ScratchDatabase) -> None:
    from datetime import timedelta

    tenant = seed_tenant(migrated_db)
    stale = session_caller(tenant.id, tenant.admin, Role.ADMIN, signed_in=timedelta(minutes=16))
    async with admin_client(migrated_db, stale) as http:
        assert (await http.get("/v1/tenant/sso")).status_code == 200  # reading needs none
        for method, path, body in (
            ("PATCH", "/v1/tenant/sso", {"jit_provisioning": True}),
            ("POST", "/v1/tenant/sso/domains", {"domain": "a.example"}),
            ("POST", f"/v1/tenant/sso/domains/{uuid.uuid4()}/verify", None),
            ("DELETE", f"/v1/tenant/sso/domains/{uuid.uuid4()}", None),
        ):
            response = await http.request(method, path, json=body)
            assert (response.status_code, response.json()["code"]) == (
                401,
                "reauthentication_required",
            ), path


# ---- the operator's record ----


@pytest.fixture
def operator_client(migrated_db: ScratchDatabase) -> Iterator[TestClient]:
    with TestClient(create_operator_app(settings_for(migrated_db), sts=FakeSts())) as client:
        yield client


@pytest.fixture
def operator_token(operator_client: TestClient) -> str:
    response = operator_client.post("/v1/operator/token", json=token_request())
    assert response.status_code == 201, response.text
    return str(response.json()["token"])


def prove(db: ScratchDatabase, tenant_id: uuid.UUID, by: uuid.UUID, domain: str) -> uuid.UUID:
    domain_id = uuid.uuid4()
    db.sql(
        "INSERT INTO sso_domains (id, tenant_id, domain, verification_token, verified_at, "
        "created_by) VALUES (:id, :t, :d, repeat('a', 32), now(), :by)",
        id=domain_id,
        t=tenant_id,
        d=domain,
        by=by,
    )
    return domain_id


def configure(
    client: TestClient, token: str, tenant_id: uuid.UUID, domain: str, **overrides: Any
) -> httpx.Response:
    body = {
        "kind": "oidc",
        "provider_name": tenant_id.hex,
        "issuer": "https://idp.corp.example",
        "status": "active",
        "domains": [domain],
        "sso_required": False,
        **overrides,
    }
    return client.put(  # type: ignore[return-value]
        f"/v1/operator/tenants/{tenant_id}/sso", json=body, headers=bearer(token)
    )


def test_an_operator_records_the_provider_and_links_proven_domains(
    migrated_db: ScratchDatabase, operator_client: TestClient, operator_token: str
) -> None:
    tenant = seed_tenant(migrated_db)
    domain = unique_domain()
    unproven = configure(operator_client, operator_token, tenant.id, domain)
    assert unproven.status_code == 422  # the tenant hasn't proven the domain
    prove(migrated_db, tenant.id, tenant.admin, domain)
    wrong_name = configure(
        operator_client, operator_token, tenant.id, domain, provider_name="other"
    )
    assert wrong_name.status_code == 422
    no_mfa = configure(operator_client, operator_token, tenant.id, domain)
    assert no_mfa.status_code == 422  # active needs an admin's MFA confirmation
    member = configure(
        operator_client, operator_token, tenant.id, domain, sso_mfa_confirmed_by=str(tenant.member)
    )
    assert member.status_code == 422  # only an active admin confirms
    recorded = configure(
        operator_client, operator_token, tenant.id, domain, sso_mfa_confirmed_by=str(tenant.admin)
    )
    assert recorded.status_code == 200, recorded.text
    body = recorded.json()
    assert body["provider_name"] == tenant.id.hex
    assert [d["domain"] for d in body["domains"]] == [domain]
    assert body["sso_mfa_confirmed_by"] == str(tenant.admin)
    assert migrated_db.sql(
        "SELECT count(*) FROM sso_domains WHERE tenant_id = :t AND idp_connection_id = :c",
        t=tenant.id,
        c=uuid.UUID(body["idp_connection_id"]),
    ) == [(1,)]
    # The same configuration again changes nothing and writes no second tenant record.
    again = configure(
        operator_client, operator_token, tenant.id, domain, sso_mfa_confirmed_by=str(tenant.admin)
    )
    assert again.json()["idp_connection_id"] == body["idp_connection_id"]
    assert migrated_db.sql(
        "SELECT count(*) FROM audit_events WHERE action = 'tenant_sso.configured' "
        "AND tenant_id = :t",
        t=tenant.id,
    ) == [(1,)]


# ---- sign-in through the tenant's provider ----


def unique_domain(label: str = "corp") -> str:
    """A domain of this test alone: a proven domain is one tenant's, and the database is shared."""
    return f"{label}-{uuid.uuid4().hex[:8]}.example"


def sso_tenant(db: ScratchDatabase, tenant_id: uuid.UUID, admin_id: uuid.UUID) -> tuple[str, str]:
    """The harness member's tenant, with its provider and a proven, linked domain."""
    provider = tenant_id.hex
    domain = unique_domain()
    connection = uuid.uuid4()
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, :t, 'oidc', :p, 'https://idp.corp.example', 'active')",
        id=connection,
        t=tenant_id,
        p=provider,
    )
    domain_id = prove(db, tenant_id, admin_id, domain)
    db.sql("UPDATE sso_domains SET idp_connection_id = :c WHERE id = :d", c=connection, d=domain_id)
    return provider, domain


async def start_sso(harness: Harness, domain: str) -> dict[str, list[str]]:
    started = await harness.client.get(
        "/v1/auth/sign-in", params={"method": "sso", "sso_domain": domain, "return_to": "/"}
    )
    assert started.status_code == 302
    query = parse_qs(urlsplit(started.headers["location"]).query)
    harness.pool.nonce = query["nonce"][0]
    return query


async def finish(harness: Harness, query: dict[str, list[str]]) -> httpx.Response:
    return await harness.client.get(
        "/v1/auth/callback", params={"code": "good-code", "state": query["state"][0]}
    )


def federated(provider: str, subject: str, email: str, groups: str | None = None) -> dict[str, Any]:
    claims: dict[str, Any] = {
        "sub": f"pool-{subject}",
        "cognito:username": f"{provider}_{subject}",
        "identities": [{"providerName": provider, "userId": subject}],
        "email": email,
        "amr": [],
    }
    if groups is not None:
        claims["custom:sso_groups"] = groups
    return claims


def refusals(db: ScratchDatabase) -> list[str]:
    return [
        str(r)
        for (r,) in db.sql(
            "SELECT details->>'reason' FROM audit_events "
            "WHERE action = 'member.sign_in_refused' ORDER BY occurred_at, id"
        )
    ]


async def test_a_proven_domain_routes_to_the_tenants_provider_and_an_unproven_one_doesnt(
    harness: Harness,
) -> None:
    admin_id = harness.member.user_id
    provider, domain = sso_tenant(harness.db, harness.member.tenant_id, admin_id)
    routed = await start_sso(harness, domain.upper())
    assert routed["identity_provider"] == [provider]
    assert routed["prompt"] == ["login"]
    # A claim that isn't proven, a domain nobody claimed, an inactive connection: local sign-in.
    harness.db.sql(
        "INSERT INTO sso_domains (id, tenant_id, domain, verification_token, created_by) "
        "VALUES (:id, :t, 'pending.example', repeat('b', 32), :by)",
        id=uuid.uuid4(),
        t=harness.member.tenant_id,
        by=admin_id,
    )
    for domain in ("pending.example", "nobody.example", "not a domain"):
        assert (await start_sso(harness, domain))["identity_provider"] == ["COGNITO"]
    harness.db.sql(
        "UPDATE idp_connections SET status = 'inactive' WHERE provider_name = :p", p=provider
    )
    assert (await start_sso(harness, domain))["identity_provider"] == ["COGNITO"]


async def test_a_first_sso_sign_in_creates_the_member_with_their_groups_role(
    harness: Harness,
) -> None:
    tenant_id = harness.member.tenant_id
    provider, domain = sso_tenant(harness.db, tenant_id, harness.member.user_id)
    harness.db.sql(
        "INSERT INTO sso_group_roles (id, tenant_id, group_name, role) "
        "VALUES (:id, :t, 'sft admins', 'admin')",
        id=uuid.uuid4(),
        t=tenant_id,
    )
    harness.pool.claims = federated(
        provider, "idp-1", f"New.Person@{domain}", "[staff,sft%20admins]"
    )
    await finish(harness, await start_sso(harness, domain))
    assert SESSION_COOKIE in harness.client.cookies, refusals(harness.db)
    me = (await harness.client.get("/v1/me")).json()
    assert me["tenant"]["id"] == str(tenant_id)
    assert me["user"]["email"] == f"New.Person@{domain}"
    assert me["user"]["role"] == "admin"
    assert me["session"]["auth_method"] == "sso"
    assert me["session"]["effective_role"] == "admin"  # an SSO admin acts as one (3.3)
    [(details,)] = harness.db.sql(
        "SELECT details FROM audit_events WHERE action = 'user.provisioned'"
    )
    assert details["role"] == "admin"
    # The second sign-in finds the identity; no second member.
    harness.client.cookies.clear()
    await finish(harness, await start_sso(harness, domain))
    assert harness.db.sql(
        "SELECT count(*) FROM users WHERE tenant_id = :t AND email_normalized = "
        "'new.person@' || :d",
        t=tenant_id,
        d=domain,
    ) == [(1,)]


async def test_an_existing_member_is_bound_by_their_address_on_a_linked_domain(
    harness: Harness,
) -> None:
    tenant_id = harness.member.tenant_id
    provider, domain = sso_tenant(harness.db, tenant_id, harness.member.user_id)
    existing = uuid.uuid4()
    harness.db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) "
        "VALUES (:id, :t, :email, :email, 'member', 'invited')",
        id=existing,
        t=tenant_id,
        email=f"kim@{domain}",
    )
    harness.pool.claims = federated(provider, "idp-kim", f"KIM@{domain}")
    await finish(harness, await start_sso(harness, domain))
    me = (await harness.client.get("/v1/me")).json()
    assert me["user"]["id"] == str(existing)
    assert me["user"]["status"] == "active"  # the invitation is accepted at the first sign-in
    assert harness.db.sql(
        "SELECT action FROM audit_events WHERE target_id = :u AND action = 'user.identity_bound'",
        u=existing,
    )


@pytest.mark.parametrize(
    ("email", "jit", "reason"),
    [
        ("someone@elsewhere.example", True, "domain_not_proven"),
        (None, True, "domain_not_proven"),
        ("new@{domain}", False, "provisioning_off"),
    ],
)
async def test_a_first_sso_sign_in_is_refused_outside_the_rules(
    harness: Harness, email: str | None, jit: bool, reason: str
) -> None:
    tenant_id = harness.member.tenant_id
    provider, domain = sso_tenant(harness.db, tenant_id, harness.member.user_id)
    harness.db.sql("UPDATE tenants SET sso_jit = :jit WHERE id = :t", jit=jit, t=tenant_id)
    claims = federated(provider, "idp-x", (email or "x@{domain}").format(domain=domain))
    if email is None:
        del claims["email"]
    harness.pool.claims = claims
    callback = await finish(harness, await start_sso(harness, domain))
    assert callback.headers["location"].endswith("/sign-in?error=sign_in_failed")
    assert refusals(harness.db)[-1] == reason
    # Refused through the tenant's connection: the tenant's log has it.
    assert harness.db.sql(
        "SELECT count(*) FROM audit_events WHERE action = 'member.sign_in_refused' "
        "AND tenant_id = :t",
        t=tenant_id,
    ) == [(1,)]


async def test_another_tenants_provider_never_signs_into_this_tenant(harness: Harness) -> None:
    # The token names tenant B's provider, but the pre-auth record chose tenant A's.
    provider, domain = sso_tenant(harness.db, harness.member.tenant_id, harness.member.user_id)
    other = uuid.uuid4()
    harness.db.sql("INSERT INTO tenants (id, name, status) VALUES (:id, 'B', 'active')", id=other)
    harness.db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, :t, 'oidc', :p, 'https://idp.corp.example', 'active')",
        id=uuid.uuid4(),
        t=other,
        p=other.hex,
    )
    query = await start_sso(harness, domain)
    harness.pool.claims = federated(other.hex, "idp-1", f"a@{domain}")
    await finish(harness, query)
    assert SESSION_COOKIE not in harness.client.cookies
    assert refusals(harness.db)[-1] == "connection_mismatch"
    del provider


async def test_a_tenant_that_requires_sso_refuses_local_sign_in_except_fallback_admins(
    harness: Harness,
) -> None:
    tenant_id, user_id = harness.member.tenant_id, harness.member.user_id
    harness.db.sql("UPDATE tenants SET sso_required = true WHERE id = :t", t=tenant_id)
    await harness.sign_in()
    assert SESSION_COOKIE not in harness.client.cookies
    assert refusals(harness.db)[-1] == "sso_required"
    harness.db.sql("UPDATE users SET role = 'admin', sso_fallback = true WHERE id = :u", u=user_id)
    await harness.sign_in()
    assert SESSION_COOKIE in harness.client.cookies
    [(critical, details)] = harness.db.sql(
        "SELECT security_critical, details FROM audit_events WHERE action = 'member.signed_in' "
        "AND actor_id = :u",
        u=user_id,
    )
    assert critical is True
    assert details["sso_fallback_sign_in"] is True


# ---- DLP: proven domains are trusted recipients (#219) ----


async def test_proven_sso_domains_are_trusted_in_the_dlp_decision(
    migrated_db: ScratchDatabase,
) -> None:
    tenant = seed_tenant(migrated_db)
    domain = unique_domain()
    prove(migrated_db, tenant.id, tenant.admin, domain)
    migrated_db.sql(
        "INSERT INTO sso_domains (id, tenant_id, domain, verification_token, created_by) "
        "VALUES (:id, :t, 'pending.example', repeat('c', 32), :by)",
        id=uuid.uuid4(),
        t=tenant.id,
        by=tenant.admin,
    )
    for role_name in (API, SCAN):  # the API, and the scan worker, which decide
        database = Database.connect(migrated_db.url(role_name), pool_size=1)
        try:
            async with database.transaction(Scope.tenant(tenant.id)) as session:
                policy = await decision_policy(session)
        finally:
            await database.dispose()
        assert policy is not None
        assert domain in policy.trusted_domains
        assert "pending.example" not in policy.trusted_domains


# ---- units ----


@pytest.mark.parametrize(
    ("value", "groups"),
    [
        (["a", "b", ""], ("a", "b")),
        ("[a,b%2Cc, d%20e]", ("a", "b,c", "d e")),
        ("solo", ("solo",)),
        ("[]", ()),
        (None, ()),
        (7, ()),
    ],
)
def test_groups_come_as_a_list_or_cognitos_string(value: object, groups: tuple[str, ...]) -> None:
    assert groups_of(value) == groups


async def test_the_static_resolver_reads_names_without_case_or_trailing_dot() -> None:
    resolver = sso.StaticTxtResolver.from_json('{"_sft-verification.A.example.": ["x"]}')
    assert await resolver.txt("_sft-verification.a.example") == ("x",)
    assert await resolver.txt("other.example") == ()
    with pytest.raises(ValueError, match="JSON object"):
        sso.StaticTxtResolver.from_json('["x"]')


def test_the_auth_method_of_a_federated_token_is_sso() -> None:
    from sft.service.oidc import IdToken
    from sft.service.signin import auth_method_of

    token = IdToken("s", None, ("pwd",), None, ({"providerName": "p"},))
    assert auth_method_of(token, federated=True) is AuthMethod.SSO
