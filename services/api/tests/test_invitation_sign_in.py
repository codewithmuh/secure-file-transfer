# ruff: noqa: F811 - `harness`, the sign-in tests' fixture, is imported and then requested
"""Sign-in from an SSO invitation, and an operator's temporary local sign-in (#239; authn and
authz 2.5).

`startInvitationSignIn` takes the token the web app read from the invitation link, puts the invited
user and their tenant's connection in the pre-auth record and returns the provider's URL; the
callback binds the provider's subject to that user and consumes the invitation. It is public but
unsafe, so the origin checks apply, and it reveals nothing about a token it doesn't know.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest

from api_settings import WEB_ORIGIN
from pg import ScratchDatabase
from sft.api.caller import AUTH_COOKIE, SESSION_COOKIE
from test_signin import Harness, harness, role, states_of  # noqa: F401 - the harness, its role
from test_sso import federated, refusals, sso_tenant

pytestmark = pytest.mark.anyio

SAME_SITE = {"Origin": WEB_ORIGIN, "Sec-Fetch-Site": "same-site"}


def invite(
    db: ScratchDatabase, tenant_id: uuid.UUID, email: str, *, days: int = 7
) -> tuple[uuid.UUID, str]:
    """An invited member of the tenant with a live invitation link: their ID and the token."""
    user_id, token = uuid.uuid4(), secrets.token_urlsafe(32)
    db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status, "
        "invitation_token_hash, invitation_expires_at) VALUES (:id, :t, :e, lower(:e), 'member', "
        "'invited', :hash, now() + make_interval(days => :days))",
        id=user_id,
        t=tenant_id,
        e=email,
        hash=hashlib.sha256(token.encode()).digest(),
        days=days,
    )
    return user_id, token


async def start(harness: Harness, token: str, **headers: str) -> httpx.Response:
    return await harness.client.post(
        "/v1/auth/invitations", json={"token": token}, headers={**SAME_SITE, **headers}
    )


async def callback(harness: Harness, location: str) -> httpx.Response:
    query = parse_qs(urlsplit(location).query)
    harness.pool.nonce = query["nonce"][0]
    return await harness.client.get(
        "/v1/auth/callback", params={"code": "good-code", "state": query["state"][0]}
    )


async def test_an_invited_member_signs_in_from_their_invitation(harness: Harness) -> None:
    tenant_id = harness.member.tenant_id
    provider, domain = sso_tenant(harness.db, tenant_id, harness.member.user_id)
    # The invitation, not the address, binds: an address outside the proven domains works too.
    user_id, token = invite(harness.db, tenant_id, "invited@elsewhere.example")
    started = await start(harness, token)
    assert started.status_code == 200, started.text
    assert started.headers["cache-control"] == "no-store"
    assert AUTH_COOKIE in started.headers["set-cookie"]
    location = started.json()["location"]
    query = parse_qs(urlsplit(location).query)
    assert query["identity_provider"] == [provider]
    assert query["prompt"] == ["login"]
    [pending] = states_of(harness).records.values()
    assert pending.invited_user_id == user_id
    assert pending.invitation == hashlib.sha256(token.encode()).hexdigest()
    assert token not in pending.to_json()

    harness.pool.claims = federated(provider, "idp-invited", "someone.else@" + domain)
    done = await callback(harness, location)
    assert done.status_code == 302, refusals(harness.db)
    assert SESSION_COOKIE in done.headers["set-cookie"], refusals(harness.db)
    me = (await harness.client.get("/v1/me")).json()
    assert me["user"]["id"] == str(user_id)
    assert me["user"]["status"] == "active"
    assert harness.db.sql(
        "SELECT status, invitation_token_hash FROM users WHERE id = :u", u=user_id
    ) == [("active", None)]
    assert harness.db.sql("SELECT subject FROM user_identities WHERE user_id = :u", u=user_id) == [
        ("idp-invited",)
    ]
    actions = [
        a
        for (a,) in harness.db.sql(
            "SELECT action FROM audit_events WHERE tenant_id = :t AND target_id = :u "
            "ORDER BY occurred_at, id",
            t=tenant_id,
            u=user_id,
        )
    ]
    assert actions == ["user.identity_bound", "user.activated"]
    # Used up: the same link starts nothing again, and says no more than an unknown one.
    again = await start(harness, token)
    assert (again.status_code, again.json()["code"]) == (404, "not_found")


async def test_an_invitation_is_refused_when_it_cant_be_used(harness: Harness) -> None:
    tenant_id = harness.member.tenant_id
    provider, _ = sso_tenant(harness.db, tenant_id, harness.member.user_id)
    unknown = await start(harness, secrets.token_urlsafe(32))
    assert (unknown.status_code, unknown.json()["code"]) == (404, "not_found")
    _, expired = invite(harness.db, tenant_id, "late@example.test", days=-1)
    assert (await start(harness, expired)).status_code == 404
    # Public but unsafe: another origin, a cross-site fetch or a form body are refused.
    _, token = invite(harness.db, tenant_id, "careful@example.test")
    other = await start(harness, token, Origin="https://evil.test")
    assert (other.status_code, other.json()["code"]) == (403, "csrf_failed")
    cross = await start(harness, token, **{"Sec-Fetch-Site": "cross-site"})
    assert (cross.status_code, cross.json()["code"]) == (403, "csrf_failed")
    form = await harness.client.post(
        "/v1/auth/invitations",
        content=f"token={token}",
        headers={**SAME_SITE, "Content-Type": "application/x-www-form-urlencoded"},
    )
    assert form.status_code in (403, 415)  # refused before the route, as a form body
    # A tenant without an active connection can't use an invitation now.
    harness.db.sql(
        "UPDATE idp_connections SET status = 'inactive' WHERE provider_name = :p", p=provider
    )
    assert (await start(harness, token)).status_code == 404
    assert states_of(harness).records == {}


async def test_an_invitation_binds_only_a_new_subject_through_the_tenants_provider(
    harness: Harness,
) -> None:
    tenant_id = harness.member.tenant_id
    provider, domain = sso_tenant(harness.db, tenant_id, harness.member.user_id)
    # A subject already bound to someone else is refused, and the invitation stays.
    [(connection,)] = harness.db.sql(
        "SELECT id FROM idp_connections WHERE provider_name = :p", p=provider
    )
    harness.db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :t, :u, :c, 'idp-taken')",
        id=uuid.uuid4(),
        t=tenant_id,
        u=harness.member.user_id,
        c=connection,
    )
    harness.pool.claims = federated(provider, "idp-taken", f"first@{domain}")
    user_id, token = invite(harness.db, tenant_id, "second@example.test")
    started = await start(harness, token)
    done = await callback(harness, started.json()["location"])
    assert "error=sign_in_failed" in done.headers["location"]
    assert refusals(harness.db)[-1] == "identity_conflict"
    assert harness.db.sql("SELECT status FROM users WHERE id = :u", u=user_id) == [("invited",)]
    # A local sign-in can't complete an invitation.
    harness.pool.claims = {"sub": harness.member.subject, "cognito:username": str(user_id)}
    started = await start(harness, token)
    done = await callback(harness, started.json()["location"])
    assert "error=sign_in_failed" in done.headers["location"]
    assert refusals(harness.db)[-1] == "connection_mismatch"


async def test_an_invitation_replaced_before_the_callback_is_refused(harness: Harness) -> None:
    tenant_id = harness.member.tenant_id
    provider, domain = sso_tenant(harness.db, tenant_id, harness.member.user_id)
    user_id, token = invite(harness.db, tenant_id, "racing@example.test")
    started = await start(harness, token)
    harness.db.sql(
        "UPDATE users SET invitation_token_hash = :h WHERE id = :u",
        h=hashlib.sha256(b"a newer invitation").digest(),
        u=user_id,
    )
    harness.pool.claims = federated(provider, "idp-racing", f"racing@{domain}")
    done = await callback(harness, started.json()["location"])
    assert "error=sign_in_failed" in done.headers["location"]
    assert refusals(harness.db)[-1] == "invitation_invalid"
    # Refused as a whole: nothing was bound.
    assert harness.db.sql("SELECT count(*) FROM user_identities WHERE user_id = :u", u=user_id) == [
        (0,)
    ]


# ---- an operator's temporary local sign-in (recoverTenantAdmin) ----


async def test_a_temporary_local_sign_in_works_in_an_sso_tenant_until_it_expires(
    harness: Harness,
) -> None:
    tenant_id = harness.member.tenant_id
    sso_tenant(harness.db, tenant_id, harness.member.user_id)
    harness.db.sql("UPDATE tenants SET sso_required = true WHERE id = :t", t=tenant_id)
    # A permanent local identity of a member who isn't a fallback admin: refused.
    refused = await harness.sign_in()
    assert "error=sign_in_failed" in refused.headers["location"]
    assert refusals(harness.db)[-1] == "sso_required"
    # The identity the worker records for an operator's recovery expires: let in, and audited.
    ends = datetime.now(UTC) + timedelta(hours=72)
    harness.db.sql(
        "UPDATE user_identities SET expires_at = :e WHERE user_id = :u",
        e=ends,
        u=harness.member.user_id,
    )
    harness.client.cookies.clear()
    signed_in = await harness.sign_in()
    assert SESSION_COOKIE in signed_in.headers.get("set-cookie", ""), refusals(harness.db)
    [(critical, details)] = harness.db.sql(
        "SELECT security_critical, details FROM audit_events WHERE action = 'member.signed_in' "
        "AND tenant_id = :t",
        t=tenant_id,
    )
    assert critical is True
    assert details["temporary_sign_in"] is True
    # Once it has expired, refused.
    harness.db.sql(
        "UPDATE user_identities SET expires_at = now() - interval '1 second' WHERE user_id = :u",
        u=harness.member.user_id,
    )
    harness.client.cookies.clear()
    expired = await harness.sign_in()
    assert "error=sign_in_failed" in expired.headers["location"]
    assert refusals(harness.db)[-1] == "identity_expired"
