"""Member sign-in end to end (#113): the routes, the service and PostgreSQL, with a stand-in user
pool that signs real RS256 ID tokens. The acceptance criteria: a member signs in and calls
`GET /me`; an unsafe request without the CSRF token is refused; a revoked session stops at once."""

import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
import pytest
from joserfc import jwt
from joserfc.jwk import RSAKey

from api_settings import CSRF_KEYRING, ISSUER, WEB_ORIGIN
from member_fixtures import EMAIL_KEYRING, RecordingLimiter
from pg import ScratchDatabase
from sft.api.app import create_app
from sft.api.caller import AUTH_COOKIE, SESSION_COOKIE
from sft.api.rate_limits import get_rate_limiter
from sft.data.database import Database
from sft.data.signin_state import PendingSignIn
from sft.service.csrf import CsrfKeyring
from sft.service.oidc import OidcClient
from sft.service.rate_limits.limits import KeyType
from sft.service.signin import SignIn, SignInConfig

pytestmark = pytest.mark.anyio

CLIENT_ID = "sft-api-test"
REDIRECT_URI = "https://api.sft.test/v1/auth/callback"
LOGOUT_URL = f"{ISSUER}/protocol/openid-connect/logout"
API = "https://api.sft.test"


class MemoryStates:
    """The sign-in state store, in memory: `take` returns a record once."""

    def __init__(self) -> None:
        self.records: dict[str, PendingSignIn] = {}

    async def put(self, cookie: str, pending: PendingSignIn) -> None:
        self.records[cookie] = pending

    async def take(self, cookie: str) -> PendingSignIn | None:
        return self.records.pop(cookie, None)

    async def aclose(self) -> None:
        return None


@dataclass
class Pool:
    """The stand-in user pool: discovery, keys, the token endpoint and revocation."""

    key: RSAKey = field(default_factory=lambda: RSAKey.generate_key(2048, parameters={"kid": "k1"}))
    claims: dict[str, Any] = field(default_factory=dict)
    nonce: str = ""
    revoked: list[str] = field(default_factory=list)

    def sign(self, **overrides: Any) -> str:
        now = int(time.time())
        claims = {
            "iss": ISSUER,
            "aud": CLIENT_ID,
            "exp": now + 300,
            "iat": now,
            "auth_time": now,
            "token_use": "id",
            "nonce": self.nonce,
            **self.claims,
            **overrides,
        }
        return jwt.encode({"alg": "RS256", "kid": "k1"}, claims, self.key)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": f"{ISSUER}/auth",
                    "token_endpoint": f"{ISSUER}/token",
                    "jwks_uri": f"{ISSUER}/certs",
                    "revocation_endpoint": f"{ISSUER}/revoke",
                },
            )
        if path.endswith("/certs"):
            return httpx.Response(200, json={"keys": [self.key.as_dict(private=False)]})
        if path.endswith("/token"):
            form = parse_qs(request.content.decode())
            if form.get("code") != ["good-code"]:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"id_token": self.sign(), "refresh_token": "rt-1"})
        if path.endswith("/revoke"):
            self.revoked.append(parse_qs(request.content.decode())["token"][0])
            return httpx.Response(200)
        return httpx.Response(404)


@dataclass
class Member:
    tenant_id: uuid.UUID
    user_id: uuid.UUID
    subject: str


def seed_member(
    db: ScratchDatabase, provider_name: str, *, status: str = "active", role: str = "member"
) -> Member:
    """A tenant, a member and their identity at the pool's connection, as the superuser."""
    tenant_id, user_id, connection_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    subject = f"sub-{uuid.uuid4()}"
    db.sql(
        "INSERT INTO tenants (id, name, status) VALUES (:id, 'Signin Co', 'active')", id=tenant_id
    )
    db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) "
        "VALUES (:id, :tenant, :email, :email, :role, :status)",
        id=user_id,
        tenant=tenant_id,
        email=f"{user_id}@example.test",
        status=status,
        role=role,
    )
    db.sql(
        "INSERT INTO idp_connections (id, tenant_id, kind, provider_name, issuer, status) "
        "VALUES (:id, NULL, 'local', :name, :issuer, 'active')",
        id=connection_id,
        name=provider_name,
        issuer=ISSUER,
    )
    db.sql(
        "INSERT INTO user_identities (id, tenant_id, user_id, idp_connection_id, subject) "
        "VALUES (:id, :tenant, :user, :connection, :subject)",
        id=uuid.uuid4(),
        tenant=tenant_id,
        user=user_id,
        connection=connection_id,
        subject=subject,
    )
    return Member(tenant_id, user_id, subject)


@dataclass
class Harness:
    client: httpx.AsyncClient
    pool: Pool
    member: Member
    db: ScratchDatabase
    limiter: RecordingLimiter
    service: SignIn

    async def sign_in(self, code: str = "good-code", return_to: str = "/files") -> httpx.Response:
        started = await self.client.get(
            "/v1/auth/sign-in", params={"method": "local", "return_to": return_to}
        )
        assert started.status_code == 302
        query = parse_qs(urlsplit(started.headers["location"]).query)
        self.pool.nonce = query["nonce"][0]
        return await self.client.get(
            "/v1/auth/callback", params={"code": code, "state": query["state"][0]}
        )


@pytest.fixture
def role() -> str:
    return "member"


@pytest.fixture
async def harness(
    migrated_db: ScratchDatabase, api_db: Database, role: str
) -> AsyncIterator[Harness]:
    provider_name = f"pool-{uuid.uuid4()}"
    member = seed_member(migrated_db, provider_name, role=role)
    pool = Pool(claims={"sub": member.subject, "cognito:username": str(member.user_id)})
    oidc = OidcClient(
        issuer=ISSUER,
        client_id=CLIENT_ID,
        client_secret="test-only-client-secret",  # noqa: S106 - obviously fake
        redirect_uri=REDIRECT_URI,
        http=httpx.AsyncClient(transport=httpx.MockTransport(pool.handle)),
    )
    app = create_app()
    app.state.database = api_db
    app.state.email_keyring = EMAIL_KEYRING
    limiter = RecordingLimiter()
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    app.state.sign_in = service = SignIn(
        api_db,
        oidc,
        MemoryStates(),
        CsrfKeyring.from_json(CSRF_KEYRING),
        SignInConfig(provider_name=provider_name, web_origin=WEB_ORIGIN, logout_url=LOGOUT_URL),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=API) as client:
        yield Harness(client, pool, member, migrated_db, limiter, service)
    await oidc.aclose()


async def test_a_member_signs_in_calls_me_and_signs_out(harness: Harness) -> None:
    callback = await harness.sign_in()
    assert callback.status_code == 302
    assert callback.headers["location"] == f"{WEB_ORIGIN}/auth/callback?return_path=%2Ffiles"
    assert callback.headers["cache-control"] == "no-store"
    cookie = callback.headers["set-cookie"]
    assert SESSION_COOKIE in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "samesite=strict" in cookie.lower()
    assert harness.pool.revoked == ["rt-1"]  # the refresh token is never kept

    me = await harness.client.get("/v1/me")
    assert me.status_code == 200, me.text
    body = me.json()
    assert body["user"]["id"] == str(harness.member.user_id)
    assert body["tenant"]["id"] == str(harness.member.tenant_id)
    assert body["session"]["effective_role"] == "member"
    csrf = body["csrf_token"]

    # The session's token is stored only as a hash.
    [stored] = harness.db.sql(
        "SELECT session_hash FROM member_sessions WHERE user_id = :user",
        user=harness.member.user_id,
    )
    token = harness.client.cookies[SESSION_COOKIE]
    assert token.encode() not in bytes(stored[0])  # type: ignore[arg-type]

    # An unsafe request without the CSRF token, or from another origin, is refused.
    no_token = await harness.client.post("/v1/auth/sign-out", headers={"Origin": WEB_ORIGIN})
    assert no_token.status_code == 403
    wrong_origin = await harness.client.post(
        "/v1/auth/sign-out", headers={"Origin": "https://evil.test", "X-CSRF-Token": csrf}
    )
    assert wrong_origin.status_code == 403
    cross_site = await harness.client.post(
        "/v1/auth/sign-out",
        headers={"Origin": WEB_ORIGIN, "X-CSRF-Token": csrf, "Sec-Fetch-Site": "cross-site"},
    )
    assert cross_site.status_code == 403

    out = await harness.client.post(
        "/v1/auth/sign-out", headers={"Origin": WEB_ORIGIN, "X-CSRF-Token": csrf}
    )
    assert out.status_code == 200, out.text
    assert out.json() == {"logout_url": LOGOUT_URL}

    # Revoked: the same token stops working at once.
    harness.client.cookies.set(SESSION_COOKIE, token, domain="api.sft.test")
    after = await harness.client.get("/v1/me")
    assert after.status_code == 401
    assert "session_expired" in after.text


async def test_a_revoked_session_stops_at_once(harness: Harness) -> None:
    await harness.sign_in()
    assert (await harness.client.get("/v1/me")).status_code == 200
    harness.db.sql(
        "UPDATE member_sessions SET revoked_at = now(), revoked_reason = 'signed_out_by_admin' "
        "WHERE user_id = :user",
        user=harness.member.user_id,
    )
    assert (await harness.client.get("/v1/me")).status_code == 401


async def test_sign_out_of_every_session(harness: Harness) -> None:
    await harness.sign_in()
    first = harness.client.cookies[SESSION_COOKIE]
    harness.client.cookies.clear()
    await harness.sign_in()
    csrf = (await harness.client.get("/v1/me")).json()["csrf_token"]
    out = await harness.client.post(
        "/v1/auth/sign-out",
        json={"all_sessions": True},
        headers={"Origin": WEB_ORIGIN, "X-CSRF-Token": csrf},
    )
    assert out.status_code == 200, out.text
    harness.client.cookies.clear()
    harness.client.cookies.set(SESSION_COOKIE, first, domain="api.sft.test")
    assert (await harness.client.get("/v1/me")).status_code == 401


async def test_a_new_sign_in_ends_the_previous_session(harness: Harness) -> None:
    await harness.sign_in()
    first = harness.client.cookies[SESSION_COOKIE]
    await harness.sign_in()  # the browser still sends the first cookie
    harness.client.cookies.clear()
    harness.client.cookies.set(SESSION_COOKIE, first, domain="api.sft.test")
    assert (await harness.client.get("/v1/me")).status_code == 401


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"code": "bad-code"}, "code_rejected"),
        ({"nonce": "not-the-nonce"}, "nonce_mismatch"),
        ({"aud": "someone-else"}, "token_invalid"),
        ({"token_use": "access"}, "token_invalid"),
        ({"sub": "nobody"}, "unknown_identity"),
        ({"cognito:username": str(uuid.uuid4())}, "user_mismatch"),
        ({"auth_time": int(time.time()) - 3600}, "stale_authentication"),
    ],
)
async def test_a_refused_sign_in_gets_no_session_and_is_audited(
    harness: Harness, change: dict[str, Any], reason: str
) -> None:
    code = change.pop("code", "good-code")
    harness.pool.claims.update(change)
    if "nonce" in change:
        # The pool signs the nonce it was given; make it sign another.
        original = harness.pool.sign
        harness.pool.sign = lambda **o: original(**{**o, "nonce": "not-the-nonce"})  # type: ignore[method-assign]
    callback = await harness.sign_in(code)
    assert callback.status_code == 302
    assert callback.headers["location"] == f"{WEB_ORIGIN}/sign-in?error=sign_in_failed"
    assert SESSION_COOKIE not in harness.client.cookies
    rows = harness.db.sql(
        "SELECT details->>'reason' FROM audit_events WHERE action = 'member.sign_in_refused' "
        "AND details->>'reason' = :reason",
        reason=reason,
    )
    assert rows


async def test_a_callback_without_its_state_is_refused(harness: Harness) -> None:
    started = await harness.client.get("/v1/auth/sign-in?method=sso&sso_domain=example.test")
    assert AUTH_COOKIE in started.headers["set-cookie"]
    callback = await harness.client.get(
        "/v1/auth/callback", params={"code": "good-code", "state": "forged"}
    )
    assert callback.headers["location"].endswith("error=sign_in_failed")
    # The record is used up: even the right state can't replay it.
    harness.client.cookies.clear()
    again = await harness.client.get("/v1/auth/callback", params={"code": "good-code"})
    assert again.headers["location"].endswith("error=sign_in_failed")
    denied = await harness.client.get("/v1/auth/callback", params={"error": "access_denied"})
    assert denied.headers["location"].endswith("error=sign_in_failed")


async def test_sso_needs_a_domain(harness: Harness) -> None:
    r = await harness.client.get("/v1/auth/sign-in?method=sso")
    assert r.status_code == 422


async def test_member_routes_need_exactly_one_credential(harness: Harness) -> None:
    assert (await harness.client.get("/v1/me")).status_code == 401
    bearer = await harness.client.get("/v1/me", headers={"Authorization": "Bearer x"})
    assert bearer.status_code == 401
    # No bearer token is valid yet (API keys come in M5): a failed authentication.
    assert bearer.json()["code"] == "credentials_invalid"
    assert bearer.headers["www-authenticate"] == 'Bearer error="invalid_token"'
    await harness.sign_in()
    both = await harness.client.get("/v1/me", headers={"Authorization": "Bearer x"})
    assert both.status_code == 401
    assert "credentials_invalid" in both.text
    assert (await harness.client.get("/v1/me")).status_code == 200


async def test_an_unsafe_request_with_a_form_body_is_refused(harness: Harness) -> None:
    await harness.sign_in()
    csrf = (await harness.client.get("/v1/me")).json()["csrf_token"]
    r = await harness.client.post(
        "/v1/auth/sign-out",
        content=b"all_sessions=true",
        headers={
            "Origin": WEB_ORIGIN,
            "X-CSRF-Token": csrf,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert r.status_code == 403


async def test_a_deactivated_member_cannot_sign_in(harness: Harness) -> None:
    harness.db.sql(
        "UPDATE users SET status = 'deactivated' WHERE id = :id", id=harness.member.user_id
    )
    callback = await harness.sign_in()
    assert callback.headers["location"].endswith("error=sign_in_failed")


async def test_the_sign_in_routes_apply_their_rate_limits(harness: Harness) -> None:
    await harness.sign_in()
    await harness.client.get("/v1/me")
    assert [ids for ids, _ in harness.limiter.checks] == [
        ("B.start_ip",),
        ("B.callback_ip",),
        ("H.caller_requests", "H.tenant_requests"),
    ]
    _, keys = harness.limiter.checks[-1]
    assert keys[KeyType.ACCOUNT] == str(harness.member.user_id)
    assert keys[KeyType.TENANT] == str(harness.member.tenant_id)


@pytest.mark.parametrize("role", ["admin"])
async def test_a_member_route_takes_the_session_and_its_csrf_token(harness: Harness) -> None:
    # The acceptance criterion on a route of its own (#112): an admin's session invites only with
    # the CSRF token, from the web app's origin.
    await harness.sign_in()
    me = (await harness.client.get("/v1/me")).json()
    assert me["session"]["effective_role"] == "admin"  # the passkey rule is off here
    invite = {"email": f"new-{uuid.uuid4().hex}@example.test"}
    refused = await harness.client.post("/v1/users", json=invite, headers={"Origin": WEB_ORIGIN})
    assert refused.status_code == 403
    assert refused.json()["code"] == "csrf_failed"
    made = await harness.client.post(
        "/v1/users", json=invite, headers={"Origin": WEB_ORIGIN, "X-CSRF-Token": me["csrf_token"]}
    )
    assert made.status_code == 201, made.text


def add_user(harness: Harness, role: str) -> uuid.UUID:
    user_id = uuid.uuid4()
    harness.db.sql(
        "INSERT INTO users (id, tenant_id, email, email_normalized, role, status) "
        "VALUES (:id, :tenant, :email, :email, :role, 'active')",
        id=user_id,
        tenant=harness.member.tenant_id,
        email=f"{user_id.hex}@example.test",
        role=role,
    )
    return user_id


@pytest.mark.parametrize("role", ["admin"])
async def test_deactivating_a_member_ends_their_sessions(harness: Harness) -> None:
    await harness.sign_in()
    me = (await harness.client.get("/v1/me")).json()
    headers = {"Origin": WEB_ORIGIN, "X-CSRF-Token": me["csrf_token"]}
    add_user(harness, "admin")  # so the tenant keeps an active admin
    user = harness.member.user_id
    gone = await harness.client.post(f"/v1/users/{user}/deactivate", headers=headers)
    assert gone.status_code == 200, gone.text
    assert harness.db.sql(
        "SELECT revoked_reason FROM member_sessions WHERE user_id = :user", user=user
    ) == [("deactivated",)]
    assert (await harness.client.get("/v1/me")).status_code == 401


@pytest.mark.parametrize("role", ["admin"])
async def test_a_role_change_ends_the_users_sessions(harness: Harness) -> None:
    await harness.sign_in()
    other = add_user(harness, "member")
    harness.db.sql(
        "INSERT INTO member_sessions (id, tenant_id, user_id, identity_id, session_hash, "
        "auth_time, auth_method, expires_at) VALUES (:id, :tenant, :user, :identity, "
        "sha256(convert_to(:token, 'UTF8')), now(), 'local', now() + interval '1 hour')",
        id=uuid.uuid4(),
        tenant=harness.member.tenant_id,
        user=other,
        identity=uuid.uuid4(),
        token=uuid.uuid4().hex,
    )
    me = (await harness.client.get("/v1/me")).json()
    headers = {"Origin": WEB_ORIGIN, "X-CSRF-Token": me["csrf_token"]}
    changed = await harness.client.patch(
        f"/v1/users/{other}", json={"role": "admin"}, headers=headers
    )
    assert changed.status_code == 200, changed.text
    assert harness.db.sql(
        "SELECT revoked_reason FROM member_sessions WHERE user_id = :user", user=other
    ) == [("role_changed",)]
    assert (await harness.client.get("/v1/me")).status_code == 200  # the admin's own goes on


async def test_the_return_path_keeps_its_own_query(harness: Harness) -> None:
    callback = await harness.sign_in(return_to="/files/1?tab=log&page=2")
    query = parse_qs(urlsplit(callback.headers["location"]).query)
    assert query == {"return_path": ["/files/1?tab=log&page=2"]}


async def test_an_unknown_cookie_fails_and_an_ended_session_expires(harness: Harness) -> None:
    # Only the first is a failed authentication, which counts against the IP (abuse 2.2, H).
    harness.client.cookies.set(SESSION_COOKIE, "never-issued", domain="api.sft.test")
    unknown = await harness.client.get("/v1/me")
    assert (unknown.status_code, unknown.json()["code"]) == (401, "credentials_invalid")
    harness.client.cookies.clear()
    await harness.sign_in()
    harness.db.sql(
        "UPDATE member_sessions SET revoked_at = now(), revoked_reason = 'signed_out' "
        "WHERE user_id = :user",
        user=harness.member.user_id,
    )
    ended = await harness.client.get("/v1/me")
    assert (ended.status_code, ended.json()["code"]) == (401, "session_expired")


DATABASE_DOWN = "postgresql://sft_api@127.0.0.1:1/sft"


async def test_sign_in_fails_closed_when_the_database_is_down(harness: Harness) -> None:
    up = harness.service.database
    down = Database.connect(DATABASE_DOWN, pool_size=1)
    try:
        harness.service.database = down
        start = await harness.client.get("/v1/auth/sign-in", params={"method": "local"})
        assert (start.status_code, start.json()["code"]) == (503, "service_unavailable")
        assert start.headers["retry-after"] == "5"

        # A sign-in started while the database was up, and called back after it went down.
        harness.service.database = up
        started = await harness.client.get("/v1/auth/sign-in", params={"method": "local"})
        query = parse_qs(urlsplit(started.headers["location"]).query)
        harness.pool.nonce = query["nonce"][0]
        harness.service.database = down
        callback = await harness.client.get(
            "/v1/auth/callback", params={"code": "good-code", "state": query["state"][0]}
        )
        assert (callback.status_code, callback.json()["code"]) == (503, "service_unavailable")
        assert callback.headers["retry-after"] == "5"
        assert callback.headers["cache-control"] == "no-store"
        cleared = callback.headers["set-cookie"]
        assert AUTH_COOKIE in cleared
        assert "Max-Age=0" in cleared or "expires=" in cleared.lower()
        assert SESSION_COOKIE not in cleared
    finally:
        harness.service.database = up
        await down.dispose()
