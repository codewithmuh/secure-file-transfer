"""Rate limits over HTTP: the route dependency, 429 and 503, counting 401s, and client IPs."""

import json
from collections.abc import Callable, Iterator, Mapping
from ipaddress import ip_network
from typing import Annotated

import pytest
import valkey
from fastapi import Depends, FastAPI, HTTPException, Request
from httpx2 import Response
from pydantic import SecretStr
from starlette.testclient import TestClient

from api_settings import API_SETTINGS
from sft.api.app import create_app
from sft.api.client_ip import rate_limit_ip
from sft.api.rate_limits import get_rate_limiter, rate_limit
from sft.core.errors import Unauthenticated
from sft.core.settings import Settings
from sft.data.counters import gcra_split
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import (
    INVITE_USER,
    SIGN_IN_START,
    TENANT_OPERATION,
    KeyType,
    KeyValue,
)
from sft.service.rate_limits.local import fallback_limit

TENANT = "11111111-1111-4111-8111-111111111111"
ACCOUNT = "22222222-2222-4222-8222-222222222222"
UNREACHABLE = "redis://u:p@127.0.0.1:1/0"


class Member:
    def rate_limit_keys(self) -> Mapping[KeyType, KeyValue]:
        return {KeyType.ACCOUNT: ACCOUNT, KeyType.TENANT: TENANT}


def member_session(request: Request) -> Member:
    # As sft.api.caller answers: no credential, a wrong one, or one whose session has ended.
    sent = request.headers.get("authorization")
    if sent is None:
        raise Unauthenticated("authentication_required")
    if sent == "Bearer ended":
        raise Unauthenticated("session_expired")
    if sent != "Bearer ok":
        raise Unauthenticated("credentials_invalid", bearer=True)
    return Member()


def app_with_routes(valkey_url: str, *, trusted_proxies: str = "") -> FastAPI:
    app = create_app(
        Settings(
            database_url=SecretStr("postgresql://sft_api@127.0.0.1:1/sft"),
            **{**API_SETTINGS, "valkey_url": valkey_url},  # type: ignore[arg-type]
            trusted_proxies=trusted_proxies,  # type: ignore[arg-type]  # split by its validator
        )
    )

    @app.post("/v1/test/sign-in", dependencies=[rate_limit(SIGN_IN_START)])
    async def sign_in() -> dict[str, str]:
        return {"ok": "sign-in"}

    @app.get("/v1/test/me", dependencies=[rate_limit(TENANT_OPERATION, caller=member_session)])
    async def me(member: Annotated[Member, Depends(member_session)]) -> dict[str, str]:
        return {"ok": "me"}

    # A stand-in for inviteUser, off the contract's paths: the app serves the real /v1/users.
    @app.post("/v1/invite", dependencies=[rate_limit(TENANT_OPERATION, caller=member_session)])
    async def invite(
        member: Annotated[Member, Depends(member_session)],
        limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
    ) -> dict[str, str]:
        from sft.core.pseudonyms import EmailPseudonyms

        address = EmailPseudonyms("e1:AAAAAAAAAAAAAAAAAAAAAA").within(TENANT)
        await limiter.check(
            INVITE_USER, {**member.rate_limit_keys(), KeyType.TENANT_EMAIL: address}
        )
        return {"ok": "invited"}

    @app.get("/v1/step-up")
    async def step_up() -> None:
        # A valid session whose sign-in is too old for the operation (authn and authz 3.3).
        raise Unauthenticated("reauthentication_required")

    return app


def flush(valkey_url: str) -> None:
    with valkey.Valkey.from_url(valkey_url) as empty:  # type: ignore[no-untyped-call]
        empty.flushdb()


@pytest.fixture
def client(valkey_url: str) -> Iterator[TestClient]:
    flush(valkey_url)
    with TestClient(app_with_routes(valkey_url)) as client:
        yield client


@pytest.fixture
def down() -> Iterator[TestClient]:
    with TestClient(app_with_routes(UNREACHABLE)) as client:
        yield client


def until_refused(send: Callable[[], Response], limit: int) -> Response:
    """Send until refused: at least the burst passes; real time lets a few more through (GCRA)."""
    burst = gcra_split(limit)[0]
    for sent in range(burst + 50):
        response = send()
        if response.status_code != 200:
            assert sent >= burst
            return response
    raise AssertionError("never refused")


def test_over_the_limit_is_a_429_problem(client: TestClient) -> None:
    response = until_refused(lambda: client.post("/v1/test/sign-in"), 60)
    assert response.status_code == 429
    assert response.headers["content-type"] == "application/problem+json"
    assert response.headers["retry-after"] in ("1", "2")  # the rest of a 2 s interval
    body = response.json()
    assert body["code"] == "rate_limited"
    assert body["status"] == 429
    assert body["type"].endswith("/problems/rate_limited")
    assert "detail" not in body  # never names the key


def test_the_caller_keys_come_from_the_authentication_dependency(client: TestClient) -> None:
    auth = {"authorization": "Bearer ok"}
    assert until_refused(lambda: client.get("/v1/test/me", headers=auth), 300).status_code == 429


def test_a_handler_applies_the_limits_whose_keys_it_finds(client: TestClient) -> None:
    auth = {"authorization": "Bearer ok"}
    for _ in range(3):  # 3 invitations a day to one address
        assert client.post("/v1/invite", headers=auth).status_code == 200
    response = client.post("/v1/invite", headers=auth)
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 86000


def test_a_step_up_401_is_no_failed_authentication(client: TestClient) -> None:
    # Admins behind one NAT with older sessions mustn't block their office's IP.
    for _ in range(120):
        response = client.get("/v1/step-up")
        assert (response.status_code, response.json()["code"]) == (
            401,
            "reauthentication_required",
        )
    assert client.get("/v1/test/me", headers={"authorization": "Bearer ok"}).status_code == 200


WRONG = {"authorization": "Bearer wrong"}


@pytest.mark.parametrize("headers", [{}, {"authorization": "Bearer ended"}])
def test_no_credential_or_an_ended_session_is_no_failed_authentication(
    client: TestClient, headers: dict[str, str]
) -> None:
    # Signed-out page loads and returning members behind one NAT mustn't block their office.
    for _ in range(120):
        assert client.get("/v1/test/me", headers=headers).status_code == 401
    assert client.get("/v1/test/me", headers={"authorization": "Bearer ok"}).status_code == 200


def test_100_failed_authentications_block_the_ip_on_every_route(client: TestClient) -> None:
    for _ in range(100):
        assert client.get("/v1/test/me", headers=WRONG).status_code == 401
    # The block is checked before authentication: the 101st bad credential gets no 401 to learn
    # from, and a valid member, another route or no route at all from that IP waits 15 minutes.
    for response in (
        client.get("/v1/test/me"),
        client.get("/v1/test/me", headers=WRONG),
        client.get("/v1/test/me", headers={"authorization": "Bearer ok"}),
        client.post("/v1/test/sign-in"),
        client.get("/v1/nowhere"),
    ):
        assert response.status_code == 429
        assert response.headers["retry-after"] == "900"
        assert response.headers["content-type"] == "application/problem+json"
        assert response.json()["code"] == "rate_limited"


def test_failed_authentications_block_per_pod_when_the_store_is_down(down: TestClient) -> None:
    for _ in range(fallback_limit(100)):
        assert down.get("/v1/test/me", headers=WRONG).status_code == 401
    response = down.get("/v1/test/me", headers=WRONG)
    assert response.status_code == 429
    assert response.headers["retry-after"] == "900"


def test_clients_behind_the_load_balancer_are_blocked_apart(valkey_url: str) -> None:
    flush(valkey_url)
    app = app_with_routes(valkey_url, trusted_proxies="10.0.0.0/20")
    # The load balancer's address as a dual-stack socket gives it, and entries with a port.
    with TestClient(app, client=("::ffff:10.0.1.5", 50000)) as balancer:
        guesser = {"x-forwarded-for": "198.51.100.1, 203.0.113.9:4321", **WRONG}
        for _ in range(100):
            assert balancer.get("/v1/test/me", headers=guesser).status_code == 401
        assert balancer.get("/v1/test/me", headers=guesser).status_code == 429
        member = {"x-forwarded-for": "203.0.113.10:5555", "authorization": "Bearer ok"}
        assert balancer.get("/v1/test/me", headers=member).status_code == 200


def test_sign_in_fails_closed_when_the_store_is_down(down: TestClient) -> None:
    response = down.post("/v1/test/sign-in")
    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"
    assert response.json()["code"] == "service_unavailable"


def test_tenant_calls_carry_on_per_pod_when_the_store_is_down(down: TestClient) -> None:
    auth = {"authorization": "Bearer ok"}
    response = until_refused(lambda: down.get("/v1/test/me", headers=auth), fallback_limit(300))
    assert response.status_code == 429


def test_an_app_without_settings_has_no_limiter() -> None:
    app = create_app()

    @app.post("/v1/test/sign-in", dependencies=[rate_limit(SIGN_IN_START)])
    async def sign_in() -> None: ...

    client = TestClient(app, raise_server_exceptions=False)
    assert client.post("/v1/test/sign-in").status_code == 500

    # And a 401 without a limiter is just a 401.
    @app.get("/v1/test/me")
    async def me() -> None:
        raise HTTPException(401)

    assert client.get("/v1/test/me").status_code == 401


def test_the_lifespan_closes_the_store(valkey_url: str) -> None:
    app = app_with_routes(valkey_url)
    with TestClient(app):
        limiter = app.state.rate_limiter
    assert isinstance(limiter, RateLimiter)
    assert limiter._store._client.connection_pool._available_connections == []


# ---- the client's IP (ADR-0002) ----

LB = [ip_network("10.0.0.0/20")]


def request_from(peer: str | None, *forwarded: str) -> Request:
    headers = [(b"x-forwarded-for", value.encode()) for value in forwarded]
    scope = {"type": "http", "headers": headers, "client": (peer, 1234) if peer else None}
    return Request(scope)


@pytest.mark.parametrize(
    ("peer", "forwarded", "expected"),
    [
        ("198.51.100.4", (), "198.51.100.4"),
        # Not from the load balancer: the header is the client's own and never read.
        ("198.51.100.4", ("203.0.113.9",), "198.51.100.4"),
        # From the load balancer: its entry, the last one, whatever the client put first.
        ("10.0.1.5", ("1.1.1.1, 203.0.113.9",), "203.0.113.9"),
        ("10.0.1.5", ("1.1.1.1", "203.0.113.9"), "203.0.113.9"),
        ("10.0.1.5", (), "10.0.1.5"),
        ("10.0.1.5", ("not-an-ip",), "10.0.1.5"),
        # IPv6 counts per /64; an IPv4-mapped address as IPv4.
        ("2001:db8:1:2:3:4:5:6", (), "2001:db8:1:2::/64"),
        ("::ffff:198.51.100.4", (), "198.51.100.4"),
        ("10.0.1.5", ("2001:db8:1:2::9",), "2001:db8:1:2::/64"),
        ("10.0.1.5", ("1.1.1.1, ::ffff:203.0.113.9",), "203.0.113.9"),
        # The load balancer's own address IPv4-mapped, as a dual-stack socket gives it: trusted.
        ("::ffff:10.0.1.5", ("203.0.113.9",), "203.0.113.9"),
        ("::ffff:198.51.100.4", ("203.0.113.9",), "198.51.100.4"),
        # An entry with a port.
        ("10.0.1.5", ("203.0.113.9:4321",), "203.0.113.9"),
        ("10.0.1.5", ("[2001:db8:1:2::9]:4321",), "2001:db8:1:2::/64"),
        ("10.0.1.5", ("[2001:db8:1:2::9]",), "2001:db8:1:2::/64"),
        # Not an address and a port: unusable, so the load balancer's own address.
        ("10.0.1.5", ("203.0.113.9:http",), "10.0.1.5"),
        ("10.0.1.5", ("203.0.113.9:65536",), "10.0.1.5"),
        ("10.0.1.5", ("203.0.113.9:",), "10.0.1.5"),
        ("10.0.1.5", ("[2001:db8::9]4321",), "10.0.1.5"),
        ("10.0.1.5", ("[2001:db8::9",), "10.0.1.5"),
        (None, (), "unknown"),
        ("testclient", (), "unknown"),
    ],
)
def test_client_ip(peer: str | None, forwarded: tuple[str, ...], expected: str) -> None:
    assert rate_limit_ip(request_from(peer, *forwarded), LB) == expected


def test_a_trusted_proxy_without_a_usable_entry_is_logged_without_addresses(
    json_logs: Callable[[], list[dict[str, object]]],
) -> None:
    rate_limit_ip(request_from("10.0.1.5"), LB)
    rate_limit_ip(request_from("10.0.1.5", "203.0.113.9:http"), LB)
    rate_limit_ip(request_from("10.0.1.5", "203.0.113.9"), LB)  # usable
    rate_limit_ip(request_from("198.51.100.4"), LB)  # not from the load balancer
    lines = json_logs()
    assert [(line["level"], line["reason"]) for line in lines] == [
        ("warning", "missing"),
        ("warning", "unreadable"),
    ]
    for address in ("10.0.1.5", "203.0.113.9", "198.51.100.4"):
        assert address not in json.dumps(lines)


def test_problem_errors_carry_their_detail_and_retry_after() -> None:
    from sft.core.errors import ServiceUnavailable

    app = create_app()

    @app.get("/v1/busy")
    async def busy() -> None:
        raise ServiceUnavailable(0, detail="Try again shortly.")

    response = TestClient(app).get("/v1/busy")
    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"  # at least 1
    assert response.json()["detail"] == "Try again shortly."
