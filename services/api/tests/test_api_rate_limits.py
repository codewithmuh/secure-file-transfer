"""Rate limits over HTTP: the route dependency, 429 and 503, counting 401s, and client IPs."""

from collections.abc import Callable, Iterator, Mapping
from ipaddress import ip_network
from typing import Annotated

import pytest
import valkey
from fastapi import Depends, FastAPI, HTTPException, Request
from httpx2 import Response
from pydantic import SecretStr
from starlette.testclient import TestClient

from sft.api.app import create_app
from sft.api.client_ip import rate_limit_ip
from sft.api.rate_limits import get_rate_limiter, rate_limit
from sft.core.settings import Settings
from sft.service.rate_limits import RateLimiter
from sft.service.rate_limits.limits import (
    INVITE_USER,
    SIGN_IN_START,
    TENANT_OPERATION,
    KeyType,
    KeyValue,
)

TENANT = "11111111-1111-4111-8111-111111111111"
ACCOUNT = "22222222-2222-4222-8222-222222222222"
UNREACHABLE = "redis://u:p@127.0.0.1:1/0"


class Member:
    def rate_limit_keys(self) -> Mapping[KeyType, KeyValue]:
        return {KeyType.ACCOUNT: ACCOUNT, KeyType.TENANT: TENANT}


def member_session(request: Request) -> Member:
    if request.headers.get("authorization") != "Bearer ok":
        raise HTTPException(401)
    return Member()


def app_with_routes(valkey_url: str) -> FastAPI:
    app = create_app(
        Settings(
            database_url=SecretStr("postgresql://sft_api@127.0.0.1:1/sft"),
            valkey_url=SecretStr(valkey_url),
        )
    )

    @app.post("/v1/auth/sign-in", dependencies=[rate_limit(SIGN_IN_START)])
    async def sign_in() -> dict[str, str]:
        return {"ok": "sign-in"}

    @app.get("/v1/me", dependencies=[rate_limit(TENANT_OPERATION, caller=member_session)])
    async def me(member: Annotated[Member, Depends(member_session)]) -> dict[str, str]:
        return {"ok": "me"}

    @app.post("/v1/users", dependencies=[rate_limit(TENANT_OPERATION, caller=member_session)])
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

    return app


@pytest.fixture
def client(valkey_url: str) -> Iterator[TestClient]:
    with valkey.Valkey.from_url(valkey_url) as empty:  # type: ignore[no-untyped-call]
        empty.flushdb()
    with TestClient(app_with_routes(valkey_url)) as client:
        yield client


@pytest.fixture
def down() -> Iterator[TestClient]:
    with TestClient(app_with_routes(UNREACHABLE)) as client:
        yield client


def until_refused(send: Callable[[], Response], limit: int) -> Response:
    """Send until refused: at least `limit` pass; real time lets a few more through (GCRA)."""
    for sent in range(limit + 50):
        response = send()
        if response.status_code != 200:
            assert sent >= limit
            return response
    raise AssertionError("never refused")


def test_over_the_limit_is_a_429_problem(client: TestClient) -> None:
    response = until_refused(lambda: client.post("/v1/auth/sign-in"), 60)
    assert response.status_code == 429
    assert response.headers["content-type"] == "application/problem+json"
    assert response.headers["retry-after"] == "1"
    body = response.json()
    assert body["code"] == "rate_limited"
    assert body["status"] == 429
    assert body["type"].endswith("/problems/rate_limited")
    assert "detail" not in body  # never names the key


def test_the_caller_keys_come_from_the_authentication_dependency(client: TestClient) -> None:
    auth = {"authorization": "Bearer ok"}
    assert until_refused(lambda: client.get("/v1/me", headers=auth), 300).status_code == 429


def test_a_handler_applies_the_limits_whose_keys_it_finds(client: TestClient) -> None:
    auth = {"authorization": "Bearer ok"}
    for _ in range(3):  # 3 invitations a day to one address
        assert client.post("/v1/users", headers=auth).status_code == 200
    response = client.post("/v1/users", headers=auth)
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) > 86000


def test_100_failed_authentications_block_the_ip(client: TestClient) -> None:
    for _ in range(100):
        assert client.get("/v1/me").status_code == 401
    # Now even a valid member from that IP waits 15 minutes.
    response = client.get("/v1/me", headers={"authorization": "Bearer ok"})
    assert response.status_code == 429
    assert response.headers["retry-after"] == "900"


def test_sign_in_fails_closed_when_the_store_is_down(down: TestClient) -> None:
    response = down.post("/v1/auth/sign-in")
    assert response.status_code == 503
    assert response.headers["retry-after"] == "5"
    assert response.json()["code"] == "service_unavailable"


def test_tenant_calls_carry_on_per_pod_when_the_store_is_down(down: TestClient) -> None:
    auth = {"authorization": "Bearer ok"}  # a third of 300
    assert until_refused(lambda: down.get("/v1/me", headers=auth), 100).status_code == 429


def test_an_app_without_settings_has_no_limiter() -> None:
    app = create_app()

    @app.post("/v1/auth/sign-in", dependencies=[rate_limit(SIGN_IN_START)])
    async def sign_in() -> None: ...

    client = TestClient(app, raise_server_exceptions=False)
    assert client.post("/v1/auth/sign-in").status_code == 500

    # And a 401 without a limiter is just a 401.
    @app.get("/v1/me")
    async def me() -> None:
        raise HTTPException(401)

    assert client.get("/v1/me").status_code == 401


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
        (None, (), "unknown"),
        ("testclient", (), "unknown"),
    ],
)
def test_client_ip(peer: str | None, forwarded: tuple[str, ...], expected: str) -> None:
    assert rate_limit_ip(request_from(peer, *forwarded), LB) == expected


def test_problem_errors_carry_their_detail_and_retry_after() -> None:
    # The stub of #96's handlers: only the two errors rate limiting raises.
    from sft.core.errors import ServiceUnavailable

    app = create_app()

    @app.get("/v1/busy")
    async def busy() -> None:
        raise ServiceUnavailable(0, detail="Try again shortly.")

    response = TestClient(app).get("/v1/busy")
    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"  # at least 1
    assert response.json()["detail"] == "Try again shortly."
