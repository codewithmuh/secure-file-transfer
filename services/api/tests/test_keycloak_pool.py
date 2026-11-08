"""The Keycloak user pool adapter (#197, `sft.runtime.keycloak`) against a recorded admin API:
what it sends, what it reads back, and how a `409` is told apart by looking the user up, never by
reading Keycloak's message. `make web-e2e` runs it against the stack's Keycloak (an invited member
joins with the emailed temporary password)."""

from __future__ import annotations

import json
import uuid

import httpx2 as httpx
import pytest

from sft.runtime.keycloak import KeycloakUserPool
from sft.service.user_pool import (
    PoolUser,
    PoolUserExistsError,
    UserPoolError,
    new_temporary_password,
)

pytestmark = pytest.mark.anyio

BASE = "http://oidc:8080"
SUBJECT = "0b5c6f1e-2c1a-4bb0-9d1e-5f3f9f1a2b3c"
MINE = {"id": SUBJECT, "username": "user-1", "attributes": {"enrolment_id": ["invitation"]}}
SOMEONE = {"id": "another", "username": "someone-else", "email": "a@example.test"}


class Recorder:
    def __init__(self, answers: list[httpx.Response]) -> None:
        self.answers = answers
        self.requests: list[httpx.Request] = []
        self.tokens = 0

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/protocol/openid-connect/token"):
            self.tokens += 1
            return httpx.Response(
                200, json={"access_token": f"token-{self.tokens}", "expires_in": 300}
            )
        self.requests.append(request)
        return self.answers.pop(0)

    def calls(self) -> list[tuple[str, str]]:
        return [(r.method, r.url.path) for r in self.requests]


def pool(recorder: Recorder) -> KeycloakUserPool:
    return KeycloakUserPool(
        base_url=BASE,
        realm="sft",
        client_id="sft-notify-local",
        client_secret="local-only-notify-pool-secret",  # noqa: S106 - the stack's fake secret
        provider_name="local-keycloak",
        http=httpx.AsyncClient(transport=httpx.MockTransport(recorder)),
    )


async def create(keycloak: KeycloakUserPool, password: str = "p" * 24) -> str:
    return await keycloak.create_user(
        username="user-1",
        email="a@example.test",
        tenant_id=uuid.UUID(int=1),
        temporary_password=password,
        enrolment="invitation",
    )


async def test_create_sends_a_verified_user_with_a_temporary_password_and_its_enrolment() -> None:
    location = f"{BASE}/admin/realms/sft/users/{SUBJECT}"
    recorder = Recorder([httpx.Response(201, headers={"Location": location})])
    password = new_temporary_password()
    assert await create(pool(recorder), password) == SUBJECT
    [request] = recorder.requests
    assert (request.method, request.url.path) == ("POST", "/admin/realms/sft/users")
    assert request.headers["authorization"] == "Bearer token-1"
    body = json.loads(request.content)
    assert body["username"] == "user-1"
    assert body["emailVerified"] is True
    assert body["attributes"] == {
        "tenant_id": [str(uuid.UUID(int=1))],
        "enrolment_id": ["invitation"],
    }
    assert body["credentials"] == [{"type": "password", "value": password, "temporary": True}]


@pytest.mark.parametrize(
    "message",
    [
        "User exists with same username",
        "User exists with same email",
        "User exists with same username and email",
        "",
    ],
)
async def test_our_own_user_from_an_earlier_delivery_is_taken_over(message: str) -> None:
    """Whatever Keycloak's message says, a user with our username is ours: it gets this delivery's
    password and enrolment, and its subject comes back (#197 review)."""
    recorder = Recorder(
        [
            httpx.Response(409, json={"errorMessage": message}),
            httpx.Response(200, json=[MINE]),
            httpx.Response(204),
            httpx.Response(204),
        ]
    )
    assert await create(pool(recorder), "n" * 24) == SUBJECT
    assert recorder.calls() == [
        ("POST", "/admin/realms/sft/users"),
        ("GET", "/admin/realms/sft/users"),
        ("PUT", f"/admin/realms/sft/users/{SUBJECT}"),
        ("PUT", f"/admin/realms/sft/users/{SUBJECT}/reset-password"),
    ]
    assert recorder.requests[1].url.params["username"] == "user-1"
    assert json.loads(recorder.requests[3].content)["value"] == "n" * 24


@pytest.mark.parametrize(
    "message", ["User exists with same email", "User exists with same username", ""]
)
async def test_another_user_with_the_address_is_a_conflict(message: str) -> None:
    recorder = Recorder(
        [
            httpx.Response(409, json={"errorMessage": message}),
            httpx.Response(200, json=[]),  # no user with our username
            httpx.Response(200, json=[SOMEONE]),  # someone else has the address
        ]
    )
    with pytest.raises(PoolUserExistsError) as raised:
        await create(pool(recorder))
    assert raised.value.kind == "email"
    assert recorder.requests[2].url.params["email"] == "a@example.test"


async def test_a_conflict_with_nobody_to_find_is_a_retry() -> None:
    recorder = Recorder(
        [httpx.Response(409, json={}), httpx.Response(200, json=[]), httpx.Response(200, json=[])]
    )
    with pytest.raises(UserPoolError, match="has no such user"):
        await create(pool(recorder))


async def test_find_reads_the_enrolment_and_delete_is_idempotent() -> None:
    recorder = Recorder(
        [
            httpx.Response(200, json=[MINE]),
            httpx.Response(200, json=[MINE]),
            httpx.Response(204),
            httpx.Response(200, json=[]),
        ]
    )
    keycloak = pool(recorder)
    assert await keycloak.find_user(username="user-1") == PoolUser(SUBJECT, "invitation")
    assert await keycloak.delete_user(username="user-1") is True
    assert await keycloak.delete_user(username="user-1") is False  # gone already
    assert recorder.requests[0].url.params["exact"] == "true"
    assert recorder.tokens == 1  # one token, kept until it nears its expiry


async def test_an_expired_token_is_renewed_once() -> None:
    recorder = Recorder([httpx.Response(401), httpx.Response(200, json=[])])
    assert await pool(recorder).delete_user(username="user-1") is False
    assert recorder.tokens == 2
    assert recorder.requests[1].headers["authorization"] == "Bearer token-2"


async def test_an_unreachable_or_refusing_pool_is_a_retry() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    keycloak = KeycloakUserPool(
        base_url=BASE,
        realm="sft",
        client_id="c",
        client_secret="s",  # noqa: S106 - a fake
        provider_name="p",
        http=httpx.AsyncClient(transport=httpx.MockTransport(down)),
    )
    with pytest.raises(UserPoolError, match="can't be reached"):
        await keycloak.delete_user(username="u")
    with pytest.raises(UserPoolError, match="didn't create"):
        await create(pool(Recorder([httpx.Response(500)])))


def test_temporary_passwords_fit_the_pools_policy() -> None:
    passwords = {new_temporary_password() for _ in range(50)}
    assert len(passwords) == 50
    assert all(15 <= len(p) <= 99 and p.isascii() and " " not in p for p in passwords)
