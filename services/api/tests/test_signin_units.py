"""The pure parts of member sign-in (#113): the CSRF keyring, the return path, the OIDC client."""

import base64
import hashlib
import json
import uuid

import httpx2 as httpx
import pytest

from sft.data.signin_state import (
    LIFETIME_SECONDS,
    PendingSignIn,
    StateStoreUnavailableError,
    ValkeyStateStore,
)
from sft.service.csrf import CsrfKeyring, KeyringError
from sft.service.oidc import OidcClient, OidcError, OidcFailure, Pkce
from sft.service.signin import safe_return_path

KEY_A = base64.b64encode(b"a" * 32).decode()
KEY_B = base64.b64encode(b"b" * 32).decode()


def ring(*entries: dict[str, str]) -> CsrfKeyring:
    return CsrfKeyring.from_json(json.dumps(list(entries)))


def test_a_csrf_token_is_bound_to_its_session() -> None:
    keys = ring({"id": "a", "state": "active", "key": KEY_A})
    token = keys.token_for("session-1")
    assert token.startswith("a.")
    assert keys.verify("session-1", token)
    assert not keys.verify("session-2", token)
    assert not keys.verify("session-1", None)
    assert not keys.verify("session-1", "a")
    assert not keys.verify("session-1", "zz." + token[2:])


def test_a_rotated_keyring_still_verifies_the_old_key() -> None:
    old = ring({"id": "a", "state": "active", "key": KEY_A}).token_for("s")
    rotated = ring(
        {"id": "a", "state": "verify", "key": KEY_A}, {"id": "b", "state": "active", "key": KEY_B}
    )
    assert rotated.verify("s", old)
    assert rotated.token_for("s").startswith("b.")


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "[]",
        '{"id": "a"}',
        '["a"]',
        json.dumps([{"id": "bad id", "state": "active", "key": KEY_A}]),
        json.dumps([{"id": "a", "state": "retired", "key": KEY_A}]),
        json.dumps([{"id": "a", "state": "active", "key": "!!"}]),
        json.dumps([{"id": "a", "state": "active", "key": base64.b64encode(b"short").decode()}]),
        json.dumps([{"id": "a", "state": "verify", "key": KEY_A}]),
        json.dumps(
            [
                {"id": "a", "state": "active", "key": KEY_A},
                {"id": "a", "state": "verify", "key": KEY_B},
            ]
        ),
    ],
)
def test_a_bad_keyring_is_refused_without_echoing_a_key(raw: str) -> None:
    with pytest.raises(KeyringError) as caught:
        CsrfKeyring.from_json(raw)
    assert KEY_A not in str(caught.value)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/files", "/files"),
        ("/files/1?tab=log", "/files/1?tab=log"),
        (None, "/"),
        ("https://evil.test/", "/"),
        ("//evil.test", "/"),
        ("/a/../b", "/"),
        ("/a//b", "/"),
        ("/" + "a" * 600, "/"),
        ("/\\evil", "/"),
    ],
)
def test_the_return_path_is_never_an_open_redirect(raw: str | None, expected: str) -> None:
    assert safe_return_path(raw) == expected


def test_pkce_uses_s256() -> None:
    pkce = Pkce.new()
    assert len(pkce.verifier) >= 43
    assert pkce.challenge != pkce.verifier


def client(handler: httpx.MockTransport) -> OidcClient:
    return OidcClient(
        issuer="https://idp.test",
        client_id="c",
        client_secret="test-only",  # noqa: S106 - obviously fake
        redirect_uri="https://api.test/v1/auth/callback",
        http=httpx.AsyncClient(transport=handler),
    )


@pytest.mark.anyio
async def test_discovery_naming_another_issuer_refuses_every_sign_in() -> None:
    document = {
        "issuer": "https://other.test",
        "authorization_endpoint": "https://idp.test/auth",
        "token_endpoint": "https://idp.test/token",
        "jwks_uri": "https://idp.test/certs",
    }
    oidc = client(httpx.MockTransport(lambda r: httpx.Response(200, json=document)))
    with pytest.raises(OidcError) as caught:
        await oidc.metadata()
    assert caught.value.reason == OidcFailure.UNAVAILABLE
    await oidc.aclose()


@pytest.mark.anyio
async def test_an_unreachable_provider_is_unavailable() -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    oidc = client(httpx.MockTransport(refuse))
    with pytest.raises(OidcError) as caught:
        await oidc.metadata()
    assert caught.value.reason == OidcFailure.UNAVAILABLE
    await oidc.aclose()


# ---- the sign-in state store, against a real Valkey ----


def pending() -> PendingSignIn:
    return PendingSignIn(
        state="s", verifier="v", nonce="n", connection_id=uuid.uuid4(), return_to="/files"
    )


@pytest.mark.anyio
async def test_a_pre_auth_record_is_taken_once_and_kept_under_a_hash(valkey_url: str) -> None:
    store = ValkeyStateStore.from_url(valkey_url)
    try:
        record = pending()
        await store.put("cookie-1", record)
        keys = await store._client.keys("signin:state:*")  # read here only to see the key
        assert keys
        assert all("cookie-1" not in str(key) for key in keys)
        ttl = await store._client.ttl(keys[0])
        assert 0 < ttl <= LIFETIME_SECONDS
        assert await store.take("cookie-1") == record
        assert await store.take("cookie-1") is None  # used up
    finally:
        await store.aclose()


@pytest.mark.anyio
async def test_an_unreadable_record_is_no_record(valkey_url: str) -> None:
    store = ValkeyStateStore.from_url(valkey_url)
    try:
        await store.put("cookie-2", pending())
        [key] = [
            k
            for k in await store._client.keys("signin:state:*")
            if k.endswith(hashlib.sha256(b"cookie-2").hexdigest())
        ]
        await store._client.set(key, "not json")
        assert await store.take("cookie-2") is None
    finally:
        await store.aclose()


@pytest.mark.anyio
async def test_an_unreachable_store_fails_sign_in_closed() -> None:
    store = ValkeyStateStore.from_url("redis://u:p@127.0.0.1:1/0")
    try:
        with pytest.raises(StateStoreUnavailableError):
            await store.put("cookie", pending())
        with pytest.raises(StateStoreUnavailableError):
            await store.take("cookie")
    finally:
        await store.aclose()
