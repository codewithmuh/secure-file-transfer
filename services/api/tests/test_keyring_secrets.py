"""Keyrings read from Secrets Manager, and their 5-minute refresh (#184, #162; encryption and keys
6.4, 6.5). Secrets Manager is botocore's Stubber over a real client: nothing reaches AWS."""

import asyncio
import base64
import json
from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from botocore.stub import Stubber
from prometheus_client import CollectorRegistry
from pydantic import SecretStr
from starlette.testclient import TestClient

from api_settings import API_SETTINGS, CSRF_KEYRING, EMAIL_HMAC_KEYRING
from sft.api.app import create_app
from sft.core.hmac_keyrings import CodeKeyring, LinkKeyring
from sft.core.keyrings import KeyringError, check_keyring_setting, secret_reference
from sft.core.pseudonyms import EmailKeyring
from sft.core.settings import Settings
from sft.runtime.secrets import Keyrings, KeyringUnavailableError, SecretsClient
from sft.service.csrf import CsrfKeyring

SECRET_ID = "sft/dev/app/csrf-hmac"  # noqa: S105 - a secret's name
ARN = f"arn:aws:secretsmanager:ap-northeast-1:000000000000:secret:{SECRET_ID}-AbCdEf"


def key(fill: str) -> str:
    return base64.b64encode(fill.encode() * 32).decode()


def ring(*entries: tuple[str, str]) -> str:
    return json.dumps([{"id": i, "state": s, "key": key(i[-1])} for i, s in entries])


V1 = ring(("k1", "active"))
V2_STAGED = ring(("k1", "active"), ("k2", "staged"))
V3_ACTIVE = ring(("k2", "active"), ("k1", "verify"))


@pytest.fixture
def stubbed() -> Iterator[tuple[Any, Stubber]]:
    client = boto3.client(
        "secretsmanager",
        region_name="ap-northeast-1",
        aws_access_key_id="test-only-key-id",
        aws_secret_access_key="fake-secret-not-a-real-key",  # noqa: S106 - fake
    )
    with Stubber(client) as stubber:
        yield client, stubber
        stubber.assert_no_pending_responses()


def answer(stubber: Stubber, value: str, version: str) -> None:
    stubber.add_response(
        "get_secret_value",
        {"ARN": ARN, "Name": SECRET_ID, "SecretString": value, "VersionId": version.ljust(32, "0")},
        {"SecretId": SECRET_ID},
    )


def keyrings(client: SecretsClient) -> tuple[Keyrings, CollectorRegistry]:
    registry = CollectorRegistry()
    return Keyrings(lambda: client, _metrics(registry), clock=lambda: 1234.0), registry


def _metrics(registry: CollectorRegistry) -> Any:
    from sft.runtime.secrets import KeyringMetrics

    return KeyringMetrics.create(registry)


REFERENCE = SecretStr(f"secretsmanager:{SECRET_ID}")


@pytest.mark.anyio
async def test_a_rotation_takes_effect_without_a_restart(stubbed: tuple[Any, Stubber]) -> None:
    """Stage, activate: each step reaches the loaded keyring at the next refresh, in place."""
    client, stubber = stubbed
    answer(stubber, V1, "v1")
    answer(stubber, V2_STAGED, "v2")
    answer(stubber, V3_ACTIVE, "v3")
    rings, registry = keyrings(client)
    csrf = await rings.load(REFERENCE, CsrfKeyring.from_json, name="CSRF")
    assert rings.named == ("CSRF",)
    before = csrf.token_for("session-token")
    assert before.startswith("k1.")

    await rings.refresh()  # staged: loaded, not used yet
    assert csrf.token_for("session-token") == before

    await rings.refresh()  # activated: new tokens use k2, k1's still verify through the overlap
    after = csrf.token_for("session-token")
    assert after.startswith("k2.")
    assert csrf.verify("session-token", before)
    assert csrf.verify("session-token", after)
    assert (
        registry.get_sample_value("sft_keyring_refreshed_timestamp_seconds", {"keyring": "CSRF"})
        == 1234.0
    )


@pytest.mark.anyio
async def test_an_unchanged_version_is_not_parsed_again(stubbed: tuple[Any, Stubber]) -> None:
    client, stubber = stubbed
    answer(stubber, V1, "v1")
    answer(stubber, "not even JSON", "v1")  # same version: never read
    rings, registry = keyrings(client)
    csrf = await rings.load(REFERENCE, CsrfKeyring.from_json, name="CSRF")
    await rings.refresh()
    assert csrf.active_id == "k1"
    failures = registry.get_sample_value("sft_keyring_refresh_failures_total", {"keyring": "CSRF"})
    assert not failures


@pytest.mark.anyio
async def test_a_malformed_version_or_a_failed_read_keeps_the_loaded_keyring(
    stubbed: tuple[Any, Stubber], caplog: pytest.LogCaptureFixture
) -> None:
    client, stubber = stubbed
    answer(stubber, V1, "v1")
    two_active = json.dumps(
        [
            {"id": "k1", "state": "active", "key": key("x")},
            {"id": "k2", "state": "active", "key": key("y")},
        ]
    )
    answer(stubber, two_active, "v2")
    stubber.add_client_error("get_secret_value", "InternalServiceError", "try again")
    rings, registry = keyrings(client)
    csrf = await rings.load(REFERENCE, CsrfKeyring.from_json, name="CSRF")
    token = csrf.token_for("s")
    await rings.refresh()
    await rings.refresh()
    assert csrf.token_for("s") == token
    assert registry.get_sample_value("sft_keyring_refresh_failures_total", {"keyring": "CSRF"}) == 2
    reasons = [r.__dict__.get("reason") for r in caplog.records if "refresh failed" in r.message]
    assert reasons == ["the CSRF keyring needs exactly one active key", "InternalServiceError"]
    assert key("x") not in caplog.text


@pytest.mark.anyio
async def test_a_keyring_that_cant_be_read_stops_the_startup(
    stubbed: tuple[Any, Stubber],
) -> None:
    client, stubber = stubbed
    stubber.add_client_error("get_secret_value", "AccessDeniedException", "no")
    rings, _ = keyrings(client)
    with pytest.raises(KeyringUnavailableError, match="CSRF keyring can't be loaded: AccessDenied"):
        await rings.load(REFERENCE, CsrfKeyring.from_json, name="CSRF")
    stubber.add_response(
        "get_secret_value",
        {"ARN": ARN, "Name": SECRET_ID, "SecretBinary": b"x"},
        {"SecretId": SECRET_ID},
    )
    with pytest.raises(KeyringUnavailableError, match="holds no string"):
        await rings.load(REFERENCE, CsrfKeyring.from_json, name="CSRF")


@pytest.mark.anyio
async def test_a_keyring_in_the_setting_never_reaches_secrets_manager() -> None:
    def no_client() -> SecretsClient:
        raise AssertionError("no secret is named")

    rings = Keyrings(no_client, _metrics(CollectorRegistry()))
    email = await rings.load(SecretStr(EMAIL_HMAC_KEYRING), EmailKeyring.from_json, name="email")
    assert email.active_key_id == "t1"
    assert rings.named == ()
    await asyncio.wait_for(rings.run(), timeout=1)  # nothing to refresh: returns at once


@pytest.mark.anyio
async def test_run_refreshes_every_interval(stubbed: tuple[Any, Stubber]) -> None:
    client, stubber = stubbed
    answer(stubber, V1, "v1")
    answer(stubber, V3_ACTIVE, "v2")
    rings = Keyrings(lambda: client, _metrics(CollectorRegistry()), interval=0.01)
    csrf = await rings.load(REFERENCE, CsrfKeyring.from_json, name="CSRF")
    task = asyncio.create_task(rings.run())
    for _ in range(200):
        if csrf.active_id == "k2":
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert csrf.active_id == "k2"


def test_each_keyring_reloads_whole_or_not_at_all() -> None:
    link = LinkKeyring.from_json(V1.replace("k1", "l1"))
    link.reload(V3_ACTIVE)
    assert (link.active_id, link.knows("k1"), link.knows("l1")) == ("k2", True, False)
    code = CodeKeyring.from_json(V1)
    with pytest.raises(KeyringError):
        code.reload("[]")
    assert code.active_id == "k1"
    email = EmailKeyring.from_json(EMAIL_HMAC_KEYRING)
    rotated = json.loads(EMAIL_HMAC_KEYRING)
    rotated[0]["state"] = "verify"
    rotated.append(
        {"id": "t2", "state": "active", "key": key("z"), "activated_at": "2026-11-01T00:00:00Z"}
    )
    email.reload(json.dumps(rotated))
    assert email.active_key_id == "t2"
    assert len(email.every_version("a@example.com")) == 2
    csrf = CsrfKeyring.from_json(CSRF_KEYRING)
    with pytest.raises(KeyringError):
        csrf.reload("{}")
    assert csrf.active_id == "k1"


def test_the_api_reads_its_keyrings_and_a_rotation_reaches_every_service(
    stubbed: tuple[Any, Stubber], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The API's lifespan reads its three named keyrings, and a refresh swaps the CSRF keyring that
    sign-in and the link steps share, in the running app (#184, #162)."""
    client, stubber = stubbed
    # The lifespan reads them in this order: email, code, CSRF; and each refresh the same.
    names = {"email-hmac": EMAIL_HMAC_KEYRING, "code-hmac": ring(("c1", "active")), "csrf-hmac": V1}
    for name, value in names.items():
        secret_id = f"sft/dev/app/{name}"
        stubber.add_response(
            "get_secret_value",
            {"Name": secret_id, "SecretString": value, "VersionId": "v1".ljust(32, "0")},
            {"SecretId": secret_id},
        )
    monkeypatch.setattr("sft.runtime.secrets.boto3.client", lambda *_a, **_k: client)
    references = {
        "csrf_keyring": "secretsmanager:sft/dev/app/csrf-hmac",
        "email_hmac_keyring": "secretsmanager:sft/dev/app/email-hmac",
        "code_hmac_keyring": "secretsmanager:sft/dev/app/code-hmac",
    }
    settings = Settings(
        database_url=SecretStr("postgresql://sft_api@127.0.0.1:1/sft"),
        **{**API_SETTINGS, **references},  # type: ignore[arg-type]
    )
    app = create_app(settings)
    with TestClient(app) as http:
        csrf = app.state.link_services.csrf
        assert csrf is app.state.sign_in.csrf
        assert csrf.active_id == "k1"
        assert app.state.keyrings.named == ("email", "code", "CSRF")
        for name in ("email-hmac", "code-hmac"):  # unchanged
            secret_id = f"sft/dev/app/{name}"
            stubber.add_response(
                "get_secret_value",
                {"Name": secret_id, "SecretString": names[name], "VersionId": "v1".ljust(32, "0")},
                {"SecretId": secret_id},
            )
        answer(stubber, V3_ACTIVE, "v2")  # the CSRF keyring's new version
        http.portal.call(app.state.keyrings.refresh)  # type: ignore[union-attr]
        assert app.state.sign_in.csrf.active_id == "k2"


def test_a_setting_may_name_its_secret() -> None:
    assert secret_reference("secretsmanager:sft/dev/app/code-hmac", name="code") == (
        "sft/dev/app/code-hmac"
    )
    assert secret_reference(V1, name="code") is None
    with pytest.raises(KeyringError, match="must name a secret ID"):
        secret_reference("secretsmanager:", name="code")
    with pytest.raises(KeyringError, match="must name a secret ID"):
        check_keyring_setting("secretsmanager:bad id", name="code", key_id=CodeKeyring.KEY_ID)
    check_keyring_setting(
        "secretsmanager:sft/dev/app/code-hmac", name="code", key_id=CodeKeyring.KEY_ID
    )
