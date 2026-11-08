"""The notification worker's settings (#178): a worker's, the mail adapter's, three keyrings."""

import base64

import pytest
from pydantic import ValidationError

from sft.core.settings import NotifySettings

KEY = base64.b64encode(b"k" * 32).decode()
RING = f'[{{"id":"k1","state":"active","key":"{KEY}"}}]'
EMAIL_RING = f'[{{"id":"k1","state":"active","key":"{KEY}","activated_at":"2026-01-01T00:00:00Z"}}]'
REQUIRED = {
    "DATABASE_URL": "postgresql://sft_notify@127.0.0.1:5432/sft",
    "SQS_QUEUE_PREFIX": "sft-dev-",
    "VALKEY_URL": "redis://sft-notify@127.0.0.1:6379/0",
    "MAIL_BACKEND": "smtp",
    "MAIL_FROM_ADDRESS": "no-reply@mail.sft.localhost",
    "WEB_APP_URL": "http://localhost:3000",
    "EMAIL_HMAC_KEYRING": EMAIL_RING,
    "LINK_HMAC_KEYRING": RING,
    "CODE_HMAC_KEYRING": RING,
}


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in NotifySettings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
    for name, value in REQUIRED.items():
        monkeypatch.setenv(name, value)
    return monkeypatch


def test_reads_a_workers_settings_and_the_mail_adapters(env: pytest.MonkeyPatch) -> None:
    s = NotifySettings()
    assert (s.sqs_queue_prefix, s.mail_backend, s.web_app_url) == (
        "sft-dev-",
        "smtp",
        "http://localhost:3000",
    )
    assert s.internal_port == 8001
    assert KEY not in repr(s)


@pytest.mark.parametrize("name", sorted(REQUIRED))
def test_every_required_setting_is_required(env: pytest.MonkeyPatch, name: str) -> None:
    env.delenv(name)
    with pytest.raises(ValidationError, match=name.lower()):
        NotifySettings()


@pytest.mark.parametrize("name", ["LINK_HMAC_KEYRING", "CODE_HMAC_KEYRING", "EMAIL_HMAC_KEYRING"])
def test_a_bad_keyring_stops_the_worker_and_is_never_echoed(
    env: pytest.MonkeyPatch, name: str
) -> None:
    env.setenv(name, f'[{{"id":"bad_id","state":"active","key":"{KEY}"}}]')
    with pytest.raises(ValidationError) as refused:
        NotifySettings()
    assert KEY not in str(refused.value.errors(include_input=False))


def test_without_a_pool_invitations_wait(env: pytest.MonkeyPatch) -> None:
    """Dev until #193: no pool adapter, so invitations are recorded and nothing is sent."""
    s = NotifySettings()
    assert (s.user_pool_backend, s.keycloak_url, s.keycloak_client_secret) == ("none", None, None)


def test_a_keycloak_pool_names_all_its_parts(env: pytest.MonkeyPatch) -> None:
    """The local stack's pool (#197): Keycloak's admin API, as a client that may manage users."""
    parts = {
        "USER_POOL_PROVIDER_NAME": "local-keycloak",
        "KEYCLOAK_URL": "http://oidc:8080",
        "KEYCLOAK_REALM": "sft",
        "KEYCLOAK_CLIENT_ID": "sft-notify-local",
        "KEYCLOAK_CLIENT_SECRET": "local-only-notify-pool-secret",
    }
    env.setenv("USER_POOL_BACKEND", "keycloak")
    for name, value in parts.items():
        env.setenv(name, value)
    s = NotifySettings()
    assert s.keycloak_client_secret is not None
    assert "local-only-notify-pool-secret" not in repr(s)
    env.delenv("KEYCLOAK_CLIENT_SECRET")
    with pytest.raises(ValidationError, match="KEYCLOAK_CLIENT_SECRET"):
        NotifySettings()
