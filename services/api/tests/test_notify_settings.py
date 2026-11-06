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
