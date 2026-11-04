"""MAIL_* settings (#100): environment only, checked at startup, never echoed."""

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from sft.core import settings as settings_module
from sft.core.settings import MailSettings, load_settings

Logs = Callable[[], list[dict[str, object]]]

NAMES = (
    "MAIL_BACKEND",
    "MAIL_FROM_ADDRESS",
    "MAIL_FROM_NAME",
    "WEB_APP_URL",
    "SES_REGION",
    "SES_CONFIGURATION_SET",
    "SES_TENANTS",
    "SMTP_HOST",
    "SMTP_PORT",
)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in NAMES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAIL_BACKEND", "smtp")
    monkeypatch.setenv("MAIL_FROM_ADDRESS", "no-reply@mail.sft.localhost")
    monkeypatch.setenv("WEB_APP_URL", "http://localhost:5173")
    return monkeypatch


def test_every_field_is_listed_here() -> None:
    assert {name.lower() for name in NAMES} == set(MailSettings.model_fields) - {"log_level"}


def test_local_defaults(env: pytest.MonkeyPatch) -> None:
    s = MailSettings()
    assert s.mail_backend == "smtp"
    assert s.mail_from_name == "Secure File Transfer"
    assert (s.smtp_host, s.smtp_port) == ("127.0.0.1", 1025)
    assert s.ses_region == "ap-northeast-1"
    assert s.ses_configuration_set is None
    assert s.ses_tenants is True


def test_ses_in_osaka(env: pytest.MonkeyPatch) -> None:
    env.setenv("MAIL_BACKEND", "ses")
    env.setenv("MAIL_FROM_ADDRESS", "no-reply@mail.sft.example")
    env.setenv("WEB_APP_URL", "https://app.sft.example")
    env.setenv("SES_REGION", "ap-northeast-3")
    env.setenv("SES_CONFIGURATION_SET", "sft-prod-ap-northeast-3")
    env.setenv("SES_TENANTS", "false")
    s = MailSettings()
    assert (s.ses_region, s.ses_configuration_set, s.ses_tenants) == (
        "ap-northeast-3",
        "sft-prod-ap-northeast-3",
        False,
    )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("MAIL_BACKEND", "sendmail"),
        ("MAIL_FROM_ADDRESS", "Name <no-reply@mail.sft.example>"),
        ("MAIL_FROM_ADDRESS", "nobody"),
        ("MAIL_FROM_NAME", "Évil\r\nBcc: x"),
        ("MAIL_FROM_NAME", '"quoted"'),
        ("WEB_APP_URL", "http://app.sft.example"),  # https outside localhost
        ("WEB_APP_URL", "https://app.sft.example/"),  # no trailing slash
        ("WEB_APP_URL", "https://app.sft.example/path"),
        ("WEB_APP_URL", "https://app.sft.example?x=1"),
        ("WEB_APP_URL", "javascript:alert(1)"),
        ("SES_REGION", "us-east-1"),  # email stays in Japan (NFR-21)
        ("SMTP_PORT", "0"),
    ],
)
def test_rejects_bad_values(env: pytest.MonkeyPatch, name: str, value: str) -> None:
    env.setenv(name, value)
    with pytest.raises(ValidationError) as caught:
        MailSettings()
    assert value not in str(caught.value.errors(include_input=False, include_url=False))


def test_ses_needs_a_configuration_set(env: pytest.MonkeyPatch, json_logs: Logs) -> None:
    env.setattr(settings_module, "configure_logging", lambda level: None)
    env.setenv("MAIL_BACKEND", "ses")
    assert load_settings(MailSettings) is None
    [line] = json_logs()
    assert {e["setting"] for e in line["errors"]} == {"MAIL_BACKEND, SES_CONFIGURATION_SET"}  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", ["MAIL_BACKEND", "MAIL_FROM_ADDRESS", "WEB_APP_URL"])
def test_required_settings(env: pytest.MonkeyPatch, name: str) -> None:
    env.delenv(name)
    with pytest.raises(ValidationError, match=name.lower()):
        MailSettings()


@pytest.mark.parametrize("url", ["http://127.0.0.1:8080", "http://[::1]:5173", "https://app.x.jp"])
def test_accepts_origins(env: pytest.MonkeyPatch, url: str) -> None:
    env.setenv("WEB_APP_URL", url)
    assert MailSettings().web_app_url == url
