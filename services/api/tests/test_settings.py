from typing import get_args

import pytest
from pydantic import BaseModel, SecretStr, ValidationError

from sft.core.settings import Settings

ENV_NAMES = (
    "APP_VERSION",
    "LOG_LEVEL",
    "BIND_HOST",
    "PUBLIC_PORT",
    "INTERNAL_PORT",
    "SHUTDOWN_DRAIN_SECONDS",
)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_every_field_is_listed_here() -> None:
    # Keeps ENV_NAMES, and so the tests below, in step with the settings.
    assert {name.lower() for name in ENV_NAMES} == set(Settings.model_fields)


def test_defaults(clean_env: pytest.MonkeyPatch) -> None:
    s = Settings()
    assert s.app_version == "0.0.0"
    assert s.log_level == "info"
    assert s.bind_host == "127.0.0.1"
    assert (s.public_port, s.internal_port) == (8000, 8001)
    assert s.shutdown_drain_seconds == 20


def test_reads_the_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("APP_VERSION", "1.4.0")
    clean_env.setenv("LOG_LEVEL", "DEBUG")
    clean_env.setenv("BIND_HOST", "0.0.0.0")  # noqa: S104 - the value the image sets
    clean_env.setenv("PUBLIC_PORT", "9000")
    clean_env.setenv("INTERNAL_PORT", "9001")
    clean_env.setenv("SHUTDOWN_DRAIN_SECONDS", "30")
    s = Settings()
    assert s.app_version == "1.4.0"
    assert s.log_level == "debug"
    assert s.bind_host == "0.0.0.0"  # noqa: S104
    assert (s.public_port, s.internal_port) == (9000, 9001)
    assert s.shutdown_drain_seconds == 30


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("LOG_LEVEL", "loud"),
        ("PUBLIC_PORT", "0"),
        ("PUBLIC_PORT", "65536"),
        ("PUBLIC_PORT", "http"),
        ("INTERNAL_PORT", "8000"),  # the same as the public port
        ("SHUTDOWN_DRAIN_SECONDS", "0"),
        ("SHUTDOWN_DRAIN_SECONDS", "121"),
    ],
)
def test_rejects_bad_values(clean_env: pytest.MonkeyPatch, name: str, value: str) -> None:
    clean_env.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()


def test_is_frozen(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        Settings().log_level = "debug"


def secret_fields_with_defaults(model: type[BaseModel]) -> list[str]:
    def is_secret(annotation: object) -> bool:
        return annotation is SecretStr or SecretStr in get_args(annotation)

    return [
        name
        for name, field in model.model_fields.items()
        if is_secret(field.annotation) and not field.is_required()
    ]


def test_secrets_have_no_defaults() -> None:
    assert secret_fields_with_defaults(Settings) == []


def test_the_secret_check_catches_a_default() -> None:
    class Leaky(BaseModel):
        required: SecretStr
        with_default: SecretStr = SecretStr("changeme")
        optional: SecretStr | None = None

    assert secret_fields_with_defaults(Leaky) == ["with_default", "optional"]
