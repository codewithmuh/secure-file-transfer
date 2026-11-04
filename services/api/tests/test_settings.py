from collections.abc import Callable
from typing import get_args

import pytest
from pydantic import BaseModel, SecretStr, ValidationError
from pydantic_settings import BaseSettings

from sft.core import settings as settings_module
from sft.core.settings import BootstrapSettings, MigrationSettings, Settings, load_settings

ENV_NAMES = (
    "APP_VERSION",
    "LOG_LEVEL",
    "BIND_HOST",
    "PUBLIC_PORT",
    "INTERNAL_PORT",
    "SHUTDOWN_DRAIN_SECONDS",
    "DATABASE_URL",
    "DATABASE_POOL_SIZE",
)
OTHER_ENV_NAMES = ("MIGRATION_DATABASE_URL", "BOOTSTRAP_DATABASE_URL", "BOOTSTRAP_IAM_AUTH")
DATABASE_URL = "postgresql+psycopg://sft_api@127.0.0.1:5432/sft"

Logs = Callable[[], list[dict[str, object]]]


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in (*ENV_NAMES, *OTHER_ENV_NAMES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
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
    assert s.database_url.get_secret_value() == DATABASE_URL
    assert s.database_pool_size == 5


def test_reads_the_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("APP_VERSION", "1.4.0")
    clean_env.setenv("LOG_LEVEL", "DEBUG")
    clean_env.setenv("BIND_HOST", "0.0.0.0")  # noqa: S104 - the value the image sets
    clean_env.setenv("PUBLIC_PORT", "9000")
    clean_env.setenv("INTERNAL_PORT", "9001")
    clean_env.setenv("SHUTDOWN_DRAIN_SECONDS", "30")
    clean_env.setenv("DATABASE_URL", "postgresql://sft_api@db:5432/sft?sslmode=verify-full")
    clean_env.setenv("DATABASE_POOL_SIZE", "10")
    s = Settings()
    assert s.app_version == "1.4.0"
    assert s.log_level == "debug"
    assert s.bind_host == "0.0.0.0"  # noqa: S104
    assert (s.public_port, s.internal_port) == (9000, 9001)
    assert s.shutdown_drain_seconds == 30
    assert s.database_url.get_secret_value().endswith("sslmode=verify-full")
    assert s.database_pool_size == 10


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
        ("DATABASE_URL", "mysql://sft_api@db/sft"),
        ("DATABASE_URL", "postgresql+asyncpg://sft_api@db/sft"),
        ("DATABASE_POOL_SIZE", "0"),
        ("DATABASE_POOL_SIZE", "51"),
    ],
)
def test_rejects_bad_values(clean_env: pytest.MonkeyPatch, name: str, value: str) -> None:
    clean_env.setenv(name, value)
    with pytest.raises(ValidationError):
        Settings()


def test_the_database_url_is_required(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.delenv("DATABASE_URL")
    with pytest.raises(ValidationError, match="database_url"):
        Settings()


def test_a_bad_database_url_is_never_echoed(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("DATABASE_URL", "mysql://sft_api:hunter2@db/sft")
    with pytest.raises(ValidationError) as error:
        Settings()
    assert "hunter2" not in str(error.value.errors(include_input=False))


def test_is_frozen(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError):
        Settings().log_level = "debug"


def test_migration_settings(clean_env: pytest.MonkeyPatch) -> None:
    with pytest.raises(ValidationError, match="migration_database_url"):
        MigrationSettings()
    clean_env.setenv("MIGRATION_DATABASE_URL", "postgresql://sft_migrate@db/sft")
    clean_env.setenv("LOG_LEVEL", "WARNING")
    s = MigrationSettings()
    assert s.migration_database_url.get_secret_value() == "postgresql://sft_migrate@db/sft"
    assert s.log_level == "warning"


def test_bootstrap_settings_need_a_choice_of_authentication(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("BOOTSTRAP_DATABASE_URL", "postgresql://postgres@db/sft")
    with pytest.raises(ValidationError, match="bootstrap_iam_auth"):
        BootstrapSettings()
    clean_env.setenv("BOOTSTRAP_IAM_AUTH", "true")
    assert BootstrapSettings().bootstrap_iam_auth is True


def test_load_settings_names_the_bad_settings_but_not_their_values(
    clean_env: pytest.MonkeyPatch, json_logs: Logs
) -> None:
    clean_env.setattr(settings_module, "configure_logging", lambda level: None)
    clean_env.setenv("DATABASE_URL", "mysql://sft_api:hunter2@db/sft")
    clean_env.setenv("PUBLIC_PORT", "nope")
    assert load_settings(Settings) is None
    [line] = json_logs()
    assert line["msg"] == "invalid settings"
    assert {e["setting"] for e in line["errors"]} == {"PUBLIC_PORT", "DATABASE_URL"}  # type: ignore[attr-defined]
    assert "hunter2" not in str(line)


def test_load_settings_returns_the_settings(clean_env: pytest.MonkeyPatch) -> None:
    settings = load_settings(Settings)
    assert settings is not None
    assert settings.database_url.get_secret_value() == DATABASE_URL


def secret_fields_with_defaults(model: type[BaseModel]) -> list[str]:
    def is_secret(annotation: object) -> bool:
        return annotation is SecretStr or SecretStr in get_args(annotation)

    return [
        name
        for name, field in model.model_fields.items()
        if is_secret(field.annotation) and not field.is_required()
    ]


@pytest.mark.parametrize("model", [Settings, MigrationSettings, BootstrapSettings])
def test_secrets_have_no_defaults(model: type[BaseSettings]) -> None:
    assert secret_fields_with_defaults(model) == []


@pytest.mark.parametrize(
    ("model", "secrets"),
    [
        (Settings, ["database_url"]),
        (MigrationSettings, ["migration_database_url"]),
        (BootstrapSettings, ["bootstrap_database_url"]),
    ],
)
def test_database_urls_are_secrets(model: type[BaseSettings], secrets: list[str]) -> None:
    # Locally a URL may hold a password, so it is never logged or shown in a repr.
    assert [
        name
        for name, field in model.model_fields.items()
        if field.annotation is SecretStr or SecretStr in get_args(field.annotation)
    ] == secrets


def test_the_secret_check_catches_a_default() -> None:
    class Leaky(BaseModel):
        required: SecretStr
        with_default: SecretStr = SecretStr("changeme")
        optional: SecretStr | None = None

    assert secret_fields_with_defaults(Leaky) == ["with_default", "optional"]
