import pytest
from pydantic import SecretStr, ValidationError

from sft.core.settings import BootstrapSettings, Settings, setting_errors

# DATABASE_URL is required; give it, so each test sees only the error it causes.
DATABASE_URL = SecretStr("postgresql://sft_api@127.0.0.1:1/sft")
VALKEY_URL = SecretStr("redis://u:p@127.0.0.1:1/0")


def errors_for(**values: object) -> list[dict[str, str]]:
    with pytest.raises(ValidationError) as caught:
        Settings(database_url=DATABASE_URL, valkey_url=VALKEY_URL, **values)  # type: ignore[arg-type]
    return setting_errors(caught.value, Settings)


def test_names_the_bad_setting() -> None:
    [error] = errors_for(public_port=0)
    assert error["setting"] == "PUBLIC_PORT"


def test_names_both_settings_of_a_check_across_settings() -> None:
    [error] = errors_for(public_port=9000, internal_port=9000)
    assert error["setting"] == "PUBLIC_PORT, INTERNAL_PORT"
    assert "must differ" in error["error"]


def test_never_includes_the_value() -> None:
    [error] = errors_for(log_level="hunter2-secret")
    assert error["setting"] == "LOG_LEVEL"
    assert "hunter2" not in str(error)


def test_names_a_missing_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("VALKEY_URL", VALKEY_URL.get_secret_value())
    with pytest.raises(ValidationError) as caught:
        Settings()  # type: ignore[call-arg]
    assert setting_errors(caught.value, Settings) == [
        {"setting": "DATABASE_URL", "error": "Field required"}
    ]


def test_names_settings_of_the_class_being_read() -> None:
    # A job's settings are named after its own fields: BOOTSTRAP_DATABASE_URL, not DATABASE_URL.
    with pytest.raises(ValidationError) as caught:
        BootstrapSettings(bootstrap_database_url=SecretStr("mysql://x"), bootstrap_iam_auth=True)
    [error] = setting_errors(caught.value, BootstrapSettings)
    assert error["setting"] == "BOOTSTRAP_DATABASE_URL"
    assert "mysql" not in str(error)
