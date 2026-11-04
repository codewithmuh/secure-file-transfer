import pytest
from pydantic import ValidationError

from sft.api.__main__ import setting_errors
from sft.core.settings import Settings


def errors_for(**values: object) -> list[dict[str, str]]:
    with pytest.raises(ValidationError) as caught:
        Settings(**values)  # type: ignore[arg-type]
    return setting_errors(caught.value)


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
