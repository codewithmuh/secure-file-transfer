"""The workers' settings: `WorkerSettings`, and `RelaySettings` for the outbox relay."""

import pytest
from pydantic import SecretStr, ValidationError

from sft.core.settings import RelaySettings, load_settings

REQUIRED = {
    "DATABASE_URL": "postgresql://sft_relay@127.0.0.1:5432/sft",
    "SQS_QUEUE_PREFIX": "sft-dev-",
}
OPTIONAL = (
    "APP_VERSION",
    "LOG_LEVEL",
    "BIND_HOST",
    "INTERNAL_PORT",
    "SHUTDOWN_DRAIN_SECONDS",
    "DATABASE_POOL_SIZE",
    "AWS_REGION",
    "SQS_ENDPOINT_URL",
    "RELAY_BATCH_SIZE",
    "RELAY_POLL_INTERVAL_SECONDS",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "DATABASE_IAM_AUTH",
)


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in OPTIONAL:
        monkeypatch.delenv(name, raising=False)
    for name, value in REQUIRED.items():
        monkeypatch.setenv(name, value)
    return monkeypatch


def test_every_field_is_listed_here() -> None:
    assert {n.lower() for n in (*REQUIRED, *OPTIONAL)} == set(RelaySettings.model_fields)


def test_defaults(env: pytest.MonkeyPatch) -> None:
    s = RelaySettings()
    assert (s.bind_host, s.internal_port, s.shutdown_drain_seconds) == ("127.0.0.1", 8001, 15)
    assert (s.database_pool_size, s.aws_region, s.sqs_endpoint_url) == (2, "ap-northeast-1", None)
    assert (s.relay_batch_size, s.relay_poll_interval_seconds) == (50, 1.0)
    assert s.otel_exporter_otlp_endpoint is None


def test_reads_the_environment(env: pytest.MonkeyPatch) -> None:
    env.setenv("SQS_ENDPOINT_URL", "http://sqs:9324")
    env.setenv("AWS_REGION", "ap-northeast-3")
    env.setenv("RELAY_BATCH_SIZE", "10")
    env.setenv("RELAY_POLL_INTERVAL_SECONDS", "0.25")
    env.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-agent.observability:4318")
    s = RelaySettings()
    assert (s.sqs_endpoint_url, s.aws_region) == ("http://sqs:9324", "ap-northeast-3")
    assert (s.relay_batch_size, s.relay_poll_interval_seconds) == (10, 0.25)
    assert s.otel_exporter_otlp_endpoint == "http://otel-agent.observability:4318"


def test_an_empty_otlp_endpoint_means_none(env: pytest.MonkeyPatch) -> None:
    env.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    assert RelaySettings().otel_exporter_otlp_endpoint is None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("SQS_QUEUE_PREFIX", "sft-dev"),  # the prefix ends with a hyphen
        ("SQS_QUEUE_PREFIX", "SFT-dev-"),
        ("SQS_ENDPOINT_URL", "sqs:9324"),
        ("SQS_ENDPOINT_URL", "http://sqs:9324/queue/x"),
        ("AWS_REGION", "tokyo"),
        ("RELAY_BATCH_SIZE", "101"),
        ("RELAY_BATCH_SIZE", "0"),
        ("RELAY_POLL_INTERVAL_SECONDS", "0"),
        ("SHUTDOWN_DRAIN_SECONDS", "61"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-agent:4318"),
        ("DATABASE_URL", "mysql://x"),
    ],
)
def test_rejects_bad_values(env: pytest.MonkeyPatch, name: str, value: str) -> None:
    env.setenv(name, value)
    with pytest.raises(ValidationError):
        RelaySettings()


def test_the_database_url_is_a_secret_with_no_default() -> None:
    field = RelaySettings.model_fields["database_url"]
    assert field.is_required()
    assert SecretStr in (field.annotation, *getattr(field.annotation, "__args__", ()))
    secrets = [
        name for name, f in RelaySettings.model_fields.items() if "SecretStr" in repr(f.annotation)
    ]
    assert secrets == ["database_url"]


def test_load_settings_names_the_missing_ones(env: pytest.MonkeyPatch, json_logs: object) -> None:
    env.delenv("SQS_QUEUE_PREFIX")
    assert load_settings(RelaySettings) is None
