import base64
from collections.abc import Callable
from typing import get_args

import pytest
from pydantic import BaseModel, SecretStr, ValidationError
from pydantic_settings import BaseSettings

from api_settings import API_ENV
from sft.core import settings as settings_module
from sft.core.settings import (
    BootstrapSettings,
    JobSettings,
    MigrationSettings,
    OperatorSettings,
    Settings,
    load_settings,
    setting_errors,
)

ENV_NAMES = (
    "APP_VERSION",
    "LOG_LEVEL",
    "BIND_HOST",
    "PUBLIC_PORT",
    "INTERNAL_PORT",
    "SHUTDOWN_DRAIN_SECONDS",
    "DATABASE_URL",
    "DATABASE_POOL_SIZE",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "VALKEY_URL",
    "TRUSTED_PROXIES",
    *(name for name in API_ENV if name != "VALKEY_URL"),
    "OIDC_DISCOVERY_URL",
    "OIDC_REVOCATION_URL",
    "ADMIN_PASSKEY_RULE",
    "AWS_REGION",
    "S3_ENDPOINT_URL",
    "TENANT_STORAGE_QUOTA_BYTES",
    "SCAN_SMALL_POOL_MAX_BYTES",
    "AUDIT_ARCHIVE_OSAKA_BUCKET",
    "AUDIT_ARCHIVE_TOKYO_ENDPOINT_URL",
    "AUDIT_ARCHIVE_OSAKA_ENDPOINT_URL",
    "ENVIRONMENT",
    "CLOCK_OFFSET_SECONDS",
    "DOWNLOAD_RECHECK_SECONDS",
    "DOWNLOAD_STREAMS_PER_POD",
    "S3_PRESIGN_ENDPOINT_URL",
    "PUBLIC_TLS",
    "PUBLIC_TLS_CERT_FILE",
    "PUBLIC_TLS_KEY_FILE",
    "DATABASE_IAM_AUTH",
    "VALKEY_IAM_CACHE",
    # Tenant SSO (#231).
    "OIDC_IDP_HINT_PARAMETER",
    "OIDC_GROUPS_CLAIM",
    "SSO_DNS_OVERRIDES",
    "SSO_DNS_NAMESERVERS",
)
OTHER_ENV_NAMES = ("MIGRATION_DATABASE_URL", "BOOTSTRAP_DATABASE_URL", "BOOTSTRAP_IAM_AUTH")
DATABASE_URL = "postgresql+psycopg://sft_api@127.0.0.1:5432/sft"
VALKEY_URL = "redis://sft-api:local-only@127.0.0.1:6379/0"

Logs = Callable[[], list[dict[str, object]]]


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    for name in (*ENV_NAMES, *OTHER_ENV_NAMES):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DATABASE_URL", DATABASE_URL)
    for name, value in API_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("VALKEY_URL", VALKEY_URL)
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
    assert s.otel_exporter_otlp_endpoint is None
    assert s.valkey_url.get_secret_value() == VALKEY_URL
    assert s.trusted_proxies == ()
    assert (s.oidc_discovery_url, s.oidc_revocation_url) == (None, None)
    assert s.admin_passkey_rule is False
    assert s.aws_region == "ap-northeast-1"
    assert s.s3_endpoint_url is None
    assert s.tenant_storage_quota_bytes == 2 * 10**12
    assert s.scan_small_pool_max_bytes == 100_000_000  # ADR-0019's 100 MB split
    # Tokyo's archive is required; Osaka's is unset only where there is no Osaka (dev, #177).
    assert s.audit_archive_tokyo_bucket == "sft-test-audit-archive"
    assert s.audit_archive_osaka_bucket is None
    assert (s.audit_archive_tokyo_endpoint_url, s.audit_archive_osaka_endpoint_url) == (None, None)
    # The tests' environment (api_settings.py); unset is prod (#129's test below).
    assert (s.environment, s.clock_offset_seconds) == ("local", 0)
    assert (s.download_recheck_seconds, s.download_streams_per_pod) == (30.0, 100)
    assert s.s3_presign_endpoint_url is None  # in AWS S3 signs its own host (#195)
    # Cognito's provider parameter and group attribute; DNS proves SSO domains (#231).
    assert (s.oidc_idp_hint_parameter, s.oidc_groups_claim) == (
        "identity_provider",
        "custom:sso_groups",
    )
    assert (s.sso_dns_overrides, s.sso_dns_nameservers) == (None, None)


def test_reads_the_environment(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("APP_VERSION", "1.4.0")
    clean_env.setenv("LOG_LEVEL", "DEBUG")
    clean_env.setenv("BIND_HOST", "0.0.0.0")  # noqa: S104 - the value the image sets
    clean_env.setenv("PUBLIC_PORT", "9000")
    clean_env.setenv("INTERNAL_PORT", "9001")
    clean_env.setenv("SHUTDOWN_DRAIN_SECONDS", "30")
    clean_env.setenv("DATABASE_URL", "postgresql://sft_api@db:5432/sft?sslmode=verify-full")
    clean_env.setenv("DATABASE_POOL_SIZE", "10")
    clean_env.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-agent.observability:4318")
    clean_env.setenv("VALKEY_URL", "rediss://sft-api@cache.example:6379")
    clean_env.setenv("TRUSTED_PROXIES", "10.0.0.0/20, 10.0.16.0/20")
    s = Settings()
    assert s.app_version == "1.4.0"
    assert s.log_level == "debug"
    assert s.bind_host == "0.0.0.0"  # noqa: S104
    assert (s.public_port, s.internal_port) == (9000, 9001)
    assert s.shutdown_drain_seconds == 30
    assert s.database_url.get_secret_value().endswith("sslmode=verify-full")
    assert s.database_pool_size == 10
    assert s.otel_exporter_otlp_endpoint == "http://otel-agent.observability:4318"
    assert s.valkey_url.get_secret_value().startswith("rediss://")
    assert [str(n) for n in s.trusted_proxies] == ["10.0.0.0/20", "10.0.16.0/20"]


def test_an_empty_otlp_endpoint_means_none(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    assert Settings().otel_exporter_otlp_endpoint is None


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
        ("VALKEY_URL", "http://cache:6379"),
        ("TRUSTED_PROXIES", "10.0.0.0/33"),
        ("TRUSTED_PROXIES", "10.0.0.1/8"),  # host bits set: a typo, not a network
        ("DATABASE_POOL_SIZE", "0"),
        ("DATABASE_POOL_SIZE", "51"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "otel-agent:4318"),  # no scheme
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "grpc://otel-agent:4317"),
        ("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-agent:4318?x=1"),
        ("WEB_ORIGIN", "app.sft.test"),  # no scheme
        ("WEB_ORIGIN", "https://app.sft.test/"),  # a path: an origin has none
        ("OIDC_ISSUER", "ftp://idp.sft.test"),
        ("OIDC_CLIENT_ID", "has spaces"),
        ("OIDC_REDIRECT_URI", "https://api.sft.test/v1/auth/callback#x"),
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


def test_the_valkey_url_is_required(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.delenv("VALKEY_URL")
    with pytest.raises(ValidationError, match="valkey_url"):
        Settings()


@pytest.mark.parametrize("name", [n for n in API_ENV if n not in ("VALKEY_URL", "ENVIRONMENT")])
def test_every_sign_in_and_files_bucket_setting_is_required(
    clean_env: pytest.MonkeyPatch, name: str
) -> None:
    clean_env.delenv(name)
    with pytest.raises(ValidationError, match=name.lower()):
        Settings()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CSRF_KEYRING", "not json"),
        ("CSRF_KEYRING", '[{"id": "a", "state": "verify", "key": "%s"}]'),  # no active key
        ("EMAIL_HMAC_KEYRING", '[{"id": "a", "state": "active", "key": "%s"}]'),  # no activated_at
        (
            "EMAIL_HMAC_KEYRING",
            '[{"id": "a_b", "state": "active", "key": "%s", '
            '"activated_at": "2026-01-01T00:00:00Z"}]',
        ),  # "_" isn't in a pseudonym's key ID
        (
            "EMAIL_HMAC_KEYRING",
            '[{"id": "a", "state": "active", "key": "%s", "activated_at": "2026-01-01T00:00:00"}]',
        ),  # no time zone
        ("CODE_HMAC_KEYRING", '[{"id": "a_b", "state": "active", "key": "%s"}]'),  # bad key ID
        ("CODE_HMAC_KEYRING", "[]"),
    ],
)
def test_a_bad_keyring_stops_the_api_and_is_never_echoed(
    clean_env: pytest.MonkeyPatch, name: str, value: str
) -> None:
    key = base64.b64encode(b"k" * 32).decode()
    clean_env.setenv(name, value.replace("%s", key))
    with pytest.raises(ValidationError) as error:
        Settings()
    assert [e["loc"] for e in error.value.errors()] == [(name.lower(),)]
    assert key not in str(error.value.errors(include_input=False))


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("S3_FILES_BUCKET", "Sft_Files"),  # not a bucket name
        ("S3_LARGE_FILES_BUCKET", "ab"),  # too short
        ("S3_ENDPOINT_URL", "s3mock:9090"),  # no scheme
        ("TENANT_STORAGE_QUOTA_BYTES", "0"),
        ("AUDIT_ARCHIVE_TOKYO_BUCKET", "Not_A_Bucket"),
        ("AUDIT_ARCHIVE_OSAKA_BUCKET", "x"),
        ("AUDIT_ARCHIVE_OSAKA_ENDPOINT_URL", "s3:9090"),
    ],
)
def test_a_bad_files_bucket_setting_stops_the_api(
    clean_env: pytest.MonkeyPatch, name: str, value: str
) -> None:
    clean_env.setenv(name, value)
    with pytest.raises(ValidationError, match=name.lower()):
        Settings()


def test_the_operator_api_reads_none_of_the_sign_in_settings() -> None:
    # It serves no member sign-in (#111), so a missing OIDC setting can't stop it.
    assert not set(OperatorSettings.model_fields) & {n.lower() for n in API_ENV} - {"valkey_url"}


def test_a_bad_valkey_url_is_never_echoed(clean_env: pytest.MonkeyPatch) -> None:
    clean_env.setenv("VALKEY_URL", "http://sft:hunter2@cache:6379")
    with pytest.raises(ValidationError) as error:
        Settings()
    assert "hunter2" not in str(error.value.errors(include_input=False))


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


@pytest.mark.parametrize("environment", ["local", "test"])
def test_the_clock_hook_runs_in_local_and_test(
    clean_env: pytest.MonkeyPatch, environment: str
) -> None:
    clean_env.setenv("ENVIRONMENT", environment)
    clean_env.setenv("CLOCK_OFFSET_SECONDS", "90000")
    assert Settings().clock_offset_seconds == 90000


@pytest.mark.parametrize("environment", ["dev", "staging", "prod", None])
def test_the_clock_hook_is_refused_anywhere_else(
    clean_env: pytest.MonkeyPatch, environment: str | None
) -> None:
    if environment is not None:
        clean_env.setenv("ENVIRONMENT", environment)
    else:
        clean_env.delenv("ENVIRONMENT")  # unset is prod
    clean_env.setenv("TRUSTED_PROXIES", "10.0.0.0/20")  # required outside local and test (#129)
    clean_env.setenv("CLOCK_OFFSET_SECONDS", "90000")
    with pytest.raises(ValidationError, match="only ENVIRONMENT=local or test"):
        Settings()
    with pytest.raises(ValidationError, match="only ENVIRONMENT=local or test"):
        JobSettings(
            database_url="postgresql://sft_jobs@127.0.0.1/sft",
            s3_files_bucket="sft-test-files",
            s3_large_files_bucket="sft-test-large-files",
            audit_archive_tokyo_bucket="sft-test-audit-archive",
        )
    clean_env.setenv("CLOCK_OFFSET_SECONDS", "0")
    Settings()  # no offset: every environment runs


def test_job_settings_name_the_replica_buckets_together() -> None:
    base = {
        "database_url": "postgresql://sft_jobs@127.0.0.1/sft",
        "s3_files_bucket": "sft-test-files",
        "s3_large_files_bucket": "sft-test-large-files",
        "audit_archive_tokyo_bucket": "sft-test-audit-archive",
    }
    JobSettings(**base)  # type: ignore[arg-type]
    JobSettings(  # type: ignore[arg-type]
        **base,
        s3_replica_region="ap-northeast-3",
        s3_replica_files_bucket="sft-test-files-osaka",
        s3_replica_large_files_bucket="sft-test-large-files-osaka",
    )
    with pytest.raises(ValidationError, match="together"):
        JobSettings(**base, s3_replica_region="ap-northeast-3")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "model", [Settings, OperatorSettings, MigrationSettings, BootstrapSettings, JobSettings]
)
def test_secrets_have_no_defaults(model: type[BaseSettings]) -> None:
    assert secret_fields_with_defaults(model) == []


@pytest.mark.parametrize(
    ("model", "secrets"),
    [
        (
            Settings,
            [
                "database_url",
                "valkey_url",
                "oidc_client_secret",
                "csrf_keyring",
                "email_hmac_keyring",
                "code_hmac_keyring",
            ],
        ),
        (OperatorSettings, ["database_url", "valkey_url"]),
        (MigrationSettings, ["migration_database_url"]),
        (BootstrapSettings, ["bootstrap_database_url"]),
        (JobSettings, ["database_url"]),
    ],
)
def test_secret_settings_are_secret_strings(model: type[BaseSettings], secrets: list[str]) -> None:
    # Locally a URL may hold a password, and the client secret and the keyrings are secrets:
    # never logged or shown in a repr.
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


def test_part_urls_may_name_the_stand_in_as_the_browser_sees_it(
    clean_env: pytest.MonkeyPatch,
) -> None:
    """Locally the API calls S3Mock in-network and signs part URLs for the host's address (#195)."""
    clean_env.setenv("S3_ENDPOINT_URL", "http://s3:9090")
    clean_env.setenv("S3_PRESIGN_ENDPOINT_URL", "http://localhost:9090")
    s = Settings()
    assert (s.s3_endpoint_url, s.s3_presign_endpoint_url) == (
        "http://s3:9090",
        "http://localhost:9090",
    )


def test_a_presign_endpoint_needs_the_s3_stand_in(clean_env: pytest.MonkeyPatch) -> None:
    """S3_PRESIGN_ENDPOINT_URL without S3_ENDPOINT_URL would sign real S3's part URLs for another
    host: refused at startup (#195)."""
    clean_env.setenv("S3_PRESIGN_ENDPOINT_URL", "http://localhost:9090")
    with pytest.raises(ValidationError, match="for the local S3 stand-in only"):
        Settings()


# ---- #129: per-IP limits behind the load balancer need its subnets ----


@pytest.mark.parametrize("environment", ["dev", "staging", "prod", None])
def test_the_api_refuses_to_start_without_trusted_proxies_outside_local_and_test(
    clean_env: pytest.MonkeyPatch, environment: str | None
) -> None:
    """Behind the load balancer with no trusted proxy, every client's address would be the load
    balancer's: per-IP limits and the failed-authentication block would apply to everyone."""
    if environment is None:
        clean_env.delenv("ENVIRONMENT")  # unset is prod, the strictest
    else:
        clean_env.setenv("ENVIRONMENT", environment)
    with pytest.raises(ValidationError, match="TRUSTED_PROXIES is required") as refused:
        Settings()
    [error] = setting_errors(refused.value, Settings)
    assert error["setting"] == "ENVIRONMENT, TRUSTED_PROXIES"
    clean_env.setenv("TRUSTED_PROXIES", "10.0.0.0/20, 10.0.16.0/20")
    assert len(Settings().trusted_proxies) == 2


@pytest.mark.parametrize("environment", ["local", "test"])
def test_the_compose_stack_and_the_suite_need_no_trusted_proxy(
    clean_env: pytest.MonkeyPatch, environment: str
) -> None:
    clean_env.setenv("ENVIRONMENT", environment)
    assert Settings().trusted_proxies == ()


def test_the_dns_stand_in_is_a_test_hook(clean_env: pytest.MonkeyPatch) -> None:
    # #231: only the local stack and the tests prove SSO domains without DNS.
    clean_env.setenv("SSO_DNS_OVERRIDES", "{}")
    clean_env.setenv("ENVIRONMENT", "dev")
    clean_env.setenv("TRUSTED_PROXIES", "10.0.0.0/20")  # #129: required outside local and test
    with pytest.raises(ValidationError, match="SSO_DNS_OVERRIDES is a test hook"):
        Settings()
    clean_env.setenv("ENVIRONMENT", "test")
    assert Settings().sso_dns_overrides == "{}"
