"""Settings from environment variables only (architecture 8), typed and checked at startup.

Nothing is read from files: locally the shell or `compose.yaml` sets the variables, in Kubernetes
the pod spec does. A secret is a `SecretStr` field with no default, so a missing secret stops the
process at startup instead of running with a placeholder; a test fails if a secret field gets a
default. In the cloud, secrets come from AWS Secrets Manager, never from git.

Each entry point reads only the settings it needs: `Settings` for the API and `OperatorSettings`
for the operator API (both build on `ServerSettings`), `RelaySettings` for the outbox relay (and
`WorkerSettings`, its base, for the workers to come), `MigrationSettings` for the migration job,
`BootstrapSettings` for the database bootstrap job, `MailSettings` for whatever sends email (the
notification worker).
"""

from __future__ import annotations

import logging
import re
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    Field,
    IPvAnyNetwork,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from sft.core.keyrings import CSRF_KEY_ID, EMAIL_KEY_ID, parse_keyring
from sft.core.logs import configure_logging

LogLevel = Literal["debug", "info", "warning", "error", "critical"]

log = logging.getLogger(__name__)

_POSTGRES_SCHEMES = ("postgresql://", "postgresql+psycopg://")


def _postgres_url(value: SecretStr) -> SecretStr:
    # The message never includes the value: the URL may hold a password.
    if not value.get_secret_value().startswith(_POSTGRES_SCHEMES):
        raise ValueError("must start with postgresql:// or postgresql+psycopg://")
    return value


# A PostgreSQL URL. In AWS it names the login role and has no password: the role signs in with IAM
# database authentication (encryption and keys 6.3). Locally it may hold a fake password.
PostgresUrl = Annotated[SecretStr, AfterValidator(_postgres_url)]

_VALKEY_SCHEMES = ("redis://", "rediss://", "valkey://", "valkeys://")


def _valkey_url(value: SecretStr) -> SecretStr:
    if not value.get_secret_value().startswith(_VALKEY_SCHEMES):
        raise ValueError("must start with redis://, rediss://, valkey:// or valkeys://")
    return value


# A Valkey URL with its credentials: locally the ACL user and its fake password; in AWS `rediss://`
# and the workload's user, whose IAM token M4 signs per connection (ADR-0014).
ValkeyUrl = Annotated[SecretStr, AfterValidator(_valkey_url)]


# Pods set enableServiceLinks: false, so Service variables can't clash with these (architecture 8).
class _Base(BaseSettings):
    model_config = SettingsConfigDict(frozen=True)

    log_level: LogLevel = "info"

    @field_validator("log_level", mode="before")
    @classmethod
    def _lower_case_level(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value


class _Traced(_Base):
    """What every long-running workload reads to export its traces: the API and the workers."""

    otel_exporter_otlp_endpoint: str | None = Field(
        default=None,
        pattern=r"^https?://[^/?#\s]+(/[^?#\s]*)?$",
        description="The collector's OTLP/HTTP base URL; spans go to <endpoint>/v1/traces. "
        "Unset: traces are made for the logs and messages but not exported (ADR-0009).",
    )

    @field_validator("otel_exporter_otlp_endpoint", mode="before")
    @classmethod
    def _empty_endpoint_is_unset(cls, value: object) -> object:
        # A chart that renders the variable empty means "don't export", not a bad URL.
        return None if value == "" else value


class ServerSettings(_Traced):
    """What every API app reads: its two listeners, its database role and the counter store.

    The public API (`Settings`) and the operator API (`OperatorSettings`) each add their own. The
    field name in capitals is the environment variable.
    """

    app_version: str = Field(default="0.0.0", description="Set by the image build.")
    # 127.0.0.1 keeps a laptop run off the network; the image sets BIND_HOST=0.0.0.0.
    bind_host: str = "127.0.0.1"
    public_port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="The API, behind the load balancer.",
    )
    internal_port: int = Field(
        default=8001,
        ge=1,
        le=65535,
        description="Probes and metrics; the public load balancer doesn't route to it.",
    )
    shutdown_drain_seconds: int = Field(
        default=20,
        ge=1,
        le=120,
        description="How long in-flight requests get to finish after SIGTERM (architecture 8).",
    )
    database_url: PostgresUrl = Field(
        description="The workload's own login role, never the migration role or the master user.",
    )
    database_pool_size: int = Field(
        default=5,
        ge=1,
        le=50,
        description="Connections per process, with no overflow, so the total is predictable.",
    )
    valkey_url: ValkeyUrl = Field(
        description="The rate-limit counter store, with its credentials (ADR-0014).",
    )
    trusted_proxies: Annotated[tuple[IPvAnyNetwork, ...], NoDecode] = Field(
        default=(),
        description="Our load balancer's subnets, comma-separated. Only a request from them has "
        "its client address taken from X-Forwarded-For (ADR-0002); empty locally.",
    )

    @field_validator("trusted_proxies", mode="before")
    @classmethod
    def _split_networks(cls, value: object) -> object:
        if isinstance(value, str):
            return tuple(part.strip() for part in value.split(",") if part.strip())
        return value

    @model_validator(mode="after")
    def _ports_differ(self) -> Self:
        if self.public_port == self.internal_port:
            raise ValueError("PUBLIC_PORT and INTERNAL_PORT must differ")
        return self


# An origin (scheme, host and port, no path) and an http(s) URL, for the sign-in settings.
_ORIGIN = r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?$"
_HTTP_URL = r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s?#]*)?(\?[^\s#]*)?$"


class Settings(ServerSettings):
    """The public API's settings: the server's, and member sign-in's (ADR-0016; authentication and
    authorization 2.4 and 3). Locally Keycloak stands in for the Cognito user pool
    (docs/local-development.md)."""

    web_origin: str = Field(
        pattern=_ORIGIN,
        description="The web app's origin, such as https://app.example.com: where sign-in returns, "
        "and the only Origin an unsafe request may come from (authn-authz 3.4).",
    )
    oidc_issuer: str = Field(
        pattern=_HTTP_URL,
        description="The user pool's issuer; an ID token's `iss` must equal it.",
    )
    oidc_discovery_url: str | None = Field(
        default=None,
        pattern=_HTTP_URL,
        description="Where to read the issuer's OpenID configuration, if not under the issuer: "
        "locally the stand-in's in-network address, so a container can reach it.",
    )
    oidc_client_id: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    oidc_client_secret: SecretStr = Field(
        description="The confidential app client's secret (sft/{env}/app/idp-client/<region>).",
    )
    oidc_redirect_uri: str = Field(
        pattern=_HTTP_URL,
        description="This API's callback, as registered with the app client: .../v1/auth/callback.",
    )
    oidc_logout_url: str = Field(
        pattern=_HTTP_URL,
        description="The pool's logout URL that signOut returns, so managed login's own cookie "
        "is cleared too (authn-authz 3.5).",
    )
    oidc_revocation_url: str | None = Field(
        default=None,
        pattern=_HTTP_URL,
        description="The token revocation endpoint. Cognito's isn't in its discovery document "
        "(/oauth2/revoke on the managed login domain); otherwise discovery's is used.",
    )
    oidc_provider_name: str = Field(
        min_length=1,
        max_length=128,
        description="This pool's `idp_connections.provider_name`: its pool ID in AWS, "
        "`local-keycloak` locally. Local sign-ins resolve their connection by it.",
    )
    csrf_keyring: SecretStr = Field(
        description="K_csrf, the keyring CSRF tokens are derived with (sft/{env}/app/csrf-hmac, "
        "encryption and keys 6.5): a JSON list of keys with `id`, `state` and base64 `key`.",
    )
    email_hmac_keyring: SecretStr = Field(
        description="The keyring of email pseudonyms (sft/{env}/app/email-hmac, encryption and "
        "keys 6.2): what per-address rate limits count under, so the counters never hold an "
        "address. Like CSRF_KEYRING, with `activated_at` on the active key.",
    )
    admin_passkey_rule: bool = Field(
        default=False,
        description="The launch switch of ADR-0016: a local admin acts as an admin only in a "
        "session signed in with a passkey. Off until both pools issue `amr`.",
    )

    @field_validator("csrf_keyring")
    @classmethod
    def _csrf_keyring(cls, value: SecretStr) -> SecretStr:
        # Read here, so a bad keyring stops the process at startup; the message holds no key.
        parse_keyring(value.get_secret_value(), name="CSRF", key_id=CSRF_KEY_ID)
        return value

    @field_validator("email_hmac_keyring")
    @classmethod
    def _email_hmac_keyring(cls, value: SecretStr) -> SecretStr:
        parse_keyring(
            value.get_secret_value(), name="email", key_id=EMAIL_KEY_ID, needs_activation=True
        )
        return value


_QUEUE_PREFIX = r"^[a-z0-9]+(-[a-z0-9]+)*-$"


class WorkerSettings(_Traced):
    """What every worker reads: its probes, its database role, SQS, traces (architecture 8)."""

    app_version: str = Field(default="0.0.0", description="Set by the image build.")
    bind_host: str = "127.0.0.1"
    internal_port: int = Field(
        default=8001,
        ge=1,
        le=65535,
        description="Probes and metrics; a worker has no other port.",
    )
    shutdown_drain_seconds: int = Field(
        default=15,
        ge=1,
        le=60,
        description="How long the work in hand gets to finish after SIGTERM.",
    )
    database_url: PostgresUrl = Field(
        description="The workload's own login role, never the migration role or the master user.",
    )
    database_pool_size: int = Field(default=2, ge=1, le=20)
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    sqs_queue_prefix: str = Field(
        pattern=_QUEUE_PREFIX,
        description="Names the environment's queues: `sft-dev-` makes `sft-dev-notify`. Required.",
    )
    sqs_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only, for ElasticMQ. In AWS the SDK finds SQS's VPC endpoint itself.",
    )


class RelaySettings(WorkerSettings):
    """The outbox relay's settings (ADR-0013)."""

    relay_batch_size: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Rows claimed per transaction; sent in batches of 10, one call per queue.",
    )
    relay_poll_interval_seconds: float = Field(
        default=1.0,
        ge=0.05,
        le=30,
        description="The wait after a batch that wasn't full, before looking for due rows again.",
    )


class OperatorSettings(ServerSettings):
    """The operator API's settings (FR-34, authentication and authorization 8.2).

    The same listeners as the API and none of member sign-in. Its `DATABASE_URL` names
    `sft_operator`, and it checks operators' signed STS requests against this environment's
    account and `Operator` role, which Terraform writes into the pod spec.
    """

    operator_environment: Literal["dev", "staging", "prod"] = Field(
        description="This environment; the audience operators sign is `operator-api-<env>`.",
    )
    operator_aws_account_id: str = Field(
        pattern=r"^[0-9]{12}$",
        description="This environment's AWS account. STS must answer with it.",
    )
    operator_role_name: str = Field(
        pattern=r"^AWSReservedSSO_Operator_[0-9a-f]{16}$",
        description="The IAM role of this account's `Operator` permission set, exactly.",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    operator_sts_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="The STS endpoint the API sends signed requests to; by default the "
        "regional one, `https://sts.<AWS_REGION>.amazonaws.com`. Never taken from a request.",
    )

    @property
    def operator_audience(self) -> str:
        return f"operator-api-{self.operator_environment}"

    @property
    def sts_endpoint(self) -> str:
        return (
            self.operator_sts_endpoint_url or f"https://sts.{self.aws_region}.amazonaws.com"
        ).rstrip("/")


class MigrationSettings(_Base):
    """The migration job's settings (data model 7)."""

    migration_database_url: PostgresUrl = Field(
        description="The `sft_migrate` login role, which becomes `sft_owner` to run migrations.",
    )


class BootstrapSettings(_Base):
    """The database bootstrap job's settings: it creates the roles, once per environment."""

    bootstrap_database_url: PostgresUrl = Field(
        description="The master user (in AWS) or a local superuser; never used by a workload.",
    )
    bootstrap_iam_auth: bool = Field(
        description="True on Aurora: the login roles sign in with IAM database authentication. "
        "False locally, where they get passwords some other way. No default: choose.",
    )


# Email stays in Japan (NFR-21): Tokyo, and Osaka for failover (ADR-0015).
SesRegion = Literal["ap-northeast-1", "ap-northeast-3"]

_LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")
_ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
_DISPLAY_NAME = re.compile(r"[A-Za-z0-9 .-]{1,64}")
_WEB_APP_URL = re.compile(r"(?P<scheme>https?)://(?P<host>[A-Za-z0-9.-]+|\[::1\])(:[0-9]{1,5})?")


class MailSettings(_Base):
    """How the notification worker sends email (ADR-0015, #100); its settings class adds these."""

    mail_backend: Literal["ses", "smtp"] = Field(
        description="`ses` in AWS; `smtp` only for the local stack's Mailpit. No default: choose.",
    )
    mail_from_address: str = Field(
        description="The `From` address, on our sending subdomain (`no-reply@mail.<domain>`).",
    )
    mail_from_name: str = Field(
        default="Secure File Transfer",
        description="The `From` display name: ASCII letters, digits, spaces, dots and dashes.",
    )
    web_app_url: str = Field(
        description="The web app's origin, the only place emails link to (abuse 7.5), such as "
        "`https://app.<domain>`. `http` only for localhost.",
    )
    ses_region: SesRegion = Field(
        default="ap-northeast-1",
        description="The region whose SES identity sends: Tokyo, or Osaka after a failover.",
    )
    ses_configuration_set: str | None = Field(
        default=None,
        description="The region's configuration set (TLS required, events). Required for `ses`.",
    )
    ses_tenants: bool = Field(
        default=True,
        description="Name the sending tenant's SES tenant in every send. False only in a region "
        "without SES tenant management (ADR-0015, consequences).",
    )
    smtp_host: str = Field(default="127.0.0.1", description="Mailpit's SMTP host, for `smtp`.")
    smtp_port: int = Field(default=1025, ge=1, le=65535, description="Mailpit's SMTP port.")

    @field_validator("mail_from_address")
    @classmethod
    def _address(cls, value: str) -> str:
        if not _ADDRESS.fullmatch(value):
            raise ValueError("must be a plain email address, such as no-reply@mail.example.com")
        return value

    @field_validator("mail_from_name")
    @classmethod
    def _display_name(cls, value: str) -> str:
        if not _DISPLAY_NAME.fullmatch(value):
            raise ValueError("must be 1 to 64 ASCII letters, digits, spaces, dots or dashes")
        return value

    @field_validator("web_app_url")
    @classmethod
    def _origin(cls, value: str) -> str:
        match = _WEB_APP_URL.fullmatch(value)
        if not match:
            raise ValueError("must be an origin with no path or trailing slash, like https://app.x")
        if match["scheme"] == "http" and match["host"] not in _LOCAL_HOSTS:
            raise ValueError("must use https, except for localhost")
        return value

    @model_validator(mode="after")
    def _ses_needs_a_configuration_set(self) -> Self:
        if self.mail_backend == "ses" and not self.ses_configuration_set:
            raise ValueError("MAIL_BACKEND=ses needs SES_CONFIGURATION_SET")
        return self


EXIT_BAD_SETTINGS = 2
"""The exit status of every entry point whose settings are wrong."""


def setting_errors(exc: ValidationError, cls: type[BaseSettings]) -> list[dict[str, str]]:
    """Which settings of `cls` are wrong and why, never their values: one may be a secret."""
    names = [name.upper() for name in cls.model_fields]
    errors = []
    for error in exc.errors(include_url=False, include_input=False):
        if error["loc"]:
            setting = ".".join(map(str, error["loc"])).upper()
        else:
            # A check across settings, such as the two ports differing, has no location; its
            # message names the settings it checks.
            named = [name for name in names if re.search(rf"\b{name}\b", error["msg"])]
            setting = ", ".join(named) or "(see error)"
        errors.append({"setting": setting, "error": error["msg"]})
    return errors


def load_settings[S: BaseSettings](cls: type[S]) -> S | None:
    """Read `cls` from the environment, or log which settings are wrong and return None.

    Every entry point starts with it, so each exits the same way on bad settings: status
    `EXIT_BAD_SETTINGS` and one log line that names the settings, never their values.
    """
    try:
        return cls()
    except ValidationError as exc:
        configure_logging("info")
        log.critical("invalid settings", extra={"errors": setting_errors(exc, cls)})
        return None
