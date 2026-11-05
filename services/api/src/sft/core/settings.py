"""Settings from environment variables only (architecture 8), typed and checked at startup.

Nothing is read from files: locally the shell or `compose.yaml` sets the variables, in Kubernetes
the pod spec does. A secret is a `SecretStr` field with no default, so a missing secret stops the
process at startup instead of running with a placeholder; a test fails if a secret field gets a
default. In the cloud, secrets come from AWS Secrets Manager, never from git.

Each entry point reads only the settings it needs: `Settings` for the API, `RelaySettings` for the
outbox relay (and `WorkerSettings`, its base, for the workers to come), `MigrationSettings` for the
migration job, `BootstrapSettings` for the database bootstrap job.
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


class Settings(_Traced):
    """The API's settings. The field name in capitals is the environment variable."""

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
