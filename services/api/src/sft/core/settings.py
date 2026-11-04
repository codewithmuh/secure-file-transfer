"""Settings from environment variables only (architecture 8), typed and checked at startup.

Nothing is read from files: locally the shell or `compose.yaml` sets the variables, in Kubernetes
the pod spec does. A secret is a `SecretStr` field with no default, so a missing secret stops the
process at startup instead of running with a placeholder; a test fails if a secret field gets a
default. In the cloud, secrets come from AWS Secrets Manager, never from git.
"""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

LogLevel = Literal["debug", "info", "warning", "error", "critical"]


class Settings(BaseSettings):
    """Every setting the process reads. The field name in capitals is the environment variable."""

    model_config = SettingsConfigDict(frozen=True)

    app_version: str = Field(default="0.0.0", description="Set by the image build.")
    log_level: LogLevel = "info"
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

    @field_validator("log_level", mode="before")
    @classmethod
    def _lower_case_level(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value

    @model_validator(mode="after")
    def _ports_differ(self) -> Self:
        if self.public_port == self.internal_port:
            raise ValueError("PUBLIC_PORT and INTERNAL_PORT must differ")
        return self
