"""The probe's settings, from environment variables only (architecture 8), checked at startup.

The API key is the synthetic tenant's, from Secrets Manager through External Secrets in AWS
(`deploy/charts/sft/templates/probe.yaml`); it is a `SecretStr` with no default, so a pod without
it stops at startup. The local stand-ins (Mailpit, a part URL host rewrite, plain HTTP) are refused
outside `local` and `test`, so a values mistake can't point the probe at them in AWS.
"""

from __future__ import annotations

from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from sft.core.settings import LogLevel

ProbeEnvironment = Literal["local", "test", "dev", "staging", "prod"]
_LOCAL: frozenset[str] = frozenset({"local", "test"})


def _origin(value: str) -> str:
    """`scheme://host[:port]` with nothing after it."""
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("must be an http:// or https:// URL")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("must be an origin: a scheme and a host, no path")
    return f"{parts.scheme}://{parts.netloc}"


class ProbeSettings(BaseSettings):
    model_config = SettingsConfigDict(frozen=True)

    log_level: LogLevel = "info"
    environment: ProbeEnvironment = Field(
        description="The environment the probe measures: the CloudWatch metric's dimension."
    )
    aws_region: str = "ap-northeast-1"

    probe_api_url: str = Field(description="The public API's origin, https://api.<serviceDomain>.")
    probe_web_origin: str = Field(
        description="The web app's origin, https://app.<serviceDomain>: the Origin header a "
        "recipient's browser sends, and the origin the edge checks read."
    )
    probe_api_key: SecretStr = Field(description="The synthetic tenant's API key (FR-32).")

    probe_mailbox: Literal["s3", "mailpit"] = "s3"
    probe_mailbox_domain: str = Field(description="The probe mailbox's domain, probe.<domain>.")
    probe_mailbox_local_part: str = "probe"
    probe_mailbox_bucket: str | None = None
    probe_mailbox_prefix: str = "probe/"
    probe_mailpit_url: str | None = None
    s3_endpoint_url: str | None = None

    probe_part_url_host: str | None = Field(
        default=None,
        description="Local only: send part URLs to this origin instead of the one they name, as "
        "the journey test does when the stand-in's published port differs.",
    )
    probe_timeout_seconds: int = Field(default=240, ge=30, le=280)
    probe_file_bytes: int = Field(default=64 * 1024, ge=1024, le=5 * 1024 * 1024)

    probe_cloudwatch: bool = False
    probe_image_digest: str | None = Field(
        default=None,
        pattern=r"^sha256:[0-9a-f]{64}$",
        description="The image digest this environment runs: the promotion gate's dimension.",
    )
    metrics_pushgateway_url: str | None = None

    @field_validator(
        "probe_api_url", "probe_web_origin", "probe_mailpit_url", "probe_part_url_host"
    )
    @classmethod
    def _origins(cls, value: str | None) -> str | None:
        return None if value is None else _origin(value)

    @field_validator("probe_mailbox_domain")
    @classmethod
    def _domain(cls, value: str) -> str:
        value = value.strip().lower()
        if not value or "@" in value or any(c.isspace() for c in value):
            raise ValueError("must be a domain name")
        return value

    @field_validator("probe_mailbox_local_part")
    @classmethod
    def _local_part(cls, value: str) -> str:
        if not value.isalnum():
            raise ValueError("must be letters and digits: the run's tag follows a +")
        return value.lower()

    @model_validator(mode="after")
    def _where(self) -> Self:
        local = self.environment in _LOCAL
        if self.probe_mailbox == "s3" and not self.probe_mailbox_bucket:
            raise ValueError("PROBE_MAILBOX_BUCKET is required with PROBE_MAILBOX=s3")
        if self.probe_mailbox == "mailpit":
            if not local:
                raise ValueError("PROBE_MAILBOX=mailpit is for the local stack only")
            if not self.probe_mailpit_url:
                raise ValueError("PROBE_MAILPIT_URL is required with PROBE_MAILBOX=mailpit")
        if not local:
            if self.probe_part_url_host or self.s3_endpoint_url:
                raise ValueError(
                    "PROBE_PART_URL_HOST and S3_ENDPOINT_URL are for the local stack only"
                )
            for name, origin in (
                ("PROBE_API_URL", self.probe_api_url),
                ("PROBE_WEB_ORIGIN", self.probe_web_origin),
            ):
                if not origin.startswith("https://"):
                    raise ValueError(f"{name} must be https:// outside the local stack")
        return self
