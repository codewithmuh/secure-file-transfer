"""Settings from environment variables only (architecture 8), typed and checked at startup.

Nothing is read from files: locally the shell or `compose.yaml` sets the variables, in Kubernetes
the pod spec does. A secret is a `SecretStr` field with no default, so a missing secret stops the
process at startup instead of running with a placeholder; a test fails if a secret field gets a
default. In the cloud, secrets come from AWS Secrets Manager, never from git.

Each entry point reads only the settings it needs: `Settings` for the API and `OperatorSettings`
for the operator API (both build on `ServerSettings`), `RelaySettings` for the outbox relay (and
`WorkerSettings`, its base, for the workers to come), `MigrationSettings` for the migration job,
`BootstrapSettings` for the database bootstrap job, `MailSettings` for whatever sends email (the
notification worker, whose `NotifySettings` adds it to a worker's), `InspectorSettings` for the
DLP inspector, `ScanSettings` for the scan workers, `JobSettings` for the lifecycle jobs and
`FieldKeySettings` for the field key job (#236).
`ClockSettings` (`ENVIRONMENT` and the clock's test hook) is part of the API's and the jobs'.

In AWS (#184) the database and Valkey URLs name a user and no password: with `DATABASE_IAM_AUTH`
and `VALKEY_IAM_CACHE` the process signs an IAM token for each new connection (`sft.data.iam_auth`).
A keyring setting may name its Secrets Manager secret, `secretsmanager:<id>`, instead of holding the
keyring (`sft.core.keyrings`), and `PUBLIC_TLS` turns on TLS on the API's public port
(`sft.runtime.tls`). Locally all three stay off: passwords in the URLs, keyrings in the environment,
plain HTTP.
"""

from __future__ import annotations

import logging
import re
from typing import Annotated, Literal, Self
from urllib.parse import parse_qs, urlsplit

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyNetwork,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from sft.core.hmac_keyrings import CODE_KEY_ID, LINK_KEY_ID
from sft.core.keyrings import CSRF_KEY_ID, EMAIL_KEY_ID, check_keyring_setting
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

# An S3 bucket name: 3 to 63 lower-case letters, digits, dots and hyphens.
_BUCKET = r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"

_VALKEY_SCHEMES = ("redis://", "rediss://", "valkey://", "valkeys://")


def _valkey_url(value: SecretStr) -> SecretStr:
    if not value.get_secret_value().startswith(_VALKEY_SCHEMES):
        raise ValueError("must start with redis://, rediss://, valkey:// or valkeys://")
    return value


# A Valkey URL with its credentials: locally the ACL user and its fake password; in AWS `rediss://`
# and the workload's user, whose IAM token is signed per connection (ADR-0014, VALKEY_IAM_CACHE).
ValkeyUrl = Annotated[SecretStr, AfterValidator(_valkey_url)]


def _iam_database(url: SecretStr, setting: str) -> None:
    """IAM database authentication: the URL names the login role and no password, and verifies
    the server's certificate, which IAM authentication needs (encryption and keys 2.2, 6.3)."""
    parts = urlsplit(url.get_secret_value())
    if not parts.username or parts.password is not None:
        raise ValueError(f"with DATABASE_IAM_AUTH, {setting} names its login role and no password")
    if parse_qs(parts.query).get("sslmode") != ["verify-full"]:
        raise ValueError(f"with DATABASE_IAM_AUTH, {setting} needs sslmode=verify-full")


def _iam_valkey(url: SecretStr) -> None:
    """IAM authentication to Valkey: TLS, and the workload's user with no password (ADR-0014)."""
    parts = urlsplit(url.get_secret_value())
    if parts.scheme not in ("rediss", "valkeys"):
        raise ValueError("VALKEY_IAM_CACHE needs a TLS VALKEY_URL: rediss:// or valkeys://")
    if not parts.username or parts.password:
        raise ValueError("with VALKEY_IAM_CACHE, VALKEY_URL names its user and no password")


# The audit archive's surviving-region mode (#257): the region left after a regional loss, which
# the failover runbook names in the chart (`auditArchive.survivingRegionOnly`). The API, the
# lifecycle jobs and the archive job then write that region's archive alone.
ArchiveRegion = Literal["ap-northeast-1", "ap-northeast-3"]
_SURVIVING_REGION = (
    "The region whose audit archive alone takes writes during a regional loss (#257): set by the "
    "failover runbook through the chart's `auditArchive.survivingRegionOnly`, cleared at "
    "failback, when the archive job back-fills the other. Unset: both regions."
)


def _surviving_region(region: str | None, osaka_bucket: str | None) -> None:
    # Only an environment with both regions can lose one; dev has Tokyo alone (architecture 3.3).
    if region is not None and osaka_bucket is None:
        raise ValueError(
            "AUDIT_ARCHIVE_SURVIVING_REGION needs AUDIT_ARCHIVE_OSAKA_BUCKET: only an environment "
            "with both regions' archive can lose one"
        )


_CACHE_NAME = r"^[a-z][a-z0-9-]{0,39}$"
# A keyring setting holds the keyring, or `secretsmanager:<id>` (sft.core.keyrings).
_KEYRING_SETTING = "a JSON list of keys with `id`, `state` and base64 `key`, or secretsmanager:<id>"


# Read when the settings load, so a bad keyring stops the process at startup; the message holds no
# key. A secret it names is read, and checked the same way, when the process starts. The API and
# the notification worker read the same two keyrings, so each rule is written once, here (#192).
def _email_keyring(value: SecretStr) -> SecretStr:
    check_keyring_setting(
        value.get_secret_value(), name="email", key_id=EMAIL_KEY_ID, needs_activation=True
    )
    return value


def _code_keyring(value: SecretStr) -> SecretStr:
    check_keyring_setting(value.get_secret_value(), name="code", key_id=CODE_KEY_ID)
    return value


EmailKeyringSetting = Annotated[SecretStr, AfterValidator(_email_keyring)]
CodeKeyringSetting = Annotated[SecretStr, AfterValidator(_code_keyring)]


# The fields key (#236, encryption and keys 3.2, 4.1): its alias or ARN, or `local` for the
# in-process stand-in of the local stack and the tests (`sft.runtime.kms.LocalKms`).
_FIELDS_KEY = (
    r"^(local|alias/[A-Za-z0-9/_-]{1,250}|mrk-[0-9a-f]{32}|"
    r"arn:aws:kms:[a-z0-9-]+:[0-9]{12}:(key/mrk-[0-9a-f]{32}|alias/[A-Za-z0-9/_-]{1,250}))$"
)
_FIELDS_KEY_DESCRIPTION = (
    "The fields key that wraps the tenants' data keys (encryption and keys 3.2): its alias, "
    "`alias/sft/<env>/fields`, or ARN; `local` for the in-process stand-in of the local stack "
    "and the tests, which the chart never sets (deploy/tests) and which warns at startup "
    "outside ENVIRONMENT=local or test."
)


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

    # AWS (#184): TLS on the public port, and IAM tokens for the database and Valkey.
    public_tls: Literal["off", "generated", "files"] = Field(
        default="off",
        description="TLS on PUBLIC_PORT (encryption and keys 2.2). `generated`: the process makes "
        "an ECDSA P-256 certificate at start, which the load balancer accepts without checking. "
        "`files`: PUBLIC_TLS_CERT_FILE and PUBLIC_TLS_KEY_FILE, such as an issuer's certificate. "
        "`off` only locally. The internal port is always plain HTTP.",
    )
    public_tls_cert_file: str | None = Field(default=None, min_length=1)
    public_tls_key_file: str | None = Field(default=None, min_length=1)
    database_iam_auth: bool = Field(
        default=False,
        description="Sign an IAM token for each new database connection, as DATABASE_URL's role "
        "(encryption and keys 6.3). Off locally, where the URL holds a password.",
    )
    valkey_iam_cache: str | None = Field(
        default=None,
        pattern=_CACHE_NAME,
        description="The serverless cache's name, sft-<env>-<region-short>-valkey: set, each new "
        "Valkey connection signs an IAM token for VALKEY_URL's user (ADR-0014). Unset locally.",
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

    @model_validator(mode="after")
    def _tls_files_with_files(self) -> Self:
        named = (self.public_tls_cert_file, self.public_tls_key_file)
        if self.public_tls == "files" and None in named:
            raise ValueError("PUBLIC_TLS=files needs PUBLIC_TLS_CERT_FILE and PUBLIC_TLS_KEY_FILE")
        if self.public_tls != "files" and named != (None, None):
            raise ValueError("PUBLIC_TLS_CERT_FILE and PUBLIC_TLS_KEY_FILE need PUBLIC_TLS=files")
        return self

    @model_validator(mode="after")
    def _iam_urls(self) -> Self:
        if self.database_iam_auth:
            _iam_database(self.database_url, "DATABASE_URL")
        if self.valkey_iam_cache is not None:
            _iam_valkey(self.valkey_url)
        return self


Environment = Literal["local", "test", "dev", "staging", "prod"]
_HOOK_ENVIRONMENTS = ("local", "test")


class ClockSettings(_Base):
    """Which environment this is, and the test hook on the clock (#182, `sft.core.clock`).

    `ENVIRONMENT` is #129's: local for the compose stack, test for the test suite, and the
    environment's name in AWS. Unset, it is `prod`, the strictest: a pod spec that forgets it never
    gets a test hook. `CLOCK_OFFSET_SECONDS` moves what the API and the lifecycle jobs read as
    "now"; the process refuses to start with it set anywhere but local or test.
    """

    environment: Environment = Field(
        default="prod",
        description="local (the compose stack), test (the test suite), or dev, staging or prod. "
        "Unset is prod.",
    )
    clock_offset_seconds: int = Field(
        default=0,
        ge=-366 * 86400,
        le=366 * 86400,
        description="A test hook: seconds added to now. Only ENVIRONMENT=local or test may set it.",
    )

    @model_validator(mode="after")
    def _clock_hook_only_in_tests(self) -> Self:
        if self.clock_offset_seconds and self.environment not in _HOOK_ENVIRONMENTS:
            raise ValueError(
                "CLOCK_OFFSET_SECONDS is a test hook: only ENVIRONMENT=local or test may set it"
            )
        return self


# An origin (scheme, host and port, no path) and an http(s) URL, for the sign-in settings.
_ORIGIN = r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?$"
_HTTP_URL = r"^https?://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s?#]*)?(\?[^\s#]*)?$"


class Settings(ServerSettings, ClockSettings):
    """The public API's settings: the server's, member sign-in's (ADR-0016; authentication and
    authorization 2.4 and 3) and the files buckets' (#114). Locally Keycloak stands in for the
    Cognito user pool and S3Mock for S3 (docs/local-development.md)."""

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
        f"encryption and keys 6.5): {_KEYRING_SETTING}, read again every 5 minutes.",
    )
    email_hmac_keyring: EmailKeyringSetting = Field(
        description="The keyring of email pseudonyms (sft/{env}/app/email-hmac, encryption and "
        "keys 6.2): what per-address rate limits count under, so the counters never hold an "
        "address. Like CSRF_KEYRING, with `activated_at` on the active key.",
    )
    admin_passkey_rule: bool = Field(
        default=False,
        description="The launch switch of ADR-0016: a local admin acts as an admin only in a "
        "session signed in with a passkey. Off until both pools issue `amr`.",
    )
    # Object storage for file uploads (#114, ADR-0012): the region's two files buckets and the
    # files key. Required, so a deploy without them stops at startup instead of failing uploads.
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    s3_files_bucket: str = Field(
        pattern=_BUCKET,
        description="The files bucket for files up to 2 GB, e.g. `sft-dev-files`.",
    )
    s3_large_files_bucket: str = Field(
        pattern=_BUCKET,
        description="The files bucket for files over 2 GB, which GuardDuty scans (ADR-0019).",
    )
    s3_files_kms_key_id: str = Field(
        min_length=1,
        max_length=2048,
        description="The files key for SSE-KMS. S3Mock takes only its bare key ID (local dev 4).",
    )
    s3_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only, for S3Mock. In AWS the SDK finds S3's endpoint itself.",
    )
    tenant_storage_quota_bytes: int = Field(
        default=2 * 10**12,
        ge=1,
        description="Each tenant's storage quota, the same for every tenant (abuse 6.1): 2 TB.",
    )
    scan_small_pool_max_bytes: int = Field(
        default=100_000_000,
        ge=1,
        le=2_000_000_000,
        description="The largest file the small scan pool takes; larger ones, up to 2 GB, go to "
        "the large pool (ADR-0019's 100 MB split).",
    )

    # The audit archive in both regions (#177, architecture 5.2): security-critical records are
    # written straight to each region's bucket before the API answers 2xx (data model 2.5).
    audit_archive_tokyo_bucket: str = Field(
        pattern=_BUCKET,
        description="The audit archive bucket in Tokyo, `sft-<env>-apne1-audit-archive-<account>`.",
    )
    audit_archive_osaka_bucket: str | None = Field(
        default=None,
        pattern=_BUCKET,
        description="The audit archive bucket in Osaka. Unset only in an environment without "
        "Osaka (dev, architecture 3.3): records then go to Tokyo's archive alone.",
    )
    audit_archive_tokyo_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only, for S3Mock. In AWS the SDK finds Tokyo's S3 endpoint itself.",
    )
    audit_archive_osaka_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only, for S3Mock's Osaka stand-in. In AWS the SDK finds Osaka's "
        "endpoint, through the cross-region S3 endpoint (ADR-0021).",
    )
    # Verification codes (#179, data model 2.4): the API checks what the notification worker made.
    code_hmac_keyring: CodeKeyringSetting = Field(
        description="K_code, the keyring of verification codes' HMACs (sft/{env}/app/code-hmac, "
        "encryption and keys 6.2): like CSRF_KEYRING.",
    )

    # Downloads (#180, abuse and rate limits 5): the stream's re-check and the pod's stream cap.
    download_recheck_seconds: float = Field(
        default=30.0,
        gt=0,
        le=30,
        description="How often a running download re-checks its grant, session, transfer and "
        "file, records the bytes it sent and renews its lease (abuse 5.4). 30 s meets NFR-6's 60.",
    )
    download_streams_per_pod: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Streams one API pod serves at once; the next gets 503, Retry-After: 10 "
        "(abuse 5.7).",
    )
    # Part URLs a browser can reach (#195): locally the API calls S3Mock in-network (`s3:9090`),
    # but the browser uploads parts from the host, where the stand-in is `localhost:9090`.
    s3_presign_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only: the S3 stand-in's address as the browser sees it, used only to "
        "sign part URLs; every other S3 call keeps S3_ENDPOINT_URL. Needs S3_ENDPOINT_URL. In AWS "
        "neither is set and S3 signs its own host.",
    )
    # Tenant API keys (#215, authn and authz 5.1): the environment in every key this API makes
    # and takes. Required everywhere but the test suite, so a deploy can't make keys of the wrong
    # environment; the local stack uses `dev` (a local key's hash exists only in its database).
    api_key_environment: Literal["dev", "stg", "prd"] | None = Field(
        default=None,
        description="dev, stg or prd: the `sft_<env>_` of API keys. Required unless "
        "ENVIRONMENT=test.",
    )
    # Tenant SSO (#231, authn and authz 2.4, 2.5): how the pool is told which provider to use, where
    # the identity provider's groups arrive, and the local stand-in for DNS when a domain is proven.
    oidc_idp_hint_parameter: Literal["identity_provider", "kc_idp_hint"] = Field(
        default="identity_provider",
        description="The authorization request's parameter that names the provider: Cognito's "
        "`identity_provider`, or Keycloak's `kc_idp_hint` for the local stand-in.",
    )
    oidc_groups_claim: str = Field(
        default="custom:sso_groups",
        min_length=1,
        max_length=128,
        description="The ID token claim with the identity provider's groups, mapped by the pool "
        "(user pool attribute `custom:sso_groups`): a list, or Cognito's `[a,b]` string.",
    )
    sso_dns_overrides: str | None = Field(
        default=None,
        max_length=65536,
        description="A test hook: JSON object of TXT record name to its values, used instead of "
        "DNS to prove SSO domains. Only ENVIRONMENT=local or test may set it.",
    )
    sso_dns_nameservers: str | None = Field(
        default=None,
        max_length=1024,
        pattern=r"^[0-9a-fA-F.:]+(,[0-9a-fA-F.:]+)*$",
        description="Comma-separated resolver addresses for proving SSO domains; by default the "
        "system's (in AWS, the VPC resolver).",
    )

    @model_validator(mode="after")
    def _dns_overrides_only_in_tests(self) -> Self:
        if self.sso_dns_overrides is not None and self.environment not in _HOOK_ENVIRONMENTS:
            raise ValueError(
                "SSO_DNS_OVERRIDES is a test hook: only ENVIRONMENT=local or test may set it"
            )
        return self

    # Field encryption (#236, #233): the fields key the tenants' data keys are wrapped under.
    fields_kms_key_id: str = Field(pattern=_FIELDS_KEY, description=_FIELDS_KEY_DESCRIPTION)

    @model_validator(mode="after")
    def _api_keys_need_their_environment(self) -> Self:
        if self.api_key_environment is None and self.environment != "test":
            raise ValueError("api_key_environment (API_KEY_ENVIRONMENT) is required: dev, stg, prd")
        return self

    @model_validator(mode="after")
    def _presign_endpoint_needs_the_stand_in(self) -> Self:
        if self.s3_presign_endpoint_url is not None and self.s3_endpoint_url is None:
            raise ValueError(
                "S3_PRESIGN_ENDPOINT_URL is for the local S3 stand-in only: set S3_ENDPOINT_URL too"
            )
        return self

    @field_validator("csrf_keyring")
    @classmethod
    def _csrf_keyring(cls, value: SecretStr) -> SecretStr:
        # Read here, so a bad keyring stops the process at startup; the message holds no key. A
        # secret it names is read, and checked the same way, when the process starts.
        check_keyring_setting(value.get_secret_value(), name="CSRF", key_id=CSRF_KEY_ID)
        return value

    @model_validator(mode="after")
    def _trusted_proxies_behind_the_load_balancer(self) -> Self:
        # #129: behind the load balancer with no trusted proxy, every client's address would be
        # the load balancer's, so per-IP limits and the failed-authentication block would apply
        # to everyone at once. Only the compose stack and the test suite have no load balancer.
        if not self.trusted_proxies and self.environment not in _HOOK_ENVIRONMENTS:
            raise ValueError(
                "TRUSTED_PROXIES is required unless ENVIRONMENT=local or test: the load "
                "balancer's subnets, so per-IP limits count clients, not the load balancer"
            )
        return self

    audit_archive_surviving_region: ArchiveRegion | None = Field(
        default=None, description=_SURVIVING_REGION
    )

    @model_validator(mode="after")
    def _surviving_archive_region(self) -> Self:
        _surviving_region(self.audit_archive_surviving_region, self.audit_archive_osaka_bucket)
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
    database_iam_auth: bool = Field(
        default=False,
        description="Sign an IAM token for each new database connection (encryption and keys "
        "6.3), as the API's setting of the same name. Off locally.",
    )

    @model_validator(mode="after")
    def _iam_database_url(self) -> Self:
        if self.database_iam_auth:
            _iam_database(self.database_url, "DATABASE_URL")
        return self


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


class ScanSettings(WorkerSettings):
    """The scan worker's settings (ADR-0019, ADR-0022, #175, #176): its pool, the engines beside
    it, the files buckets it reads, and the counter store that holds its tenants' scan leases."""

    scan_pool: Literal["small", "large"] = Field(
        description="Which pool this worker is: `small` reads the scan-small queue, files up to "
        "100 MB; `large` reads scan-large, files up to 2 GB. Required.",
    )
    valkey_url: ValkeyUrl | None = Field(
        default=None,
        description="The counter store, for the per-tenant scan caps (ADR-0014). Unset or "
        "unreachable, the caps are skipped and the fair queue alone applies (ADR-0019).",
    )
    s3_files_bucket: str = Field(
        pattern=_BUCKET, description="The files bucket for files up to 2 GB."
    )
    s3_large_files_bucket: str = Field(
        pattern=_BUCKET, description="The files bucket for files over 2 GB, for their tags."
    )
    s3_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only, for S3Mock. In AWS the SDK finds S3's endpoint itself.",
    )
    clamd_host: str = Field(
        default="clamd",
        min_length=1,
        description="clamd beside this worker: the node-local `clamd` Service in EKS.",
    )
    clamd_port: int = Field(default=3310, ge=1, le=65535)
    clamd_connect_timeout_seconds: float = Field(
        default=5.0,
        gt=0,
        le=60,
        description="How long to wait for clamd's connection. The scan itself has a timeout "
        "that grows with the file's size (sft.service.scan_timing).",
    )
    inspector_host: str = Field(
        default="dlp-inspector",
        min_length=1,
        description="The DLP inspector beside this worker: the node-local `dlp-inspector` Service.",
    )
    inspector_port: int = Field(default=8070, ge=1, le=65535)
    scan_small_tenant_cap: int = Field(
        default=4,
        ge=1,
        le=100,
        description="Small-file scans one tenant may run at once (ADR-0019).",
    )
    scan_large_pool_size: int = Field(
        default=2,
        ge=1,
        le=100,
        description="The large pool's workers: one tenant runs at most one fewer at once, and "
        "at least one (ADR-0019).",
    )

    valkey_iam_cache: str | None = Field(
        default=None,
        pattern=_CACHE_NAME,
        description="The serverless cache's name, for IAM tokens, as the API's setting.",
    )

    # DLP data keys (#233, encryption and keys 3.3): the worker unwraps `dlp-dek` keys only.
    fields_kms_key_id: str = Field(pattern=_FIELDS_KEY, description=_FIELDS_KEY_DESCRIPTION)

    @model_validator(mode="after")
    def _iam_valkey_url(self) -> Self:
        if self.valkey_iam_cache is not None:
            if self.valkey_url is None:
                raise ValueError("VALKEY_IAM_CACHE needs VALKEY_URL")
            _iam_valkey(self.valkey_url)
        return self

    @property
    def tenant_cap(self) -> int:
        if self.scan_pool == "small":
            return self.scan_small_tenant_cap
        return max(1, self.scan_large_pool_size - 1)


class JobSettings(ClockSettings):
    """The lifecycle jobs' settings (#181; architecture 4.5, data model 6): their database role,
    the files buckets they delete from, both regions' audit archive (reconciliation rewrites a
    grant's committed record), and where they push their metrics. Each job is a one-shot command."""

    app_version: str = Field(default="0.0.0", description="Set by the image build.")
    database_url: PostgresUrl = Field(
        description="The `sft_jobs` login role, never the migration role or the master user.",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    s3_files_bucket: str = Field(pattern=_BUCKET, description="The files bucket, up to 2 GB.")
    s3_large_files_bucket: str = Field(
        pattern=_BUCKET, description="The files bucket for files over 2 GB."
    )
    s3_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only, for S3Mock. In AWS the SDK finds S3's endpoint itself.",
    )
    s3_replica_region: str | None = Field(
        default=None,
        pattern=r"^[a-z]{2}(-[a-z]+)+-\d$",
        description="The region of the files buckets' replicas, Osaka's in staging and prod. "
        "Unset where there are none: dev and the local stack (architecture 3.3).",
    )
    s3_replica_files_bucket: str | None = Field(default=None, pattern=_BUCKET)
    s3_replica_large_files_bucket: str | None = Field(default=None, pattern=_BUCKET)
    audit_archive_tokyo_bucket: str = Field(
        pattern=_BUCKET, description="The audit archive bucket in Tokyo, as the API's."
    )
    audit_archive_osaka_bucket: str | None = Field(
        default=None, pattern=_BUCKET, description="The audit archive bucket in Osaka."
    )
    audit_archive_tokyo_endpoint_url: str | None = Field(
        default=None, pattern=r"^https?://[^\s/]+(:\d+)?/?$", description="Local only."
    )
    audit_archive_osaka_endpoint_url: str | None = Field(
        default=None, pattern=r"^https?://[^\s/]+(:\d+)?/?$", description="Local only."
    )
    scan_small_pool_max_bytes: int = Field(
        default=100_000_000,
        ge=1,
        le=2_000_000_000,
        description="ADR-0019's split between the scan pools, as the API's setting of the same "
        "name: reconciliation routes a completion it finishes by it. Keep the two equal.",
    )
    metrics_pushgateway_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Where a run pushes its metrics, a one-shot job having no port to scrape. "
        "Unset: the run logs them only (the local stack; M7 adds the gateway).",
    )
    database_iam_auth: bool = Field(
        default=False,
        description="Sign an IAM token for each new database connection (encryption and keys "
        "6.3). Off locally.",
    )

    @model_validator(mode="after")
    def _iam_database_url(self) -> Self:
        if self.database_iam_auth:
            _iam_database(self.database_url, "DATABASE_URL")
        return self

    @model_validator(mode="after")
    def _replicas_together(self) -> Self:
        named = (self.s3_replica_files_bucket, self.s3_replica_large_files_bucket)
        if (self.s3_replica_region is None) != all(b is None for b in named) or (
            self.s3_replica_region is not None and None in named
        ):
            raise ValueError(
                "set S3_REPLICA_REGION, S3_REPLICA_FILES_BUCKET and S3_REPLICA_LARGE_FILES_BUCKET "
                "together, or none of them"
            )
        return self

    audit_archive_surviving_region: ArchiveRegion | None = Field(
        default=None, description=_SURVIVING_REGION
    )

    @model_validator(mode="after")
    def _surviving_archive_region(self) -> Self:
        _surviving_region(self.audit_archive_surviving_region, self.audit_archive_osaka_bucket)
        return self


class ArchiveJobSettings(_Base):
    """The audit archive job's settings (#183; architecture 5.2, data model 2.5): its database
    role, both regions' archive buckets, and where it pushes its metrics. A one-shot command, run
    every minute."""

    app_version: str = Field(default="0.0.0", description="Set by the image build.")
    database_url: PostgresUrl = Field(
        description="The `sft_archive` login role: it reads audit events and moves the archive "
        "cursor, nothing else.",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    audit_archive_tokyo_bucket: str = Field(
        pattern=_BUCKET, description="The audit archive bucket in Tokyo."
    )
    audit_archive_osaka_bucket: str | None = Field(
        default=None,
        pattern=_BUCKET,
        description="The audit archive bucket in Osaka. Unset in dev, which has no Osaka.",
    )
    audit_archive_tokyo_endpoint_url: str | None = Field(
        default=None, pattern=r"^https?://[^\s/]+(:\d+)?/?$", description="Local only."
    )
    audit_archive_osaka_endpoint_url: str | None = Field(
        default=None, pattern=r"^https?://[^\s/]+(:\d+)?/?$", description="Local only."
    )
    metrics_pushgateway_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Where a run pushes its metrics, a one-shot job having no port to scrape. "
        "Unset: the run logs them only (the local stack).",
    )
    database_iam_auth: bool = Field(
        default=False,
        description="Sign an IAM token for each new database connection (encryption and keys "
        "6.3). Off locally.",
    )

    @model_validator(mode="after")
    def _iam_database_url(self) -> Self:
        if self.database_iam_auth:
            _iam_database(self.database_url, "DATABASE_URL")
        return self

    audit_archive_surviving_region: ArchiveRegion | None = Field(
        default=None, description=_SURVIVING_REGION
    )

    @model_validator(mode="after")
    def _surviving_archive_region(self) -> Self:
        _surviving_region(self.audit_archive_surviving_region, self.audit_archive_osaka_bucket)
        return self


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
    # Break-glass in the service (#232, authn and authz 8.3): a second operator approves, unless
    # the environment has one maintainer, where self-approval is allowed, marked and alerted.
    break_glass_self_approval: bool = Field(
        default=False,
        description="Lets the requester approve their own break-glass request, marked "
        "`self_approved` and alerted (threat model R-08). For a single-maintainer run only.",
    )
    break_glass_sweep_seconds: float = Field(
        default=30.0,
        gt=0,
        le=60,
        description="How often the operator API records expired and lapsed break-glass requests "
        "and refreshes the break-glass metrics.",
    )
    # Break-glass records (#239, authn and authz 8.3): the reconciliation job reads the Identity
    # Center assignments from the management account's CloudTrail through a read-only role there.
    # Without the role it doesn't run (dev and the local stack).
    break_glass_trail_role_arn: str | None = Field(
        default=None,
        pattern=r"^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$",
        description="The management account's role the reconciliation job assumes to read "
        "CloudTrail and the identity store. Empty: no reconciliation.",
    )
    break_glass_permission_set_arn: str | None = Field(
        default=None,
        pattern=r"^arn:aws:sso:::permissionSet/ssoins-[0-9a-f]{16}/ps-[0-9a-f]{16}$",
        description="The `BreakGlass` permission set, whose assignments to this account count.",
    )
    identity_store_id: str | None = Field(
        default=None,
        pattern=r"^d-[0-9a-f]{10}$",
        description="Identity Center's identity store, for the requester's user name.",
    )
    identity_center_region: str = Field(
        default="ap-northeast-1",
        pattern=r"^[a-z]{2}(-[a-z]+)+-\d$",
        description="Identity Center's home Region (ADR-0006), where its CloudTrail events are.",
    )
    break_glass_reconcile_seconds: float = Field(
        default=900.0,
        gt=0,
        le=3600,
        description="How often the reconciliation job records missing break-glass grants.",
    )
    # The daily SSO drift check (#239, authn and authz 2.5): each tenant's recorded provider
    # against both user pools. Without pools it doesn't run (the local stack).
    sso_drift_pools: list[IdpClient] = Field(
        default_factory=list,
        description="JSON: each user pool and its app client, Tokyo's and in staging and prod "
        "Osaka's, as [{region, user_pool_id, client_id}]. Empty: no drift check.",
    )
    sso_drift_check_seconds: float = Field(
        default=86400.0,
        gt=0,
        le=86400,
        description="How often the operator API compares the tenants' SSO providers with the "
        "pools.",
    )
    # The audit archive (#239): `recoverTenantAdmin` is a security-critical record, in both
    # regions' archive before the `202`, as the public API's are (architecture 5.2).
    audit_archive_tokyo_bucket: str | None = Field(
        default=None,
        pattern=_BUCKET,
        description="The audit archive bucket in Tokyo. Unset: `recoverTenantAdmin` takes effect "
        "and answers 503, since its record can't reach the archive.",
    )
    audit_archive_osaka_bucket: str | None = Field(
        default=None,
        pattern=_BUCKET,
        description="The audit archive bucket in Osaka. Unset only in an environment without "
        "Osaka (dev).",
    )
    audit_archive_tokyo_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only, for S3Mock.",
    )
    audit_archive_osaka_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Local only, for S3Mock's Osaka stand-in.",
    )
    # During a regional loss the operator's records go to the surviving region alone, as the
    # public API's do (#257), so `recoverTenantAdmin` works in Osaka with Tokyo lost.
    audit_archive_surviving_region: ArchiveRegion | None = Field(
        default=None, description=_SURVIVING_REGION
    )

    @model_validator(mode="after")
    def _surviving_archive_region(self) -> Self:
        _surviving_region(self.audit_archive_surviving_region, self.audit_archive_osaka_bucket)
        return self

    @model_validator(mode="after")
    def _the_trail_names_its_parts(self) -> Self:
        parts = (
            self.break_glass_trail_role_arn,
            self.break_glass_permission_set_arn,
            self.identity_store_id,
        )
        if any(parts) and not all(parts):
            raise ValueError(
                "BREAK_GLASS_TRAIL_ROLE_ARN, BREAK_GLASS_PERMISSION_SET_ARN and IDENTITY_STORE_ID "
                "go together"
            )
        return self

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
    database_iam_auth: bool = Field(
        default=False,
        description="Sign an IAM token for the connection as `sft_migrate` (encryption and keys "
        "6.3). Off locally.",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")

    @model_validator(mode="after")
    def _iam_database_url(self) -> Self:
        if self.database_iam_auth:
            _iam_database(self.migration_database_url, "MIGRATION_DATABASE_URL")
        return self


class BootstrapSettings(_Base):
    """The database bootstrap job's settings: it creates the roles, once per environment."""

    bootstrap_database_url: PostgresUrl = Field(
        description="The master user (in AWS) or a local superuser; never used by a workload.",
    )
    bootstrap_iam_auth: bool = Field(
        description="True on Aurora: the login roles sign in with IAM database authentication. "
        "False locally, where they get passwords some other way. No default: choose.",
    )
    # In AWS (#278): the master password is read from Secrets Manager by the job's own role, never
    # handed to it through a Kubernetes Secret (encryption and keys 6.3).
    bootstrap_master_secret: str | None = Field(
        default=None,
        pattern=r"^secretsmanager:[A-Za-z0-9/_+=.@-]{1,512}$",
        description="`secretsmanager:<id>` of the master user's secret (`sft/<env>/db/master`, "
        "JSON with `username` and `password`): the job reads the password once, in `AWS_REGION`, "
        "and `BOOTSTRAP_DATABASE_URL` names the user and no password. Unset locally.",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")

    @model_validator(mode="after")
    def _master_secret_alone(self) -> Self:
        parts = urlsplit(self.bootstrap_database_url.get_secret_value())
        if self.bootstrap_master_secret is not None and (
            not parts.username or parts.password is not None
        ):
            raise ValueError(
                "with BOOTSTRAP_MASTER_SECRET, BOOTSTRAP_DATABASE_URL names the master user and "
                "no password"
            )
        return self


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


class NotifySettings(WorkerSettings, MailSettings):
    """The notification worker's settings (#178, #179; ADR-0013, ADR-0015): a worker's, how it
    sends email, its three keyrings and the counter store that holds the cross-tenant cap."""

    valkey_url: ValkeyUrl = Field(
        description="The counter store, for the 100 link emails a day to one address across "
        "tenants (abuse 7.2). Unreachable, the cap counts in this pod (abuse 4.5).",
    )
    email_hmac_keyring: EmailKeyringSetting = Field(
        description="The email-hmac keyring (sft/{env}/app/email-hmac): the suppression list's "
        "pseudonyms and the cap's key, like the API's.",
    )
    link_hmac_keyring: SecretStr = Field(
        description="K_link (sft/{env}/app/link-hmac, data model 2.2), which only this worker "
        "reads: it derives each link token. Keep an old key loaded at least 14 days.",
    )
    code_hmac_keyring: CodeKeyringSetting = Field(
        description="K_code (sft/{env}/app/code-hmac, data model 2.4): the HMAC of each new "
        "verification code.",
    )

    # The user pool's admin side (#197, #193; authn and authz 2.5): the worker creates an invited
    # member's pool user and records the identity. Cognito's admin API in AWS; locally Keycloak's
    # stands in for it; without a pool (`none`) invitations are recorded, nothing sent.
    user_pool_backend: Literal["none", "keycloak", "cognito"] = Field(
        default="none",
        description="`cognito` in AWS, `keycloak` in the local stack; `none` sends no invitation.",
    )
    user_pool_provider_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="The pool's `idp_connections.provider_name` (the API's OIDC_PROVIDER_NAME), "
        "whose connection each recorded identity names.",
    )
    keycloak_url: str | None = Field(
        default=None,
        pattern=_HTTP_URL,
        description="Keycloak's in-network address, such as http://oidc:8080. Local only.",
    )
    keycloak_realm: str | None = Field(
        default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$"
    )
    keycloak_client_id: str | None = Field(
        default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._-]+$"
    )
    keycloak_client_secret: SecretStr | None = Field(
        default=None,
        description="The client whose service account may manage the realm's users. Local only.",
    )
    cognito_user_pool_id: str | None = Field(
        default=None,
        pattern=r"^[a-z]{2}(-[a-z]+)+-\d_[0-9A-Za-z]+$",
        description="This region's user pool (`ap-northeast-1_…`), for `cognito`; the pool's "
        "provider name is the same ID, as the API's OIDC_PROVIDER_NAME is.",
    )

    @model_validator(mode="after")
    def _a_pool_names_its_parts(self) -> Self:
        if self.user_pool_backend == "cognito":
            missing = [
                name
                for name in ("user_pool_provider_name", "cognito_user_pool_id")
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(f"USER_POOL_BACKEND=cognito needs {', '.join(missing).upper()}")
            if self.user_pool_provider_name != self.cognito_user_pool_id:
                raise ValueError("USER_POOL_PROVIDER_NAME must be COGNITO_USER_POOL_ID for cognito")
        if self.user_pool_backend == "keycloak":
            missing = [
                name
                for name in (
                    "user_pool_provider_name",
                    "keycloak_url",
                    "keycloak_realm",
                    "keycloak_client_id",
                    "keycloak_client_secret",
                )
                if getattr(self, name) is None
            ]
            if missing:
                raise ValueError(f"USER_POOL_BACKEND=keycloak needs {', '.join(missing).upper()}")
        return self

    @field_validator("link_hmac_keyring")
    @classmethod
    def _link_hmac_keyring(cls, value: SecretStr) -> SecretStr:
        check_keyring_setting(value.get_secret_value(), name="link", key_id=LINK_KEY_ID)
        return value

    valkey_iam_cache: str | None = Field(
        default=None,
        pattern=_CACHE_NAME,
        description="The serverless cache's name, for IAM tokens, as the API's setting.",
    )

    @model_validator(mode="after")
    def _iam_valkey_url(self) -> Self:
        if self.valkey_iam_cache is not None:
            _iam_valkey(self.valkey_url)
        return self


class InspectorSettings(_Base):
    """The DLP inspector's settings (ADR-0022). It has no secrets: it holds no credentials."""

    # 127.0.0.1 keeps a laptop run off the network; the pod sets BIND_HOST=0.0.0.0, and its
    # network policy admits only the scan workers.
    bind_host: str = "127.0.0.1"
    inspector_port: int = Field(
        default=8070,
        ge=1,
        le=65535,
        description="Where scan workers connect; one file per connection (sft.dlp.protocol).",
    )
    inspector_scratch_dir: str = Field(
        min_length=1,
        description="The 4 GiB scratch volume, the only writable path. No default: choose.",
    )
    inspector_io_timeout_seconds: int = Field(
        default=60,
        ge=1,
        le=900,
        description="How long a scan worker may leave the connection idle before it is dropped.",
    )
    internal_port: int = Field(
        default=8001,
        ge=1,
        le=65535,
        description="`/healthz` and `/readyz` for the kubelet, plain HTTP on their own port, so a "
        "probe never reaches the framed protocol (#184).",
    )

    @model_validator(mode="after")
    def _ports_differ(self) -> Self:
        if self.inspector_port == self.internal_port:
            raise ValueError("INSPECTOR_PORT and INTERNAL_PORT must differ")
        return self


class IdpClient(BaseModel):
    """One user pool's app client, whose secret the key rotation job rotates (encryption 6.4)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    region: Literal["ap-northeast-1", "ap-northeast-3"]
    user_pool_id: str = Field(pattern=r"^ap-northeast-[13]_[0-9A-Za-z]+$")
    client_id: str = Field(pattern=r"^[0-9a-z]{1,128}$")

    @model_validator(mode="after")
    def _pool_in_its_region(self) -> Self:
        if not self.user_pool_id.startswith(f"{self.region}_"):
            raise ValueError("a user pool ID starts with its region")
        return self


# The operator API's SSO drift pools (#239) are `IdpClient`s, defined after its settings.
OperatorSettings.model_rebuild()


class KeyRotationSettings(_Base):
    """The key rotation job's settings (encryption and keys 6.4, 6.5; #185). It runs in Tokyo only,
    on a schedule, and reaches Osaka's idp-client through the Osaka endpoint. It holds no secret
    of its own: its role writes the secrets, and its Kubernetes token may only restart the
    workloads that load them."""

    environment: Literal["dev", "staging", "prod"]
    aws_region: Literal["ap-northeast-1"] = Field(
        default="ap-northeast-1",
        description="Tokyo: the keyrings' primary region, which replicates them to Osaka.",
    )
    idp_clients: list[IdpClient] = Field(
        default_factory=list,
        description="JSON: each user pool's app client, Tokyo's and in staging and prod "
        "Osaka's, as [{region, user_pool_id, client_id}].",
    )
    restart_deployments: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["api"],
        description="Comma-separated: the Deployments that read the user pool client from "
        "External Secrets at start, restarted after a new client secret. Empty: nothing is "
        "restarted (the local stack).",
    )
    external_secrets: Annotated[list[str], NoDecode] = Field(
        default_factory=lambda: ["api-secrets"],
        description="Comma-separated: the ExternalSecrets synced again before the restart.",
    )
    kubernetes_namespace: str = Field(default="sft", pattern=r"^[a-z0-9-]{1,63}$")
    kubernetes_url: str = Field(
        default="https://kubernetes.default.svc", pattern=r"^https://[^\s/]+(:\d+)?$"
    )
    kubernetes_token_path: str = Field(
        default="/var/run/secrets/tokens/kubernetes/token",
        description="The projected service account token, for its own audience and 10 minutes.",
    )
    kubernetes_ca_path: str = Field(
        default="/var/run/secrets/tokens/kubernetes/ca.crt",
        description="The cluster's CA bundle, projected with the token.",
    )

    @field_validator("restart_deployments", "external_secrets", mode="before")
    @classmethod
    def _comma_separated(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value


class FieldKeySettings(ClockSettings):
    """The field key job's settings (#236; encryption and keys 3.2, 7.2): it runs as the API's
    workload, the only one that may unwrap field data keys, so it has the API's database role and
    the fields key; nothing else."""

    database_url: PostgresUrl = Field(
        description="The API's login role, `sft_api`: the field key job acts as the API.",
    )
    database_iam_auth: bool = Field(
        default=False,
        description="Sign an IAM token for each new database connection, as the API does.",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    fields_kms_key_id: str = Field(pattern=_FIELDS_KEY, description=_FIELDS_KEY_DESCRIPTION)
    field_key_batch_size: int = Field(
        default=200,
        ge=1,
        le=1000,
        description="Rows resealed per transaction, so each stays well inside 30 seconds.",
    )
    field_key_steps: Annotated[list[Literal["backfill", "rotate", "rewrap", "purge"]], NoDecode] = (
        Field(
            default_factory=list,
            description="Comma-separated: the steps a run takes, in order, when the command names "
            "none (the chart's CronJob: rotate,backfill,purge).",
        )
    )
    field_key_max_age_days: int = Field(
        default=365,
        ge=30,
        le=730,
        description="`rotate`: a live data key version older than this gets a successor "
        "(encryption and keys 7.2: yearly).",
    )

    @field_validator("field_key_steps", mode="before")
    @classmethod
    def _steps(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @model_validator(mode="after")
    def _iam_database_url(self) -> Self:
        if self.database_iam_auth:
            _iam_database(self.database_url, "DATABASE_URL")
        return self


class GuardDutyStandInSettings(_Base):
    """The local GuardDuty stand-in's settings (#234, `sft.workers.guardduty_standin`): S3Mock's
    large-files bucket, which it scans, and ElasticMQ's `guardduty-results` queue, to which it
    sends each result. It runs only in the compose stack and the tests."""

    environment: Environment = Field(
        default="prod",
        description="local or test: the stand-in refuses to start anywhere else.",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    s3_endpoint_url: str = Field(
        pattern=r"^https?://[^\s/]+(:\d+)?/?$", description="S3Mock, in the compose network."
    )
    s3_large_files_bucket: str = Field(pattern=_BUCKET)
    sqs_endpoint_url: str = Field(
        pattern=r"^https?://[^\s/]+(:\d+)?/?$", description="ElasticMQ, in the compose network."
    )
    sqs_queue_prefix: str = Field(pattern=_QUEUE_PREFIX)
    guardduty_poll_seconds: float = Field(
        default=5.0, gt=0, le=300, description="How often it lists the bucket for new versions."
    )

    @model_validator(mode="after")
    def _local_only(self) -> Self:
        if self.environment not in _HOOK_ENVIRONMENTS:
            raise ValueError("the GuardDuty stand-in runs only with ENVIRONMENT=local or test")
        return self


class SignInTriggerSettings(_Base):
    """The Cognito sign-in triggers' settings (#238, `sft.workers.signin_trigger`): the counter
    store, which holds each account's failed sign-ins, and the `signin-events` queue. The Lambda
    function's environment sets them; AWS_REGION and AWS_LAMBDA_RUNTIME_API are Lambda's own."""

    valkey_url: ValkeyUrl = Field(
        description="The counter store, as the triggers' own Valkey user, "
        "sft-<env>-signin-trigger.",
    )
    valkey_iam_cache: str | None = Field(
        default=None,
        pattern=_CACHE_NAME,
        description="The serverless cache's name, for IAM tokens. Unset only in tests.",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    sqs_queue_prefix: str = Field(
        pattern=_QUEUE_PREFIX,
        description="Names the environment's queues: `sft-dev-apne1-` makes its signin-events.",
    )
    sqs_endpoint_url: str | None = Field(
        default=None,
        pattern=r"^https?://[^\s/]+(:\d+)?/?$",
        description="Tests only, for ElasticMQ. In AWS the SDK finds SQS's VPC endpoint itself.",
    )

    @model_validator(mode="after")
    def _iam_valkey_url(self) -> Self:
        if self.valkey_iam_cache is not None:
            _iam_valkey(self.valkey_url)
        return self


class RecoverySettings(_Base):
    """The recovery job's settings (#258; `sft.workers.recovery`, disaster-recovery.md 4): the
    `sft_recovery` role, this region's audit archive, which it reads, and the steps and times
    the runbook renders into the `recovery` CronJob's run. A one-shot command, run by hand. The
    CronJob carries the three `RECOVERY_*` variables and `AUDIT_ARCHIVE_REGION` empty, so a
    runbook's `yq` finds them; empty means unset."""

    app_version: str = Field(default="0.0.0", description="Set by the image build.")
    database_url: PostgresUrl = Field(
        description="The `sft_recovery` login role: recovery scope only (data model 4.2).",
    )
    aws_region: str = Field(default="ap-northeast-1", pattern=r"^[a-z]{2}(-[a-z]+)+-\d$")
    audit_archive_bucket: str = Field(
        pattern=_BUCKET,
        description="This region's audit archive bucket, which the job lists and reads: the "
        "surviving region's after a failover, Tokyo's after a restore; Osaka's for the failback's "
        "replay, with `AUDIT_ARCHIVE_REGION`.",
    )
    audit_archive_endpoint_url: str | None = Field(
        default=None, pattern=r"^https?://[^\s/]+(:\d+)?/?$", description="Local only."
    )
    recovery_steps: str = Field(
        default="",
        description="Comma-separated: generation, partitions, replay, outbox. They run in that "
        "order, whatever order they are named in. Empty as the CronJob is rendered: the runbook "
        "names them, and a run with none refuses to start.",
    )
    recovery_since: AwareDatetime | None = Field(
        default=None,
        description="Records and outbox messages after this time, with its offset: the restore "
        "point, an hour before a failure, or 24 hours back for the outbox.",
    )
    recovery_rewind_to: AwareDatetime | None = Field(
        default=None,
        description="The archive cursor goes back to the oldest event since this time, with its "
        "offset, under the new generation.",
    )
    database_iam_auth: bool = Field(
        default=False,
        description="Sign an IAM token for each new database connection (encryption and keys "
        "6.3). Off locally.",
    )

    @field_validator("recovery_since", "recovery_rewind_to", mode="before")
    @classmethod
    def _empty_is_unset(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value

    @field_validator("recovery_steps")
    @classmethod
    def _known_steps(cls, value: str) -> str:
        names = {part.strip() for part in value.split(",") if part.strip()}
        if names - {"generation", "partitions", "replay", "outbox"}:
            raise ValueError("name steps from: generation, partitions, replay, outbox")
        return value

    @model_validator(mode="after")
    def _times_for_the_steps(self) -> Self:
        names = {part.strip() for part in self.recovery_steps.split(",")}
        if "generation" in names and self.recovery_rewind_to is None:
            raise ValueError("RECOVERY_STEPS=generation needs RECOVERY_REWIND_TO")
        if names & {"partitions", "replay", "outbox"} and self.recovery_since is None:
            raise ValueError("RECOVERY_STEPS partitions, replay and outbox need RECOVERY_SINCE")
        return self

    @model_validator(mode="after")
    def _iam_database_url(self) -> Self:
        if self.database_iam_auth:
            _iam_database(self.database_url, "DATABASE_URL")
        return self

    # The failback's replay (#276): Tokyo's job reads Osaka's archive, which alone holds what Osaka
    # wrote between the hold and the fence until the back-fill (regional-failback.md step 6).
    audit_archive_region: ArchiveRegion | None = Field(
        default=None,
        description="The S3 Region of `AUDIT_ARCHIVE_BUCKET` when it isn't this one "
        "(`AWS_REGION`), which stays the database's. Empty, as the CronJob is rendered: this "
        "Region's archive.",
    )

    @field_validator("audit_archive_region", mode="before")
    @classmethod
    def _empty_region_is_this_one(cls, value: object) -> object:
        return None if isinstance(value, str) and not value.strip() else value


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
