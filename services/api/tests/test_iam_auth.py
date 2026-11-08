"""IAM tokens for Aurora and Valkey (#184, encryption and keys 6.3, ADR-0014). No AWS: tokens are
signed locally from fake static credentials, and compared with what the SDK itself signs."""

from typing import Any
from urllib.parse import parse_qs, urlsplit

import boto3
import psycopg
import pytest
from botocore.credentials import ReadOnlyCredentials
from pydantic import SecretStr, ValidationError

from sft.core.settings import JobSettings, MigrationSettings, ScanSettings
from sft.data import iam_auth
from sft.data.counters import ValkeyIam, iam_url
from sft.data.database import Database, sync_engine
from sft.data.iam_auth import (
    TOKEN_SECONDS,
    TokenSigner,
    ValkeyIamCredentials,
    elasticache_token,
    rds_token,
    valkey_iam,
)

FAKE = ReadOnlyCredentials("test-only-key-id", "fake-secret-not-a-real-key", None)
HOST = "sft-dev.cluster-example.ap-northeast-1.rds.amazonaws.com"


def fake() -> ReadOnlyCredentials:
    return FAKE


def query(token: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(f"https://{token}").query)


def test_the_database_token_is_the_sdks() -> None:
    client = boto3.client(
        "rds",
        region_name="ap-northeast-1",
        aws_access_key_id=FAKE.access_key,
        aws_secret_access_key=FAKE.secret_key,
    )
    for _ in range(3):  # both must be signed in the same second to be equal
        ours = rds_token(HOST, 5432, "sft_api", region="ap-northeast-1", credentials=fake)
        sdks = client.generate_db_auth_token(HOST, 5432, "sft_api", Region="ap-northeast-1")
        if query(ours)["X-Amz-Date"] == query(sdks)["X-Amz-Date"]:
            assert ours == sdks
            break
    else:
        pytest.fail("never signed within one second")
    assert ours.startswith(f"{HOST}:5432/?")
    params = query(ours)
    assert params["Action"] == ["connect"]
    assert params["DBUser"] == ["sft_api"]
    assert params["X-Amz-Expires"] == [str(TOKEN_SECONDS)]


def test_the_valkey_token_signs_connect_for_the_serverless_cache() -> None:
    token = elasticache_token(
        "sft-dev-apne1-valkey", "sft-dev-api", region="ap-northeast-1", credentials=fake
    )
    assert token.startswith("sft-dev-apne1-valkey/?")
    params = query(token)
    assert params["Action"] == ["connect"]
    assert params["User"] == ["sft-dev-api"]
    assert params["ResourceType"] == ["ServerlessCache"]
    assert params["X-Amz-Expires"] == ["900"]
    [credential] = params["X-Amz-Credential"]
    assert credential.endswith("/ap-northeast-1/elasticache/aws4_request")
    assert "X-Amz-Signature" in params


def test_a_token_is_reused_for_ten_minutes_then_signed_again() -> None:
    now = [1000.0]
    signed: list[int] = []

    def sign() -> str:
        signed.append(1)
        return f"token-{len(signed)}"

    signer = TokenSigner(sign, clock=lambda: now[0])
    assert signer.token() == "token-1"
    now[0] += 599
    assert signer.token() == "token-1"  # still 5 minutes and more left
    now[0] += 1
    assert signer.token() == "token-2"
    assert "token" not in repr(signer).replace("TokenSigner", "")
    with pytest.raises(ValueError, match="less than its lifetime"):
        TokenSigner(sign, reuse_seconds=TOKEN_SECONDS)


def test_no_credentials_fail_the_connection_not_the_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NoCredentials:
        def get_credentials(self) -> None:
            return None

    monkeypatch.setattr(iam_auth.boto3, "Session", NoCredentials)
    frozen = iam_auth.default_credentials()
    with pytest.raises(iam_auth.CredentialsUnavailableError):
        frozen()


def test_valkey_takes_the_user_from_the_url_into_the_credentials() -> None:
    bare, credentials = valkey_iam(
        "rediss://sft-dev-api@valkey.example:6379/0",
        "sft-dev-apne1-valkey",
        region="ap-northeast-1",
    )
    assert bare == "rediss://valkey.example:6379/0"
    assert credentials.user == "sft-dev-api"
    with pytest.raises(ValueError, match="no password"):
        valkey_iam("rediss://u:p@valkey.example:6379", "c", region="ap-northeast-1")
    assert iam_url("redis://u:p@h:1/0", None) == ("redis://u:p@h:1/0", {})
    # VALKEY_IAM_CACHE unset (locally): no IAM, the URL's password signs in.
    assert ValkeyIam.of(None, "ap-northeast-1") is None
    assert ValkeyIam.of("sft-dev-apne1-valkey", "ap-northeast-1") == ValkeyIam(
        "sft-dev-apne1-valkey", "ap-northeast-1"
    )


def test_valkey_credentials_sign_per_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(iam_auth, "default_credentials", lambda: fake)
    credentials = ValkeyIamCredentials(
        "sft-dev-apne1-valkey", "sft-dev-api", region="ap-northeast-1"
    )
    user, token = credentials.get_credentials()
    assert user == "sft-dev-api"
    assert query(token)["User"] == ["sft-dev-api"]
    assert "X-Amz-Signature" not in repr(credentials)


def test_each_new_database_connection_gets_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """The do_connect hook puts a fresh token where the password goes, and nothing else changes."""
    monkeypatch.setattr(iam_auth, "default_credentials", lambda: fake)
    seen: list[dict[str, Any]] = []

    class StopError(Exception):
        pass

    def connect(*args: object, **kwargs: Any) -> None:
        seen.append(kwargs)
        raise StopError

    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(psycopg.Connection, "connect", connect)
    url = f"postgresql://sft_migrate@{HOST}:5432/sft?sslmode=verify-full"
    engine = sync_engine(url, iam_region="ap-northeast-1")
    with pytest.raises(Exception) as caught:  # noqa: PT011 - SQLAlchemy may wrap it
        engine.connect()
    assert isinstance(caught.value, StopError) or isinstance(caught.value.__cause__, StopError)
    [params] = seen
    assert params["user"] == "sft_migrate"
    assert params["host"] == HOST
    assert params["sslmode"] == "verify-full"
    assert query(params["password"])["DBUser"] == ["sft_migrate"]


def test_an_iam_pool_refuses_a_url_with_a_password() -> None:
    with pytest.raises(ValueError, match="no password"):
        Database.connect(
            "postgresql://sft_api:hunter2@db.example:5432/sft?sslmode=verify-full",
            iam_region="ap-northeast-1",
        )


def test_iam_settings_need_tls_and_no_password() -> None:
    base: dict[str, Any] = {
        "aws_region": "ap-northeast-1",
        "s3_files_bucket": "sft-test-files",
        "s3_large_files_bucket": "sft-test-large-files",
        "audit_archive_tokyo_bucket": "sft-test-audit-archive",
    }
    with pytest.raises(ValidationError, match="names its login role and no password"):
        JobSettings(
            database_url=SecretStr("postgresql://sft_jobs:pw@db:5432/sft?sslmode=verify-full"),
            database_iam_auth=True,
            **base,
        )
    with pytest.raises(ValidationError, match="sslmode=verify-full"):
        JobSettings(
            database_url=SecretStr("postgresql://sft_jobs@db:5432/sft?sslmode=require"),
            database_iam_auth=True,
            **base,
        )
    JobSettings(
        database_url=SecretStr("postgresql://sft_jobs@db:5432/sft?sslmode=verify-full"),
        database_iam_auth=True,
        **base,
    )
    with pytest.raises(ValidationError, match="MIGRATION_DATABASE_URL"):
        MigrationSettings(
            migration_database_url=SecretStr("postgresql://sft_migrate@db:5432/sft"),
            database_iam_auth=True,
        )


def test_valkey_iam_settings_need_tls_and_no_password() -> None:
    scan: dict[str, Any] = {
        "database_url": SecretStr("postgresql://sft_scan@db:5432/sft"),
        "sqs_queue_prefix": "sft-dev-",
        "scan_pool": "small",
        "s3_files_bucket": "sft-test-files",
        "s3_large_files_bucket": "sft-test-large-files",
        "valkey_iam_cache": "sft-dev-apne1-valkey",
    }
    with pytest.raises(ValidationError, match="TLS VALKEY_URL"):
        ScanSettings(valkey_url=SecretStr("redis://sft-dev-scan@valkey:6379"), **scan)
    with pytest.raises(ValidationError, match="no password"):
        ScanSettings(valkey_url=SecretStr("rediss://sft-dev-scan:pw@valkey:6379"), **scan)
    with pytest.raises(ValidationError, match="needs VALKEY_URL"):
        ScanSettings(**scan)
    ScanSettings(valkey_url=SecretStr("rediss://sft-dev-scan@valkey:6379"), **scan)


@pytest.mark.anyio
async def test_the_counter_store_signs_in_with_the_credentials(
    valkey_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Against a real Valkey: the URL's user signs in with what the credentials give, here the
    test user's own password standing in for a token."""
    from prometheus_client import CollectorRegistry

    from sft.data.counters import CounterMetrics, CounterStore

    parts = urlsplit(valkey_url)
    if not parts.password:
        pytest.skip("needs a Valkey URL with a password")
    password = parts.password
    # requirepass is the `default` user's password, so a URL without a user signs in as it.
    user = parts.username or "default"
    host = parts.netloc.rpartition("@")[2]
    without_password = f"{parts.scheme}://{user}@{host}{parts.path}"
    monkeypatch.setattr(iam_auth, "default_credentials", lambda: fake)
    monkeypatch.setattr(iam_auth, "elasticache_token", lambda *a, **k: password)
    store = CounterStore.connect(
        without_password,
        CounterMetrics.create(CollectorRegistry()),
        iam=ValkeyIam("sft-test-valkey", "ap-northeast-1"),
    )
    try:
        verdict = await store.rate(
            "iam-test", now_ms=1_000, limit=10, period_ms=60_000, cost=1, peek=True
        )
        assert verdict.allowed
    finally:
        await store.close()
