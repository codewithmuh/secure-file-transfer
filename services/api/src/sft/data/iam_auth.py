"""IAM authentication tokens for Aurora and Valkey (encryption and keys 6.3, ADR-0014, #184).

In AWS no workload has a database or Valkey password. Its pod's role (EKS Pod Identity) signs a
token for each new connection, and the token is the password:

- **Aurora**: a SigV4-presigned `connect` request for the cluster's host and port and the login
  role, for `rds-db`, valid 15 minutes. IAM authentication needs TLS, so the URL has
  `sslmode=verify-full` (sft.core.settings checks it).
- **Valkey** (ElastiCache Serverless): a SigV4-presigned `connect` request for the cache's name and
  the user, `ResourceType=ServerlessCache`, for `elasticache`, valid 15 minutes. ElastiCache closes
  an IAM-authenticated connection after 12 hours; the client then reconnects with a new token.

Both are signed locally from the role's credentials; nothing is sent to AWS. A token need only be
valid when a connection opens, so `TokenSigner` reuses one for at most 10 minutes and signs a new
one after that: every connection gets a token with at least 5 minutes left. The credentials
themselves refresh in the SDK before they expire. No log line, span or message holds a token.

Locally neither is used: the URLs hold the stand-ins' fake passwords.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Final
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import boto3
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials, ReadOnlyCredentials
from valkey.credentials import CredentialProvider

TOKEN_SECONDS: Final = 900
"""How long a token signs in for: 15 minutes, the most either service accepts."""
REUSE_SECONDS: Final = 600
"""How long one token is handed to new connections: 5 minutes before it expires."""


class CredentialsUnavailableError(RuntimeError):
    """The pod has no AWS credentials to sign with, so a connection can't open."""


def default_credentials() -> Callable[[], ReadOnlyCredentials]:
    """The SDK's credential chain (Pod Identity in EKS), frozen fresh for each signature."""
    resolved: Credentials | None = boto3.Session().get_credentials()

    def frozen() -> ReadOnlyCredentials:
        if resolved is None:
            raise CredentialsUnavailableError("no AWS credentials to sign an IAM token with")
        return resolved.get_frozen_credentials()

    return frozen


def _presign(
    url: str, *, service: str, region: str, credentials: Callable[[], ReadOnlyCredentials]
) -> str:
    request = AWSRequest(method="GET", url=url)
    SigV4QueryAuth(credentials(), service, region, expires=TOKEN_SECONDS).add_auth(request)
    return str(request.url)


def rds_token(
    host: str,
    port: int,
    user: str,
    *,
    region: str,
    credentials: Callable[[], ReadOnlyCredentials],
) -> str:
    """An Aurora IAM token: what `boto3`'s `generate_db_auth_token` makes, without an RDS client."""
    scheme = "https://"
    query = urlencode({"Action": "connect", "DBUser": user}, quote_via=quote)
    signed = _presign(
        f"{scheme}{host}:{port}/?{query}", service="rds-db", region=region, credentials=credentials
    )
    return signed.removeprefix(scheme)


def elasticache_token(
    cache_name: str,
    user: str,
    *,
    region: str,
    credentials: Callable[[], ReadOnlyCredentials],
) -> str:
    """An ElastiCache Serverless IAM token for `user`, signed as AWS's IAM authentication guide
    signs it."""
    scheme = "http://"
    query = urlencode(
        {"Action": "connect", "User": user, "ResourceType": "ServerlessCache"}, quote_via=quote
    )
    signed = _presign(
        f"{scheme}{cache_name}/?{query}",
        service="elasticache",
        region=region,
        credentials=credentials,
    )
    return signed.removeprefix(scheme)


class TokenSigner:
    """One connection target's tokens: a new one at most every `reuse_seconds`.

    Thread-safe: the database pool connects from its own threads, Valkey from the event loop.
    """

    def __init__(
        self,
        sign: Callable[[], str],
        *,
        reuse_seconds: float = REUSE_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not 0 < reuse_seconds < TOKEN_SECONDS:
            raise ValueError("a token is reused for less than its lifetime")
        self._sign = sign
        self._reuse = reuse_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._token: str | None = None
        self._signed_at = 0.0

    def __repr__(self) -> str:
        return "TokenSigner(...)"  # never the token

    def token(self) -> str:
        with self._lock:
            now = self._clock()
            if self._token is None or now - self._signed_at >= self._reuse:
                self._token = self._sign()
                self._signed_at = now
            return self._token


def rds_signer(
    host: str,
    port: int,
    user: str,
    *,
    region: str,
    credentials: Callable[[], ReadOnlyCredentials] | None = None,
) -> TokenSigner:
    """Tokens for one database login role."""
    creds = credentials or default_credentials()
    return TokenSigner(lambda: rds_token(host, port, user, region=region, credentials=creds))


class ValkeyIamCredentials(CredentialProvider):
    """valkey-py's credentials for each new connection: the user and a fresh enough token."""

    def __init__(
        self,
        cache_name: str,
        user: str,
        *,
        region: str,
        credentials: Callable[[], ReadOnlyCredentials] | None = None,
    ) -> None:
        creds = credentials or default_credentials()
        self.user = user
        self._signer = TokenSigner(
            lambda: elasticache_token(cache_name, user, region=region, credentials=creds)
        )

    def __repr__(self) -> str:
        return f"ValkeyIamCredentials(user={self.user!r})"

    def get_credentials(self) -> tuple[str, str]:
        return self.user, self._signer.token()


def valkey_iam(url: str, cache_name: str, *, region: str) -> tuple[str, ValkeyIamCredentials]:
    """The URL without its user, and the credentials that sign in as that user: valkey-py takes a
    user from the URL or a credential provider, never both."""
    parts = urlsplit(url)
    if not parts.username or parts.password:
        raise ValueError("an IAM-authenticated Valkey URL names its user and no password")
    host = parts.netloc.rpartition("@")[2]
    bare = urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
    return bare, ValkeyIamCredentials(cache_name, parts.username, region=region)
