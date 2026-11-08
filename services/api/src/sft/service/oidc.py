"""The OIDC authorization code flow with PKCE, against the user pool (ADR-0016; authn-authz 2.4).

One client per process, for the environment's pool: Cognito in AWS, Keycloak locally
(docs/local-development.md). The issuer's endpoints come from its discovery document; Cognito's
token revocation endpoint isn't in it, so that one can come from settings.

- **The authorization request** carries `state`, a `nonce`, the S256 PKCE challenge,
  `prompt=login` (so managed login's own one-hour cookie can't undo our idle timeout) and the
  identity provider the API chose. The verifier never leaves the server.
- **The code exchange** authenticates the confidential client with HTTP Basic and sends the
  verifier. Only the ID token is read; the refresh token is revoked at once and nothing is kept.
- **The ID token** is checked once, with joserfc: an RS256 signature by one of the pool's
  published keys, `iss`, `aud`, `exp` (60 seconds of leeway), `token_use = id`, and the nonce in
  constant time. A key ID the cached key set doesn't hold refreshes it once, at most once a minute,
  so a rotation at the pool is picked up and a flood of made-up key IDs is not.

Every failure is an `OidcError` with a reason code for the audit log, never the token or the
provider's text.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final
from urllib.parse import unquote, urlencode

import httpx2 as httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

log = logging.getLogger(__name__)

ALGORITHMS: Final = ("RS256",)
LEEWAY_SECONDS: Final = 60
JWKS_REFRESH_SECONDS: Final = 60
TIMEOUT_SECONDS: Final = 5.0
SCOPE: Final = "openid email"


class OidcFailure(StrEnum):
    """Why the provider's answer was refused. Goes into the audit event's details."""

    PROVIDER_ERROR = "provider_error"
    """The provider sent `error` to the callback, such as `access_denied`."""
    UNAVAILABLE = "provider_unavailable"
    """Discovery, the key set or the token endpoint couldn't be reached or answered badly."""
    CODE_REJECTED = "code_rejected"
    """The token endpoint refused the code: used, expired, or the verifier doesn't match."""
    TOKEN_INVALID = "token_invalid"  # noqa: S105 - a reason code, not a secret
    """The ID token's signature, issuer, audience, expiry or `token_use` is wrong."""
    NONCE_MISMATCH = "nonce_mismatch"


class OidcError(Exception):
    def __init__(self, reason: OidcFailure) -> None:
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    revocation_endpoint: str | None


@dataclass(frozen=True, slots=True)
class Pkce:
    """A PKCE pair (RFC 7636, S256): the verifier stays on the server."""

    verifier: str
    challenge: str

    @classmethod
    def new(cls) -> Pkce:
        verifier = secrets.token_urlsafe(48)  # 64 characters, within RFC 7636's 43 to 128
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return cls(verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii"))


@dataclass(frozen=True, slots=True)
class IdToken:
    """The claims sign-in reads from a validated ID token."""

    subject: str
    username: str | None
    """`cognito:username`: our user ID for a local member."""
    amr: tuple[str, ...]
    auth_time: int | None
    identities: tuple[Mapping[str, Any], ...]
    """Cognito's `identities` claim, present for a federated (SSO) sign-in."""
    email: str | None = None
    """The address the pool, or for SSO the identity provider, sent. It never finds a user in
    another tenant or outside the connection's proven domains (#231, `sft.service.signin`)."""
    groups: tuple[str, ...] = ()
    """The identity provider's groups, as the pool mapped them (`OIDC_GROUPS_CLAIM`)."""


class OidcClient:
    """The confidential client of one user pool."""

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        discovery_url: str | None = None,
        revocation_url: str | None = None,
        http: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
        hint_parameter: str = "identity_provider",
        groups_claim: str = "custom:sso_groups",
    ) -> None:
        self.issuer = issuer
        self.hint_parameter = hint_parameter
        self.groups_claim = groups_claim
        self.client_id = client_id
        self._secret = client_secret
        self.redirect_uri = redirect_uri
        self._discovery_url = (
            discovery_url or f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        )
        self._revocation_url = revocation_url
        self._http = http or httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False)
        self._clock = clock
        self._metadata: ProviderMetadata | None = None
        self._keys: KeySet | None = None
        self._keys_fetched_at = float("-inf")

    async def aclose(self) -> None:
        await self._http.aclose()

    # ---- discovery and keys ----

    async def metadata(self) -> ProviderMetadata:
        if self._metadata is None:
            document = await self._get_json(self._discovery_url)
            try:
                metadata = ProviderMetadata(
                    issuer=str(document["issuer"]),
                    authorization_endpoint=str(document["authorization_endpoint"]),
                    token_endpoint=str(document["token_endpoint"]),
                    jwks_uri=str(document["jwks_uri"]),
                    revocation_endpoint=self._revocation_url or document.get("revocation_endpoint"),
                )
            except KeyError as exc:
                log.warning("oidc discovery document is incomplete")
                raise OidcError(OidcFailure.UNAVAILABLE) from exc
            if metadata.issuer != self.issuer:
                # A misconfiguration, not an attack: say so in the log, refuse every sign-in.
                log.error("oidc discovery names another issuer than OIDC_ISSUER")
                raise OidcError(OidcFailure.UNAVAILABLE)
            self._metadata = metadata
        return self._metadata

    async def _key_set(self, *, refresh: bool = False) -> KeySet:
        now = self._clock()
        stale = refresh and now - self._keys_fetched_at >= JWKS_REFRESH_SECONDS
        if self._keys is None or stale:
            document = await self._get_json((await self.metadata()).jwks_uri)
            try:
                self._keys = KeySet.import_key_set(document)  # type: ignore[arg-type]
            except (JoseError, ValueError, TypeError, KeyError) as exc:
                raise OidcError(OidcFailure.UNAVAILABLE) from exc
            self._keys_fetched_at = now
        return self._keys

    async def _get_json(self, url: str) -> dict[str, Any]:
        try:
            response = await self._http.get(url)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("oidc request failed", extra={"error": type(exc).__name__})
            raise OidcError(OidcFailure.UNAVAILABLE) from exc
        if not isinstance(body, dict):
            raise OidcError(OidcFailure.UNAVAILABLE)
        return body

    # ---- the flow ----

    async def authorization_url(
        self, *, state: str, nonce: str, pkce: Pkce, identity_provider: str
    ) -> str:
        endpoint = (await self.metadata()).authorization_endpoint
        query = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": SCOPE,
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
            "prompt": "login",
            # Cognito's `identity_provider`; Keycloak, the local stand-in, reads `kc_idp_hint`.
            self.hint_parameter: identity_provider,
        }
        separator = "&" if "?" in endpoint else "?"
        return f"{endpoint}{separator}{urlencode(query)}"

    async def exchange(self, code: str, verifier: str) -> tuple[str, str | None]:
        """The ID token and the refresh token, if any, for an authorization code."""
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": verifier,
        }
        endpoint = (await self.metadata()).token_endpoint
        try:
            response = await self._http.post(
                endpoint, data=form, auth=(self.client_id, self._secret)
            )
        except httpx.HTTPError as exc:
            log.warning("oidc token request failed", extra={"error": type(exc).__name__})
            raise OidcError(OidcFailure.UNAVAILABLE) from exc
        if response.status_code in (400, 401):
            raise OidcError(OidcFailure.CODE_REJECTED)
        try:
            response.raise_for_status()
            body = response.json()
            id_token = body["id_token"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise OidcError(OidcFailure.UNAVAILABLE) from exc
        if not isinstance(id_token, str):
            raise OidcError(OidcFailure.UNAVAILABLE)
        refresh = body.get("refresh_token")
        return id_token, refresh if isinstance(refresh, str) else None

    async def validate(self, id_token: str, nonce: str) -> IdToken:
        """The ID token's claims, once its signature and claims are checked."""
        try:
            token = jwt.decode(id_token, await self._key_set(), algorithms=list(ALGORITHMS))
        except JoseError as exc:
            if not _unknown_key(exc):
                raise OidcError(OidcFailure.TOKEN_INVALID) from exc
            # The pool may have rotated its keys since they were fetched.
            try:
                keys = await self._key_set(refresh=True)
                token = jwt.decode(id_token, keys, algorithms=list(ALGORITHMS))
            except JoseError as again:
                raise OidcError(OidcFailure.TOKEN_INVALID) from again
        except (ValueError, TypeError) as exc:
            raise OidcError(OidcFailure.TOKEN_INVALID) from exc
        claims = token.claims
        registry = jwt.JWTClaimsRegistry(
            now=lambda: int(self._clock()),
            leeway=LEEWAY_SECONDS,
            iss={"essential": True, "value": self.issuer},
            aud={"essential": True, "value": self.client_id},
            exp={"essential": True},
            sub={"essential": True},
        )
        try:
            registry.validate(claims)
        except JoseError as exc:
            raise OidcError(OidcFailure.TOKEN_INVALID) from exc
        audience = claims.get("aud")
        if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != self.client_id:
            raise OidcError(OidcFailure.TOKEN_INVALID)
        if claims.get("token_use") != "id":
            raise OidcError(OidcFailure.TOKEN_INVALID)
        sent = claims.get("nonce")
        if not isinstance(sent, str) or not hmac.compare_digest(sent.encode(), nonce.encode()):
            raise OidcError(OidcFailure.NONCE_MISMATCH)
        return _id_token(claims, self.groups_claim)

    async def revoke(self, refresh_token: str) -> None:
        """Revoke the refresh token; best effort, since nothing keeps it (ADR-0016)."""
        endpoint = (await self.metadata()).revocation_endpoint
        if endpoint is None:
            log.warning("oidc refresh token not revoked: no revocation endpoint")
            return
        form = {"token": refresh_token, "token_type_hint": "refresh_token"}
        try:
            response = await self._http.post(
                endpoint, data=form, auth=(self.client_id, self._secret)
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("oidc refresh token not revoked", extra={"error": type(exc).__name__})


def _unknown_key(exc: JoseError) -> bool:
    return type(exc).__name__ in ("InvalidKeyIdError", "MissingKeyError")


def groups_of(value: object) -> tuple[str, ...]:
    """The groups claim: a JSON list, or Cognito's mapped attribute, one string `[a,b]` whose
    values are each URL-encoded (#231)."""
    if isinstance(value, list):
        return tuple(v for v in value if isinstance(v, str) and v)
    if not isinstance(value, str):
        return ()
    text = value.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return tuple(unquote(part.strip()) for part in text.split(",") if part.strip())


def _id_token(claims: Mapping[str, Any], groups_claim: str = "custom:sso_groups") -> IdToken:
    def strings(value: object) -> tuple[str, ...]:
        if isinstance(value, list):
            return tuple(v for v in value if isinstance(v, str))
        return ()

    username = claims.get("cognito:username")
    auth_time = claims.get("auth_time")
    identities = claims.get("identities")
    if isinstance(identities, dict):
        # One object rather than a list: Keycloak's nested claim, the local stand-in's.
        identities = [identities]
    email = claims.get("email")
    return IdToken(
        subject=str(claims["sub"]),
        username=username if isinstance(username, str) else None,
        amr=strings(claims.get("amr")),
        auth_time=auth_time
        if isinstance(auth_time, int) and not isinstance(auth_time, bool)
        else None,
        identities=tuple(i for i in identities if isinstance(i, dict))
        if isinstance(identities, list)
        else (),
        email=email if isinstance(email, str) and email else None,
        groups=groups_of(claims.get(groups_claim)),
    )
