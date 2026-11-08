"""The operator's side of tenant SSO: a tenant's identity provider in the user pools (#231; FR-26;
authn and authz 2.5). Run by an operator with their own credentials, never by a workload:

    python -m sft.runtime.sso_providers cognito --pool-id <tokyo pool> --pool-id <osaka pool> \\
        --app-client-id <client> --tenant-id <id> --kind oidc --issuer https://idp.example \\
        --idp-client-id <id> --idp-client-secret-file <file>

    python -m sft.runtime.sso_providers keycloak --url http://localhost:8180 --realm sft \\
        --tenant-id <id> --issuer http://oidc:8080/realms/customer --idp-client-id sft-pool \\
        --idp-client-secret-file <file>

It creates the provider, or updates it, in each pool, named after the tenant (`provider_name_for`:
the tenant ID without dashes), mapping only the email, the subject and the groups
(`custom:sso_groups`), with signed SAML assertions; then adds it to the app client's identity
providers, which Terraform leaves to it (infra/modules/user-pool). No Terraform, and the API role
never manages providers. It prints the provider's name; the operator then records it with
`configureTenantSso`. The client secret is read from a file and never printed or logged.

**Keycloak**, the local stand-in, brokers to the customer's provider (locally a second realm,
`customer`), with mappers that put the federated subject and the provider's name in the ID token as
Cognito's `identities` claim does (`local/keycloak/sft-realm.json` declares the attributes).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Literal, Protocol
from urllib.parse import quote
from uuid import UUID

import httpx2 as httpx

from sft.service.sso import provider_name_for

Kind = Literal["oidc", "saml"]

OIDC_ATTRIBUTES: Final = {"email": "email", "username": "sub", "custom:sso_groups": "groups"}
SAML_ATTRIBUTES: Final = {
    "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "custom:sso_groups": "http://schemas.xmlsoap.org/claims/Group",
}
# What UpdateUserPoolClient takes back from DescribeUserPoolClient: anything left out is reset.
CLIENT_FIELDS: Final = (
    "ClientName",
    "RefreshTokenValidity",
    "AccessTokenValidity",
    "IdTokenValidity",
    "TokenValidityUnits",
    "ReadAttributes",
    "WriteAttributes",
    "ExplicitAuthFlows",
    "SupportedIdentityProviders",
    "CallbackURLs",
    "LogoutURLs",
    "DefaultRedirectURI",
    "AllowedOAuthFlows",
    "AllowedOAuthScopes",
    "AllowedOAuthFlowsUserPoolClient",
    "AnalyticsConfiguration",
    "PreventUserExistenceErrors",
    "EnableTokenRevocation",
    "EnablePropagateAdditionalUserContextData",
    "AuthSessionValidity",
    "RefreshTokenRotation",
)


class ProviderError(Exception):
    """A pool refused the provider; the message names the pool's error code, never a secret."""


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    tenant_id: UUID
    kind: Kind
    issuer: str | None = None
    """OIDC: the provider's issuer."""
    client_id: str | None = None
    client_secret: str | None = None
    metadata_url: str | None = None
    """SAML: where its metadata is published."""

    @property
    def name(self) -> str:
        return provider_name_for(self.tenant_id)

    def __post_init__(self) -> None:
        if self.kind == "oidc" and not (self.issuer and self.client_id and self.client_secret):
            raise ValueError("an OIDC provider needs its issuer, client ID and client secret")
        if self.kind == "saml" and not self.metadata_url:
            raise ValueError("a SAML provider needs its metadata URL")


class CognitoIdp(Protocol):
    def describe_identity_provider(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def create_identity_provider(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def update_identity_provider(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def describe_user_pool_client(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def update_user_pool_client(self, **kwargs: Any) -> Mapping[str, Any]: ...


def cognito_details(spec: ProviderSpec) -> tuple[str, dict[str, str], dict[str, str]]:
    """The provider type, its details and its attribute mapping, as Cognito takes them."""
    if spec.kind == "oidc":
        # __post_init__ checked them.
        assert spec.issuer  # noqa: S101
        assert spec.client_id  # noqa: S101
        assert spec.client_secret  # noqa: S101
        details = {
            "client_id": spec.client_id,
            "client_secret": spec.client_secret,
            "attributes_request_method": "GET",
            "oidc_issuer": spec.issuer,
            "authorize_scopes": "openid email profile",
        }
        return "OIDC", details, dict(OIDC_ATTRIBUTES)
    assert spec.metadata_url  # noqa: S101 - __post_init__
    # Cognito refuses unsigned SAML responses; no IdP-initiated sign-in, no single logout (v1).
    details = {"MetadataURL": spec.metadata_url, "IDPInit": "false", "IDPSignout": "false"}
    return "SAML", details, dict(SAML_ATTRIBUTES)


def put_cognito(
    idp: CognitoIdp, pool_ids: Sequence[str], app_client_id: str, spec: ProviderSpec
) -> str:
    """Create or update the provider in each pool and enable it on the app client."""
    kind, details, mapping = cognito_details(spec)
    for pool_id in pool_ids:
        try:
            try:
                idp.describe_identity_provider(UserPoolId=pool_id, ProviderName=spec.name)
            except Exception as exc:
                if _code(exc) != "ResourceNotFoundException":
                    raise
                idp.create_identity_provider(
                    UserPoolId=pool_id,
                    ProviderName=spec.name,
                    ProviderType=kind,
                    ProviderDetails=details,
                    AttributeMapping=mapping,
                    IdpIdentifiers=[],  # our sign-in page picks the provider (authn-authz 2.4)
                )
            else:
                idp.update_identity_provider(
                    UserPoolId=pool_id,
                    ProviderName=spec.name,
                    ProviderDetails=details,
                    AttributeMapping=mapping,
                    IdpIdentifiers=[],
                )
            client = idp.describe_user_pool_client(UserPoolId=pool_id, ClientId=app_client_id)[
                "UserPoolClient"
            ]
            providers = list(client.get("SupportedIdentityProviders") or [])
            if spec.name not in providers:
                update = {k: client[k] for k in CLIENT_FIELDS if k in client}
                update["SupportedIdentityProviders"] = [*providers, spec.name]
                idp.update_user_pool_client(UserPoolId=pool_id, ClientId=app_client_id, **update)
        except Exception as exc:
            raise ProviderError(f"pool {pool_id}: {_code(exc)}") from None
    return spec.name


def _code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", type(exc).__name__))
    return type(exc).__name__


# ---- Keycloak, the local stand-in ----


def keycloak_provider(spec: ProviderSpec) -> dict[str, Any]:
    """The broker's identity provider representation (OIDC only, locally)."""
    if spec.kind != "oidc":
        raise ValueError("the local stand-in brokers OIDC only")
    issuer = (spec.issuer or "").rstrip("/")
    return {
        "alias": spec.name,
        "providerId": "oidc",
        "enabled": True,
        "trustEmail": True,
        "storeToken": False,
        "firstBrokerLoginFlowAlias": "first broker login",
        "config": {
            "issuer": issuer,
            "authorizationUrl": f"{issuer}/protocol/openid-connect/auth",
            "tokenUrl": f"{issuer}/protocol/openid-connect/token",
            "jwksUrl": f"{issuer}/protocol/openid-connect/certs",
            "useJwksUrl": "true",
            "validateSignature": "true",
            "clientId": spec.client_id,
            "clientSecret": spec.client_secret,
            "clientAuthMethod": "client_secret_post",
            "defaultScope": "openid email",
            "pkceEnabled": "true",
            "pkceMethod": "S256",
            "syncMode": "FORCE",
            "prompt": "login",
        },
    }


def keycloak_mappers(spec: ProviderSpec) -> list[dict[str, Any]]:
    """Cognito's `identities` claim, built from the broker's user attributes, and the groups."""
    alias = spec.name

    def mapper(name: str, kind: str, config: dict[str, str]) -> dict[str, Any]:
        return {
            "name": name,
            "identityProviderAlias": alias,
            "identityProviderMapper": kind,
            "config": {"syncMode": "FORCE", **config},
        }

    return [
        mapper(
            "username",
            "oidc-username-idp-mapper",
            {"template": "${ALIAS}.${CLAIM.sub}", "target": "LOCAL"},
        ),
        mapper(
            "subject",
            "oidc-user-attribute-idp-mapper",
            {"claim": "sub", "user.attribute": "idp_user_id"},
        ),
        mapper(
            "provider",
            "hardcoded-attribute-idp-mapper",
            {"attribute": "idp_provider_name", "attribute.value": alias},
        ),
        mapper(
            "groups",
            "oidc-user-attribute-idp-mapper",
            {"claim": "groups", "user.attribute": "sso_groups"},
        ),
    ]


def put_keycloak(
    http: httpx.Client, base_url: str, realm: str, token: str, spec: ProviderSpec
) -> str:
    """Create or replace the broker's provider and its mappers in the local realm."""
    root = (
        f"{base_url.rstrip('/')}/admin/realms/{quote(realm, safe='')}/identity-provider/instances"
    )
    headers = {"Authorization": f"Bearer {token}"}
    alias = quote(spec.name, safe="")
    body = keycloak_provider(spec)
    response = http.post(root, json=body, headers=headers)
    if response.status_code == httpx.codes.CONFLICT:
        response = http.put(f"{root}/{alias}", json=body, headers=headers)
    if response.status_code not in (httpx.codes.CREATED, httpx.codes.NO_CONTENT):
        raise ProviderError(f"keycloak refused the provider ({response.status_code})")
    existing = http.get(f"{root}/{alias}/mappers", headers=headers)
    names = {m.get("name") for m in existing.json()} if existing.status_code == 200 else set()
    for mapper in keycloak_mappers(spec):
        if mapper["name"] in names:
            continue
        added = http.post(f"{root}/{alias}/mappers", json=mapper, headers=headers)
        if added.status_code != httpx.codes.CREATED:
            raise ProviderError(f"keycloak refused a mapper ({added.status_code})")
    return spec.name


def keycloak_admin_token(http: httpx.Client, base_url: str, user: str, password: str) -> str:
    response = http.post(
        f"{base_url.rstrip('/')}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": user,
            "password": password,
        },
    )
    if response.status_code != httpx.codes.OK:
        raise ProviderError(f"keycloak refused the admin sign-in ({response.status_code})")
    return str(response.json()["access_token"])


# ---- the command line ----


def _spec(args: argparse.Namespace) -> ProviderSpec:
    secret = None
    if args.idp_client_secret_file:
        secret = Path(args.idp_client_secret_file).read_text().strip()
    return ProviderSpec(
        tenant_id=UUID(args.tenant_id),
        kind=args.kind,
        issuer=args.issuer,
        client_id=args.idp_client_id,
        client_secret=secret,
        metadata_url=args.metadata_url,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m sft.runtime.sso_providers")
    backends = parser.add_subparsers(dest="backend", required=True)
    for name in ("cognito", "keycloak"):
        sub = backends.add_parser(name)
        sub.add_argument("--tenant-id", required=True)
        sub.add_argument("--kind", choices=["oidc", "saml"], default="oidc")
        sub.add_argument("--issuer")
        sub.add_argument("--idp-client-id")
        sub.add_argument("--idp-client-secret-file")
        sub.add_argument("--metadata-url")
        if name == "cognito":
            sub.add_argument("--pool-id", action="append", required=True)
            sub.add_argument("--app-client-id", required=True)
            sub.add_argument("--region", default="ap-northeast-1")
        else:
            sub.add_argument("--url", default="http://localhost:8180")
            sub.add_argument("--realm", default="sft")
            sub.add_argument("--admin-user", default="admin")
            sub.add_argument("--admin-password-file", required=True)
    args = parser.parse_args(argv)
    try:
        spec = _spec(args)
        if args.backend == "cognito":
            import boto3

            idp = boto3.client("cognito-idp", region_name=args.region)
            name = put_cognito(idp, args.pool_id, args.app_client_id, spec)  # type: ignore[arg-type]
        else:
            password = Path(args.admin_password_file).read_text().strip()
            with httpx.Client(timeout=10.0) as http:
                token = keycloak_admin_token(http, args.url, args.admin_user, password)
                name = put_keycloak(http, args.url, args.realm, token, spec)
    except (ProviderError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
