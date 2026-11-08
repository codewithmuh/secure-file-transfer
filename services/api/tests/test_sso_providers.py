"""The operator's side of tenant SSO (#231): the provider in each user pool, without Terraform, with
stand-ins for Cognito's admin API and Keycloak's. The live calls are pending the AWS run."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import httpx2 as httpx
import pytest
from botocore.exceptions import ClientError

from sft.runtime import sso_providers
from sft.runtime.sso_providers import ProviderError, ProviderSpec, put_cognito, put_keycloak

TENANT = uuid.UUID("0190f0f0-0000-7000-8000-00000000abcd")


def oidc() -> ProviderSpec:
    return ProviderSpec(
        tenant_id=TENANT,
        kind="oidc",
        issuer="https://idp.corp.example",
        client_id="sft-pool",
        client_secret="test-only-idp-secret",  # noqa: S106 - obviously fake
    )


@dataclass
class FakeCognito:
    """Cognito's admin API, for one app client in each pool."""

    providers: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    clients: dict[str, dict[str, Any]] = field(default_factory=dict)
    refuse: str | None = None

    def _error(self, code: str) -> ClientError:
        return ClientError({"Error": {"Code": code, "Message": "x"}}, "op")

    def describe_identity_provider(self, **kw: Any) -> Mapping[str, Any]:
        key = (kw["UserPoolId"], kw["ProviderName"])
        if key not in self.providers:
            raise self._error("ResourceNotFoundException")
        return {"IdentityProvider": self.providers[key]}

    def create_identity_provider(self, **kw: Any) -> Mapping[str, Any]:
        if self.refuse:
            raise self._error(self.refuse)
        self.providers[(kw["UserPoolId"], kw["ProviderName"])] = kw
        return {}

    def update_identity_provider(self, **kw: Any) -> Mapping[str, Any]:
        self.providers[(kw["UserPoolId"], kw["ProviderName"])].update(kw)
        return {}

    def describe_user_pool_client(self, **kw: Any) -> Mapping[str, Any]:
        return {"UserPoolClient": dict(self.clients[kw["UserPoolId"]])}

    def update_user_pool_client(self, **kw: Any) -> Mapping[str, Any]:
        pool = kw.pop("UserPoolId")
        kw.pop("ClientId")
        self.clients[pool] = kw
        return {}


def test_the_provider_goes_into_both_pools_and_onto_the_app_client() -> None:
    client = {
        "ClientName": "sft-api",
        "SupportedIdentityProviders": ["COGNITO"],
        "CallbackURLs": ["https://api.example/v1/auth/callback"],
        "AllowedOAuthFlows": ["code"],
        "ClientSecret": "never-sent-back",
    }
    cognito = FakeCognito(clients={"tokyo": dict(client), "osaka": dict(client)})
    name = put_cognito(cognito, ["tokyo", "osaka"], "client-1", oidc())  # type: ignore[arg-type]
    assert name == TENANT.hex
    for pool in ("tokyo", "osaka"):
        created = cognito.providers[(pool, name)]
        assert created["ProviderType"] == "OIDC"
        assert created["IdpIdentifiers"] == []  # our sign-in page picks the provider
        assert created["AttributeMapping"]["custom:sso_groups"] == "groups"
        updated = cognito.clients[pool]
        assert updated["SupportedIdentityProviders"] == ["COGNITO", name]
        assert updated["CallbackURLs"] == client["CallbackURLs"]  # nothing else is reset
        assert "ClientSecret" not in updated
    # Run again: the provider is updated in place, and the client isn't touched twice.
    put_cognito(cognito, ["tokyo"], "client-1", oidc())  # type: ignore[arg-type]
    assert cognito.clients["tokyo"]["SupportedIdentityProviders"] == ["COGNITO", name]


def test_a_refusal_names_the_pool_and_the_code_never_the_secret() -> None:
    cognito = FakeCognito(clients={"tokyo": {}}, refuse="InvalidParameterException")
    with pytest.raises(ProviderError) as raised:
        put_cognito(cognito, ["tokyo"], "client-1", oidc())  # type: ignore[arg-type]
    assert str(raised.value) == "pool tokyo: InvalidParameterException"
    assert "test-only-idp-secret" not in str(raised.value)


def test_a_saml_provider_needs_its_metadata_and_maps_the_email() -> None:
    with pytest.raises(ValueError, match="metadata URL"):
        ProviderSpec(tenant_id=TENANT, kind="saml")
    kind, details, mapping = sso_providers.cognito_details(
        ProviderSpec(tenant_id=TENANT, kind="saml", metadata_url="https://idp.example/metadata")
    )
    assert (kind, details["IDPInit"], details["IDPSignout"]) == ("SAML", "false", "false")
    assert mapping["email"].endswith("/emailaddress")


def test_the_local_stand_in_brokers_with_the_identities_mappers() -> None:
    seen: list[tuple[str, str, Any]] = []

    def handle(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        seen.append((request.method, request.url.path, body))
        if request.method == "POST" and request.url.path.endswith("/instances"):
            return httpx.Response(409)  # it exists already: replaced
        if request.method == "PUT":
            return httpx.Response(204)
        if request.method == "GET":
            return httpx.Response(200, json=[{"name": "username"}])
        return httpx.Response(201)

    with httpx.Client(transport=httpx.MockTransport(handle)) as http:
        put_keycloak(http, "http://kc:8080", "sft", "token", oidc())
    put = next(body for method, _, body in seen if method == "PUT")
    assert put["alias"] == TENANT.hex
    assert put["config"]["issuer"] == "https://idp.corp.example"
    added = [body["name"] for method, path, body in seen if path.endswith("/mappers") and body]
    assert added == ["subject", "provider", "groups"]  # "username" was there already


def test_the_command_line_prints_the_name_and_hides_the_secret(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = tmp_path / "secret"
    secret.write_text("test-only-idp-secret\n")
    password = tmp_path / "admin"
    password.write_text("local-only-admin\n")
    calls: list[ProviderSpec] = []
    monkeypatch.setattr(sso_providers, "keycloak_admin_token", lambda *a: "token")
    monkeypatch.setattr(
        sso_providers, "put_keycloak", lambda h, u, r, t, spec: calls.append(spec) or spec.name
    )
    code = sso_providers.main(
        [
            "keycloak",
            "--tenant-id",
            str(TENANT),
            "--issuer",
            "http://oidc:8080/realms/customer",
            "--idp-client-id",
            "sft-pool",
            "--idp-client-secret-file",
            str(secret),
            "--admin-password-file",
            str(password),
        ]
    )
    out = capsys.readouterr()
    assert (code, out.out.strip()) == (0, TENANT.hex)
    assert calls[0].client_secret == "test-only-idp-secret"  # noqa: S105
    assert "test-only-idp-secret" not in out.out + out.err
    assert (
        sso_providers.main(
            ["keycloak", "--tenant-id", str(TENANT), "--admin-password-file", str(password)]
        )
        == 1
    )
