"""The user pools' providers, as the daily SSO drift check reads them (#239; authn and authz 2.5).

The adapter behind `sft.service.sso_drift.ProviderDirectory`, for Cognito: in each pool,
`ListIdentityProviders`, then `DescribeIdentityProvider` for each one, and
`DescribeUserPoolClient` for the app client's providers. Read only: the operator API's role may
call these three on the two pools and nothing else of Cognito (authn and authz 2.5); the CLI, with
the operator's own credentials, is what changes providers. Osaka's pool is read through Osaka's
endpoint. A provider's client secret is in `ProviderDetails` and is never kept, logged or
compared: only the issuer is read from it.

The local stack has no drift check: Keycloak plays a single pool there, and `SSO_DRIFT_POOLS` is
empty, so the operator API doesn't start it. boto3 is synchronous, so the calls run in a thread.
Pending the AWS run.
"""

from __future__ import annotations

import asyncio
import contextvars
from collections.abc import Mapping, Sequence
from typing import Any

from sft.core.settings import IdpClient
from sft.service.sso_drift import PoolProvider, PoolRegion, PoolSnapshot


def provider_of(described: Mapping[str, Any]) -> PoolProvider:
    """`DescribeIdentityProvider`'s `IdentityProvider`, without its secrets."""
    details = described.get("ProviderDetails") or {}
    return PoolProvider(
        name=str(described.get("ProviderName") or ""),
        type=str(described.get("ProviderType") or ""),
        issuer=details.get("oidc_issuer"),
        attribute_mapping=dict(described.get("AttributeMapping") or {}),
        identifiers=tuple(described.get("IdpIdentifiers") or ()),
    )


class CognitoProviderDirectory:
    """Both pools, each with its app client; credentials from the pod's role."""

    def __init__(
        self, pools: Sequence[IdpClient], clients: Mapping[str, Any] | None = None
    ) -> None:
        self._pools = {PoolRegion(p.region): p for p in pools}
        self._clients = dict(clients or {})

    @property
    def pools(self) -> Sequence[PoolRegion]:
        return tuple(self._pools)

    def _client(self, pool: PoolRegion) -> Any:
        if pool.value not in self._clients:  # pragma: no cover - AWS
            import boto3
            from botocore.config import Config

            from sft.core.telemetry import trace_aws_client

            config = Config(region_name=pool.value, connect_timeout=2, read_timeout=5)
            client = boto3.session.Session().client("cognito-idp", config=config)
            trace_aws_client(client)
            self._clients[pool.value] = client
        return self._clients[pool.value]

    async def snapshot(self, pool: PoolRegion) -> PoolSnapshot:
        call = contextvars.copy_context().run
        return await asyncio.to_thread(call, self._read, pool)

    def _read(self, pool: PoolRegion) -> PoolSnapshot:
        client, settings = self._client(pool), self._pools[pool]
        names: list[str] = []
        token: str | None = None
        while True:
            page = client.list_identity_providers(
                UserPoolId=settings.user_pool_id,
                MaxResults=60,
                **({"NextToken": token} if token else {}),
            )
            names += [str(p["ProviderName"]) for p in page.get("Providers", [])]
            token = page.get("NextToken")
            if not token:
                break
        providers = {}
        for name in names:
            described = client.describe_identity_provider(
                UserPoolId=settings.user_pool_id, ProviderName=name
            )["IdentityProvider"]
            providers[name] = provider_of(described)
        app = client.describe_user_pool_client(
            UserPoolId=settings.user_pool_id, ClientId=settings.client_id
        )["UserPoolClient"]
        return PoolSnapshot(providers, frozenset(app.get("SupportedIdentityProviders") or ()))


__all__ = ["CognitoProviderDirectory", "provider_of"]
