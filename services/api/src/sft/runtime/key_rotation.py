"""The key rotation job's adapters (`sft.service.key_rotation`; encryption and keys 6.4; #185):
Secrets Manager and Cognito in either region, and the Kubernetes API for the reload.

- **Secrets Manager** through the VPC endpoint in Tokyo, and Osaka's endpoint for Osaka's
  idp-client, which lives only there. A secret with no value yet reads as None.
- **Cognito**: `ListUserPoolClientSecrets`, `AddUserPoolClientSecret` and
  `DeleteUserPoolClientSecret` on the two app clients, through the egress proxy (ADR-0021).
- **The reload**: External Secrets syncs the user pool client into the API's Secret, which the
  pods read at start (6.4; the keyrings they read themselves, #184). So after a new client secret
  the job asks each ExternalSecret to sync now (the `force-sync` annotation), waits until each
  has, then restarts each Deployment as `kubectl rollout restart` does. Its Kubernetes token is
  projected for 10 minutes, and its Role may only read and annotate those ExternalSecrets and
  patch those Deployments, by name (deploy/charts).

boto3 is synchronous, so each AWS call runs in a worker thread. Errors name AWS's error code or
the HTTP status, never a value.
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

import boto3
import httpx2 as httpx
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from sft.core.settings import IdpClient
from sft.core.telemetry import trace_aws_client
from sft.service.key_rotation import ClientSecret, RotationError

if TYPE_CHECKING:
    from types_boto3_cognito_idp.client import CognitoIdentityProviderClient
    from types_boto3_secretsmanager.client import SecretsManagerClient

SYNC_TIMEOUT_SECONDS: Final = 300
SYNC_POLL_SECONDS: Final = 5.0


def _code(exc: ClientError) -> str:
    return str(exc.response.get("Error", {}).get("Code", "ClientError"))


def _config(region: str) -> Config:
    return Config(
        region_name=region,
        connect_timeout=2,
        read_timeout=10,
        retries={"mode": "standard", "max_attempts": 3},
    )


async def _call[T](fn: Callable[..., T], /, **kwargs: object) -> T:
    return await asyncio.to_thread(functools.partial(fn, **kwargs))


class SecretsManagerStore:
    """The `sft/<env>/app/*` secrets, by region."""

    def __init__(self, clients: dict[str, SecretsManagerClient]) -> None:
        self._clients = clients

    @classmethod
    def create(cls, regions: Sequence[str]) -> SecretsManagerStore:
        session = boto3.session.Session()
        clients = {}
        for region in regions:
            client = session.client("secretsmanager", config=_config(region))
            trace_aws_client(client)
            clients[region] = client
        return cls(clients)

    async def read(self, name: str, *, region: str) -> str | None:
        try:
            found = await _call(self._clients[region].get_secret_value, SecretId=name)
        except ClientError as exc:
            # A secret Terraform made has no version until the job's first write.
            if _code(exc) == "ResourceNotFoundException":
                return None
            raise RotationError(f"{name} couldn't be read ({_code(exc)})") from None
        except BotoCoreError as exc:
            raise RotationError(f"{name} couldn't be read ({type(exc).__name__})") from None
        return found.get("SecretString")

    async def write(self, name: str, value: str, *, region: str) -> None:
        try:
            await _call(self._clients[region].put_secret_value, SecretId=name, SecretString=value)
        except ClientError as exc:
            raise RotationError(f"{name} couldn't be written ({_code(exc)})") from None
        except BotoCoreError as exc:
            raise RotationError(f"{name} couldn't be written ({type(exc).__name__})") from None


class CognitoClientSecrets:
    """The app clients' secrets, each through its own region's Cognito."""

    def __init__(self, clients: dict[str, CognitoIdentityProviderClient]) -> None:
        self._clients = clients

    @classmethod
    def create(cls, regions: Sequence[str]) -> CognitoClientSecrets:
        session = boto3.session.Session()
        clients = {}
        for region in regions:
            client = session.client("cognito-idp", config=_config(region))
            trace_aws_client(client)
            clients[region] = client
        return cls(clients)

    async def _do(self, what: str, fn: Callable[..., Any], /, **kwargs: object) -> Any:
        try:
            return await _call(fn, **kwargs)
        except ClientError as exc:
            raise RotationError(f"the app client's secrets: {what} failed ({_code(exc)})") from None
        except BotoCoreError as exc:
            raise RotationError(
                f"the app client's secrets: {what} failed ({type(exc).__name__})"
            ) from None

    async def list(self, client: IdpClient) -> Sequence[ClientSecret]:
        cognito, found, token = self._clients[client.region], [], None
        while True:
            more: dict[str, str] = {} if token is None else {"NextToken": token}
            page = await self._do(
                "list",
                cognito.list_user_pool_client_secrets,
                UserPoolId=client.user_pool_id,
                ClientId=client.client_id,
                **more,
            )
            found += [
                ClientSecret(s["ClientSecretId"], s["ClientSecretCreateDate"])
                for s in page.get("ClientSecrets", [])
            ]
            token = page.get("NextToken")
            if not token:
                return found

    async def add(self, client: IdpClient) -> tuple[ClientSecret, str]:
        added = await self._do(
            "add",
            self._clients[client.region].add_user_pool_client_secret,
            UserPoolId=client.user_pool_id,
            ClientId=client.client_id,
        )
        descriptor = added["ClientSecretDescriptor"]
        return (
            ClientSecret(descriptor["ClientSecretId"], descriptor["ClientSecretCreateDate"]),
            descriptor["ClientSecretValue"],
        )

    async def delete(self, client: IdpClient, secret_id: str) -> None:
        await self._do(
            "delete",
            self._clients[client.region].delete_user_pool_client_secret,
            UserPoolId=client.user_pool_id,
            ClientId=client.client_id,
            ClientSecretId=secret_id,
        )


class KubernetesReloader:
    """Sync the ExternalSecrets now, then restart the Deployments that read them."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        *,
        namespace: str,
        external_secrets: Sequence[str],
        deployments: Sequence[str],
        token: Callable[[], str],
        poll_seconds: float = SYNC_POLL_SECONDS,
        timeout_seconds: float = SYNC_TIMEOUT_SECONDS,
    ) -> None:
        self._http = http
        self._namespace = namespace
        self._external_secrets = external_secrets
        self._deployments = deployments
        self._token = token
        self._poll = poll_seconds
        self._timeout = timeout_seconds

    @classmethod
    def create(
        cls,
        *,
        url: str,
        token_path: str,
        ca_path: str,
        namespace: str,
        external_secrets: Sequence[str],
        deployments: Sequence[str],
    ) -> KubernetesReloader:
        http = httpx.AsyncClient(base_url=url, verify=ca_path, timeout=10.0)
        return cls(
            http,
            namespace=namespace,
            external_secrets=external_secrets,
            deployments=deployments,
            # Read at each call: the kubelet renews the projected token before it expires.
            token=lambda: Path(token_path).read_text().strip(),
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._token()}", **kwargs.pop("headers", {})}
        try:
            response = await self._http.request(method, path, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise RotationError(
                f"the Kubernetes API can't be reached ({type(exc).__name__})"
            ) from None
        if response.status_code >= 400:
            raise RotationError(
                f"the Kubernetes API refused {method} {path} ({response.status_code})"
            )
        body: dict[str, Any] = response.json()
        return body

    def _external_secret(self, name: str) -> str:
        return f"/apis/external-secrets.io/v1/namespaces/{self._namespace}/externalsecrets/{name}"

    async def reload(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        stamp = now.isoformat().replace("+00:00", "Z")
        merge = {"Content-Type": "application/merge-patch+json"}
        for name in self._external_secrets:
            await self._request(
                "PATCH",
                self._external_secret(name),
                headers=merge,
                json={"metadata": {"annotations": {"force-sync": stamp}}},
            )
        await self._synced(now)
        for name in self._deployments:
            await self._request(
                "PATCH",
                f"/apis/apps/v1/namespaces/{self._namespace}/deployments/{name}",
                headers={"Content-Type": "application/strategic-merge-patch+json"},
                json={
                    "spec": {
                        "template": {
                            "metadata": {
                                "annotations": {"kubectl.kubernetes.io/restartedAt": stamp}
                            }
                        }
                    }
                },
            )

    async def _synced(self, since: datetime) -> None:
        waiting = list(self._external_secrets)
        deadline = asyncio.get_running_loop().time() + self._timeout
        while waiting:
            for name in list(waiting):
                status = (await self._request("GET", self._external_secret(name))).get("status", {})
                if _refreshed(status, since):
                    waiting.remove(name)
            if not waiting:
                return
            if asyncio.get_running_loop().time() >= deadline:
                raise RotationError(f"External Secrets didn't sync {', '.join(waiting)} in time")
            await asyncio.sleep(self._poll)


def _refreshed(status: dict[str, Any], since: datetime) -> bool:
    """Whether the ExternalSecret synced at or after `since`, and is ready."""
    refreshed = status.get("refreshTime")
    ready = any(
        c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", [])
    )
    if not ready or not isinstance(refreshed, str):
        return False
    try:
        return datetime.fromisoformat(refreshed) >= since
    except ValueError:
        return False
