"""The key rotation job (#185; encryption and keys 6.4, 6.5): each keyring's stage, activate and
retire steps, read back by the workloads' own parsers; the app clients' secrets added, written and
the older one deleted after its overlap; the reload through the Kubernetes API; and the AWS
adapters against botocore's Stubber. No value ever reaches a report or a log line."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
import httpx2 as httpx
import pytest
from botocore.config import Config
from botocore.stub import Stubber
from pydantic import ValidationError

from sft.core.hmac_keyrings import CodeKeyring, LinkKeyring
from sft.core.pseudonyms import EmailKeyring
from sft.core.settings import IdpClient, KeyRotationSettings
from sft.runtime.key_rotation import CognitoClientSecrets, KubernetesReloader, SecretsManagerStore
from sft.service.csrf import CsrfKeyring
from sft.service.key_rotation import (
    KEYRINGS,
    ClientSecret,
    KeyRotation,
    RotationError,
    next_keyring,
)
from sft.workers import key_rotation as entry

pytestmark = pytest.mark.anyio

T0 = datetime(2026, 11, 8, 0, 0, tzinfo=UTC)
TOKYO = IdpClient(region="ap-northeast-1", user_pool_id="ap-northeast-1_Tokyo1", client_id="tokyo1")
OSAKA = IdpClient(region="ap-northeast-3", user_pool_id="ap-northeast-3_Osaka1", client_id="osaka1")
POLICY = {p.name: p for p in KEYRINGS}


def states(raw: str) -> list[tuple[str, str]]:
    return [(e["id"], e["state"]) for e in json.loads(raw)]


# --- The keyrings' steps --------------------------------------------------------------------------


@pytest.mark.parametrize("name", list(POLICY))
def test_each_keyring_goes_through_its_steps_and_its_readers_accept_each(name: str) -> None:
    policy = POLICY[name]
    raw, step, first = next_keyring(None, policy, T0) or ("", "", "")
    assert (step, states(raw)) == ("written", [(first, "active")])
    assert next_keyring(raw, policy, T0 + policy.period - timedelta(minutes=1)) is None

    later = T0 + policy.period
    raw, step, staged = next_keyring(raw, policy, later) or ("", "", "")
    assert (step, states(raw)) == ("staged", [(first, "active"), (staged, "staged")])
    assert next_keyring(raw, policy, later + timedelta(minutes=14)) is None

    switch = later + timedelta(minutes=15)
    raw, step, key = next_keyring(raw, policy, switch) or ("", "", "")
    assert (step, key) == ("activated", staged)
    assert states(raw) == [(first, "verify"), (staged, "active")]
    readers = {
        "csrf-hmac": CsrfKeyring.from_json,
        "email-hmac": EmailKeyring.from_json,
        "code-hmac": CodeKeyring.from_json,
        "link-hmac": LinkKeyring.from_json,
    }
    readers[name](raw)  # what the API and the notification worker load

    assert next_keyring(raw, policy, switch + policy.overlap - timedelta(minutes=1)) is None
    retired = next_keyring(raw, policy, switch + policy.overlap)
    if policy.retires:
        assert retired is not None
        assert retired[1:] == ("retired", first)
        assert states(retired[0]) == [(staged, "active")]
    else:  # email-hmac: only when no suppression row uses it, which the job can't see
        assert retired is None


def test_a_keyring_the_workloads_would_refuse_stops_the_run() -> None:
    with pytest.raises(ValueError, match="csrf"):
        next_keyring("[]", POLICY["csrf-hmac"], T0)


# --- One run, with fakes --------------------------------------------------------------------------


@dataclass
class Store:
    values: dict[tuple[str, str], str] = field(default_factory=dict)
    writes: list[str] = field(default_factory=list)

    async def read(self, name: str, *, region: str) -> str | None:
        return self.values.get((region, name))

    async def write(self, name: str, value: str, *, region: str) -> None:
        self.values[(region, name)] = value
        self.writes.append(name)


@dataclass
class Clients:
    live: dict[str, list[ClientSecret]]
    now: datetime = T0
    added: dict[str, int] = field(default_factory=dict)

    async def list(self, client: IdpClient) -> Sequence[ClientSecret]:
        return list(self.live[client.client_id])

    async def add(self, client: IdpClient) -> tuple[ClientSecret, str]:
        assert len(self.live[client.client_id]) < 2, "Cognito holds two client secrets at most"
        n = self.added[client.client_id] = self.added.get(client.client_id, 0) + 1
        secret = ClientSecret(f"{client.client_id}-s{n}", self.now)
        self.live[client.client_id].append(secret)
        return secret, f"value-{n}-" + "v" * 40

    async def delete(self, client: IdpClient, secret_id: str) -> None:
        self.live[client.client_id] = [s for s in self.live[client.client_id] if s.id != secret_id]


@dataclass
class Reloads:
    count: int = 0

    async def reload(self) -> None:
        self.count += 1


@pytest.fixture
def world() -> tuple[KeyRotation, Store, Clients, Reloads]:
    store, reloads = Store(), Reloads()
    made_by_terraform = T0 - timedelta(days=1)
    clients = Clients(
        {
            "tokyo1": [ClientSecret("tokyo1-terraform", made_by_terraform)],
            "osaka1": [ClientSecret("osaka1-terraform", made_by_terraform)],
        }
    )
    rotation = KeyRotation(
        environment="staging",
        region="ap-northeast-1",
        store=store,
        client_secrets=clients,
        clients=[TOKYO, OSAKA],
        reloader=reloads,
    )
    return rotation, store, clients, reloads


async def test_the_first_run_writes_every_secret_and_replaces_the_client_secret_in_state(
    world: tuple[KeyRotation, Store, Clients, Reloads],
) -> None:
    rotation, store, clients, reloads = world
    report = await rotation.run(T0)
    assert sorted(store.writes) == [
        "sft/staging/app/code-hmac",
        "sft/staging/app/csrf-hmac",
        "sft/staging/app/email-hmac",
        "sft/staging/app/idp-client/ap-northeast-1",
        "sft/staging/app/idp-client/ap-northeast-3",
        "sft/staging/app/link-hmac",
    ]
    # Osaka's client secret goes to Osaka's store: it lives only there (6.4).
    assert ("ap-northeast-3", "sft/staging/app/idp-client/ap-northeast-3") in store.values
    tokyo = json.loads(
        store.values[("ap-northeast-1", "sft/staging/app/idp-client/ap-northeast-1")]
    )
    assert (tokyo["client_id"], tokyo["client_secret_id"]) == ("tokyo1", "tokyo1-s1")
    assert reloads.count == 1
    assert "value-" not in repr(report)
    assert "value-" not in json.dumps(report.steps)

    # Nothing is due an hour later; Cognito's own first secret is deleted after the overlap.
    clients.now = T0 + timedelta(minutes=10)
    assert (await rotation.run(T0 + timedelta(minutes=10))).steps == []
    report = await rotation.run(T0 + timedelta(minutes=15))
    assert [s["client_secret_id"] for s in report.steps] == ["tokyo1-terraform"]
    assert [s.id for s in clients.live["tokyo1"]] == ["tokyo1-s1"]
    # Osaka's pods load it on their own schedule, so its older secret stays a day.
    assert [s.id for s in clients.live["osaka1"]] == ["osaka1-terraform", "osaka1-s1"]
    await rotation.run(T0 + timedelta(days=1))
    assert [s.id for s in clients.live["osaka1"]] == ["osaka1-s1"]
    # Only a new client secret in this region restarts the API; a deletion needs no reload.
    assert reloads.count == 1


async def test_a_keyring_step_needs_no_reload(
    world: tuple[KeyRotation, Store, Clients, Reloads],
) -> None:
    """The workloads read the keyrings themselves every 5 minutes (#184): nothing restarts."""
    rotation, _, clients, reloads = world
    await rotation.run(T0)
    clients.now = T0 + timedelta(days=2)
    await rotation.run(T0 + timedelta(days=2))  # the older client secrets go
    reloads.count = 0
    report = await rotation.run(T0 + timedelta(days=91))
    assert {s["step"] for s in report.steps} == {"staged"}
    assert reloads.count == 0


async def test_a_client_secret_a_year_old_is_replaced_keeping_the_stored_one_meanwhile(
    world: tuple[KeyRotation, Store, Clients, Reloads],
) -> None:
    rotation, store, clients, reloads = world
    await rotation.run(T0)
    await rotation.run(T0 + timedelta(days=2))
    year = T0 + timedelta(days=365)
    clients.now = year
    await rotation.run(year)
    assert reloads.count == 2  # the first secret, then the year's: each restarts the API
    assert [s.id for s in clients.live["tokyo1"]] == ["tokyo1-s1", "tokyo1-s2"]
    stored = json.loads(
        store.values[("ap-northeast-1", "sft/staging/app/idp-client/ap-northeast-1")]
    )
    assert stored["client_secret_id"] == "tokyo1-s2"  # noqa: S105 - an ID, not a secret


async def test_a_stored_secret_that_is_no_longer_live_is_replaced(
    world: tuple[KeyRotation, Store, Clients, Reloads],
) -> None:
    rotation, _, clients, _ = world
    clients.live["tokyo1"].append(ClientSecret("tokyo1-other", T0))
    await rotation.run(T0)  # two live, neither stored: the oldest makes room
    assert [s.id for s in clients.live["tokyo1"]] == ["tokyo1-other", "tokyo1-s1"]


# --- The adapters ---------------------------------------------------------------------------------


def stubbed(service: str, region: str = "ap-northeast-1") -> Any:
    return boto3.session.Session().client(
        service,
        config=Config(region_name=region),
        aws_access_key_id="testing",
        aws_secret_access_key="testing",  # noqa: S106
    )


async def test_the_store_reads_a_secret_without_a_value_as_none_and_names_only_codes() -> None:
    client = stubbed("secretsmanager")
    store = SecretsManagerStore({"ap-northeast-1": client})
    with Stubber(client) as stub:
        stub.add_client_error("get_secret_value", "ResourceNotFoundException")
        stub.add_response(
            "get_secret_value", {"SecretString": "[1]"}, {"SecretId": "sft/dev/app/code-hmac"}
        )
        stub.add_response(
            "put_secret_value",
            {},
            {"SecretId": "sft/dev/app/code-hmac", "SecretString": "secret-value"},
        )
        stub.add_client_error("put_secret_value", "AccessDeniedException")
        assert await store.read("sft/dev/app/code-hmac", region="ap-northeast-1") is None
        assert await store.read("sft/dev/app/code-hmac", region="ap-northeast-1") == "[1]"
        await store.write("sft/dev/app/code-hmac", "secret-value", region="ap-northeast-1")
        with pytest.raises(RotationError) as raised:
            await store.write("sft/dev/app/code-hmac", "secret-value", region="ap-northeast-1")
        assert "AccessDeniedException" in str(raised.value)
        assert "secret-value" not in str(raised.value)
        stub.assert_no_pending_responses()


async def test_the_client_secrets_are_listed_added_and_deleted_on_their_own_pool() -> None:
    client = stubbed("cognito-idp")
    secrets = CognitoClientSecrets({"ap-northeast-1": client})
    ids = {"UserPoolId": TOKYO.user_pool_id, "ClientId": TOKYO.client_id}
    with Stubber(client) as stub:
        stub.add_response(
            "list_user_pool_client_secrets",
            {
                "ClientSecrets": [{"ClientSecretId": "a", "ClientSecretCreateDate": T0}],
                "NextToken": "n",
            },
            ids,
        )
        stub.add_response(
            "list_user_pool_client_secrets",
            {"ClientSecrets": [{"ClientSecretId": "b", "ClientSecretCreateDate": T0}]},
            {**ids, "NextToken": "n"},
        )
        stub.add_response(
            "add_user_pool_client_secret",
            {
                "ClientSecretDescriptor": {
                    "ClientSecretId": "c",
                    "ClientSecretValue": "v" * 51,
                    "ClientSecretCreateDate": T0,
                }
            },
            ids,
        )
        stub.add_response("delete_user_pool_client_secret", {}, {**ids, "ClientSecretId": "a"})
        stub.add_client_error("delete_user_pool_client_secret", "LimitExceededException")
        assert [s.id for s in await secrets.list(TOKYO)] == ["a", "b"]
        added, value = await secrets.add(TOKYO)
        assert (added.id, value) == ("c", "v" * 51)
        await secrets.delete(TOKYO, "a")
        with pytest.raises(RotationError, match="LimitExceededException"):
            await secrets.delete(TOKYO, "b")
        stub.assert_no_pending_responses()


def kubernetes(handler: Any) -> KubernetesReloader:
    http = httpx.AsyncClient(
        base_url="https://kubernetes.default.svc", transport=httpx.MockTransport(handler)
    )
    return KubernetesReloader(
        http,
        namespace="sft",
        external_secrets=["api-secrets"],
        deployments=["api", "notifier"],
        token=lambda: "projected-token",
        poll_seconds=0,
        timeout_seconds=1,
    )


async def test_the_reload_syncs_the_external_secrets_then_restarts_the_deployments() -> None:
    calls: list[tuple[str, str, Any]] = []
    syncs = iter([None, datetime.now(UTC) + timedelta(seconds=5)])

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer projected-token"
        body = json.loads(request.content) if request.content else None
        calls.append((request.method, request.url.path, body))
        if request.method == "GET":
            refreshed = next(syncs)
            status: dict[str, Any] = {"conditions": [{"type": "Ready", "status": "True"}]}
            if refreshed is not None:
                status["refreshTime"] = refreshed.isoformat()
            return httpx.Response(200, json={"status": status})
        return httpx.Response(200, json={})

    reloader = kubernetes(handler)
    await reloader.reload()
    await reloader.aclose()
    es = "/apis/external-secrets.io/v1/namespaces/sft/externalsecrets/api-secrets"
    assert [(m, p) for m, p, _ in calls] == [
        ("PATCH", es),
        ("GET", es),
        ("GET", es),
        ("PATCH", "/apis/apps/v1/namespaces/sft/deployments/api"),
        ("PATCH", "/apis/apps/v1/namespaces/sft/deployments/notifier"),
    ]
    assert "force-sync" in calls[0][2]["metadata"]["annotations"]
    template = calls[3][2]["spec"]["template"]["metadata"]["annotations"]
    assert "kubectl.kubernetes.io/restartedAt" in template


async def test_a_refusal_or_a_sync_that_never_comes_fails_the_run() -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={})

    with pytest.raises(RotationError, match="403"):
        await kubernetes(refused).reload()

    def stale(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": {"refreshTime": "2020-01-01T00:00:00Z"}})

    with pytest.raises(RotationError, match="didn't sync"):
        await kubernetes(stale).reload()


# --- Settings and the entry point -----------------------------------------------------------------


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.setenv("ENVIRONMENT", "staging")
    return monkeypatch


def test_the_settings_read_the_clients_and_the_workloads(env: pytest.MonkeyPatch) -> None:
    env.setenv(
        "IDP_CLIENTS",
        json.dumps([TOKYO.model_dump(), OSAKA.model_dump()]),
    )
    env.setenv("RESTART_DEPLOYMENTS", "api, notifier")
    settings = KeyRotationSettings()
    assert settings.idp_clients == [TOKYO, OSAKA]
    assert settings.restart_deployments == ["api", "notifier"]
    env.setenv("RESTART_DEPLOYMENTS", "")
    assert KeyRotationSettings().restart_deployments == []
    env.setenv(
        "IDP_CLIENTS",
        json.dumps(
            [{"region": "ap-northeast-3", "user_pool_id": "ap-northeast-1_X", "client_id": "a"}]
        ),
    )
    with pytest.raises(ValidationError, match="starts with its region"):
        KeyRotationSettings()


def test_bad_settings_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert entry.main() == 2


async def test_a_failed_step_exits_1_and_logs_no_value(
    env: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class Failing:
        async def run(self) -> None:
            raise RotationError("sft/staging/app/csrf-hmac couldn't be written (Throttling)")

    env.setattr(entry, "KeyRotation", lambda **_: Failing())
    env.setenv("RESTART_DEPLOYMENTS", "")
    with caplog.at_level(logging.ERROR):
        assert await entry.run(KeyRotationSettings()) == 1
    [record] = [r for r in caplog.records if r.getMessage().startswith("key rotation failed")]
    assert "Throttling" in record.error  # type: ignore[attr-defined]


async def test_a_run_logs_its_steps(
    env: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class Done:
        async def run(self) -> Any:
            from sft.service.key_rotation import Report

            report = Report()
            report.add("sft/staging/app/csrf-hmac", "written", key_id="k1")
            return report

    env.setattr(entry, "KeyRotation", lambda **_: Done())
    env.setenv("RESTART_DEPLOYMENTS", "api")
    env.setattr(
        KubernetesReloader, "create", classmethod(lambda cls, **_: kubernetes(lambda r: None))
    )
    with caplog.at_level(logging.INFO):
        assert await entry.run(KeyRotationSettings()) == 0
    [record] = [r for r in caplog.records if r.getMessage() == "key rotation done"]
    assert record.steps == [  # type: ignore[attr-defined]
        {"secret": "sft/staging/app/csrf-hmac", "step": "written", "key_id": "k1"}
    ]
