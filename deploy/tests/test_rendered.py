"""Checks every rendered manifest against the runtime contract (architecture 8) and the pod rules of ADR-0004.

Renders every cluster with deploy/render.sh (helm on PATH), the way Argo CD will, then inspects the objects. Run from
the repository root: `uv run --project services/api --locked pytest deploy/tests` (`make deploy-check` does it all).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
import yaml
from pydantic_settings import BaseSettings
from sft.core.settings import (
    ArchiveJobSettings,
    InspectorSettings,
    JobSettings,
    KeyRotationSettings,
    MigrationSettings,
    NotifySettings,
    OperatorSettings,
    RelaySettings,
    ScanSettings,
    Settings,
)
from sft.probe.settings import ProbeSettings

ROOT = Path(__file__).resolve().parents[2]
CLUSTERS = [
    ("dev", "ap-northeast-1"),
    ("staging", "ap-northeast-1"),
    ("staging", "ap-northeast-3"),
    ("prod", "ap-northeast-1"),
    ("prod", "ap-northeast-3"),
]
OSAKA = "ap-northeast-3"
PARTS = {"application": "sft", "operator": "sft-operator"}
POD_KINDS = {"Deployment", "CronJob", "Job"}
DIGEST = re.compile(
    r"^[0-9]{12}\.dkr\.ecr\.(ap-northeast-[13])\.amazonaws\.com/(sft/app|mirror/[a-z0-9./-]+)@sha256:[0-9a-f]{64}$"
)
INTERNAL_PORT = 8001
# Workloads that hold no AWS identity and never touch the database (ADR-0019, ADR-0022).
NO_IDENTITY = {"clamd", "dlp-inspector", "signature-mirror"}
# Only these reach the internet, through their own egress proxy listener (ADR-0021).
PROXIED = {
    "api": 3128,
    "notifier": 3129,
    "invite-backlog": 3129,
    "key-rotation": 3133,
    "synthetic-probe": 3134,
}
# The DLP inspector speaks its own framed protocol, one file per connection, on a port of its own (ADR-0022); its
# probes are on the internal port like everyone's (#184).
OWN_PORT = {"dlp-inspector": "inspector"}
# The entry points that exist today and the settings each reads at startup (sft.core.settings).
SETTINGS: dict[str, type[BaseSettings]] = {
    "sft.api": Settings,
    "sft.api.operator": OperatorSettings,
    "sft.workers.relay": RelaySettings,
    "sft.data.migrate": MigrationSettings,
    "sft.dlp.inspector": InspectorSettings,
    "sft.workers.scan": ScanSettings,
    "sft.workers.notify": NotifySettings,
    "sft.workers.invite_backlog": NotifySettings,  # the notification worker's one-off pass (#193)
    "sft.workers.key_rotation": KeyRotationSettings,
    # The lifecycle jobs (#181), one module per CronJob, all reading JobSettings.
    "sft.workers.expiry": JobSettings,
    "sft.workers.deletion": JobSettings,
    "sft.workers.reconciliation": JobSettings,
    "sft.workers.storage_audit": JobSettings,
    "sft.workers.cleanup": JobSettings,
    "sft.workers.purge": JobSettings,  # #224
    "sft.workers.audit_partitions": JobSettings,
    "sft.workers.audit_archive": ArchiveJobSettings,  # #183
    "sft.probe": ProbeSettings,  # #248, rendered on here (the fixture)
}
REGION_SHORT = {"ap-northeast-1": "apne1", "ap-northeast-3": "apne3"}

Manifest = dict[str, Any]


@pytest.fixture(scope="session")
def rendered(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[tuple[str, str, str], list[Manifest]]:
    out = tmp_path_factory.mktemp("rendered")
    # The synthetic probe is off by default until each environment's AWS side exists (#248): rendered on here, so its
    # pod, policy and identity are checked like every other workload's before a values file turns it on.
    subprocess.run(
        [str(ROOT / "deploy" / "render.sh"), str(out)],
        check=True,
        capture_output=True,
        env={**os.environ, "SFT_RENDER_SET": "probe.enabled=true"},
    )
    result = {}
    for env, region in CLUSTERS:
        for part in [*PARTS, "argocd"]:
            text = (out / f"{env}-{region}-{part}.yaml").read_text()
            result[(env, region, part)] = [d for d in yaml.safe_load_all(text) if d]
    return result


def chart_objects(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> Iterator[tuple[str, str, str, Manifest]]:
    for (env, region, part), objects in rendered.items():
        if part in PARTS:
            for obj in objects:
                yield env, region, part, obj


def pod_spec(obj: Manifest) -> Manifest:
    if obj["kind"] == "CronJob":
        return obj["spec"]["jobTemplate"]["spec"]["template"]["spec"]
    return obj["spec"]["template"]["spec"]


def pod_labels(obj: Manifest) -> dict[str, str]:
    template = (
        obj["spec"]["jobTemplate"]["spec"]["template"]
        if obj["kind"] == "CronJob"
        else obj["spec"]["template"]
    )
    return dict(template["metadata"]["labels"])


def pods(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> Iterator[tuple[str, str, str, Manifest]]:
    for env, region, part, obj in chart_objects(rendered):
        if obj["kind"] in POD_KINDS:
            yield env, region, part, obj


def component(obj: Manifest) -> str:
    return str(obj["metadata"]["labels"]["app.kubernetes.io/component"])


def env_of(container: Manifest) -> dict[str, str]:
    """Plain settings by name; one from a Secret shows as `secret:<name>/<key>`."""
    result = {}
    for e in container.get("env", []):
        if "value" in e:
            result[e["name"]] = e["value"]
        else:
            ref = e["valueFrom"]["secretKeyRef"]
            result[e["name"]] = f"secret:{ref['name']}/{ref['key']}"
    return result


def runs_our_module(container: Manifest) -> bool:
    """A server or job of ours: `python -m sft....`, which follows architecture 8 itself."""
    command = container.get("command", [])
    return command[:2] == ["python", "-m"] and command[2].startswith("sft.")


def test_every_cluster_renders_both_parts(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    for env, region in CLUSTERS:
        for part, namespace in PARTS.items():
            objects = rendered[(env, region, part)]
            assert objects, (env, region, part)
            assert {o["metadata"]["namespace"] for o in objects} == {namespace}


def test_every_pod_is_hardened(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """Architecture 8's security row and Pod Security Admission at restricted (ADR-0004)."""
    for env, region, _, obj in pods(rendered):
        where = (env, region, obj["kind"], obj["metadata"]["name"])
        spec = pod_spec(obj)
        assert spec["enableServiceLinks"] is False, where  # architecture 8, Config
        assert spec["automountServiceAccountToken"] is False, where
        for forbidden in ("hostNetwork", "hostPID", "hostIPC", "hostUsers"):
            assert not spec.get(forbidden), where
        security = spec["securityContext"]
        assert security["runAsNonRoot"] is True, where
        assert security["runAsUser"] > 0, where
        assert security["seccompProfile"]["type"] == "RuntimeDefault", where
        assert all("hostPath" not in volume for volume in spec.get("volumes", [])), (
            where
        )
        # Never on, or tolerating, the system pool (#103, #104).
        assert spec["nodeSelector"].get("sft.io/pool") in {"main", "scan"}, where
        for toleration in spec.get("tolerations", []):
            assert (
                toleration.get("key") == "sft.io/pool"
                and toleration.get("value") == "scan"
            ), where
        for container in spec["containers"] + spec.get("initContainers", []):
            where_c = (*where, container["name"])
            context = container["securityContext"]
            assert context["readOnlyRootFilesystem"] is True, where_c
            assert context["allowPrivilegeEscalation"] is False, where_c
            assert context.get("privileged") is not True, where_c
            assert context["capabilities"]["drop"] == ["ALL"], where_c
            assert "add" not in context["capabilities"], where_c
            match = DIGEST.match(container["image"])
            assert match, where_c  # by digest, from our registry (ADR-0007)
            assert match.group(1) == region, (
                where_c
            )  # Osaka pulls from the Osaka replica
            assert all("hostPort" not in port for port in container.get("ports", [])), (
                where_c
            )
            resources = container["resources"]
            assert {"cpu", "memory"} <= resources["requests"].keys(), where_c
            assert "memory" in resources["limits"], where_c
        for container in spec["containers"]:  # a writable /tmp on the read-only root
            assert any(m["mountPath"] == "/tmp" for m in container["volumeMounts"]), (
                *where,
                container["name"],
            )


def test_every_server_follows_the_runtime_contract(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """Probes on the internal port, liveness on /healthz and readiness on /readyz (architecture 8)."""
    seen = set()
    for env, region, _, obj in pods(rendered):
        if obj["kind"] != "Deployment":
            continue
        spec = pod_spec(obj)
        for container in spec["containers"]:
            where = (env, region, obj["metadata"]["name"], container["name"])
            if container.get("ports"):
                assert "livenessProbe" in container and "readinessProbe" in container, (
                    where
                )
            if not runs_our_module(container):
                continue
            seen.add(component(obj))
            ports = {p["name"]: p["containerPort"] for p in container["ports"]}
            assert ports["internal"] == INTERNAL_PORT, where
            if component(obj) in OWN_PORT:
                assert set(ports) == {OWN_PORT[component(obj)], "internal"}, where
                assert env_of(container)["INSPECTOR_PORT"] == str(ports["inspector"])
            else:
                assert set(ports) <= {"http", "internal"}, where
            assert container["livenessProbe"]["httpGet"] == {
                "path": "/healthz",
                "port": "internal",
            }, where
            assert container["readinessProbe"]["httpGet"] == {
                "path": "/readyz",
                "port": "internal",
            }, where
            assert container["startupProbe"]["httpGet"]["port"] == "internal", where
            assert env_of(container)["BIND_HOST"] == "0.0.0.0", where
    assert seen == {
        "api",
        "relay",
        "notifier",
        "scan-worker",
        "dlp-inspector",
        "operator-api",
    }


def test_shutdown_fits_the_grace_period(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """preStop sleep, then the drain, inside the grace period; the API's is 150 s (architecture 8, abuse 5.7)."""
    for env, region, _, obj in pods(rendered):
        if obj["kind"] != "Deployment":
            continue
        spec = pod_spec(obj)
        grace = spec["terminationGracePeriodSeconds"]
        if component(obj) == "api":
            assert grace == 150, (env, region)
        for container in spec["containers"]:
            sleep = (
                container.get("lifecycle", {})
                .get("preStop", {})
                .get("sleep", {})
                .get("seconds", 0)
            )
            drain = (
                int(env_of(container).get("SHUTDOWN_DRAIN_SECONDS", "20"))
                if runs_our_module(container)
                else 0
            )
            assert sleep + drain < grace, (
                env,
                region,
                obj["metadata"]["name"],
                container["name"],
            )
            if component(obj) in {
                "api",
                "operator-api",
            }:  # behind a Service or port-forward
                assert sleep > 0, (env, region, obj["metadata"]["name"])


def test_api_service_exposes_only_its_ports(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    for env, region, _, obj in chart_objects(rendered):
        if obj["kind"] == "Service":
            assert obj["spec"]["type"] == "ClusterIP", (
                env,
                region,
                obj["metadata"]["name"],
            )
            if obj["metadata"]["name"] == "api":
                assert {p["port"] for p in obj["spec"]["ports"]} == {
                    8000,
                    INTERNAL_PORT,
                }
            if obj["metadata"]["name"] in {"clamd", "dlp-inspector"}:
                assert (
                    obj["spec"]["internalTrafficPolicy"] == "Local"
                )  # the engines beside the worker
    for env, region in CLUSTERS:
        bindings = [
            o
            for o in rendered[(env, region, "application")]
            if o["kind"] == "TargetGroupBinding"
        ]
        # The load balancer is Terraform's (#105): no Ingress or LoadBalancer Service, only the API's targets.
        assert [b["spec"]["serviceRef"] for b in bindings] == [
            {"name": "api", "port": 8000}
        ], (env, region)
        assert bindings[0]["spec"]["targetType"] == "ip"
        # By name, the edge stack's sft-<env>-<region-short>-api (#105): the controller may register only there.
        assert (
            bindings[0]["spec"]["targetGroupName"]
            == f"sft-{env}-{REGION_SHORT[region]}-api"
        )
        assert "targetGroupARN" not in bindings[0]["spec"]
        kinds = {o["kind"] for part in PARTS for o in rendered[(env, region, part)]}
        assert "Ingress" not in kinds and "Secret" not in kinds


def test_identities_and_settings(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """IAM database logins carry no password; the engines have no database; only the API and notifier are proxied."""
    for (env, region, part), objects in rendered.items():
        if part not in PARTS:
            continue
        accounts = {
            o["metadata"]["name"]: o for o in objects if o["kind"] == "ServiceAccount"
        }
        assert all(
            a["automountServiceAccountToken"] is False for a in accounts.values()
        )
        for obj in objects:
            if obj["kind"] not in POD_KINDS:
                continue
            spec = pod_spec(obj)
            assert spec["serviceAccountName"] in accounts, (
                env,
                region,
                obj["metadata"]["name"],
            )
            name = component(obj)
            for container in spec["containers"]:
                settings = env_of(container)
                for key in ("DATABASE_URL", "MIGRATION_DATABASE_URL"):
                    if key in settings:
                        assert re.match(
                            r"^postgresql://sft_[a-z]+@[^:@/]+:5432/sft\?sslmode=verify-full$",
                            settings[key],
                        )
                if name in NO_IDENTITY:
                    assert spec["serviceAccountName"] == name
                    assert not {"DATABASE_URL", "HTTPS_PROXY"} & settings.keys()
                if name in PROXIED:
                    assert settings["HTTPS_PROXY"].endswith(f":{PROXIED[name]}")
                    assert "cognito" not in settings["NO_PROXY"]
                    # The probe calls no AWS service through an interface endpoint: S3 by its gateway, CloudWatch
                    # through its listener, everything else through the public API (#248).
                    if name != "synthetic-probe":
                        assert f"sqs.{region}.amazonaws.com" in settings[
                            "NO_PROXY"
                        ].split(",")
                else:
                    assert "HTTPS_PROXY" not in settings, (env, region, name)


def test_every_workload_has_a_pdb_and_its_own_network_policy(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    for (env, region, part), objects in rendered.items():
        if part not in PARTS:
            continue
        policies = {
            o["metadata"]["name"]: o for o in objects if o["kind"] == "NetworkPolicy"
        }
        assert policies["default-deny"]["spec"] == {
            "podSelector": {},
            "policyTypes": ["Ingress", "Egress"],
        }
        pdbs = [
            o["spec"]["selector"]["matchLabels"]
            for o in objects
            if o["kind"] == "PodDisruptionBudget"
        ]
        for obj in objects:
            if obj["kind"] not in POD_KINDS:
                continue
            labels = pod_labels(obj)
            selected = [
                n
                for n, p in policies.items()
                if n != "default-deny"
                and p["spec"]["podSelector"]["matchLabels"].items() <= labels.items()
            ]
            assert len(selected) == 1, (env, region, obj["metadata"]["name"], selected)
            if obj["kind"] == "Deployment":
                assert obj["spec"]["selector"]["matchLabels"].items() <= labels.items()
                assert any(s == obj["spec"]["selector"]["matchLabels"] for s in pdbs), (
                    obj["metadata"]["name"]
                )
        if part == "application":
            inspector = policies["dlp-inspector"]["spec"]
            assert (
                inspector["egress"] == []
            )  # no egress at all, not even DNS (ADR-0022)
            sources = [
                peer["podSelector"]["matchLabels"]
                for rule in inspector["ingress"]
                for peer in rule["from"]
            ]
            assert sources == [
                {
                    "app.kubernetes.io/name": "sft",
                    "app.kubernetes.io/component": "scan-worker",
                }
            ]
            clamd_out = policies["clamd"]["spec"]["egress"]
            assert all(
                "ipBlock" not in peer for rule in clamd_out for peer in rule["to"]
            )  # only DNS and the mirror


def test_pilot_light(rendered: dict[tuple[str, str, str], list[Manifest]]) -> None:
    """Osaka: nothing runs, jobs are suspended, and no migration touches the read-only replica (architecture 3.2)."""
    for env, region, _, obj in pods(rendered):
        osaka = region == OSAKA
        if obj["kind"] == "Deployment":
            assert (obj["spec"]["replicas"] == 0) == osaka, (
                env,
                region,
                obj["metadata"]["name"],
            )
        if obj["kind"] == "CronJob" and obj["metadata"]["name"] == "invite-backlog":
            assert obj["spec"]["suspend"] is True  # run by hand, once (#193)
        elif obj["kind"] == "CronJob":
            assert obj["spec"]["suspend"] is osaka
            assert obj["spec"]["concurrencyPolicy"] == "Forbid"
    for env, region in CLUSTERS:
        objects = rendered[(env, region, "application")]
        jobs = [o for o in objects if o["kind"] == "Job"]
        if region == OSAKA:
            assert jobs == []
        else:
            (job,) = jobs
            assert (
                job["metadata"]["annotations"]["argocd.argoproj.io/hook"] == "PreSync"
            )  # ADR-0005
            assert pod_spec(job)["containers"][0]["command"] == [
                "python",
                "-m",
                "sft.data.migrate",
            ]
            hooks = [
                o
                for o in objects
                if o["kind"] == "ServiceAccount" and o["metadata"].get("annotations")
            ]
            assert [h["metadata"]["name"] for h in hooks] == [
                pod_spec(job)["serviceAccountName"]
            ]


def test_one_image_per_cluster(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """The API and every worker come from one image (architecture 2), the digest of the cluster's values file."""
    for env, region in CLUSTERS:
        digest = yaml.safe_load(
            (
                ROOT / "deploy" / "environments" / env / region / "values.yaml"
            ).read_text()
        )
        images = {
            c["image"]
            for part in PARTS
            for o in rendered[(env, region, part)]
            if o["kind"] in POD_KINDS
            for c in pod_spec(o)["containers"]
            if "/sft/app@" in c["image"]
        }
        assert {image.split("@")[1] for image in images} == {digest["image"]["digest"]}


@pytest.mark.parametrize(("env", "region"), CLUSTERS)
def test_values_file_keeps_the_promotion_shape(env: str, region: str) -> None:
    """The promotion workflow (#107) edits one line: `  digest: sha256:<64 hex>` inside the top-level image block."""
    lines = (
        (ROOT / "deploy" / "environments" / env / region / "values.yaml")
        .read_text()
        .splitlines()
    )
    start = lines.index("image:")
    block = []
    for line in lines[start + 1 :]:
        if line and not line.startswith(" "):
            break
        block.append(line)
    assert (
        len(
            [
                line
                for line in block
                if re.match(r"^  digest: sha256:[0-9a-f]{64}( +#.*)?$", line)
            ]
        )
        == 1
    )


def test_argo_cd_applications(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """Argo CD syncs main only, auto-sync with prune and self-heal, restricted namespaces (ADR-0004, ADR-0005)."""
    for env, region in CLUSTERS:
        objects = rendered[(env, region, "argocd")]
        (project,) = [o for o in objects if o["kind"] == "AppProject"]
        assert project["spec"]["clusterResourceWhitelist"] == [
            {"group": "", "kind": "Namespace"}
        ]
        assert {"group": "", "kind": "Secret"} not in project["spec"][
            "namespaceResourceWhitelist"
        ]
        apps = {o["metadata"]["name"]: o for o in objects if o["kind"] == "Application"}
        assert set(apps) == {"sft", "sft-operator"}
        for name, app in apps.items():
            source = app["spec"]["source"]
            assert source["targetRevision"] == "main"
            assert (
                source["repoURL"]
                == "https://github.com/codewithmuh/secure-file-transfer.git"
            )
            for values in source["helm"]["valueFiles"]:
                assert (ROOT / source["path"] / values).resolve() == (
                    ROOT / "deploy" / "environments" / env / region / "values.yaml"
                )
            assert source["helm"]["valuesObject"]["part"] == (
                "application" if name == "sft" else "operator"
            )
            assert app["spec"]["destination"]["namespace"] == name
            assert app["spec"]["syncPolicy"]["automated"] == {
                "prune": True,
                "selfHeal": True,
            }
            labels = app["spec"]["syncPolicy"]["managedNamespaceMetadata"]["labels"]
            assert labels["pod-security.kubernetes.io/enforce"] == "restricted"


def test_every_entry_point_gets_its_required_settings(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """Every setting without a default (sft.core.settings) is in the pod spec, so no pod stops at startup for one."""
    seen = set()
    for env, region, _, obj in pods(rendered):
        for container in pod_spec(obj)["containers"]:
            if (
                not runs_our_module(container)
                or container["command"][2] not in SETTINGS
            ):
                continue
            module = container["command"][2]
            seen.add(module)
            fields = SETTINGS[module].model_fields
            required = {
                name.upper() for name, field in fields.items() if field.is_required()
            }
            settings = env_of(container)
            missing = required - settings.keys()
            assert not missing, (env, region, obj["metadata"]["name"], sorted(missing))
            unknown = {
                name
                for name in settings
                # The proxy variables and AWS_REGION are read by the HTTP client and the AWS SDK, not by our settings.
                if name.lower() not in fields
                and name not in {"HTTPS_PROXY", "NO_PROXY", "AWS_REGION"}
            }
            assert not unknown, (env, region, obj["metadata"]["name"], sorted(unknown))
            # Secrets only from the External Secrets Secret or named in Secrets Manager, never a value (encryption 6.4).
            for name, field in fields.items():
                if field.annotation is not None and "SecretStr" in str(
                    field.annotation
                ):
                    value = settings.get(name.upper(), "")
                    if name.upper().endswith(("DATABASE_URL", "VALKEY_URL")):
                        continue  # IAM authentication: the URL holds a user, never a password
                    if name.upper().endswith("_KEYRING"):
                        # The process reads the keyring itself, every 5 minutes (#184).
                        assert value.startswith(f"secretsmanager:sft/{env}/app/"), (
                            module,
                            name,
                        )
                        continue
                    assert value.startswith("secret:") or not value, (module, name)
    assert seen == set(SETTINGS)


def test_keyrings_are_read_from_secrets_manager_and_the_client_through_external_secrets(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """The API and the notification worker read their keyrings from Secrets Manager themselves, every 5 minutes, so a
    rotation needs no restart (encryption 6.4, #184); only the API's user pool client comes through External Secrets,
    and the synthetic tenant's API key for the probe (#248)."""
    for env, region in CLUSTERS:
        objects = rendered[(env, region, "application")]
        externals = {
            o["metadata"]["name"]: o["spec"]
            for o in objects
            if o["kind"] == "ExternalSecret"
        }
        assert set(externals) == {"api-secrets", "probe-secrets"}
        assert externals["probe-secrets"]["secretStoreRef"] == {
            "kind": "ClusterSecretStore",
            "name": "application-secrets",
        }
        assert [d["remoteRef"] for d in externals["probe-secrets"]["data"]] == [
            {"key": f"sft/{env}/app/probe-api-key", "property": "api_key"}
        ]
        spec = externals["api-secrets"]
        assert spec["secretStoreRef"] == {
            "kind": "ClusterSecretStore",
            "name": "application-secrets",
        }
        keys = {d["secretKey"]: d["remoteRef"] for d in spec["data"]}
        # Each region's API reads only its own user pool's client (encryption 6.1).
        assert keys == {
            "OIDC_CLIENT_ID": {
                "key": f"sft/{env}/app/idp-client/{region}",
                "property": "client_id",
            },
            "OIDC_CLIENT_SECRET": {
                "key": f"sft/{env}/app/idp-client/{region}",
                "property": "client_secret",
            },
        }
        containers = {
            component(o): pod_spec(o)["containers"][0]
            for o in objects
            if o["kind"] == "Deployment" and component(o) in {"api", "notifier"}
        }
        api, notifier = env_of(containers["api"]), env_of(containers["notifier"])
        ref = f"secretsmanager:sft/{env}/app"
        assert {k: v for k, v in api.items() if k.endswith("_KEYRING")} == {
            "CSRF_KEYRING": f"{ref}/csrf-hmac",
            "EMAIL_HMAC_KEYRING": f"{ref}/email-hmac",
            "CODE_HMAC_KEYRING": f"{ref}/code-hmac",
        }  # never K_link: only the notification worker derives links (data model 2.2)
        # The environment of the API keys it makes and takes (#215, authn-authz 5.1).
        assert (
            api["API_KEY_ENVIRONMENT"]
            == {"dev": "dev", "staging": "stg", "prod": "prd"}[env]
        )
        assert {k: v for k, v in notifier.items() if k.endswith("_KEYRING")} == {
            "EMAIL_HMAC_KEYRING": f"{ref}/email-hmac",
            "LINK_HMAC_KEYRING": f"{ref}/link-hmac",
            "CODE_HMAC_KEYRING": f"{ref}/code-hmac",
        }
        assert not [
            o
            for o in rendered[(env, region, "operator")]
            if o["kind"] == "ExternalSecret"
        ]
    # Each reader's own role may read exactly its keyrings (infra/modules/eks-cluster, encryption 6.4).
    roles = (ROOT / "infra/modules/eks-cluster/workload-roles.tf").read_text()
    assert (
        'local.app_secrets["code-hmac"], local.app_secrets["email-hmac"], local.app_secrets["csrf-hmac"]'
        in roles
    )
    assert (
        'local.app_secrets["code-hmac"], local.app_secrets["email-hmac"], local.app_secrets["link-hmac"]'
        in roles
    )


def test_tls_to_the_pods_and_iam_tokens_match_the_edge_and_the_data_layer(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """The edge sends HTTPS to 8000 and checks health over HTTP on 8001 (encryption 2.2); the API and the operator API
    serve TLS on 8000 and plain probes on 8001. Every database and Valkey user signs in with IAM tokens (#184)."""
    edge = (ROOT / "infra/modules/edge/load-balancer.tf").read_text()
    group = edge[edge.index('resource "aws_lb_target_group" "api"') :]
    group = group[: group.index("\n}\n")]
    assert re.search(r'^  protocol\s+= "HTTPS"$', group, re.MULTILINE), group
    assert re.search(r'^    protocol\s+= "HTTP"$', group, re.MULTILINE), group
    assert 'path                = "/readyz"' in group
    variables = (ROOT / "infra/modules/edge/variables.tf").read_text()
    for name, port in (("api_public_port", 8000), ("api_internal_port", INTERNAL_PORT)):
        block = variables[variables.index(f'variable "{name}"') :]
        assert f"default     = {port}" in block[: block.index("\n}\n")], name
    valkey = (ROOT / "infra/modules/valkey/main.tf").read_text()
    assert 'name = "${var.name_prefix}-valkey"' in valkey
    served = set()
    for env, region, _, obj in pods(rendered):
        for container in pod_spec(obj)["containers"]:
            if not runs_our_module(container):
                continue
            where = (env, region, obj["metadata"]["name"])
            settings = env_of(container)
            ports = {p["name"] for p in container.get("ports", [])}
            if "http" in ports:
                served.add(component(obj))
                assert settings["PUBLIC_TLS"] == "generated", where
                assert container["readinessProbe"]["httpGet"] == {
                    "path": "/readyz",
                    "port": "internal",
                }
                # No scheme: the probe is plain HTTP.
                assert "scheme" not in container["readinessProbe"]["httpGet"]
            else:
                assert "PUBLIC_TLS" not in settings, where
            if "DATABASE_URL" in settings or "MIGRATION_DATABASE_URL" in settings:
                assert settings["DATABASE_IAM_AUTH"] == "true", where
                url = settings.get("DATABASE_URL") or settings["MIGRATION_DATABASE_URL"]
                assert "sslmode=verify-full" in url, where
                assert urlsplit(url).password is None, where
            if "VALKEY_URL" in settings:
                cache = f"sft-{env}-{REGION_SHORT[region]}-valkey"
                assert settings["VALKEY_IAM_CACHE"] == cache, where
                assert settings["VALKEY_URL"].startswith(f"rediss://sft-{env}-"), where
    assert served == {"api", "operator-api"}


def test_platform_wiring_matches_terraform(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """What the chart needs from Terraform exists there: Pod Identity bindings, mirror repositories, Kyverno digests."""
    infra = ROOT / "infra"
    # Pod Identity binds each workload role to one namespace and service account (#103).
    roles = (infra / "modules/eks-cluster/workload-roles.tf").read_text()
    bound = {
        (namespace, account)
        for namespace, accounts in re.findall(
            r'namespace = "(sft|sft-operator)", service_accounts = \[([^\]]*)\]', roles
        )
        for account in re.findall(r'"([^"]+)"', accounts)
    }
    used = set()
    for (_, _, part), objects in rendered.items():
        if part in PARTS:
            for obj in objects:
                if obj["kind"] in POD_KINDS:
                    account = pod_spec(obj)["serviceAccountName"]
                    if account not in NO_IDENTITY:
                        used.add((PARTS[part], account))
    assert used == bound, (sorted(used ^ bound),)
    # Every mirrored image the cluster pulls has a repository in the shared registry (ADR-0007, #105).
    mirrored = set(
        re.findall(
            r'repository = "mirror/([^"]+)"',
            (infra / "modules/cluster-bootstrap/images.tf").read_text(),
        )
    )
    chart = yaml.safe_load((ROOT / "deploy/charts/sft/values.yaml").read_text())
    mirrored.add(chart["clamav"]["repository"].removeprefix("mirror/"))
    shared = (infra / "shared/variables.tf").read_text()
    block = shared[shared.index('variable "mirror_repositories"') :]
    listed = set(re.findall(r'^    "([a-z0-9./-]+)",$', block, re.MULTILINE))
    assert mirrored <= listed, sorted(mirrored - listed)
    # Kyverno admits clamd's digest in every cluster (cluster-bootstrap's additional_mirror_digests).
    for env, region in CLUSTERS:
        root = infra / "environments" / env / region / "cluster-bootstrap/main.tf"
        assert f'"{chart["clamav"]["digest"]}"' in root.read_text(), (env, region)


def test_the_key_rotation_job_runs_in_tokyo_with_a_token_for_the_reload_only(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """Tokyo only (encryption 6.4); its Role patches only the API's Deployment and ExternalSecret, by name, since the
    workloads read the keyrings themselves (#184); nobody else has a token; it rotates Osaka's app client too outside
    dev (#185)."""
    for env, region in CLUSTERS:
        objects = rendered[(env, region, "application")]
        jobs = [
            o
            for o in objects
            if o["kind"] == "CronJob" and o["metadata"]["name"] == "key-rotation"
        ]
        roles = [
            o
            for o in objects
            if o["kind"] in {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}
        ]
        if region == OSAKA:
            assert not jobs and not roles
            continue
        [job] = jobs
        assert sorted(o["kind"] for o in roles) == ["Role", "RoleBinding"]
        [role] = [o for o in roles if o["kind"] == "Role"]
        assert role["rules"] == [
            {
                "apiGroups": ["external-secrets.io"],
                "resources": ["externalsecrets"],
                "resourceNames": ["api-secrets"],
                "verbs": ["get", "patch"],
            },
            {
                "apiGroups": ["apps"],
                "resources": ["deployments"],
                "resourceNames": ["api"],
                "verbs": ["patch"],
            },
        ]
        spec = pod_spec(job)
        assert spec["serviceAccountName"] == "key-rotation"
        [projected] = [v["projected"] for v in spec["volumes"] if "projected" in v]
        assert (
            projected["sources"][0]["serviceAccountToken"]["expirationSeconds"] == 600
        )
        clients = json.loads(env_of(spec["containers"][0])["IDP_CLIENTS"])
        assert [c["region"] for c in clients] == (
            ["ap-northeast-1"] if env == "dev" else ["ap-northeast-1", OSAKA]
        )
    for objects in rendered.values():
        for obj in objects:
            if obj["kind"] in POD_KINDS and component(obj) != "key-rotation":
                assert not any(
                    "projected" in v for v in pod_spec(obj).get("volumes", [])
                )


def test_the_notifier_sends_with_the_configuration_set_and_invites_through_cognito(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """SES_CONFIGURATION_SET from the identity layer (#185), the pool's admin side on this region's pool (#193)."""
    for env, region in CLUSTERS:
        for obj in rendered[(env, region, "application")]:
            if obj["kind"] in POD_KINDS and component(obj) in {
                "notifier",
                "invite-backlog",
            }:
                container = pod_spec(obj)["containers"][0]
                settings = env_of(container)
                if component(obj) == "invite-backlog":
                    # A run-to-completion pass with no listener: no port and no probes (#193).
                    assert not {
                        "ports",
                        "startupProbe",
                        "livenessProbe",
                        "readinessProbe",
                    } & set(container)
                assert settings["SES_CONFIGURATION_SET"] == f"sft-{env}"
                assert settings["USER_POOL_BACKEND"] == "cognito"
                assert (
                    settings["COGNITO_USER_POOL_ID"]
                    == settings["USER_POOL_PROVIDER_NAME"]
                    == f"{region}_Example0"
                )


def test_only_the_api_identity_unwraps_field_data_keys_and_never_the_stand_in(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """#236, #233: the API, the scan workers and the field key job name the fields key by its alias, never the local
    KMS stand-in; the field key job runs as the API (its service account and login role), in Tokyo only."""
    for env, region, _, obj in pods(rendered):
        name = component(obj)
        for container in pod_spec(obj)["containers"]:
            settings = env_of(container)
            if name in ("api", "scan-worker", "field-keys"):
                assert settings["FIELDS_KMS_KEY_ID"] == f"alias/sft/{env}/fields", (
                    env,
                    region,
                    name,
                )
            else:
                assert "FIELDS_KMS_KEY_ID" not in settings, (env, region, name)
        if name == "field-keys":
            assert region == "ap-northeast-1"
            assert pod_spec(obj)["serviceAccountName"] == "api"
            [container] = pod_spec(obj)["containers"]
            assert env_of(container)["DATABASE_URL"].startswith("postgresql://sft_api@")
            assert env_of(container)["FIELD_KEY_STEPS"] == "rotate,backfill,purge"
    jobs = [
        (env, region)
        for env, region, _, obj in pods(rendered)
        if component(obj) == "field-keys"
    ]
    assert len(jobs) == len({env for env, _ in CLUSTERS})
