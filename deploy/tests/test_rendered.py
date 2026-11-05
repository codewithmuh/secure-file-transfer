"""Checks every rendered manifest against the runtime contract (architecture 8) and the pod rules of ADR-0004.

Renders every cluster with deploy/render.sh (helm on PATH), the way Argo CD will, then inspects the objects. Run from
the repository root: `uv run --project services/api --locked pytest deploy/tests` (`make deploy-check` does it all).
"""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic_settings import BaseSettings
from sft.core.settings import (
    InspectorSettings,
    MigrationSettings,
    OperatorSettings,
    RelaySettings,
    Settings,
)

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
PROXIED = {"api": 3128, "notifier": 3129}
# The DLP inspector speaks its own framed protocol, one file per connection, and has no internal listener (ADR-0022).
NO_INTERNAL_PORT = {"dlp-inspector"}
# The entry points that exist today and the settings each reads at startup (sft.core.settings).
SETTINGS: dict[str, type[BaseSettings]] = {
    "sft.api": Settings,
    "sft.api.operator": OperatorSettings,
    "sft.workers.relay": RelaySettings,
    "sft.data.migrate": MigrationSettings,
    "sft.dlp.inspector": InspectorSettings,
}
REGION_SHORT = {"ap-northeast-1": "apne1", "ap-northeast-3": "apne3"}

Manifest = dict[str, Any]


@pytest.fixture(scope="session")
def rendered(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[tuple[str, str, str], list[Manifest]]:
    out = tmp_path_factory.mktemp("rendered")
    subprocess.run(
        [str(ROOT / "deploy" / "render.sh"), str(out)], check=True, capture_output=True
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
            if container.get("ports") and component(obj) not in NO_INTERNAL_PORT:
                assert "livenessProbe" in container and "readinessProbe" in container, (
                    where
                )
            if not runs_our_module(container):
                continue
            seen.add(component(obj))
            if component(obj) in NO_INTERNAL_PORT:
                ports = {p["name"]: p["containerPort"] for p in container["ports"]}
                assert set(ports) == {"inspector"}, where
                assert env_of(container)["INSPECTOR_PORT"] == str(ports["inspector"])
                assert env_of(container)["BIND_HOST"] == "0.0.0.0", where
                continue
            ports = {p["name"]: p["containerPort"] for p in container["ports"]}
            assert ports["internal"] == INTERNAL_PORT, where
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
                    assert f"sqs.{region}.amazonaws.com" in settings["NO_PROXY"].split(
                        ","
                    )
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
        if obj["kind"] == "CronJob":
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
            # Secrets only from the External Secrets Secret, never a value (encryption 6.4).
            for name, field in fields.items():
                if field.annotation is not None and "SecretStr" in str(
                    field.annotation
                ):
                    value = settings.get(name.upper(), "")
                    if name.upper().endswith(("DATABASE_URL", "VALKEY_URL")):
                        continue  # IAM authentication: the URL holds a user, never a password
                    assert value.startswith("secret:") or not value, (module, name)
    assert seen == set(SETTINGS)


def test_api_secrets_come_from_external_secrets(
    rendered: dict[tuple[str, str, str], list[Manifest]],
) -> None:
    """The API's keyrings and client secret come from Secrets Manager through the application store (encryption 6.4)."""
    for env, region in CLUSTERS:
        objects = rendered[(env, region, "application")]
        (external,) = [o for o in objects if o["kind"] == "ExternalSecret"]
        spec = external["spec"]
        assert spec["secretStoreRef"] == {
            "kind": "ClusterSecretStore",
            "name": "application-secrets",
        }
        assert spec["target"]["name"] == "api-secrets"
        keys = {d["secretKey"]: d["remoteRef"] for d in spec["data"]}
        assert keys["CSRF_KEYRING"] == {"key": f"sft/{env}/app/csrf-hmac"}
        assert keys["EMAIL_HMAC_KEYRING"] == {"key": f"sft/{env}/app/email-hmac"}
        # Each region's API reads only its own user pool's client (encryption 6.1).
        assert keys["OIDC_CLIENT_SECRET"]["key"] == f"sft/{env}/app/idp-client/{region}"
        assert not [
            o
            for o in rendered[(env, region, "operator")]
            if o["kind"] == "ExternalSecret"
        ]


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
