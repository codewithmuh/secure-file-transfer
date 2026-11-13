"""The observability stack as Argo CD will render it (ADR-0009, #243), checked against the pod rules of ADR-0004, the
network design of ADR-0021 and the wiring #243 asks for.

Inspects every cluster as deploy/render.sh renders it (the `rendered` fixture, deploy/conftest.py; helm on PATH). Run
from the repository root:
`uv run --project services/api --locked pytest deploy/observability/tests`.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]
OBS = ROOT / "deploy" / "observability"
CLUSTERS = [
    ("dev", "ap-northeast-1"),
    ("staging", "ap-northeast-1"),
    ("staging", "ap-northeast-3"),
    ("prod", "ap-northeast-1"),
    ("prod", "ap-northeast-3"),
]
CHARTS = {
    "prometheus": "monitoring",
    "loki": "monitoring",
    "tempo": "monitoring",
    "collectors": "monitoring",
    "grafana": "grafana",
}
NAMESPACES = {"monitoring", "grafana", "node-agents"}
POD_KINDS = {"Deployment", "StatefulSet", "DaemonSet"}
IMAGE = re.compile(
    r"^[0-9]{12}\.dkr\.ecr\.(ap-northeast-[13])\.amazonaws\.com/(mirror/[a-z0-9./-]+):[a-z0-9.-]+@(sha256:[0-9a-f]{64})$"
)
# The one host path the stack mounts: the node agents read the pods' log files (ADR-0009).
HOST_PATHS = {("node-agents", "/var/log/pods")}

Manifest = dict[str, Any]
Rendered = dict[tuple[str, str, str], list[Manifest]]


def stack(rendered: Rendered) -> Iterator[tuple[str, str, str, Manifest]]:
    """Every object the observability Applications render, with its chart."""
    for (env, region, part), objects in rendered.items():
        if part.startswith("observability-") and part != "observability-argocd":
            for obj in objects:
                yield env, region, part.removeprefix("observability-"), obj


def namespace(chart: str, obj: Manifest) -> str:
    return str(obj["metadata"].get("namespace", CHARTS[chart]))


def pod_template(obj: Manifest) -> Manifest:
    return dict(obj["spec"]["template"])


def images_tf() -> dict[str, str]:
    """digest -> mirror repository, as cluster-bootstrap pins them (ADR-0007)."""
    text = (ROOT / "infra/modules/cluster-bootstrap/images.tf").read_text()
    pairs = re.findall(
        r'repository = "(mirror/[^"]+)"\s+tag\s+= "[^"]+"\s+digest\s+= "(sha256:[0-9a-f]{64})"',
        text,
    )
    return {digest: repo for repo, digest in pairs}


def test_tokyo_runs_the_stack_and_a_pilot_light_does_not(rendered: Rendered) -> None:
    """Architecture 3.2 and ADR-0009: Osaka's pilot light has no observability Applications; every other cluster has
    one per chart, each on main, synced from Git alone."""
    for env, region in CLUSTERS:
        objects = rendered[(env, region, "observability-argocd")]
        (project,) = [o for o in objects if o["kind"] == "AppProject"]
        assert project["metadata"]["name"] == "observability"
        assert project["spec"]["clusterResourceWhitelist"] == []
        assert {d["namespace"] for d in project["spec"]["destinations"]} == NAMESPACES
        assert project["spec"]["roles"] == []
        assert not [
            k
            for k in project["spec"]["namespaceResourceWhitelist"]
            if k["kind"] in {"Secret", "Role"}
        ]
        apps = {o["metadata"]["name"]: o for o in objects if o["kind"] == "Application"}
        pilot = yaml.safe_load(
            (ROOT / "deploy/environments" / env / region / "values.yaml").read_text()
        )["pilotLight"]
        if pilot:
            assert apps == {}, (env, region)
            assert not [
                p
                for (e, r, p) in rendered
                if (e, r) == (env, region)
                and p.startswith("observability-")
                and p != "observability-argocd"
            ]
            continue
        assert set(apps) == {f"observability-{c}" for c in CHARTS}, (env, region)
        for name, app in apps.items():
            chart = name.removeprefix("observability-")
            source = app["spec"]["source"]
            assert source["targetRevision"] == "main"
            assert source["path"] == f"deploy/observability/charts/{chart}"
            assert app["spec"]["project"] == "observability"
            assert app["spec"]["destination"]["namespace"] == CHARTS[chart]
            assert app["spec"]["syncPolicy"]["automated"] == {
                "prune": True,
                "selfHeal": True,
            }
            assert (
                "CreateNamespace=true" not in app["spec"]["syncPolicy"]["syncOptions"]
            )  # cluster-bootstrap's
            files = [
                (ROOT / source["path"] / f).resolve()
                for f in source["helm"]["valueFiles"]
            ]
            assert files == [
                ROOT / "deploy/environments" / env / region / "values.yaml",
                OBS / "environments" / f"{env}.yaml",
            ]
            facts = source["helm"]["valuesObject"]["global"]
            assert facts["sft"] == {
                "environment": env,
                "region": region,
                "accountId": "000000000000",
            }
            assert (
                facts["imageRegistry"] == f"000000000000.dkr.ecr.{region}.amazonaws.com"
            )


def test_every_kind_is_one_the_project_allows(rendered: Rendered) -> None:
    (project,) = [
        o
        for o in rendered[("dev", "ap-northeast-1", "observability-argocd")]
        if o["kind"] == "AppProject"
    ]
    allowed = {
        (k["group"], k["kind"]) for k in project["spec"]["namespaceResourceWhitelist"]
    }
    for env, region, chart, obj in stack(rendered):
        group = obj["apiVersion"].rpartition("/")[0]
        assert (group, obj["kind"]) in allowed, (env, region, chart, obj["kind"])
        assert namespace(chart, obj) in NAMESPACES, (chart, obj["metadata"]["name"])
        assert obj["kind"] != "Secret"


def test_images_are_our_mirror_by_the_digests_cluster_bootstrap_pins(
    rendered: Rendered,
) -> None:
    """ADR-0007: every image from our registry in the cluster's Region, by a digest images.tf pins, which the mirror
    workflow copies and Kyverno admits."""
    pinned = images_tf()
    seen = set()
    for env, region, chart, obj in stack(rendered):
        if obj["kind"] in POD_KINDS:
            spec = pod_template(obj)["spec"]
            containers = spec["containers"] + spec.get("initContainers", [])
        elif obj["kind"] in {"Prometheus", "Alertmanager"}:
            containers = [{"name": obj["kind"], "image": obj["spec"]["image"]}]
        else:
            continue
        for c in containers:
            match = IMAGE.match(c["image"])
            assert match, (env, region, chart, c["image"])
            assert match.group(1) == region
            assert pinned.get(match.group(3)) == match.group(2), (chart, c["image"])
            seen.add(match.group(3))
    # Every image the stack runs from Git; the operator, its config reloader and kube-state-metrics run from
    # cluster-bootstrap.
    assert {pinned[d] for d in seen} == {
        f"mirror/{r}"
        for r in (
            "prometheus/prometheus",
            "prometheus/alertmanager",
            "prometheus/pushgateway",
            "prom/cloudwatch-exporter",
            "grafana/grafana",
            "grafana/loki",
            "grafana/tempo",
            "otel/opentelemetry-collector-contrib",
        )
    }


def test_every_pod_is_hardened(rendered: Rendered) -> None:
    """ADR-0004's pod rules: non-root, read-only root file system, no capabilities, no escalation, RuntimeDefault
    seccomp, no host namespaces; host paths only for the node agents' log files, read-only."""
    for env, region, chart, obj in stack(rendered):
        if obj["kind"] not in POD_KINDS:
            continue
        spec = pod_template(obj)["spec"]
        where = (env, region, chart, obj["metadata"]["name"])
        pod_security = spec.get("securityContext", {})
        assert pod_security.get("runAsNonRoot") is True, where
        assert pod_security.get("seccompProfile") == {"type": "RuntimeDefault"}, where
        assert (
            not spec.get("hostNetwork")
            and not spec.get("hostPID")
            and not spec.get("hostIPC")
        ), where
        assert spec.get("automountServiceAccountToken") is False, where
        for c in spec["containers"] + spec.get("initContainers", []):
            security = c.get("securityContext", {})
            assert security.get("allowPrivilegeEscalation") is False, (where, c["name"])
            assert security.get("readOnlyRootFilesystem") is True, (where, c["name"])
            assert security.get("capabilities", {}).get("drop") == ["ALL"], (
                where,
                c["name"],
            )
            assert not security.get("privileged"), (where, c["name"])
            assert all(not p.get("hostPort") for p in c.get("ports", [])), (
                where,
                c["name"],
            )
            assert (
                "limits" in c.get("resources", {})
                and "memory" in c["resources"]["limits"]
            ), (where, c["name"])
        mounts = {
            m["name"]: m for c in spec["containers"] for m in c.get("volumeMounts", [])
        }
        for volume in spec.get("volumes", []):
            if "hostPath" in volume:
                assert (
                    namespace(chart, obj),
                    volume["hostPath"]["path"],
                ) in HOST_PATHS, where
                assert mounts[volume["name"]].get("readOnly") is True, where


def _selects(selector: Manifest, labels: dict[str, str]) -> bool:
    if any(labels.get(k) != v for k, v in selector.get("matchLabels", {}).items()):
        return False
    for e in selector.get("matchExpressions", []):
        if e["operator"] == "In" and labels.get(e["key"]) not in e["values"]:
            return False
    return True


def test_default_deny_and_a_policy_for_every_pod(rendered: Rendered) -> None:
    """ADR-0021: each namespace denies by default, and every pod has a policy of its own naming what it may reach."""
    for env, region in CLUSTERS:
        objects = [(c, o) for e, r, c, o in stack(rendered) if (e, r) == (env, region)]
        if not objects:
            continue
        policies = [
            (namespace(c, o), o) for c, o in objects if o["kind"] == "NetworkPolicy"
        ]
        for ns in NAMESPACES:
            assert [
                p
                for n, p in policies
                if n == ns
                and p["spec"]["podSelector"] == {}
                and set(p["spec"]["policyTypes"]) == {"Ingress", "Egress"}
                and not p["spec"].get("ingress")
                and not p["spec"].get("egress")
            ], (env, region, ns)
        for chart, obj in objects:
            if obj["kind"] not in POD_KINDS:
                continue
            labels = pod_template(obj)["metadata"]["labels"]
            ns = namespace(chart, obj)
            own = [
                p
                for n, p in policies
                if n == ns
                and p["spec"]["podSelector"]
                and _selects(p["spec"]["podSelector"], labels)
            ]
            assert own, (env, region, obj["metadata"]["name"])
        # Prometheus' and Alertmanager's pods come from the operator, with these labels.
        for name in ("prometheus", "alertmanager"):
            assert [
                p
                for n, p in policies
                if n == "monitoring"
                and _selects(p["spec"]["podSelector"], {"app.kubernetes.io/name": name})
                and p["spec"]["podSelector"]
            ], name


def test_a_budget_for_every_workload_and_no_outside_listener(
    rendered: Rendered,
) -> None:
    """One pod at a time (ADR-0004), and Grafana and the rest only inside the cluster: port-forward, never a load
    balancer (ADR-0009, T-05)."""
    for env, region in CLUSTERS:
        objects = [(c, o) for e, r, c, o in stack(rendered) if (e, r) == (env, region)]
        budgets = [o for _, o in objects if o["kind"] == "PodDisruptionBudget"]
        for chart, obj in objects:
            if obj["kind"] == "Service":
                assert obj["spec"].get("type", "ClusterIP") == "ClusterIP", (
                    chart,
                    obj["metadata"]["name"],
                )
            if obj["kind"] in {"Deployment", "StatefulSet"}:
                labels = pod_template(obj)["metadata"]["labels"]
                assert [
                    b for b in budgets if _selects(b["spec"]["selector"], labels)
                ], (
                    env,
                    region,
                    obj["metadata"]["name"],
                )


def test_every_rule_file_reaches_prometheus_without_wiring(rendered: Rendered) -> None:
    """#243: each deploy/alerts/*.rules.yaml is a PrometheusRule with the same groups, by glob, and Prometheus reads
    every rule in its namespace."""
    files = sorted((ROOT / "deploy" / "alerts").glob("*.rules.yaml"))
    assert files
    for env, region in CLUSTERS:
        objects = [
            o
            for e, r, c, o in stack(rendered)
            if (e, r, c) == (env, region, "prometheus")
        ]
        if not objects:
            continue
        rules = {
            o["metadata"]["name"]: o for o in objects if o["kind"] == "PrometheusRule"
        }
        assert set(rules) == {f.name.removesuffix(".rules.yaml") for f in files}
        for f in files:
            assert (
                rules[f.name.removesuffix(".rules.yaml")]["spec"]["groups"]
                == yaml.safe_load(f.read_text())["groups"]
            )
        (prometheus,) = [o for o in objects if o["kind"] == "Prometheus"]
        assert prometheus["spec"]["ruleSelector"] == {}


def test_prometheus_scrapes_only_the_internal_port_the_application_admits(
    rendered: Rendered,
) -> None:
    """Architecture 8: the application's metrics only on its internal port, and only from pods whose network policy
    admits Prometheus there (deploy/charts/sft)."""
    for env, region in CLUSTERS:
        objects = [
            o
            for e, r, c, o in stack(rendered)
            if (e, r, c) == (env, region, "prometheus")
        ]
        if not objects:
            continue
        app = (
            rendered[(env, region, "application")] + rendered[(env, region, "operator")]
        )
        admitted = set()
        for policy in (o for o in app if o["kind"] == "NetworkPolicy"):
            for rule in policy["spec"].get("ingress", []):
                sources = [
                    s.get("podSelector", {}).get("matchLabels", {})
                    for s in rule.get("from", [])
                ]
                ports = [p["port"] for p in rule.get("ports", [])]
                if {"app.kubernetes.io/name": "prometheus"} in sources and ports == [
                    "internal"
                ]:
                    labels = policy["spec"]["podSelector"]["matchLabels"]
                    admitted.add(
                        (
                            policy["metadata"].get("namespace", ""),
                            labels["app.kubernetes.io/component"],
                        )
                    )
        scraped = set()
        for monitor in (
            o
            for o in objects
            if o["kind"] == "PodMonitor"
            and o["metadata"]["name"] in {"sft", "sft-operator"}
        ):
            assert [e["port"] for e in monitor["spec"]["podMetricsEndpoints"]] == [
                "internal"
            ]
            (expression,) = monitor["spec"]["selector"]["matchExpressions"]
            for component in expression["values"]:
                scraped.add(component)
        assert scraped == {c for _, c in admitted}, (env, region)


def test_sizes_follow_capacity_and_adr_0009(rendered: Rendered) -> None:
    """30 days of metrics on two replicas in prod, 7 in staging and 3 in dev; Loki simple scalable only in prod."""
    expected = {"dev": (1, "3d"), "staging": (1, "7d"), "prod": (2, "30d")}
    for env, region in CLUSTERS:
        objects = [(c, o) for e, r, c, o in stack(rendered) if (e, r) == (env, region)]
        if not objects:
            continue
        (prometheus,) = [o for c, o in objects if o["kind"] == "Prometheus"]
        assert (
            prometheus["spec"]["replicas"],
            prometheus["spec"]["retention"],
        ) == expected[env]
        loki = {
            o["metadata"]["name"]
            for c, o in objects
            if c == "loki" and o["kind"] in POD_KINDS
        }
        assert loki == (
            {"loki-write", "loki-read", "loki-backend"} if env == "prod" else {"loki"}
        ), env


def test_the_pushgateway_is_where_the_jobs_push(rendered: Rendered) -> None:
    """sft.workers.jobs pushes to METRICS_PUSHGATEWAY_URL: http://pushgateway.monitoring.svc.cluster.local:9091."""
    services = {
        o["metadata"]["name"]: o
        for e, r, c, o in stack(rendered)
        if (e, r, c) == ("dev", "ap-northeast-1", "prometheus")
        and o["kind"] == "Service"
    }
    assert [p["port"] for p in services["pushgateway"]["spec"]["ports"]] == [9091]


def _env(container: Manifest) -> dict[str, str]:
    return {e["name"]: e.get("value", "") for e in container.get("env", [])}


def _egress_reaches(
    policy: Manifest, namespace: str, labels: dict[str, str], port: int
) -> bool:
    for rule in policy["spec"].get("egress", []):
        ports = {p.get("port") for p in rule.get("ports", [])}
        for peer in rule.get("to", []):
            ns = peer.get("namespaceSelector", {}).get("matchLabels", {})
            if (
                ns.get("kubernetes.io/metadata.name") == namespace
                and _selects(peer.get("podSelector", {}), labels)
                and port in ports
            ):
                return True
    return False


def test_the_application_reaches_the_pushgateway_and_the_agent(
    rendered: Rendered,
) -> None:
    """The one Pushgateway (#243) and the node's OTel agent, as the application chart names them (#242, #248).

    Every scheduled job pushes to the Service this stack runs, and its network policy admits the Pushgateway's pods;
    every traced workload (the API, the operator API, the workers) exports to the agent's Service and may reach it.
    """
    gateway = next(
        o
        for e, r, c, o in stack(rendered)
        if (e, r, c) == ("dev", "ap-northeast-1", "prometheus")
        and o["kind"] == "StatefulSet"
        and o["metadata"]["name"] == "pushgateway"
    )
    gateway_labels = gateway["spec"]["template"]["metadata"]["labels"]
    agent = next(
        o
        for e, r, c, o in stack(rendered)
        if (e, r, c) == ("dev", "ap-northeast-1", "collectors")
        and o["kind"] == "DaemonSet"
    )
    agent_labels = agent["spec"]["template"]["metadata"]["labels"]
    traced = {"api", "relay", "notifier", "scan-worker", "operator-api"}
    for env, region in CLUSTERS:
        objects = (
            rendered[(env, region, "application")] + rendered[(env, region, "operator")]
        )
        policies = {
            o["metadata"]["name"]: o for o in objects if o["kind"] == "NetworkPolicy"
        }
        for obj in objects:
            component = obj["metadata"]["labels"].get("app.kubernetes.io/component")
            if obj["kind"] == "CronJob":
                pod = obj["spec"]["jobTemplate"]["spec"]["template"]["spec"]
                url = _env(pod["containers"][0]).get("METRICS_PUSHGATEWAY_URL")
                if obj["metadata"]["name"] in {
                    "invite-backlog",
                    "key-rotation",
                    "field-keys",
                    "recovery",  # #258: run by hand; its report is its log line
                    "standby-enrolment",  # #258: likewise
                }:
                    continue  # no metrics of their own to push (they log)
                assert url == "http://pushgateway.monitoring.svc.cluster.local:9091", (
                    env,
                    region,
                    obj["metadata"]["name"],
                )
                assert _egress_reaches(
                    policies[component], "monitoring", gateway_labels, 9091
                ), (env, component)
            elif obj["kind"] == "Deployment" and component in traced:
                for container in obj["spec"]["template"]["spec"]["containers"]:
                    assert _env(container).get("OTEL_EXPORTER_OTLP_ENDPOINT") == (
                        "http://otel-agent.node-agents.svc.cluster.local:4318"
                    ), (env, region, component)
                assert _egress_reaches(
                    policies[component], "node-agents", agent_labels, 4318
                ), (env, component)


def test_alertmanager_routes_as_deploy_alerts_says(rendered: Rendered) -> None:
    """deploy/alerts/alertmanager.yaml (#245) arrives whole: its placeholders filled, every route, matcher and
    inhibition kept, and each receiver on its own topic of the alarms module (sft-<env>-<rs>-alerts-page|ticket,
    -heartbeat, #246), sent through the egress proxy."""
    source = yaml.safe_load(
        (ROOT / "deploy" / "alerts" / "alertmanager.yaml").read_text()
    )

    def matchers(items: list[str]) -> list[dict[str, str]]:
        found = []
        for item in items:
            match = re.fullmatch(r'([a-zA-Z_][a-zA-Z0-9_]*)(=~|!~|!=|=)"(.*)"', item)
            assert match, item
            found.append({"name": match[1], "matchType": match[2], "value": match[3]})
        return found

    def route(r: Manifest) -> Manifest:
        keys = {
            "group_by": "groupBy",
            "group_wait": "groupWait",
            "group_interval": "groupInterval",
            "repeat_interval": "repeatInterval",
        }
        out: Manifest = {"receiver": r["receiver"]}
        out |= {keys[k]: v for k, v in r.items() if k in keys}
        if "matchers" in r:
            out["matchers"] = matchers(r["matchers"])
        if "routes" in r:
            out["routes"] = [route(c) for c in r["routes"]]
        return out

    for env, region in CLUSTERS:
        objects = rendered.get((env, region, "observability-prometheus"))
        if objects is None:
            continue  # a pilot light runs no stack
        rs = "apne1" if region == "ap-northeast-1" else "apne3"
        config = next(o for o in objects if o["kind"] == "AlertmanagerConfig")["spec"]
        assert config["route"] == route(source["route"])
        assert config["inhibitRules"] == [
            {
                "sourceMatch": matchers(i["source_matchers"]),
                "targetMatch": matchers(i["target_matchers"]),
            }
            | ({"equal": i["equal"]} if "equal" in i else {})
            for i in source["inhibit_rules"]
        ]
        topics = {
            r["name"]: [c["topicARN"] for c in r["snsConfigs"]]
            for r in config["receivers"]
        }
        assert topics == {
            name: [f"arn:aws:sns:{region}:000000000000:sft-{env}-{rs}-{suffix}"]
            for name, suffix in {
                "page": "alerts-page",
                "ticket": "alerts-ticket",
                "heartbeat": "heartbeat",
            }.items()
        }
        for receiver in config["receivers"]:
            for sns in receiver["snsConfigs"]:
                assert "@" not in json.dumps(sns), sns
                assert sns["sigv4"] == {"region": region}
                assert sns["httpConfig"]["proxyURL"].endswith(":3132")


def test_grafana_provisions_every_dashboard_read_only(rendered: Rendered) -> None:
    objects = [
        o
        for e, r, c, o in stack(rendered)
        if (e, r, c) == ("dev", "ap-northeast-1", "grafana")
    ]
    maps = {o["metadata"]["name"]: o for o in objects if o["kind"] == "ConfigMap"}
    files = {p.name for p in (OBS / "charts/grafana/dashboards").glob("*.json")}
    assert set(maps["grafana-dashboards"]["data"]) == files
    ini = maps["grafana-config"]["data"]["grafana.ini"]
    for line in (
        "disable_initial_admin_creation = true",
        "disable_login_form = true",
        "org_role = Viewer",
    ):
        assert line in ini
    provider = yaml.safe_load(
        maps["grafana-dashboard-provider"]["data"]["dashboards.yaml"]
    )["providers"][0]
    assert provider["allowUiUpdates"] is False and provider["editable"] is False
    (binding,) = [o for o in objects if o["kind"] == "RoleBinding"]
    assert binding["roleRef"]["name"] == "sft:portforward"


def test_vendored_charts_are_the_pinned_ones() -> None:
    """The upstream charts in Git are byte for byte the ones pinned (T-68), and the versions Chart.yaml names."""
    sums = (OBS / "charts" / "SHA256SUMS").read_text().split("\n")
    pinned = dict(reversed(line.split()) for line in sums if line.strip())
    archives = sorted(
        p.relative_to(OBS / "charts").as_posix()
        for p in (OBS / "charts").glob("*/charts/*.tgz")
    )
    assert sorted(pinned) == archives
    for path, digest in pinned.items():
        assert (
            hashlib.sha256((OBS / "charts" / path).read_bytes()).hexdigest() == digest
        ), path
        chart = yaml.safe_load(
            (OBS / "charts" / path.split("/")[0] / "Chart.yaml").read_text()
        )
        names = {f"{d['name']}-{d['version']}.tgz" for d in chart["dependencies"]}
        assert path.split("/")[-1] in names


def test_the_terraform_side_matches(rendered: Rendered) -> None:
    """What the charts expect from Terraform exists there: the Pod Identity bindings, the namespaces and the node
    agents' place in Kyverno's exemptions."""
    roles = (ROOT / "infra/modules/observability/main.tf").read_text()
    bound = set(re.findall(r'service_account = "([a-z-]+)"', roles))
    accounts = {
        o["metadata"]["name"]
        for e, r, c, o in stack(rendered)
        if (e, r) == ("prod", "ap-northeast-1")
        and o["kind"] == "ServiceAccount"
        and namespace(c, o) == "monitoring"
    }
    assert bound == {"loki", "tempo", "alertmanager", "cloudwatch-exporter"}
    assert bound <= accounts
    bootstrap = (ROOT / "infra/modules/cluster-bootstrap/observability.tf").read_text()
    for ns in ("monitoring", "grafana"):
        assert re.search(rf'^\s+{ns}\s+= "restricted"$', bootstrap, re.MULTILINE), ns
    assert 'node_agents_namespace = "node-agents"' in bootstrap
