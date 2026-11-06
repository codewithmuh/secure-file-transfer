"""What a values file may change in the application chart, and what it may not (deploy/README.md, "Settings").

A workload's `env` in the values may add settings; it never replaces one the chart computes from the cluster facts
(the database, Valkey, queue, bucket, key and sign-in wiring, the trusted proxies, the proxy settings) or a secret.
Also renders clamd's configuration with a non-default port. Run from the repository root with helm on PATH.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "deploy/charts/sft"
CLUSTER = ROOT / "deploy/environments/dev/ap-northeast-1/values.yaml"
FACTS = ROOT / "deploy/tests/trivy-values.yaml"  # dev's fake cluster facts

# Per workload values key: settings the chart computes, each with an attacker's value, and one extra setting.
OVERRIDES = {
    "api": [
        "WEB_ORIGIN",
        "TRUSTED_PROXIES",
        "OIDC_ISSUER",
        "OIDC_REDIRECT_URI",
        "S3_FILES_BUCKET",
        "S3_FILES_KMS_KEY_ID",
        "VALKEY_URL",
        "DATABASE_URL",
        "HTTPS_PROXY",
        "CSRF_KEYRING",
        "OIDC_CLIENT_SECRET",
    ],
    "relay": ["SQS_QUEUE_PREFIX", "DATABASE_URL", "BIND_HOST"],
    "notifier": [
        "SQS_QUEUE_PREFIX",
        "WEB_APP_URL",
        "MAIL_FROM_ADDRESS",
        "VALKEY_URL",
        "NO_PROXY",
    ],
    "scanWorker": [
        "SQS_QUEUE_PREFIX",
        "SCAN_POOL",
        "VALKEY_URL",
        "DATABASE_URL",
        "S3_FILES_BUCKET",
        "CLAMD_HOST",
        "INSPECTOR_HOST",
        "SCAN_LARGE_POOL_SIZE",
    ],
    "operatorApi": [
        "OPERATOR_AWS_ACCOUNT_ID",
        "OPERATOR_ROLE_NAME",
        "VALKEY_URL",
        "DATABASE_URL",
    ],
}
# Values key -> (part, Deployment names) it renders.
WORKLOADS = {
    "api": ("application", ["api"]),
    "relay": ("application", ["relay"]),
    "notifier": ("application", ["notifier"]),
    "scanWorker": ("application", ["scan-worker-small", "scan-worker-large"]),
    "operatorApi": ("operator", ["operator-api"]),
}
EVIL = "https://evil.example"


def render(part: str, *args: str) -> list[dict[str, Any]]:
    out = subprocess.run(
        [
            "helm",
            "template",
            "sft",
            str(CHART),
            "--values",
            str(CLUSTER),
            "--values",
            str(FACTS),
        ]
        + ["--set", f"part={part}", *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [d for d in yaml.safe_load_all(out) if d]


def containers(
    objects: list[dict[str, Any]], names: list[str]
) -> dict[str, dict[str, Any]]:
    return {
        o["metadata"]["name"]: o["spec"]["template"]["spec"]["containers"][0]
        for o in objects
        if o["kind"] == "Deployment" and o["metadata"]["name"] in names
    }


def test_values_env_adds_settings_but_never_replaces_computed_ones(
    tmp_path: Path,
) -> None:
    for key, settings in OVERRIDES.items():
        part, names = WORKLOADS[key]
        baseline = containers(render(part), names)
        values = tmp_path / f"{key}.yaml"
        env = {name: EVIL for name in settings} | {"EXTRA_SETTING": "kept"}
        values.write_text(yaml.safe_dump({key: {"env": env}}))
        overridden = containers(render(part, "--values", str(values)), names)
        for name in names:
            before = baseline[name]["env"]
            after = overridden[name]["env"]
            # Every computed setting is still there, once, with its computed value or Secret reference.
            for entry in before:
                assert [e for e in after if e["name"] == entry["name"]] == [entry], (
                    key,
                    name,
                    entry["name"],
                )
            # The extra setting is passed, and nothing else changed.
            extra = [e for e in after if e not in before]
            assert extra == [{"name": "EXTRA_SETTING", "value": "kept"}], (
                key,
                name,
                extra,
            )
            assert all(e.get("value") != EVIL for e in after), (key, name)


def test_clamd_listens_on_the_configured_port() -> None:
    objects = render("application", "--set", "clamd.port=3999")
    (config,) = [
        o
        for o in objects
        if o["kind"] == "ConfigMap" and o["metadata"]["name"] == "clamd-config"
    ]
    lines = config["data"]["clamd.conf"].splitlines()
    assert "TCPSocket 3999" in lines and "TCPSocket 3310" not in lines
    (service,) = [
        o
        for o in objects
        if o["kind"] == "Service" and o["metadata"]["name"] == "clamd"
    ]
    assert [p["port"] for p in service["spec"]["ports"]] == [3999]
    clamd = containers(objects, ["clamd-small"])["clamd-small"]
    assert [p["containerPort"] for p in clamd["ports"]] == [3999]
