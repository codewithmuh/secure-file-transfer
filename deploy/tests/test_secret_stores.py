"""External Secrets' stores (infra/modules/cluster-bootstrap/charts/secret-stores, encryption 6.4).

Renders the chart the way the cluster-bootstrap stack does and checks that each store assumes its own role, that no
namespace can use both, and that the roles it names are the ones the cluster layer creates. Run from the repository
root with helm on PATH: `uv run --project services/api --locked pytest deploy/tests`.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "infra/modules/cluster-bootstrap/charts/secret-stores"
FAKE_ACCOUNT = "000000000000"
NOTIFICATIONS: dict[str, Any] = {
    "apiVersion": "external-secrets.io/v1",
    "kind": "ExternalSecret",
    "metadata": {"name": "argocd-notifications-secret", "namespace": "argocd"},
    "spec": {
        "secretStoreRef": {"kind": "ClusterSecretStore", "name": "platform-secrets"}
    },
}


def render(*args: str) -> list[dict[str, Any]]:
    out = subprocess.run(
        ["helm", "template", "external-secrets-store", str(CHART), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [d for d in yaml.safe_load_all(out) if d]


@pytest.mark.parametrize(
    ("env", "region"),
    [
        ("dev", "ap-northeast-1"),
        ("staging", "ap-northeast-3"),
        ("prod", "ap-northeast-1"),
    ],
)
def test_each_store_assumes_its_own_role(env: str, region: str, tmp_path: Path) -> None:
    values = tmp_path / "values.yaml"
    values.write_text(
        yaml.safe_dump(
            {
                "environment": env,
                "region": region,
                "accountId": FAKE_ACCOUNT,
                "manifests": [NOTIFICATIONS],
            }
        )
    )
    objects = render("--values", str(values))
    stores = {
        o["metadata"]["name"]: o["spec"]
        for o in objects
        if o["kind"] == "ClusterSecretStore"
    }
    prefix = f"arn:aws:iam::{FAKE_ACCOUNT}:role/sft-{env}-external-secrets"
    assert stores["platform-secrets"]["provider"]["aws"]["role"] == f"{prefix}-platform"
    assert stores["application-secrets"]["provider"]["aws"]["role"] == f"{prefix}-app"
    for spec in stores.values():
        assert spec["provider"]["aws"]["region"] == region
        assert spec["provider"]["aws"]["service"] == "SecretsManager"
    assert stores["platform-secrets"]["conditions"] == [
        {"namespaces": ["argocd", "monitoring", "grafana"]}
    ]
    assert stores["application-secrets"]["conditions"] == [{"namespaces": ["sft"]}]
    # The extra manifests pass through unchanged.
    assert [o for o in objects if o["kind"] == "ExternalSecret"] == [NOTIFICATIONS]


def test_stores_never_share_a_role_or_a_namespace(tmp_path: Path) -> None:
    common = {
        "environment": "dev",
        "region": "ap-northeast-1",
        "accountId": FAKE_ACCOUNT,
    }
    for stores, message in (
        (
            {
                "a": {"role": "x", "namespaces": ["one"]},
                "b": {"role": "x", "namespaces": ["two"]},
            },
            "shares its role",
        ),
        (
            {
                "a": {"role": "x", "namespaces": ["one"]},
                "b": {"role": "y", "namespaces": ["one"]},
            },
            "only one store",
        ),
    ):
        values = tmp_path / "values.yaml"
        values.write_text(yaml.safe_dump({**common, "stores": stores}))
        result = subprocess.run(
            [
                "helm",
                "template",
                "s",
                str(CHART),
                "--values",
                str(values),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0 and message in result.stderr


def test_the_cluster_layer_makes_those_roles_and_the_controller_reads_nothing() -> None:
    main = (ROOT / "infra/modules/eks-cluster/main.tf").read_text()
    for suffix in ("platform", "app"):
        assert f'"${{var.global_name_prefix}}-external-secrets-{suffix}"' in main
    roles = (ROOT / "infra/modules/eks-cluster/workload-roles.tf").read_text()
    controller = roles[roles.index("    external_secrets = [") :]
    controller = controller[: controller.index("    ]\n")]
    assert re.findall(r"Action += \[([^\]]*)\]", controller) == ['"sts:AssumeRole"']
    # Each store role reads only its own secrets, and the secrets key's policy names the same roles.
    assert "external_secrets_platform = { secrets = local.platform_secrets" in roles
    assert "external_secrets_app      = { secrets = local.api_store_secrets" in roles
    keys = (ROOT / "infra/modules/kms-keys/policies.tf").read_text()
    assert 'roles   = [local.role_arns["external-secrets"]]' not in keys
    assert 'local.role_arns["external-secrets-platform"]' in keys
    assert 'local.role_arns["external-secrets-app"]' in keys
