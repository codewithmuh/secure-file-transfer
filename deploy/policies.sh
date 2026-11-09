#!/usr/bin/env bash
# Runs the cluster's admission policies (infra/modules/cluster-bootstrap/charts/kyverno-policies, #104) against every
# pod the application chart and the observability stack's charts render, with the Kyverno CLI from its pinned image,
# the same version as the clusters'. (The Prometheus Operator makes Prometheus' and Alertmanager's pods in the
# cluster, so those aren't here.) Each cluster's policies are rendered with that cluster's registry, the platform's
# mirror digests (images.tf) and the one the cluster-bootstrap root admits for clamd, and the node agents' namespace
# among the system and host-access namespaces, as cluster-bootstrap sets them, so a pod that the cluster would refuse
# fails here first. Reaches no cluster and no network.
#
# Usage: deploy/policies.sh [RENDERED_DIR]   (the output of deploy/render.sh, which it runs itself without one; needs
# helm, Docker and uv)
set -euo pipefail

KYVERNO_CLI_IMAGE="reg.kyverno.io/kyverno/kyverno-cli:v1.19.2@sha256:322ec5044d600930cb3af0e56dc33154a2d1d1fba58f4cadad3f47be7e78b11c"

root="$(cd "$(dirname "$0")/.." && pwd)"
chart="$root/infra/modules/cluster-bootstrap/charts/kyverno-policies"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
if [[ $# -gt 0 ]]; then
  rendered="$(cd "$1" && pwd)"
else
  rendered="$work/rendered"
  "$root/deploy/render.sh" "$rendered" >/dev/null
fi

fake_account=000000000000
clamav_digest="$(sed -n 's/^  digest: \(sha256:[0-9a-f]*\)$/\1/p' "$root/deploy/charts/sft/values.yaml" | head -n 1)"
# The platform's mirrored images, which the cluster admits by the digests cluster-bootstrap pins (images.tf): the
# observability stack's among them (#243).
platform_digests="$(sed -n 's/^ *digest *= "\(sha256:[0-9a-f]*\)"$/\1/p' "$root/infra/modules/cluster-bootstrap/images.tf" | paste -sd, -)"

for values in "$root"/deploy/environments/*/*/values.yaml; do
  region="$(basename "$(dirname "$values")")"
  env="$(basename "$(dirname "$(dirname "$values")")")"
  name="$env-$region"
  mkdir -p "$work/$name"

  # The policies the cluster runs on application namespaces; the signature policy needs a live registry, so it isn't
  # rendered here (its own test is the build's signing, #107).
  helm template sft-policies "$chart" \
    --set "registry=$fake_account.dkr.ecr.$region.amazonaws.com" \
    --set "mirrorDigests={$clamav_digest,$platform_digests}" \
    --set-string "trustedRoot={}" \
    --set "eksAddonRegistry=602401143452.dkr.ecr.$region.amazonaws.com" \
    --set "systemNamespaces={kube-system,argocd,kyverno,karpenter,egress-proxy,node-agents}" \
    --set "hostAccessNamespaces={node-agents}" \
    --show-only templates/images.yaml --show-only templates/pod-security.yaml \
    --show-only templates/system-pool.yaml --show-only templates/namespaces.yaml >"$work/$name/policies.yaml"

  # The CLI checks Pods, so each Deployment, Job and CronJob becomes the Pod its template makes, in a namespace with
  # the labels Argo CD gives it (deploy/argocd).
  uv run --project "$root/services/api" --locked --quiet python - "$rendered" "$name" "$work/$name/resources.yaml" <<'EOF'
import sys
from pathlib import Path

import yaml

rendered, name, out = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])


def labels(level: str) -> dict[str, str]:
    return {f"pod-security.kubernetes.io/{k}": level for k in ("enforce", "audit", "warn")}


# The namespaces as the cluster has them: Argo CD labels sft and sft-operator; cluster-bootstrap makes monitoring and
# grafana at restricted and node-agents, the node agents' host-path namespace, at privileged (observability.tf).
namespaces = {"sft": "restricted", "sft-operator": "restricted", "monitoring": "restricted", "grafana": "restricted",
              "node-agents": "privileged"}
sources = [("application", "sft"), ("operator", "sft-operator")] + [
    (f"observability-{chart}", "grafana" if chart == "grafana" else "monitoring")
    for chart in ("prometheus", "loki", "tempo", "collectors", "grafana")
]
resources = [
    {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": ns, "labels": {"kubernetes.io/metadata.name": ns, **labels(level),
                                            "pod-security.kubernetes.io/enforce-version": "latest"}},
    }
    for ns, level in namespaces.items()
]
for part, namespace in sources:
    path = rendered / f"{name}-{part}.yaml"
    if not path.exists():  # a pilot light renders no observability stack
        continue
    for obj in yaml.safe_load_all(path.read_text()):
        if not obj or obj["kind"] not in {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}:
            continue
        spec = obj["spec"]["jobTemplate"]["spec"] if obj["kind"] == "CronJob" else obj["spec"]
        template = spec["template"]
        resources.append({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": obj["metadata"]["name"], "namespace": obj["metadata"].get("namespace", namespace),
                         "labels": template["metadata"]["labels"]},
            "spec": template["spec"],
        })
out.write_text(yaml.safe_dump_all(resources))
EOF

  echo "== kyverno apply: $env $region"
  result="$(docker run --rm --network none --user "$(id -u):$(id -g)" --env HOME=/tmp \
    --volume "$work/$name:/work:ro" "$KYVERNO_CLI_IMAGE" \
    apply /work/policies.yaml --resource /work/resources.yaml 2>&1)" || {
    echo "$result"
    exit 1
  }
  echo "$result" | grep '^pass:'
  # A run that checked nothing would pass too: every pod must have been checked.
  if ! echo "$result" | grep -q '^pass: [1-9][0-9]*, fail: 0, warn: 0, error: 0, skip: 0'; then
    echo "$result"
    exit 1
  fi
done
