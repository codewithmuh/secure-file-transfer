#!/usr/bin/env bash
# The deploy config's static checks, as CI's `deploy` job runs them: helm lint for every cluster and part, the
# observability stack's charts included, helm template for every values file (render.sh), kubeconform on the output,
# Argo CD's and the Prometheus Operator's kinds included, and the vendored Prometheus Operator CRDs against the pinned
# chart (deploy/observability/crds/check.sh, #264). Every cluster is rendered once (#186): the runtime-contract tests
# run after it on the same directory, `SFT_RENDERED=DIR uv run --project services/api --locked pytest deploy/tests
# deploy/observability/tests` (deploy/conftest.py), and so do deploy/policies.sh and CI's Trivy scan.
# Needs helm 3, kubeconform and the network; their versions are pinned in .github/workflows/ci.yml. With an argument,
# the rendered manifests are kept in that directory; without one they go to a temporary directory.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
out="${1:-$work/rendered}"

# The Kubernetes version kubeconform checks against, and the CRD schemas for Argo CD's kinds, pinned to a commit.
kube_version=1.34.0
crds=https://raw.githubusercontent.com/datreeio/CRDs-catalog/501527ab9c40c827144c8f45945b25a023e344ce

for values in "$root"/deploy/environments/*/*/values.yaml; do
  region="$(basename "$(dirname "$values")")"
  env="$(basename "$(dirname "$(dirname "$values")")")"
  # The same fake facts and switches as render.sh (#186).
  "$root/deploy/tests/cluster-facts.sh" "$env" "$region" > "$work/$env-$region.yaml"
  cluster=(--values "$work/$env-$region.yaml")
  echo "== helm lint: $env $region"
  helm lint --strict --quiet "$root/deploy/argocd" "${cluster[@]}"
  for part in application operator; do
    helm lint --strict --quiet "$root/deploy/charts/sft" --values "$values" "${cluster[@]}" --set "part=$part"
  done

  # The observability stack (#243): its root's chart, then each chart with the values its Application names, unless
  # the cluster is a pilot light, which runs none of it.
  helm lint --strict --quiet "$root/deploy/observability/argocd" --values "$values" "${cluster[@]}"
  if ! grep -q '^pilotLight: true' "$values"; then
    for chart in prometheus loki tempo collectors grafana; do
      helm lint --strict --quiet "$root/deploy/observability/charts/$chart" \
        --values "$values" --values "$root/deploy/observability/environments/$env.yaml" "${cluster[@]}" \
        2> >(grep -v 'symbolic link' >&2)
    done
  fi
done

echo "== helm template: every values file"
"$root/deploy/render.sh" "$out"

echo "== kubeconform"
kubeconform -strict -summary -kubernetes-version "$kube_version" \
  -schema-location default \
  -schema-location "$crds/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
  "$out"/*.yaml

echo "== the Prometheus Operator's CRDs"
"$root/deploy/observability/crds/check.sh"
