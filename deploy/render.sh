#!/usr/bin/env bash
# Renders every cluster's manifests into an output directory, the way Argo CD will: the apps chart with the root
# Application's values, then the application chart for each of its two Applications; then the observability root's
# chart and its Applications' charts (deploy/observability). Each cluster gets its values file, then
# deploy/tests/cluster-facts.sh: the cluster facts that Terraform supplies in AWS (account IDs, the database
# endpoint), obviously fake here, and the workloads that are off until their AWS side exists, switched on (#186).
# CI's `deploy` job renders once (deploy/check.sh) and every check reads that directory: kubeconform, Kyverno, Trivy
# and deploy/tests (SFT_RENDERED, deploy/conftest.py). Needs helm 3. SFT_RENDER_SET, when set, is one more --set for
# the application chart.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:?usage: deploy/render.sh OUTPUT_DIR}"
rm -rf "$out"
mkdir -p "$out"
facts="$(mktemp -d)"
trap 'rm -rf "$facts"' EXIT

for values in "$root"/deploy/environments/*/*/values.yaml; do
  region="$(basename "$(dirname "$values")")"
  env="$(basename "$(dirname "$(dirname "$values")")")"
  name="$env-$region"
  "$root/deploy/tests/cluster-facts.sh" "$env" "$region" > "$facts/$name.yaml"

  # What the root Application renders: the AppProject and the two Applications.
  helm template root "$root/deploy/argocd" --namespace argocd --values "$facts/$name.yaml" > "$out/$name-argocd.yaml"

  # What each Application renders, with the values its source names.
  for part in application operator; do
    namespace=$([[ $part == application ]] && echo sft || echo sft-operator)
    helm template sft "$root/deploy/charts/sft" --namespace "$namespace" --values "$values" \
      --values "$facts/$name.yaml" --set "part=$part" ${SFT_RENDER_SET:+--set "$SFT_RENDER_SET"} \
      > "$out/$name-$part.yaml"
  done

  # The observability stack (ADR-0009, #243): what the observability root Application renders (deploy/observability/
  # argocd), then each of its Applications' charts with the value files and facts it names. A pilot light has no
  # observability Applications, so nothing more is rendered for it.
  helm template observability "$root/deploy/observability/argocd" --namespace argocd --values "$values" \
    --values "$facts/$name.yaml" > "$out/$name-observability-argocd.yaml"
  if ! grep -q '^pilotLight: true' "$values"; then
    for chart in prometheus loki tempo collectors grafana; do
      namespace=$([[ $chart == grafana ]] && echo grafana || echo monitoring)
      helm template "$chart" "$root/deploy/observability/charts/$chart" --namespace "$namespace" \
        --values "$values" --values "$root/deploy/observability/environments/$env.yaml" \
        --values "$facts/$name.yaml" > "$out/$name-observability-$chart.yaml" \
        2> >(grep -v 'symbolic link' >&2) # the prometheus chart's alerts/ is a link to deploy/alerts
    done
  fi
done

ls "$out"
