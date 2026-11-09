#!/usr/bin/env bash
# The deploy config's static checks, as CI's `deploy` job runs them: helm lint for every cluster and part, the
# observability stack's charts included, helm template for every values file (render.sh), and kubeconform on the
# output, Argo CD's and the Prometheus Operator's kinds included. The
# runtime-contract test runs after it: `uv run --project services/api --locked pytest deploy/tests`.
# Needs helm 3 and kubeconform; their versions are pinned in .github/workflows/ci.yml. With an argument, the rendered
# manifests are kept in that directory (CI scans them with Trivy); without one they go to a temporary directory.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
if [[ $# -gt 0 ]]; then
  out="$1"
else
  out="$(mktemp -d)"
  trap 'rm -rf "$out"' EXIT
fi

# The Kubernetes version kubeconform checks against, and the CRD schemas for Argo CD's kinds, pinned to a commit.
kube_version=1.34.0
crds=https://raw.githubusercontent.com/datreeio/CRDs-catalog/501527ab9c40c827144c8f45945b25a023e344ce

fake_account=000000000000
for values in "$root"/deploy/environments/*/*/values.yaml; do
  region="$(basename "$(dirname "$values")")"
  env="$(basename "$(dirname "$(dirname "$values")")")"
  cluster=(
    --set "environment=$env" --set "region=$region"
    --set "cluster.registry=$fake_account.dkr.ecr.$region.amazonaws.com"
    --set "cluster.databaseHost=sft-$env.cluster-example.$region.rds.amazonaws.com"
    --set-string "cluster.accountId=$fake_account"
    --set "cluster.operatorRoleName=AWSReservedSSO_Operator_0000000000000000"
    --set "cluster.serviceDomain=$([[ $env == prod ]] || echo "$env.")sft.example.com"
    --set "cluster.valkeyHost=sft-$env-valkey-example.serverless.$region.cache.amazonaws.com"
    --set "cluster.filesKeyArn=arn:aws:kms:$region:$fake_account:key/mrk-00000000000000000000000000000000"
    --set "cluster.userPoolId=${region}_Example0"
    --set "cluster.cognitoLoginDomain=sft-$env-example.auth.$region.amazoncognito.com"
    --set "cluster.sesConfigurationSet=sft-$env"
    --set "cluster.appClientId=example0client0id"
  )
  if [[ $region == ap-northeast-1 && $env != dev ]]; then
    cluster+=(--set "cluster.standbyUserPoolId=ap-northeast-3_Example0" --set "cluster.standbyAppClientId=example0standby0id")
  fi
  echo "== helm lint: $env $region"
  helm lint --strict --quiet "$root/deploy/argocd" "${cluster[@]}"
  for part in application operator; do
    helm lint --strict --quiet "$root/deploy/charts/sft" --values "$values" "${cluster[@]}" --set "part=$part"
  done

  # The observability stack (#243): its root's chart, then each chart with the values its Application names, unless
  # the cluster is a pilot light, which runs none of it.
  helm lint --strict --quiet "$root/deploy/observability/argocd" --values "$values" \
    --set "environment=$env" --set "region=$region" \
    --set "cluster.registry=$fake_account.dkr.ecr.$region.amazonaws.com" --set-string "cluster.accountId=$fake_account"
  if ! grep -q '^pilotLight: true' "$values"; then
    for chart in prometheus loki tempo collectors grafana; do
      helm lint --strict --quiet "$root/deploy/observability/charts/$chart" \
        --values "$values" --values "$root/deploy/observability/environments/$env.yaml" \
        --set "global.imageRegistry=$fake_account.dkr.ecr.$region.amazonaws.com" \
        --set "global.sft.environment=$env" --set "global.sft.region=$region" \
        --set-string "global.sft.accountId=$fake_account" 2> >(grep -v 'symbolic link' >&2)
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
