#!/usr/bin/env bash
# Renders every cluster's manifests into an output directory, the way Argo CD
# will: the apps chart with the root Application's values, then the application chart for each of its two
# Applications. The cluster facts that Terraform supplies in AWS (account IDs, the database endpoint) are obviously
# fake here. CI's `deploy` job and deploy/tests/ use it. Needs helm 3.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:?usage: deploy/render.sh OUTPUT_DIR}"
rm -rf "$out"
mkdir -p "$out"

fake_account=000000000000

for values in "$root"/deploy/environments/*/*/values.yaml; do
  region="$(basename "$(dirname "$values")")"
  env="$(basename "$(dirname "$(dirname "$values")")")"
  name="$env-$region"
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

  # What the root Application renders: the AppProject and the two Applications.
  helm template root "$root/deploy/argocd" --namespace argocd "${cluster[@]}" > "$out/$name-argocd.yaml"

  # What each Application renders, with the values its source names.
  for part in application operator; do
    namespace=$([[ $part == application ]] && echo sft || echo sft-operator)
    helm template sft "$root/deploy/charts/sft" --namespace "$namespace" --values "$values" \
      "${cluster[@]}" --set "part=$part" > "$out/$name-$part.yaml"
  done
done

ls "$out"
