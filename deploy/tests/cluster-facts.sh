#!/usr/bin/env bash
# The values every static check renders one cluster with, as a Helm values file on stdout (#186). The one source for
# deploy/render.sh and deploy/check.sh; deploy/tests/trivy-values.yaml holds dev's in Tokyo, and
# deploy/tests/test_rendered.py checks that it matches.
#
# - The cluster facts that Terraform supplies in AWS, obviously fake: what the root Applications pass the application
#   (`cluster`, #106) and what the observability Applications pass their charts (`global`, #243).
# - The workloads that stay off until their environment's AWS side exists, switched on, so every check (helm lint,
#   kubeconform, Kyverno, Trivy, deploy/tests) sees them before a values file turns them on: the synthetic probe
#   (#248), the operator API's break-glass reconciliation, whose facts come from the organization stack (#275), and
#   the database bootstrap job, which a values file turns on for one sync (#278).
#
# Usage: deploy/tests/cluster-facts.sh ENV REGION   (ENV dev, staging or prod; REGION ap-northeast-1 or -3)
set -euo pipefail

usage="usage: deploy/tests/cluster-facts.sh ENV REGION"
env="${1:?$usage}"
region="${2:?$usage}"
[[ $env =~ ^(dev|staging|prod)$ && $region =~ ^ap-northeast-[13]$ ]] || { echo "$usage" >&2; exit 2; }

account=000000000000
registry="$account.dkr.ecr.$region.amazonaws.com"
domain="$([[ $env == prod ]] || echo "$env.")sft.example.com"

cat <<EOF
environment: $env
region: $region
cluster:
  registry: $registry
  databaseHost: sft-$env.cluster-example.$region.rds.amazonaws.com
  accountId: "$account"
  operatorRoleName: AWSReservedSSO_Operator_0000000000000000
  serviceDomain: $domain
  valkeyHost: sft-$env-valkey-example.serverless.$region.cache.amazonaws.com
  filesKeyArn: arn:aws:kms:$region:$account:key/mrk-00000000000000000000000000000000
  userPoolId: ${region}_Example0
  cognitoLoginDomain: sft-$env-example.auth.$region.amazoncognito.com
  sesConfigurationSet: sft-$env
  appClientId: example0client0id
  breakGlassTrailRoleArn: arn:aws:iam::$account:role/sft-$env-break-glass-trail
  breakGlassPermissionSetArn: arn:aws:sso:::permissionSet/ssoins-0000000000000000/ps-0000000000000000
  identityStoreId: d-0000000000
EOF
# Tokyo's key rotation job also rotates Osaka's standby client (staging and prod).
if [[ $region == ap-northeast-1 && $env != dev ]]; then
  cat <<EOF
  standbyUserPoolId: ap-northeast-3_Example0
  standbyAppClientId: example0standby0id
EOF
fi
cat <<EOF
global:
  imageRegistry: $registry
  sft:
    environment: $env
    region: $region
    accountId: "$account"
probe:
  enabled: true
dbBootstrap:
  runOnSync: true
EOF
