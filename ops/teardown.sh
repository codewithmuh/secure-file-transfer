#!/usr/bin/env bash
# Timed teardown of an environment (docs/runbooks/teardown.md; architecture 3.4; NFR-19: prod destroyed in an hour,
# leaving only the retained stack; NFR-20: dev and staging torn down when idle).
#
#   ops/teardown.sh --env staging --profile sft-staging-admin                    # dry run: lists what would go
#   ops/teardown.sh --env staging --profile sft-staging-admin --account-id <id> --inventory
#   ops/teardown.sh --env prod --profile sft-prod-admin --account-id <id> --scope final --execute
#
# Script options, besides the common ones (ops/lib/common.sh):
#   --scope idle|final   idle (dev and staging only, the default there): the environment's stacks go; its bootstrap
#                        stays, so it can be built again. final (prod, the default there): also the bootstrap stacks,
#                        and in prod the retained stack's teardown apply comes first.
#   --last               with final: this is the last environment, so the shared account's registry goes too.
#   --inventory          read-only, with --account-id: list every resource each stack's state holds and every
#                        resource still tagged with the environment, then stop. Changes nothing.
#
# A dry run (the default) prints every stack in the order it would be destroyed, with the commands, and runs none.
# With --execute it runs them, times each step against NFR-19's hour, and ends with the tag search: nothing tagged
# with the environment may remain but the retained stack's (retention = audit-archive). Pending the AWS run.
set -euo pipefail

DRILL=teardown
STEPS_DOC=docs/runbooks/teardown.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'
  echo
  common_usage
}

parse_common "$@"
SCOPE=""
LAST=false
INVENTORY=false
set -- "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --last) LAST=true; shift ;;
    --inventory) INVENTORY=true; shift ;;
    *) die "unknown option $1" ;;
  esac
done
if [[ -z "$SCOPE" ]]; then
  if [[ "$ENV_NAME" == prod ]]; then SCOPE=final; else SCOPE=idle; fi
fi
[[ "$SCOPE" =~ ^(idle|final)$ ]] || die "--scope must be idle or final"
[[ "$ENV_NAME" != prod || "$SCOPE" == final ]] || die "prod has no idle teardown: it runs until the operating period ends, then goes for good (--scope final)"
! $LAST || [[ "$SCOPE" == final ]] || die "--last needs --scope final"
if $INVENTORY; then
  $EXECUTE && die "--inventory changes nothing; leave out --execute"
  [[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || die "--inventory needs --account-id"
fi

INFRA="$REPO_ROOT/infra"
# The layers of an environment, in the order they are destroyed: the reverse of infra/README.md's apply order.
LAYERS=(cluster-bootstrap identity edge cluster data network)
REGIONS=("$OSAKA" "$TOKYO") # Osaka first: it replicates Tokyo's keys and refers to Tokyo's roles
[[ "$ENV_NAME" != dev ]] || REGIONS=("$TOKYO")

roots_in_order() {
  local region layer
  for region in "${REGIONS[@]}"; do
    for layer in "${LAYERS[@]}"; do
      echo "environments/$ENV_NAME/$region/$layer"
    done
  done
  if [[ "$SCOPE" == final ]]; then
    for region in "${REGIONS[@]}"; do
      echo "bootstrap/$ENV_NAME/$region"
    done
    ! $LAST || echo "shared"
  fi
}

# tf <root> <terraform args...>: one root, with its backend for this account (infra/README.md, State).
tf() {
  local root="$1"
  shift
  local region=$TOKYO bucket
  [[ "$root" != *"/$OSAKA"* ]] || region=$OSAKA
  bucket="sft-$ENV_NAME-$(short "$region")-tfstate-$ACCOUNT_ID"
  # The retained stack keeps its state in its own bucket, under the audit key (encryption 8.4).
  [[ "$root" != environments/prod/retained ]] || bucket="sft-prod-apne1-retained-tfstate-$ACCOUNT_ID"
  run terraform -chdir="$INFRA/$root" init -input=false -reconfigure -backend-config="bucket=$bucket"
  run env "TF_VAR_account_id=$ACCOUNT_ID" terraform -chdir="$INFRA/$root" "$@"
}

tag_search() {
  # Every resource still tagged with the environment, in Tokyo, Osaka and us-east-1 (CloudFront's alarms, NFR-21).
  # The tagging API lists a deleted resource for a while after it goes, so a hit is checked before it counts.
  local region
  for region in "$TOKYO" "$OSAKA" us-east-1; do
    # shellcheck disable=SC2016 # a JMESPath literal, not a shell expansion
    run aws resourcegroupstaggingapi get-resources --region "$region" \
      --tag-filters "Key=project,Values=secure-file-transfer" "Key=environment,Values=$ENV_NAME" \
      --query 'ResourceTagMappingList[].[ResourceARN, Tags[?Key==`retention`].Value | [0]]' --output text
  done
  # What Kubernetes made outside Terraform: Karpenter's instances, volumes from claims, and their network interfaces.
  for region in "${REGIONS[@]}"; do
    run aws ec2 describe-instances --region "$region" --filters "Name=tag:karpenter.sh/discovery,Values=$(eks_cluster "$region")" \
      "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId'
    run aws ec2 describe-volumes --region "$region" \
      --filters "Name=tag:kubernetes.io/cluster/$(eks_cluster "$region"),Values=owned" --query 'Volumes[].VolumeId'
  done
}

ROOTS=()
while IFS= read -r root; do ROOTS+=("$root"); done < <(roots_in_order)

if $INVENTORY; then
  echo "== inventory, read-only: each root's state, then the tag search"
  EXECUTE=true # only reads follow: state list and the tag search
  for root in "${ROOTS[@]}"; do
    echo "-- $root"
    tf "$root" state list || echo "   (no state: already gone, or never built)"
  done
  tag_search
  exit 0
fi

echo "Would destroy, in this order ($SCOPE):"
[[ "$ENV_NAME" != prod ]] || echo "  0. environments/prod/retained: teardown apply (it stays; only its guards change)"
printf '%s\n' "${ROOTS[@]}" | nl -w3 -s'. ' | sed 's/^/ /'
if $EXECUTE && [[ "$ENV_NAME" == prod ]]; then
  [[ -n "${SFT_BUDGET_EMAIL:-}" ]] || die "set SFT_BUDGET_EMAIL: the retained stack's \$7 budget emails it (NFR-19)"
fi
confirm_execute
T0=$(date +%s)

retained_apply() {
  # Architecture 3.4 step 1: the environment's principals out of the audit key and bucket policies, the key's
  # rotation off, the retained trail's management events on, and the $7 budget (encryption 8.4).
  tf environments/prod/retained apply -var teardown=true -var "budget_email=${SFT_BUDGET_EMAIL:-<budget email>}"
}

drain_cluster() {
  local region="$1" ctx
  ctx="$(kube_context "$region")"
  # What Kubernetes made in AWS outside Terraform goes first, or the VPC can't be destroyed: Karpenter's nodes and
  # the volumes of persistent claims (the observability stack's).
  run kubectl --context "$ctx" delete nodepools.karpenter.sh --all --wait=true --timeout=10m
  run kubectl --context "$ctx" delete pvc --all-namespaces --all --wait=true --timeout=10m
}

data_teardown_apply() {
  local region="$1"
  # Aurora's deletion protection off, no final snapshot, the master secret without a recovery window (infra/README.md).
  tf "environments/$ENV_NAME/$region/data" apply -var teardown=true
}

destroy_root() {
  local root="$1"
  case "$root" in
    environments/*/cluster-bootstrap) drain_cluster "$(basename "$(dirname "$root")")" ;;
    environments/*/data) data_teardown_apply "$(basename "$(dirname "$root")")" ;;
    bootstrap/*)
      manual "The bootstrap stack's state bucket, key and key-admin role have prevent_destroy: on the teardown branch" \
        "set it false in modules/tfstate-backend and modules/key-admin-role, and move this root's state back to local" \
        "(terraform init -migrate-state with the backend block removed), as docs/runbooks/teardown.md step 5 says."
      ;;
  esac
  tf "$root" destroy -auto-approve
}

check_left() {
  tag_search
  manual "Nothing above may remain but resources tagged retention = audit-archive (prod) or nothing at all (dev and" \
    "staging). Check each hit; the tagging API shows deleted resources for a while."
}

[[ "$ENV_NAME" != prod ]] || step 600 "Retained stack: teardown apply" retained_apply
for root in "${ROOTS[@]}"; do
  step 0 "Destroy $root" destroy_root "$root"
done
step 600 "Tag search: nothing billable left but the retained stack" check_left
measure "Teardown, first step to the tag search" "$(minutes $(($(date +%s) - T0))) (NFR-19: 1h)"
manual "Check the next day's bill in Cost Explorer by environment tag, and the month's (NFR-19, NFR-20)."
finish
