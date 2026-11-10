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
# A dry run (the default) checks the prerequisites in the repository (prod: the retained stack's own state bucket,
# deploy role, trail and alerts, its teardown inputs, and the teardown inputs of the stacks prod protects), prints
# every stack in the order it would be destroyed, with the commands, and runs none. With --execute it refuses while a
# prerequisite is unmet, runs them, times each step against NFR-19's hour, and ends with the tag search: nothing
# tagged with the environment may remain but the retained stack's (retention = audit-archive). Pending the AWS run.
set -euo pipefail

DRILL=teardown
STEPS_DOC=docs/runbooks/teardown.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'
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
# The layers of an environment, in the order they are destroyed: the reverse of infra/README.md's apply order, so
# alarms, applied last, go first.
LAYERS=(alarms cluster-bootstrap identity edge cluster data network)
# prod's layers with deletion protection, which a teardown apply turns off before the destroy (TF_VAR_teardown, #263);
# data's teardown apply does more (below). dev and staging have none on.
PROTECTED_LAYERS=(cluster identity edge)
REGIONS=("$OSAKA" "$TOKYO") # Osaka first: it replicates Tokyo's keys and refers to Tokyo's roles
[[ "$ENV_NAME" != dev ]] || REGIONS=("$TOKYO")

# Layer by layer, Osaka then Tokyo within each: a Tokyo stack that reads an Osaka state (alarms reads Osaka's edge,
# cluster-bootstrap Osaka's identity) goes before the Osaka stack it reads, and Osaka's key replicas go before Tokyo's
# primaries.
roots_in_order() {
  local region layer
  for layer in "${LAYERS[@]}"; do
    for region in "${REGIONS[@]}"; do
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
    run aws ec2 describe-instances --region "$region" --filters "Name=tag:karpenter.sh/discovery,Values=$(region_prefix "$region")" \
      "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId'
    run aws ec2 describe-volumes --region "$region" \
      --filters "Name=tag:kubernetes.io/cluster/$(eks_cluster "$region"),Values=owned" --query 'Volumes[].VolumeId'
  done
}

ROOTS=()
while IFS= read -r root; do ROOTS+=("$root"); done < <(roots_in_order)

# The prerequisites of a prod teardown that live in the repository (docs/runbooks/teardown.md, "Prerequisites"):
# each is a file and a line that must be in it. Read from the checkout, so the dry run needs no AWS. The operator's
# own prerequisites (Rashid's go, no file data left to keep) are printed as operator steps below.
PREREQUISITES=(
  "the retained stack's own state bucket, under the audit key|environments/prod/retained/state.tf|resource \"aws_s3_bucket\" \"state\""
  "the retained stack's own deploy role|environments/prod/retained/deploy-role.tf|resource \"aws_iam_role\" \"deploy\""
  "the retained stack adopts the GitHub OIDC provider at teardown|environments/prod/retained/deploy-role.tf|resource \"aws_iam_openid_connect_provider\" \"github\""
  "the retained trail|environments/prod/retained/trail.tf|resource \"aws_cloudtrail\" \"retained\""
  "the retained stack's EventBridge alerts|environments/prod/retained/alerts.tf|resource \"aws_cloudwatch_event_rule\" \"retained_tokyo\""
  "the environment's roles out of the audit key and archive bucket policies at teardown|environments/prod/retained/archive.tf|environment_retired = var.teardown"
  "the audit key's rotation off at teardown|modules/kms-keys/main.tf|enable_key_rotation     = !var.environment_retired"
  "teardown rights for prod's files buckets (#42 gap 11)|modules/data-stack/storage.tf|teardown_allowed = local.teardown_allowed || var.teardown"
)
for region in "$TOKYO" "$OSAKA"; do
  for layer in "${PROTECTED_LAYERS[@]}"; do
    PREREQUISITES+=("a teardown input for prod's $region $layer deletion protection|environments/prod/$region/$layer/variables.tf|variable \"teardown\"")
  done
done

prerequisites() {
  local entry what file line unmet=0
  echo "Prerequisites of a prod teardown, in the repository:"
  for entry in "${PREREQUISITES[@]}"; do
    IFS='|' read -r what file line <<<"$entry"
    if grep -qF -- "$line" "$INFRA/$file" 2>/dev/null; then
      echo "  met:   $what (infra/$file)"
    else
      echo "  UNMET: $what (infra/$file)"
      unmet=$((unmet + 1))
    fi
  done
  echo "Inputs the operator sets before --execute:"
  local name
  for name in SFT_BUDGET_EMAIL TF_VAR_alert_emails; do
    if [[ -n "${!name:-}" ]]; then echo "  set:     $name"; else echo "  not set: $name"; fi
  done
  return "$unmet"
}

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

if [[ "$ENV_NAME" == prod ]]; then
  unmet=0
  prerequisites || unmet=$?
  if $EXECUTE; then
    ((unmet == 0)) || die "$unmet prerequisite(s) of a prod teardown unmet (docs/runbooks/teardown.md)"
    [[ -n "${SFT_BUDGET_EMAIL:-}" ]] || die "set SFT_BUDGET_EMAIL: the retained stack's \$7 budget emails it (NFR-19)"
    [[ -n "${TF_VAR_alert_emails:-}" ]] || die "set TF_VAR_alert_emails: the retained stack's alert topics reach them (encryption 8.4)"
  fi
fi
echo "Would destroy, in this order ($SCOPE):"
[[ "$ENV_NAME" != prod ]] || echo "  0. environments/prod/retained: teardown apply (it stays; only its guards change)"
printf '%s\n' "${ROOTS[@]}" | nl -w3 -s'. ' | sed 's/^/ /'
confirm_execute
T0=$(date +%s)

retained_apply() {
  # Architecture 3.4 step 1: the environment's principals out of the audit key and bucket policies, the key's
  # rotation off, the retained trail's management events on, the GitHub OIDC provider adopted, and the $7 budget
  # (encryption 8.4). Its alert topics keep TF_VAR_alert_emails. The key-changed rules page for DisableKeyRotation:
  # expected, and acknowledged in the log.
  tf environments/prod/retained apply -var teardown=true -var "budget_email=${SFT_BUDGET_EMAIL:-<budget email>}"
  manual "Acknowledge the pages this apply sets off on purpose: kms-key-destroyed and retained-key-changed for the" \
    "audit key's DisableKeyRotation (docs/runbooks/kms-key-change.md, retained-stack-change.md)."
}

protected_teardown_apply() {
  local root="$1"
  # prod only: deletion protection off before the destroy (TF_VAR_teardown, #263).
  tf "$root" apply -var teardown=true
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
    environments/prod/*/cluster | environments/prod/*/identity | environments/prod/*/edge) protected_teardown_apply "$root" ;;
    bootstrap/prod/"$TOKYO")
      # The GitHub OIDC provider stays for the retained stack's deploy role, which adopted it in step 0.
      tf "$root" state rm 'module.terraform_roles.aws_iam_openid_connect_provider.github[0]'
      manual "The bootstrap stack's state bucket, key and key-admin role have prevent_destroy: on the teardown branch" \
        "set it false in modules/tfstate-backend and modules/key-admin-role, and move this root's state back to local" \
        "(terraform init -migrate-state with the backend block removed), as docs/runbooks/teardown.md step 2 says."
      ;;
    bootstrap/*)
      manual "The bootstrap stack's state bucket, key and key-admin role have prevent_destroy: on the teardown branch" \
        "set it false in modules/tfstate-backend and modules/key-admin-role, and move this root's state back to local" \
        "(terraform init -migrate-state with the backend block removed), as docs/runbooks/teardown.md step 2 says."
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
