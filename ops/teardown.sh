#!/usr/bin/env bash
# Timed teardown of an environment (docs/runbooks/teardown.md; architecture 3.4; NFR-19: prod destroyed in an hour,
# leaving only the retained stack; NFR-20: dev and staging torn down when idle).
#
#   ops/teardown.sh --env staging --profile sft-ci                                      # dry run: lists what would go
#   ops/teardown.sh --env staging --profile sft-ci --account-id <id> --inventory
#   ops/teardown.sh --env staging --profile sft-ci --account-id <id> --part layers --execute --unattended
#
# Who runs it (#295): the environment's stacks only as its deploy role, from the environment workflow (`make aws-down`):
# SCP OnlyDeployRolesChangeIam keeps every other identity, Admin included, from deleting their IAM roles, and only the
# deploy role and BreakGlass are cluster admins (ADR-0004). prod's retained stack only as its own deploy role (the
# workflow's prod-retained job), and the bootstrap stacks only as Admin, locally: SCP OnlyAdminChangesBootstrapIam.
#
# Script options, besides the common ones (ops/lib/common.sh):
#   --scope idle|final   idle (dev and staging only, the default there): the environment's stacks go; its bootstrap
#                        stays, so it can be built again. final (prod, the default there): also the bootstrap stacks,
#                        and in prod the retained stack's teardown apply comes first.
#   --last               with final: this is the last environment, so the shared account's registry goes too.
#   --part P             what this run does, by who may do it: retained (prod, final: the retained stack's teardown
#                        apply), layers (the environment's stacks, then the tag search), bootstrap (final: the
#                        bootstrap stacks, and with --last the shared registry), or all (the default: each in turn).
#   --unattended         with --execute: nobody at the keyboard (the environment workflow): no typed confirmation,
#                        applies are approved, and operator steps are listed in the log for after the run.
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
  sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'
  echo
  common_usage
}

parse_common "$@"
SCOPE=""
PART=all
LAST=false
INVENTORY=false
set -- "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope) SCOPE="${2:-}"; shift 2 ;;
    --last) LAST=true; shift ;;
    --part) PART="${2:-}"; shift 2 ;;
    --unattended) UNATTENDED=true; ASSUME_YES=true; shift ;;
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
[[ "$PART" =~ ^(retained|layers|bootstrap|all)$ ]] || die "--part must be retained, layers, bootstrap or all"
[[ "$PART" != retained || "$ENV_NAME" == prod ]] || die "--part retained is prod's: only prod has a retained stack"
[[ "$PART" != bootstrap || "$SCOPE" == final ]] || die "--part bootstrap needs --scope final: an idle teardown keeps the bootstrap"
! $UNATTENDED || $EXECUTE || die "--unattended is for --execute"
! $UNATTENDED || [[ "$PART" =~ ^(retained|layers)$ ]] ||
  die "--unattended takes --part retained or layers: the bootstrap's teardown has steps only Admin does by hand"
# An unattended run approves its own applies; an operator at the keyboard reads each plan and types yes.
APPROVE=()
! $UNATTENDED || APPROVE=(-auto-approve -input=false)
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
  if [[ "$PART" =~ ^(layers|all)$ ]]; then
    for layer in "${LAYERS[@]}"; do
      for region in "${REGIONS[@]}"; do
        echo "environments/$ENV_NAME/$region/$layer"
      done
    done
  fi
  if [[ "$SCOPE" == final && "$PART" =~ ^(bootstrap|all)$ ]]; then
    for region in "${REGIONS[@]}"; do
      echo "bootstrap/$ENV_NAME/$region"
    done
    ! $LAST || echo "shared"
  fi
}

tag_search() {
  # Every resource still tagged with the environment, in Tokyo, Osaka and us-east-1 (CloudFront's alarms, NFR-21).
  # The tagging API lists a deleted resource for a while after it goes, so a hit is checked before it counts. A search
  # that fails doesn't stop the teardown, whose stacks are gone by then: it is listed for the operator (#299).
  local region
  for region in "$TOKYO" "$OSAKA" us-east-1; do
    # shellcheck disable=SC2016 # a JMESPath literal, not a shell expansion
    run aws resourcegroupstaggingapi get-resources --region "$region" \
      --tag-filters "Key=project,Values=secure-file-transfer" "Key=environment,Values=$ENV_NAME" \
      --query 'ResourceTagMappingList[].[ResourceARN, Tags[?Key==`retention`].Value | [0]]' --output text ||
      search_failed "the tag search in $region"
  done
  # What Kubernetes made outside Terraform: Karpenter's instances, volumes from claims, and their network interfaces.
  for region in "${REGIONS[@]}"; do
    run aws ec2 describe-instances --region "$region" --filters "Name=tag:karpenter.sh/discovery,Values=$(region_prefix "$region")" \
      "Name=instance-state-name,Values=pending,running,stopping,stopped" --query 'Reservations[].Instances[].InstanceId' ||
      search_failed "the search for Karpenter's instances in $region"
    run aws ec2 describe-volumes --region "$region" \
      --filters "Name=tag:kubernetes.io/cluster/$(eks_cluster "$region"),Values=owned" --query 'Volumes[].VolumeId' ||
      search_failed "the search for the claims' volumes in $region"
  done
}

search_failed() {
  echo "   warning: $1 failed; nothing above proves that what it covers is gone" >&2
  # The inventory reports and exits, with no list for after the run: the warning is its report.
  if $EXECUTE && ! $INVENTORY && [[ -n "$LOG_FILE" ]]; then
    echo "- $1 failed: run it again by hand, or check Cost Explorer by the environment tag." >>"$LOG_FILE.todo"
  fi
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
  for root in "${ROOTS[@]+"${ROOTS[@]}"}"; do
    echo "-- $root"
    # The addresses only, never the attributes: safe for the workflow's public log.
    { tf_init "$root" >/dev/null && run terraform -chdir="$REPO_ROOT/infra/$root" state list; } ||
      echo "   (no state: already gone, or never built)"
  done
  tag_search
  exit 0
fi

RETAINED=false
[[ "$ENV_NAME" != prod || ! "$PART" =~ ^(retained|all)$ ]] || RETAINED=true
if [[ "$ENV_NAME" == prod ]]; then
  unmet=0
  prerequisites || unmet=$?
  if $EXECUTE; then
    ((unmet == 0)) || die "$unmet prerequisite(s) of a prod teardown unmet (docs/runbooks/teardown.md)"
    ! $RETAINED || [[ -n "${SFT_BUDGET_EMAIL:-}" ]] || die "set SFT_BUDGET_EMAIL: the retained stack's \$7 budget emails it (NFR-19)"
    [[ -n "${TF_VAR_alert_emails:-}" ]] || die "set TF_VAR_alert_emails: the retained stack's alert topics reach them (encryption 8.4)"
  fi
fi
# A destroy plans like an apply: every stack's required inputs, or Terraform refuses (#295).
[[ ! "$PART" =~ ^(layers|all)$ ]] || stack_inputs
echo "Would destroy, in this order ($SCOPE, part $PART):"
! $RETAINED || echo "  0. environments/prod/retained: teardown apply (it stays; only its guards change)"
[[ -z "${ROOTS[*]+set}" ]] || printf '%s\n' "${ROOTS[@]}" | nl -w3 -s'. ' | sed 's/^/ /'
confirm_execute
T0=$(date +%s)

retained_apply() {
  # Architecture 3.4 step 1: the environment's principals out of the audit key and bucket policies, the key's
  # rotation off, the retained trail's management events on, the GitHub OIDC provider adopted, and the $7 budget
  # (encryption 8.4). Its alert topics keep TF_VAR_alert_emails. The key-changed rules page for DisableKeyRotation:
  # expected, and acknowledged in the log.
  tf_root environments/prod/retained apply -var teardown=true -var "budget_email=${SFT_BUDGET_EMAIL:-<budget email>}" \
    "${APPROVE[@]+"${APPROVE[@]}"}"
  manual "Acknowledge the pages this apply sets off on purpose: kms-key-destroyed and retained-key-changed for the" \
    "audit key's DisableKeyRotation (docs/runbooks/kms-key-change.md, retained-stack-change.md)."
}

# teardown_apply <root>: the apply before a destroy that turns the stack's guards off (TF_VAR_teardown, #263). On a
# stack with parts missing (a teardown run again after its destroy took some, or a build that stopped partway), a plain
# apply would build them back only to destroy them. Then it goes to what's there only: everything a remaining resource
# depends on remains too, as a destroy takes dependents first and a build makes them last (#299). teardown=true adds
# nothing on these stacks (only the retained stack's does, which isn't destroyed here). An operator at the keyboard
# reads the plan and types yes; an unattended run applies it.
teardown_apply() {
  local root="$1" plan adds list addr answer targets=()
  plan="${SFT_TF_LOG_DIR:-${TMPDIR:-/tmp}/sft-$DRILL-$ENV_NAME-terraform}/${root//\//_}.teardown.tfplan"
  tf_root "$root" plan -input=false -var teardown=true -out="$plan"
  if $EXECUTE; then
    adds="$(plan_count "$TF_LAST_LOG" add)"
    if [[ "$adds" != 0 ]]; then
      echo "   The plan would build $adds resource(s) back: the guards go off on what's there, and nothing else."
      list="$(state_list "$root")" || exit 2
      while IFS= read -r addr; do targets+=("-target=$addr"); done <<<"$list"
      tf_run "$root" plan -input=false -var teardown=true -out="$plan" "${targets[@]}"
      adds="$(plan_count "$TF_LAST_LOG" add)"
      [[ "$adds" == 0 ]] ||
        die "$root: its teardown plan still adds $adds resource(s), targeted at what's there; its log: $TF_LAST_LOG"
    fi
    if ! $UNATTENDED; then
      read -r -p "   Apply this plan (above; its log: $TF_LAST_LOG)? Type yes: " answer
      [[ "$answer" == yes ]] || die "stopped before $root's teardown apply"
    fi
  fi
  tf_run "$root" apply -input=false "$plan"
}

drain_cluster() {
  local region="$1" ctx
  ctx="$(kube_context "$region")"
  # Argo CD's Applications first, while Argo CD still runs: their finalizer prunes what each synced, so no workload
  # holds a claim below, and nothing syncs it back (#295).
  run kubectl --context "$ctx" -n argocd delete applications.argoproj.io --all --wait=true --timeout=15m
  # Then the AppProjects, whose finalizer only Argo CD clears: left for the destroy, they would hold the argocd
  # namespace in Terminating after Argo CD is gone (#299).
  run kubectl --context "$ctx" -n argocd delete appprojects.argoproj.io --all --wait=true --timeout=5m
  # What Kubernetes made in AWS outside Terraform goes next, or the VPC can't be destroyed: Karpenter's nodes and
  # the volumes of persistent claims (the observability stack's).
  run kubectl --context "$ctx" delete nodepools.karpenter.sh --all --wait=true --timeout=10m
  run kubectl --context "$ctx" delete pvc --all-namespaces --all --wait=true --timeout=10m
}

# The cluster's platform: drained, then its stack destroyed, both through the tunnel (the private API; the root's
# Helm and Kubernetes providers reach it only there).
cluster_bootstrap_teardown() {
  local region="$1"
  drain_cluster "$region"
  tf_root "environments/$ENV_NAME/$region/cluster-bootstrap" destroy -auto-approve
}

data_teardown_apply() {
  local region="$1"
  # Osaka's data stack takes Tokyo's key primaries (primary_key_arns, ops/lib/common.sh, #299).
  [[ "$region" != "$OSAKA" ]] || primary_key_arns
  # Aurora's deletion protection off, no final snapshot, the master secret without a recovery window (infra/README.md).
  teardown_apply "environments/$ENV_NAME/$region/data"
}

destroy_root() {
  local root="$1"
  # A stack already destroyed (a teardown run again after it stopped) is skipped: a teardown apply on an empty state
  # would build the stack again (#299).
  if [[ "$root" == environments/* ]]; then
    tf_init "$root"
    if $EXECUTE && ! has_state "$root"; then
      echo "   Already gone: its state holds nothing."
      return 0
    fi
  fi
  case "$root" in
    environments/*/cluster-bootstrap)
      with_tunnel "$(basename "$(dirname "$root")")" cluster_bootstrap_teardown "$(basename "$(dirname "$root")")"
      return
      ;;
    environments/*/data) data_teardown_apply "$(basename "$(dirname "$root")")" ;;
    # prod only: deletion protection off before the destroy.
    environments/prod/*/cluster | environments/prod/*/identity | environments/prod/*/edge) teardown_apply "$root" ;;
    bootstrap/prod/"$TOKYO")
      # The GitHub OIDC provider stays for the retained stack's deploy role, which adopted it in step 0.
      tf_root "$root" state rm 'module.terraform_roles.aws_iam_openid_connect_provider.github[0]'
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
  tf_root "$root" destroy -auto-approve
}

check_left() {
  tag_search
  if [[ "$PART" == layers && "$SCOPE" == final ]]; then
    manual "Nothing above may remain but the bootstrap stacks' resources (their part is still to come, as Admin) and" \
      "those tagged retention = audit-archive. Check each hit; the tagging API shows deleted resources for a while."
  else
    manual "Nothing above may remain but resources tagged retention = audit-archive (prod) or nothing at all (dev and" \
      "staging). Check each hit; the tagging API shows deleted resources for a while."
  fi
}

! $RETAINED || step 600 "Retained stack: teardown apply" retained_apply
for root in "${ROOTS[@]+"${ROOTS[@]}"}"; do
  step 0 "Destroy $root" destroy_root "$root"
done
[[ "$PART" == retained ]] || step 600 "Tag search: nothing billable left but the retained stack" check_left
measure "Teardown, first step to the tag search" "$(minutes $(($(date +%s) - T0))) (NFR-19: 1h)"
manual "Check the next day's bill in Cost Explorer by environment tag, and the month's (NFR-19, NFR-20)."
finish
