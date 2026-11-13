#!/usr/bin/env bash
# Rebuild of an environment on its bootstrap stacks: infra/README.md's apply order as one timed script, the counterpart
# of teardown.sh (docs/runbooks/environment-up-down.md, #295; NFR-19: built in 2 hours; NFR-20: dev and staging come
# back after an idle teardown). The environment workflow runs it as the environment's deploy role, the only identity
# that may change the environment's IAM (SCP OnlyDeployRolesChangeIam) and, with BreakGlass, its clusters (ADR-0004).
#
#   ops/rebuild.sh --env staging --profile sft-ci                                     # dry run: lists every step
#   ops/rebuild.sh --env dev --profile sft-ci --account-id <id> --stage stacks --execute --unattended
#
# Script options, besides the common ones (ops/lib/common.sh):
#   --stage stacks|after|all  stacks: network, data, cluster, edge and identity, layer by layer, Tokyo then Osaka.
#                             after: the alarms, then the first deploy: the key rotation's first run (the identity
#                             layer's secrets start empty, deploy/README.md) and Argo CD's Applications synced and
#                             healthy. cluster-bootstrap goes between the two, in its own job
#                             (cluster-bootstrap-apply.yml), so all (the default) is for a dry run only.
#   --unattended              with --execute: nobody at the keyboard (the environment workflow): no typed confirmation,
#                             and operator steps are listed in the log for after the run instead of waited for.
#   --allow-destroy           apply a plan that destroys or replaces something. Without it a rebuild refuses one: on
#                             a live environment a destroy means drift or a change that needs its own review.
#
# Safe to run again on a live environment: each apply converges, and the inputs only a first build takes (Tokyo's
# osaka_ready=false, before Osaka's data stack exists) are passed only while Osaka's data stack holds nothing.
# Prod's retained stack is not here: it is built once, before prod's first data apply, and outlives every teardown.
# Pending the AWS run.
set -euo pipefail

DRILL=rebuild
STEPS_DOC=docs/runbooks/environment-up-down.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
  echo
  common_usage
}

parse_common "$@"
STAGE=all
ALLOW_DESTROY=false
set -- "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --stage) STAGE="${2:-}"; shift 2 ;;
    --unattended) UNATTENDED=true; ASSUME_YES=true; shift ;;
    --allow-destroy) ALLOW_DESTROY=true; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$STAGE" =~ ^(stacks|after|all)$ ]] || die "--stage must be stacks, after or all"
! $EXECUTE || [[ "$STAGE" != all ]] || die "--execute takes --stage stacks or after: cluster-bootstrap runs between them, in its own job (cluster-bootstrap-apply.yml)"
! $UNATTENDED || $EXECUTE || die "--unattended is for --execute"

REGIONS=("$TOKYO" "$OSAKA")
[[ "$ENV_NAME" != dev ]] || REGIONS=("$TOKYO")
TWO_REGIONS=false
[[ "$ENV_NAME" == dev ]] || TWO_REGIONS=true
env_root() { echo "environments/$ENV_NAME/$1/$2"; }
FIRST_BUILD_FILE="$(mktemp "${TMPDIR:-/tmp}/sft-rebuild-first-build.XXXXXX")"
trap 'rm -f "$FIRST_BUILD_FILE"' EXIT

# apply <root> [-var ...]: plan, refuse a plan that destroys anything (unless --allow-destroy), then apply that plan.
apply() {
  local root="$1" destroys plan
  shift
  plan="${SFT_TF_LOG_DIR:-${TMPDIR:-/tmp}/sft-$DRILL-$ENV_NAME-terraform}/${root//\//_}.tfplan"
  tf_root "$root" plan -input=false -out="$plan" "$@"
  if $EXECUTE; then
    destroys="$(sed -n 's/^Plan: .* \([0-9][0-9]*\) to destroy\.$/\1/p' "$TF_LAST_LOG" | head -1)"
    if [[ -n "$destroys" && "$destroys" != 0 ]] && ! $ALLOW_DESTROY; then
      die "$root: the plan destroys $destroys resource(s). A rebuild only creates and updates; review the plan (its log: $TF_LAST_LOG) and run again with --allow-destroy if it is meant"
    fi
  fi
  tf_run "$root" apply -input=false "$plan"
}

# --- stacks ----------------------------------------------------------------------------------------------------------

network() { apply "$(env_root "$1" network)"; }

# Tokyo's data stack. In staging and prod the Regions need each other's keys and buckets, so a first build applies it
# with osaka_ready=false, then Osaka's, then Tokyo's again (infra/README.md). A first build is one where Osaka's data
# stack holds nothing yet; once it does, osaka_ready keeps its default, true, so no apply turns replication off.
data_tokyo() {
  local osaka
  if ! $TWO_REGIONS; then
    apply "$(env_root "$TOKYO" data)"
    return
  fi
  osaka="$(env_root "$OSAKA" data)"
  tf_init "$osaka"
  if has_state "$osaka"; then
    echo "   Osaka's data stack exists: osaka_ready keeps its default (true)."
    echo false >"$FIRST_BUILD_FILE"
    apply "$(env_root "$TOKYO" data)"
  else
    echo "   Osaka's data stack holds nothing: a first build, so Tokyo goes first with osaka_ready=false."
    echo true >"$FIRST_BUILD_FILE"
    apply "$(env_root "$TOKYO" data)" -var osaka_ready=false
  fi
}

# Osaka's data stack replicates Tokyo's key primaries: Tokyo's kms_key_arns output (modules/data-stack).
data_osaka() {
  local tokyo keys
  tokyo="$(env_root "$TOKYO" data)"
  tf_init "$tokyo"
  keys="$(tf_output "$tokyo" kms_key_arns)"
  [[ -n "$keys" && "$keys" != null ]] || die "Tokyo's data stack has no kms_key_arns output; apply it first"
  echo "   TF_VAR_primary_key_arns: Tokyo's kms_key_arns output"
  TF_VAR_primary_key_arns="$keys" apply "$(env_root "$OSAKA" data)"
}

# A first build's second apply of Tokyo's data stack, now that Osaka's buckets and key replicas exist.
data_tokyo_again() {
  if $EXECUTE && [[ "$(cat "$FIRST_BUILD_FILE")" != true ]]; then
    echo "   Not a first build: Tokyo's data stack already has osaka_ready=true."
    return 0
  fi
  apply "$(env_root "$TOKYO" data)"
}

cluster() { apply "$(env_root "$1" cluster)"; }

# Osaka's web bucket has one reader, Tokyo's distribution (Tokyo's edge output web_distribution_arn).
edge() {
  local region="$1" tokyo arn
  if [[ "$region" == "$TOKYO" ]]; then
    apply "$(env_root "$TOKYO" edge)"
    return
  fi
  tokyo="$(env_root "$TOKYO" edge)"
  tf_init "$tokyo"
  arn="$(tf_output "$tokyo" web_distribution_arn)"
  arn="${arn//\"/}"
  [[ -n "$arn" && "$arn" != null ]] || die "Tokyo's edge stack has no web_distribution_arn output; apply it first"
  echo "   TF_VAR_web_distribution_arn: Tokyo's web_distribution_arn output"
  TF_VAR_web_distribution_arn="$arn" apply "$(env_root "$OSAKA" edge)"
}

identity() {
  if $EXECUTE && [[ "$(image_digest)" =~ ^sha256:0+$ ]]; then
    die "deploy/environments/$ENV_NAME/$TOKYO/values.yaml pins no image yet (the all-zeros digest): the sign-in" \
      "triggers need one. Let build.yml build main, merge its pull request that pins dev, then run this again."
  fi
  apply "$(env_root "$1" identity)"
}

# --- after -----------------------------------------------------------------------------------------------------------

alarms() { apply "$(env_root "$1" alarms)"; }

# The first deploy (deploy/README.md, "The first deploy of an environment"): Argo CD syncs on its own once
# cluster-bootstrap has installed it; the API and the notifier wait for their keyrings, which only the key rotation job
# writes, so start it rather than wait for the hour. Running it again on a live environment is one more rotation.
first_deploy() {
  local ctx job
  ctx="$(kube_context "$TOKYO")"
  job="key-rotation-rebuild-$(date -u +%Y%m%d%H%M%S)"
  run kubectl --context "$ctx" -n argocd wait applications.argoproj.io/sft --for=create --timeout=15m
  run kubectl --context "$ctx" -n sft wait cronjob/key-rotation --for=create --timeout=15m
  run kubectl --context "$ctx" -n sft create job "$job" --from=cronjob/key-rotation
  run kubectl --context "$ctx" -n sft wait "job/$job" --for=condition=complete --timeout=15m
  synced_and_healthy "$TOKYO"
}

# synced_and_healthy <region>: every Argo CD Application in the cluster synced to main and healthy. Osaka's pilot light
# runs its Deployments at zero, which Argo CD counts as healthy.
synced_and_healthy() {
  local ctx
  ctx="$(kube_context "$1")"
  run kubectl --context "$ctx" -n argocd wait applications.argoproj.io --all \
    --for=jsonpath='{.status.sync.status}'=Synced --timeout=30m
  run kubectl --context "$ctx" -n argocd wait applications.argoproj.io --all \
    --for=jsonpath='{.status.health.status}'=Healthy --timeout=30m
  run kubectl --context "$ctx" -n argocd get applications.argoproj.io
}

# --- order -----------------------------------------------------------------------------------------------------------

stack_inputs
if [[ "$STAGE" != after ]]; then
  echo "Stacks, in this order:"
  {
    for region in "${REGIONS[@]}"; do env_root "$region" network; done
    env_root "$TOKYO" data
    if $TWO_REGIONS; then
      env_root "$OSAKA" data
      echo "$(env_root "$TOKYO" data) (again, on a first build)"
    fi
    for layer in cluster edge identity; do
      for region in "${REGIONS[@]}"; do env_root "$region" "$layer"; done
    done
  } | nl -w3 -s'. ' | sed 's/^/ /'
fi
if [[ "$STAGE" == all ]]; then
  echo "Then cluster-bootstrap, Tokyo then Osaka, in cluster-bootstrap-apply.yml."
fi
if [[ "$STAGE" != stacks ]]; then
  echo "Then the alarms ($(printf '%s ' "${REGIONS[@]}")) and the first deploy."
fi
confirm_execute
T0=$(date +%s)

if [[ "$STAGE" != after ]]; then
  for region in "${REGIONS[@]}"; do
    step 900 "Apply $(env_root "$region" network)" network "$region"
  done
  step 1800 "Apply $(env_root "$TOKYO" data)" data_tokyo
  if $TWO_REGIONS; then
    step 1800 "Apply $(env_root "$OSAKA" data)" data_osaka
    step 900 "Apply $(env_root "$TOKYO" data) again (first build only)" data_tokyo_again
  fi
  for region in "${REGIONS[@]}"; do
    step 1800 "Apply $(env_root "$region" cluster)" cluster "$region"
  done
  for region in "${REGIONS[@]}"; do
    step 1200 "Apply $(env_root "$region" edge)" edge "$region"
  done
  for region in "${REGIONS[@]}"; do
    step 900 "Apply $(env_root "$region" identity)" identity "$region"
  done
fi

if [[ "$STAGE" == all ]]; then
  manual "cluster-bootstrap, Tokyo then Osaka: the environment workflow runs cluster-bootstrap-apply.yml here."
fi

if [[ "$STAGE" != stacks ]]; then
  for region in "${REGIONS[@]}"; do
    step 600 "Apply $(env_root "$region" alarms)" alarms "$region"
  done
  manual "Each alert address confirms its SNS subscriptions: a rebuilt alarms stack makes new topics, and AWS emails" \
    "a confirmation link to every address in TF_VAR_alert_emails (infra/modules/alarms)."
  step 2700 "First deploy in $TOKYO: key rotation, Argo CD synced and healthy" with_tunnel "$TOKYO" first_deploy
  if $TWO_REGIONS; then
    step 1200 "Osaka's pilot light: Argo CD synced and healthy" with_tunnel "$OSAKA" synced_and_healthy "$OSAKA"
  fi
fi

measure "Rebuild ($STAGE), first step to the last" "$(minutes $(($(date +%s) - T0))) (NFR-19: 2h for the whole)"
finish
