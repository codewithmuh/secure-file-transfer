#!/usr/bin/env bash
# Rebuild of an environment on its bootstrap stacks: infra/README.md's apply order as one timed script, the counterpart
# of teardown.sh (docs/runbooks/environment-up-down.md, #295; NFR-19: built in 2 hours; NFR-20: dev and staging come
# back after an idle teardown). The environment workflow runs it as the environment's deploy role, the only identity
# that may change the environment's IAM (SCP OnlyDeployRolesChangeIam) and, with BreakGlass, its clusters (ADR-0004).
#
#   ops/rebuild.sh --env staging --profile sft-ci                                     # dry run: lists every step
#   ops/rebuild.sh --env dev --profile sft-ci --account-id <id> --stage foundation --execute --unattended
#
# Script options, besides the common ones (ops/lib/common.sh):
#   --stage S                 foundation: network, data, and network again for its flow log, Tokyo then Osaka.
#                             platform: cluster, edge and identity. stacks: both. after: the alarms, then the first
#                             deploy: the key rotation's first run (the identity layer's secrets start empty,
#                             deploy/README.md) and Argo CD's Applications synced and healthy. cluster-bootstrap goes
#                             between platform and after, in its own job (cluster-bootstrap-apply.yml), so all (the
#                             default) is for a dry run only. The environment workflow runs foundation and platform
#                             as two jobs, each with its own 2-hour deploy session (#299).
#   --unattended              with --execute: nobody at the keyboard (the environment workflow): no typed confirmation,
#                             and operator steps are listed in the log for after the run instead of waited for.
#   --allow-destroy           apply a plan that destroys or replaces something. Without it a rebuild refuses one: on
#                             a live environment a destroy means drift or a change that needs its own review.
#
# Safe to run again on a live environment: each apply converges, and Tokyo's osaka_ready=false, which only a first
# build takes, is passed only until Tokyo's data stack replicates to Osaka (its state holds the replication rules).
# Prod's retained stack is not here: it is built once, before prod's first data apply, and outlives every teardown.
# Pending the AWS run.
set -euo pipefail

DRILL=rebuild
STEPS_DOC=docs/runbooks/environment-up-down.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
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
[[ "$STAGE" =~ ^(foundation|platform|stacks|after|all)$ ]] || die "--stage must be foundation, platform, stacks, after or all"
! $EXECUTE || [[ "$STAGE" != all ]] || die "--execute takes --stage foundation, platform, stacks or after: cluster-bootstrap runs between platform and after, in its own job (cluster-bootstrap-apply.yml)"
DO_FOUNDATION=false
DO_PLATFORM=false
DO_AFTER=false
[[ ! "$STAGE" =~ ^(foundation|stacks|all)$ ]] || DO_FOUNDATION=true
[[ ! "$STAGE" =~ ^(platform|stacks|all)$ ]] || DO_PLATFORM=true
[[ ! "$STAGE" =~ ^(after|all)$ ]] || DO_AFTER=true
! $UNATTENDED || $EXECUTE || die "--unattended is for --execute"

REGIONS=("$TOKYO" "$OSAKA")
[[ "$ENV_NAME" != dev ]] || REGIONS=("$TOKYO")
TWO_REGIONS=false
[[ "$ENV_NAME" == dev ]] || TWO_REGIONS=true
env_root() { echo "environments/$ENV_NAME/$1/$2"; }
# Each step runs in a subshell (step, ops/lib/common.sh), so what one step learns for a later one goes in a file.
FIRST_BUILD_FILE="$(mktemp "${TMPDIR:-/tmp}/sft-rebuild-first-build.XXXXXX")"
FLOW_LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/sft-rebuild-flow-log.XXXXXX")" # the Regions whose network has its flow log
trap 'rm -f "$FIRST_BUILD_FILE" "$FLOW_LOG_FILE"' EXIT

# apply <root> [-var ...]: plan, refuse a plan that destroys anything (unless --allow-destroy), then apply that plan.
apply() {
  local root="$1" destroys plan
  shift
  plan="${SFT_TF_LOG_DIR:-${TMPDIR:-/tmp}/sft-$DRILL-$ENV_NAME-terraform}/${root//\//_}.tfplan"
  tf_root "$root" plan -input=false -out="$plan" "$@"
  if $EXECUTE; then
    destroys="$(plan_count "$TF_LAST_LOG" destroy)"
    if [[ "$destroys" != 0 ]] && ! $ALLOW_DESTROY; then
      die "$root: the plan destroys $destroys resource(s). A rebuild only creates and updates; review the plan (its log: $TF_LAST_LOG) and run again with --allow-destroy if it is meant"
    fi
  fi
  tf_run "$root" apply -input=false "$plan"
}

# --- stacks ----------------------------------------------------------------------------------------------------------

# The VPC flow log goes to the same Region's flow-log bucket, the data stack's flow_log_bucket_arn output, which a first
# build doesn't have yet: network goes once without it, then again after data (infra/README.md). Once the data stack
# exists every apply passes it, so no apply turns the flow log off.
#
# network <region> [again]: again is the apply after data, which runs only if the first had no bucket to pass (#299).
network() {
  local region="$1" again="${2:-}" data network arn list
  data="$(env_root "$region" data)"
  network="$(env_root "$region" network)"
  if [[ -n "$again" ]] && $EXECUTE && grep -qx "$region" "$FLOW_LOG_FILE"; then
    echo "   Its first apply passed the flow-log bucket already."
    return 0
  fi
  tf_init "$data"
  arn="$(tf_output "$data" flow_log_bucket_arn)" || exit 2
  arn="${arn//\"/}"
  if [[ -n "$arn" && "$arn" != null ]]; then
    echo "   TF_VAR_flow_log_destination_arn: the data stack's flow_log_bucket_arn output"
    TF_VAR_flow_log_destination_arn="$arn" apply "$network"
    echo "$region" >>"$FLOW_LOG_FILE"
    return 0
  fi
  [[ -z "$again" ]] || die "$data has no flow_log_bucket_arn output after its apply"
  if $EXECUTE; then
    # A teardown that stopped after data and before network leaves a flow log whose bucket is gone. Applied without
    # the bucket, network would plan to destroy it; after data, the bucket is back under the same name (#299).
    tf_init "$network"
    list="$(state_list "$network")" || exit 2
    if grep -q 'aws_flow_log\.this' <<<"$list"; then
      echo "   The flow log is there but its bucket isn't (a teardown that stopped partway): network waits for data."
      return 0
    fi
  fi
  echo "   No flow-log bucket yet (a first build): the flow log comes with network's apply after data."
  apply "$network"
}

# Whether Tokyo's data stack replicates to Osaka already: its state holds the files buckets' replication rules, which
# exist only with osaka_ready (modules/files-buckets). Until they do, Osaka isn't ready, whether this is a first build
# or one that stopped before Osaka's data stack was complete (#299), so the build can always be resumed.
tokyo_replicates() {
  local list
  $EXECUTE || return 1
  # Tested in an `if`, where a failure doesn't stop the script on its own: a state that can't be read exits here.
  list="$(state_list "$(env_root "$TOKYO" data)")" || exit 2
  grep -q 'aws_s3_bucket_replication_configuration\.this' <<<"$list"
}

# Tokyo's data stack. In staging and prod the Regions need each other's keys and buckets, so until Tokyo replicates,
# it goes with osaka_ready=false, then Osaka's, then Tokyo's again (infra/README.md). Once it replicates, osaka_ready
# keeps its default, true, so no apply turns replication off.
data_tokyo() {
  if ! $TWO_REGIONS; then
    apply "$(env_root "$TOKYO" data)"
    return
  fi
  tf_init "$(env_root "$TOKYO" data)"
  if tokyo_replicates; then
    echo "   Tokyo already replicates to Osaka: osaka_ready keeps its default (true)."
    echo false >"$FIRST_BUILD_FILE"
    apply "$(env_root "$TOKYO" data)"
  else
    echo "   Tokyo doesn't replicate to Osaka yet (a first build, or one that stopped early): osaka_ready=false first."
    echo true >"$FIRST_BUILD_FILE"
    apply "$(env_root "$TOKYO" data)" -var osaka_ready=false
  fi
}

# Osaka's data stack replicates Tokyo's key primaries (primary_key_arns, ops/lib/common.sh).
data_osaka() {
  primary_key_arns
  apply "$(env_root "$OSAKA" data)"
}

# A first build's second apply of Tokyo's data stack, now that Osaka's buckets and key replicas exist.
data_tokyo_again() {
  if $EXECUTE && [[ "$(cat "$FIRST_BUILD_FILE")" != true ]]; then
    echo "   Tokyo already replicates: its data stack keeps osaka_ready=true."
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
  arn="$(tf_output "$tokyo" web_distribution_arn)" || exit 2
  arn="${arn//\"/}"
  [[ -n "$arn" && "$arn" != null ]] || die "Tokyo's edge stack has no web_distribution_arn output; apply it first"
  echo "   TF_VAR_web_distribution_arn: Tokyo's web_distribution_arn output"
  TF_VAR_web_distribution_arn="$arn" apply "$(env_root "$OSAKA" edge)"
}

identity() { apply "$(env_root "$1" identity)"; }

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
# The sign-in triggers (identity) run the image the values pin. Checked before anything is built: without one, the
# build would stop at identity after about an hour of stacks that bill (#299).
if $EXECUTE && ($DO_FOUNDATION || $DO_PLATFORM) && [[ "$(image_digest)" =~ ^sha256:0+$ ]]; then
  die "deploy/environments/$ENV_NAME/$TOKYO/values.yaml pins no image yet (the all-zeros digest): the sign-in" \
    "triggers need one. Let build.yml build main, merge its pull request that pins dev, then run this again."
fi
if $DO_FOUNDATION || $DO_PLATFORM; then
  echo "Stacks, in this order:"
  {
    if $DO_FOUNDATION; then
      for region in "${REGIONS[@]}"; do env_root "$region" network; done
      env_root "$TOKYO" data
      if $TWO_REGIONS; then
        env_root "$OSAKA" data
        echo "$(env_root "$TOKYO" data) (again, until Tokyo replicates)"
      fi
      for region in "${REGIONS[@]}"; do printf '%s (again: the flow log, once data exists)\n' "$(env_root "$region" network)"; done
    fi
    if $DO_PLATFORM; then
      for layer in cluster edge identity; do
        for region in "${REGIONS[@]}"; do env_root "$region" "$layer"; done
      done
    fi
  } | nl -w3 -s'. ' | sed 's/^/ /'
fi
if [[ "$STAGE" == all ]]; then
  echo "Then cluster-bootstrap, Tokyo then Osaka, in cluster-bootstrap-apply.yml."
fi
if $DO_AFTER; then
  echo "Then the alarms ($(printf '%s ' "${REGIONS[@]}")) and the first deploy."
fi
confirm_execute
T0=$(date +%s)

if $DO_FOUNDATION; then
  for region in "${REGIONS[@]}"; do
    step 900 "Apply $(env_root "$region" network)" network "$region"
  done
  step 1800 "Apply $(env_root "$TOKYO" data)" data_tokyo
  if $TWO_REGIONS; then
    step 1800 "Apply $(env_root "$OSAKA" data)" data_osaka
    step 900 "Apply $(env_root "$TOKYO" data) again (until Tokyo replicates)" data_tokyo_again
  fi
  for region in "${REGIONS[@]}"; do
    step 600 "Apply $(env_root "$region" network) again: the flow log" network "$region" again
  done
fi

if $DO_PLATFORM; then
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

if $DO_AFTER; then
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
