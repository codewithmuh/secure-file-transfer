# shellcheck shell=bash
# What every drill and teardown script in ops/ shares (docs/operations/disaster-recovery.md, "The scripts").
#
# The safety contract, the same in every script:
# - It refuses to start without an explicit --env and --profile. The profile is passed to every AWS call, and the
#   environment's own credentials (AWS_ACCESS_KEY_ID and friends, AWS_PROFILE) are cleared first, so the default CLI
#   identity is never used (CLAUDE.md).
# - It is a dry run unless --execute is given: every command is printed, nothing runs, and the drill log goes to a
#   temporary file. With --execute it first checks that the profile signs in to the account named by --account-id,
#   then asks the operator to type the environment's name, unless --yes.
# - Every step is timed against its budget and appended to the drill log, whose layout is
#   docs/operations/drill-log-template.md. Manual steps wait for the operator and are timed the same way.
#
# A script sources this file, sets DRILL (its name) and STEPS_DOC (its runbook), calls parse_common "$@", then runs
# its steps with step/run/manual, and ends with finish.

set -euo pipefail

OPS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$OPS_ROOT/.." && pwd)"

ENV_NAME=""
PROFILE=""
ACCOUNT_ID=""
EXECUTE=false
ASSUME_YES=false
# Set by a script that accepts --unattended (rebuild.sh, teardown.sh), for the environment workflow: nobody is at the
# keyboard, so operator steps are logged for after the run instead of waited for (#295).
UNATTENDED=false
LOG_FILE=""
EXTRA_ARGS=()

# Region names and their short forms (infra/README.md, Names).
TOKYO=ap-northeast-1
OSAKA=ap-northeast-3

common_usage() {
  cat <<EOF
Common options (every script in ops/):
  --env <dev|staging|prod>   the environment; required
  --profile <name>           the named AWS CLI profile for that environment's account; required, never "default"
  --account-id <12 digits>   the account the profile must sign in to; required with --execute
  --execute                  run the commands; without it, a dry run that prints them and runs nothing
  --yes                      with --execute, don't ask to type the environment's name
  --log <file>               the drill log to append to (default: docs/operations/drills/<date>-$DRILL-<env>.md
                             with --execute, a temporary file in a dry run)
  -h, --help                 this text
EOF
}

die() {
  echo "error: $*" >&2
  exit 2
}

# parse_common "$@": the common options; anything else is kept in EXTRA_ARGS for the script.
parse_common() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --env) ENV_NAME="${2:-}"; shift 2 ;;
      --profile) PROFILE="${2:-}"; shift 2 ;;
      --account-id) ACCOUNT_ID="${2:-}"; shift 2 ;;
      --execute) EXECUTE=true; shift ;;
      --yes) ASSUME_YES=true; shift ;;
      --log) LOG_FILE="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) EXTRA_ARGS+=("$1"); shift ;;
    esac
  done

  [[ -n "$ENV_NAME" ]] || die "--env is required (dev, staging or prod); nothing runs without it"
  [[ "$ENV_NAME" =~ ^(dev|staging|prod)$ ]] || die "--env must be dev, staging or prod, not '$ENV_NAME'"
  [[ -n "$PROFILE" ]] || die "--profile is required: name the environment's AWS CLI profile; the default identity is never used"
  [[ "$PROFILE" != "default" ]] || die "--profile default is refused: name the environment's own profile"

  # Never the environment's own credentials or default profile: only --profile signs the calls.
  unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN AWS_DEFAULT_PROFILE
  export AWS_PROFILE="$PROFILE"
  export AWS_PAGER=""

  if $EXECUTE; then
    [[ "$ACCOUNT_ID" =~ ^[0-9]{12}$ ]] || die "--account-id <12 digits> is required with --execute"
  fi
  # A dry run without one prints a placeholder where the account's ID goes (bucket names, ARNs).
  ACCOUNT_ID="${ACCOUNT_ID:-<account-id>}"
  start_log
}

# The drill log: a copy of the template's header, then one row per step.
start_log() {
  local stamp
  stamp="$(date -u +%Y-%m-%d)"
  if [[ -z "$LOG_FILE" ]]; then
    if $EXECUTE; then
      LOG_FILE="$REPO_ROOT/docs/operations/drills/$stamp-$DRILL-$ENV_NAME.md"
    else
      LOG_FILE="$(mktemp "${TMPDIR:-/tmp}/sft-$DRILL-$ENV_NAME-dry-run.XXXXXX")"
    fi
  fi
  mkdir -p "$(dirname "$LOG_FILE")"
  if [[ ! -s "$LOG_FILE" ]]; then
    {
      echo "# Drill log: $DRILL, $ENV_NAME, $stamp"
      echo
      echo "Runbook: $STEPS_DOC. Template: docs/operations/drill-log-template.md."
      echo "Mode: $($EXECUTE && echo execute || echo "dry run (nothing ran)"). Operator profile: $PROFILE."
      echo
      echo "| # | Step | Budget | Started (UTC) | Ended (UTC) | Took | Within budget | Result |"
      echo "|---|---|---:|---|---|---:|---|---|"
    } >"$LOG_FILE"
  fi
  STEP_NUMBER=0
  DRILL_STARTED=$(date +%s)
  echo "== $DRILL, $ENV_NAME: $($EXECUTE && echo EXECUTE || echo "dry run, nothing runs") (log: $LOG_FILE)"
}

# confirm_execute: in execute mode, check the account and ask the operator to type the environment's name.
confirm_execute() {
  $EXECUTE || return 0
  local account
  account="$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)"
  [[ "$account" == "$ACCOUNT_ID" ]] || die "profile $PROFILE signs in to $account, not $ACCOUNT_ID"
  if ! $ASSUME_YES; then
    local typed
    read -r -p "This changes the $ENV_NAME environment in account $ACCOUNT_ID. Type '$ENV_NAME' to go on: " typed
    [[ "$typed" == "$ENV_NAME" ]] || die "not confirmed"
  fi
}

# run <command...>: print it; run it only with --execute.
run() {
  printf '   $'
  printf ' %q' "$@"
  printf '\n'
  if $EXECUTE; then
    "$@"
  fi
}

# manual <text>: an operator's action; with --execute, wait until they say it's done. In an unattended run it is
# listed in the log under "Left for the operator" instead, and the script goes on.
manual() {
  echo "   [operator] $*"
  if $EXECUTE; then
    if $UNATTENDED; then
      echo "   (unattended: left for the operator, listed at the end of the log)"
      echo "- $*" >>"$LOG_FILE.todo"
    else
      read -r -p "   Done? Press Enter when it is (Ctrl-C stops the drill): " _
    fi
  fi
}

# step <budget seconds> <name> <function> [args...]: run one timed step and log it. The function runs in a subshell
# with errexit on, so its first failing command fails the step (inside an `if`, bash would ignore errexit); it keeps
# what it measures with `measure`, which writes to a file, not a variable.
step() {
  local budget="$1" name="$2"
  shift 2
  STEP_NUMBER=$((STEP_NUMBER + 1))
  local started ended took result within status
  started=$(date +%s)
  echo
  echo "-- $STEP_NUMBER. $name (budget $(minutes "$budget"))"
  set +e
  (
    set -e
    "$@"
  )
  status=$?
  set -e
  if ((status == 0)); then result=ok; else result="failed ($status)"; fi
  ended=$(date +%s)
  took=$((ended - started))
  if $EXECUTE; then
    if ((budget == 0)); then within="n/a"; elif ((took <= budget)); then within=yes; else within=NO; fi
  else
    within="dry run"
  fi
  printf '| %s | %s | %s | %s | %s | %s | %s | %s |\n' "$STEP_NUMBER" "$name" "$(minutes "$budget")" \
    "$(utc "$started")" "$(utc "$ended")" "$(minutes "$took")" "$within" "$result" >>"$LOG_FILE"
  [[ "$result" == ok ]] || die "step $STEP_NUMBER ($name) failed; the log so far is $LOG_FILE"
}

# measure <name> <value>: a measured number for the drill report (RTO, RPO, counts), listed under the table.
measure() {
  printf '| %s | %s |\n' "$1" "$2" >>"$LOG_FILE.measures"
  echo "   measured: $1 = $2"
}

finish() {
  local took=$(($(date +%s) - DRILL_STARTED))
  {
    echo
    echo "Total: $(minutes "$took") from the first step to the last."
    if [[ -s "$LOG_FILE.measures" ]]; then
      echo
      echo "| Measure | Value |"
      echo "|---|---|"
      cat "$LOG_FILE.measures"
    fi
    if [[ -s "$LOG_FILE.todo" ]]; then
      echo
      echo "Left for the operator (an unattended run doesn't wait for these):"
      echo
      cat "$LOG_FILE.todo"
    fi
    echo
    echo "Fill in the rest of the report from docs/operations/drill-log-template.md: what went wrong, what changes."
  } >>"$LOG_FILE"
  rm -f "$LOG_FILE.measures" "$LOG_FILE.todo"
  echo
  echo "== done in $(minutes "$took"); log: $LOG_FILE"
}

minutes() {
  local s="$1"
  printf '%dm%02ds' $((s / 60)) $((s % 60))
}

utc() {
  # BSD date (macOS) and GNU date read an epoch differently.
  date -u -r "$1" +%H:%M:%S 2>/dev/null || date -u -d "@$1" +%H:%M:%S
}

# Names (infra/README.md, Names): the Aurora global database and clusters, the EKS clusters and kube contexts. The
# global database is sft-<env>-aurora until a failback after a detach makes sft-<env>-aurora-<n> (#261):
# SFT_AURORA_GENERATION names it.
global_cluster() {
  local generation="${SFT_AURORA_GENERATION:-1}"
  if [[ "$generation" == 1 ]]; then echo "sft-$ENV_NAME-aurora"; else echo "sft-$ENV_NAME-aurora-$generation"; fi
}
db_cluster() { echo "sft-$ENV_NAME-$(short "$1")-aurora"; }
# sft-<env>-<region-short>: the prefix of the region's names, Karpenter's discovery tag among them (modules/network).
region_prefix() { echo "sft-$ENV_NAME-$(short "$1")"; }
# The EKS cluster, <prefix>-eks (modules/eks-cluster), whose name Kubernetes puts in its volumes' tags.
eks_cluster() { echo "$(region_prefix "$1")-eks"; }
short() {
  case "$1" in
    "$TOKYO") echo apne1 ;;
    "$OSAKA") echo apne3 ;;
    *) die "unknown region $1" ;;
  esac
}
# kubectl reaches each private cluster API through the Systems Manager tunnel (modules/cluster-bootstrap); the
# operator names the kube context for each region, or takes these defaults.
kube_context() {
  case "$1" in
    "$TOKYO") echo "${SFT_KUBE_CONTEXT_TOKYO:-sft-$ENV_NAME-apne1}" ;;
    "$OSAKA") echo "${SFT_KUBE_CONTEXT_OSAKA:-sft-$ENV_NAME-apne3}" ;;
  esac
}

# ---------------------------------------------------------------------------------------------------------------------
# The environment's stacks, for rebuild.sh and teardown.sh (#295; infra/README.md, "Apply order").

# What every environment root takes besides its account, from the operator's shell or the environment workflow's
# variables and secrets; never committed. A destroy needs them as much as an apply: Terraform plans neither without a
# required variable.
STACK_INPUTS=(TF_VAR_domain TF_VAR_shared_account_id TF_VAR_dmarc_report_address TF_VAR_alert_emails)

# stack_inputs: print which are set; with --execute, refuse to go on without all of them.
stack_inputs() {
  local name missing=0
  echo "Inputs of the environment's stacks:"
  for name in "${STACK_INPUTS[@]}"; do
    if [[ -n "${!name:-}" ]]; then
      echo "  set:     $name"
    else
      echo "  not set: $name"
      missing=$((missing + 1))
    fi
  done
  echo "  derived: TF_VAR_signin_trigger_image, per Region, from the shared registry and the digest in" \
    "deploy/environments/$ENV_NAME/$TOKYO/values.yaml"
  if $EXECUTE && ((missing > 0)); then
    die "$missing input(s) not set (docs/runbooks/environment-up-down.md, \"Inputs\")"
  fi
  return 0
}

# image_digest: the digest the environment's values pin; the promotion workflow edits only that line (ADR-0005).
image_digest() {
  sed -n 's/^  digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p' "$REPO_ROOT/deploy/environments/$ENV_NAME/$TOKYO/values.yaml" |
    head -1
}

# signin_trigger_image <region>: the image the sign-in triggers run, from the shared registry in that Region (Lambda
# pulls only from its own Region; modules/registry replicates to Osaka), by the digest the environment runs (#238).
signin_trigger_image() {
  echo "${TF_VAR_shared_account_id:-<shared-account-id>}.dkr.ecr.$1.amazonaws.com/sft/app@$(image_digest)"
}

# tf_init <root>: terraform init for a root under infra/, with its account's state bucket (infra/README.md, State).
tf_init() {
  local root="$1" region=$TOKYO bucket
  [[ "$root" != *"/$OSAKA"* ]] || region=$OSAKA
  bucket="sft-$ENV_NAME-$(short "$region")-tfstate-$ACCOUNT_ID"
  # The retained stack keeps its state in its own bucket, under the audit key (encryption 8.4).
  [[ "$root" != environments/prod/retained ]] || bucket="sft-prod-apne1-retained-tfstate-$ACCOUNT_ID"
  tf_run "$root" init -input=false -reconfigure -backend-config="bucket=$bucket"
}

# tf_root <root> <terraform args...>: init, then the command, with the account and the inputs of the root's Region:
# the sign-in triggers' image, and the shared account's DNS role to assume, deploy (edge and identity, #185).
tf_root() {
  local root="$1" region=$TOKYO
  shift
  [[ "$root" != *"/$OSAKA"* ]] || region=$OSAKA
  export TF_VAR_account_id="$ACCOUNT_ID" TF_VAR_terraform_role=deploy
  TF_VAR_signin_trigger_image="$(signin_trigger_image "$region")"
  export TF_VAR_signin_trigger_image
  tf_init "$root"
  tf_run "$root" "$@"
}

# tf_run <root> <terraform args...>: print it; with --execute run it in infra/<root>, its whole output also kept in a
# file (SFT_TF_LOG_DIR, or a temporary directory). With SFT_TF_QUIET=1, as in the environment workflow, whose logs
# are public, only the summary and error lines are printed: plans and applies name endpoints and resource IDs.
tf_run() {
  local root="$1" logs log status=0
  shift
  printf '   $ terraform -chdir=infra/%s' "$root"
  printf ' %q' "$@"
  printf '\n'
  $EXECUTE || return 0
  logs="${SFT_TF_LOG_DIR:-${TMPDIR:-/tmp}/sft-$DRILL-$ENV_NAME-terraform}"
  mkdir -p "$logs"
  log="$logs/${root//\//_}.$1.log"
  if [[ "${SFT_TF_QUIET:-}" == 1 ]]; then
    TF_CLI_ARGS_init=-no-color TF_CLI_ARGS_plan=-no-color TF_CLI_ARGS_apply=-no-color TF_CLI_ARGS_destroy=-no-color \
      terraform -chdir="$REPO_ROOT/infra/$root" "$@" >"$log" 2>&1 || status=$?
    if ((status == 0)); then
      grep -E '^(Plan:|No changes|Apply complete|Destroy complete)' "$log" | sed 's/^/   /' || true
    else
      grep -E '^(Error|│)' "$log" | head -60 >&2 || true
    fi
  else
    terraform -chdir="$REPO_ROOT/infra/$root" "$@" 2>&1 | tee "$log" || status=$?
  fi
  # shellcheck disable=SC2034 # read by rebuild.sh's destroy guard, after the plan
  TF_LAST_LOG="$log"
  return "$status"
}

# tf_output <root> <name>: one output of an initialized root, as JSON; empty when the root has no state or no such
# output. Any other failure stops the script: an output that can't be read isn't one that's missing (#299). It runs in
# a command substitution, where that stop ends only the substitution, so callers add `|| exit 2`. A dry run prints a
# placeholder.
tf_output() {
  local out err
  if ! $EXECUTE; then
    echo "<$2 output of $1>"
    return 0
  fi
  err="$(mktemp "${TMPDIR:-/tmp}/sft-tf-output.XXXXXX")"
  if out="$(terraform -chdir="$REPO_ROOT/infra/$1" output -no-color -json "$2" 2>"$err")"; then
    rm -f "$err"
    printf '%s\n' "$out"
  elif grep -qF "Output \"$2\" not found" "$err"; then
    rm -f "$err"
  else
    out="$(cat "$err")"
    rm -f "$err"
    die "can't read infra/$1's $2 output: $out"
  fi
}

# primary_key_arns: Osaka's data stack replicates Tokyo's key primaries, a required input with no default, so it gets
# TF_VAR_primary_key_arns from Tokyo's data stack's kms_key_arns output (modules/data-stack). The rebuild applies
# Osaka's after Tokyo's, and the teardown destroys it first, so Tokyo's state has them both times.
primary_key_arns() {
  local tokyo="environments/$ENV_NAME/$TOKYO/data" keys
  tf_init "$tokyo"
  keys="$(tf_output "$tokyo" kms_key_arns)" || exit 2
  [[ -n "$keys" && "$keys" != null ]] || die "Tokyo's data stack has no kms_key_arns output, which Osaka's needs"
  echo "   TF_VAR_primary_key_arns: Tokyo's kms_key_arns output"
  export TF_VAR_primary_key_arns="$keys"
}

# state_list <root>: the resource addresses an initialized root's state holds, empty when it has none. A state that
# can't be read stops the script: guessing "empty" would plan a first build's inputs, or a create, on a live stack.
state_list() {
  local list
  if list="$(terraform -chdir="$REPO_ROOT/infra/$1" state list 2>&1)"; then
    printf '%s\n' "$list"
  elif [[ "$list" == *"No state file was found"* ]]; then
    return 0
  else
    die "can't read infra/$1's state: $list"
  fi
}

# has_state <root>: whether an initialized root holds any resource; a dry run says no. Callers test it in an `if`,
# where a failure doesn't stop the script on its own, so a state that can't be read exits here (#299).
has_state() {
  local list
  $EXECUTE || return 1
  list="$(state_list "$1")" || exit 2
  [[ -n "$list" ]]
}

# plan_count <log> <add|destroy>: how many resources a plan's log says it adds or destroys (0 when it says nothing),
# from Terraform's summary line, colored or not: "Plan: 1 to add, 0 to change, 2 to destroy." or "..., 2 to destroy,
# 1 to forget."
plan_count() {
  local n
  n="$(sed $'s/\x1b\\[[0-9;]*m//g' "$1" | grep -m1 '^Plan: ' | grep -oE "[0-9]+ to $2" | grep -oE '^[0-9]+')" || true
  echo "${n:-0}"
}

# with_tunnel <region> <command...>: run it with that Region's private cluster API reachable through the Systems
# Manager tunnel (.github/scripts/cluster-tunnel.sh, ADR-0021): KUBECONFIG holds a context under kube_context's default
# name, and TF_VAR_cluster_api_tunnel_url is the tunnel's local end, for the cluster-bootstrap root's providers. The
# tunnel closes afterwards, whatever the command did. Needs the Session Manager plugin, and an identity the cluster
# admits: the deploy role (the environment workflow) or BreakGlass.
with_tunnel() {
  local region="$1" port kubeconfig status=0
  shift
  # A port per Region, so a tunnel still closing in one never answers for the next (#299).
  port=8443
  [[ "$region" != "$OSAKA" ]] || port=8444
  port="${SFT_TUNNEL_PORT:-$port}"
  kubeconfig="${TMPDIR:-/tmp}/sft-$ENV_NAME-$(short "$region")-kubeconfig"
  run "$REPO_ROOT/.github/scripts/cluster-tunnel.sh" open "$ENV_NAME" "$region" "$port" "$kubeconfig"
  set +e
  (
    set -e
    unset SFT_KUBE_CONTEXT_TOKYO SFT_KUBE_CONTEXT_OSAKA # the tunnel's kubeconfig names the default contexts
    export KUBECONFIG="$kubeconfig" TF_VAR_cluster_api_tunnel_url="https://127.0.0.1:$port"
    "$@"
  )
  status=$?
  set -e
  run "$REPO_ROOT/.github/scripts/cluster-tunnel.sh" close
  return "$status"
}

# The recovery job (sft.service.recovery_replay, run as sft_recovery): the suspended `recovery` CronJob, rendered with
# its steps and times, as docs/runbooks/field-keys.md renders field-keys. Needs kubectl and yq.
#   recovery_job <region> <steps> [since] [rewind_to] [archive region]
# An archive region other than the job's reads that region's audit archive, with the database still the job's: the
# failback's replay in Tokyo reads Osaka's (#276).
recovery_job() {
  local region="$1" steps="$2" since="${3:-}" rewind_to="${4:-}" archive="${5:-}"
  local name
  name="recovery-$(date -u +%H%M%S)"
  local filter
  filter="(.spec.template.spec.containers[0].env[] | select(.name == \"RECOVERY_STEPS\")).value = \"$steps\""
  if [[ -n "$since" ]]; then
    filter+=" | (.spec.template.spec.containers[0].env[] | select(.name == \"RECOVERY_SINCE\")).value = \"$since\""
  fi
  if [[ -n "$rewind_to" ]]; then
    filter+=" | (.spec.template.spec.containers[0].env[] | select(.name == \"RECOVERY_REWIND_TO\")).value = \"$rewind_to\""
  fi
  if [[ -n "$archive" && "$archive" != "$region" ]]; then
    filter+=" | (.spec.template.spec.containers[0].env[] | select(.name == \"AUDIT_ARCHIVE_BUCKET\")).value = \"$(region_prefix "$archive")-audit-archive-$ACCOUNT_ID\""
    filter+=" | (.spec.template.spec.containers[0].env[] | select(.name == \"AUDIT_ARCHIVE_REGION\")).value = \"$archive\""
  fi
  printf '   $ kubectl --context %s -n sft create job --from=cronjob/recovery %s --dry-run=client -o yaml | yq %q | kubectl apply -f -\n' \
    "$(kube_context "$region")" "$name" "$filter"
  if $EXECUTE; then
    kubectl --context "$(kube_context "$region")" -n sft create job --from=cronjob/recovery "$name" \
      --dry-run=client -o yaml | yq "$filter" | kubectl --context "$(kube_context "$region")" apply -f -
    kubectl --context "$(kube_context "$region")" -n sft wait --for=condition=complete --timeout=15m "job/$name"
    kubectl --context "$(kube_context "$region")" -n sft logs "job/$name" | tail -20
  fi
}

# drill_marker <start|end> <region>: the drill's marker on that region's Pushgateway (docs/runbooks/drill-in-progress.md):
# sft_drill_active{drill="$DRILL"} is 1 while the drill runs, so Alertmanager holds back the pages and tickets it sets
# off on purpose (never those marked security="true") and the SLOs leave its window out (docs/operations/slos.md 4).
# Pushed through a port-forward to the observability stack's Pushgateway, as `job="drill"`; ended by deleting it. A
# region whose stack isn't running (a pilot light) has no Pushgateway: the push fails with a warning, never the drill.
drill_marker() {
  local action="$1" region="$2" ctx port=19091 url
  ctx="$(kube_context "$region")"
  url="http://127.0.0.1:$port/metrics/job/drill/drill/$DRILL"
  printf '   $ kubectl --context %s -n monitoring port-forward svc/pushgateway %s:9091 &\n' "$ctx" "$port"
  if [[ "$action" == start ]]; then
    printf "   \$ echo 'sft_drill_active 1' | curl --fail --data-binary @- %s\n" "$url"
  else
    printf '   $ curl --fail -X DELETE %s\n' "$url"
  fi
  $EXECUTE || return 0
  local forward ok=true
  kubectl --context "$ctx" -n monitoring port-forward svc/pushgateway "$port:9091" >/dev/null 2>&1 &
  forward=$!
  sleep 3
  if [[ "$action" == start ]]; then
    echo 'sft_drill_active 1' | curl --silent --show-error --fail --data-binary @- "$url" || ok=false
  else
    curl --silent --show-error --fail -X DELETE "$url" || ok=false
  fi
  kill "$forward" 2>/dev/null || true
  $ok || echo "   warning: the drill marker ($action) didn't reach $region's Pushgateway; see drill-in-progress.md" >&2
}
