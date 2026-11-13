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

# manual <text>: an operator's action; with --execute, wait until they say it's done.
manual() {
  echo "   [operator] $*"
  if $EXECUTE; then
    read -r -p "   Done? Press Enter when it is (Ctrl-C stops the drill): " _
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
    echo
    echo "Fill in the rest of the report from docs/operations/drill-log-template.md: what went wrong, what changes."
  } >>"$LOG_FILE"
  rm -f "$LOG_FILE.measures"
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
