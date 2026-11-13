#!/usr/bin/env bash
# The regional failover, Tokyo to Osaka, step by step and timed against the budget of architecture 7
# (docs/runbooks/regional-failover.md, NFR-10, NFR-11). The same script runs the drill and a real failover:
#
#   ops/regional-failover.sh --env staging --profile sft-staging-admin                        # dry run: prints it all
#   ops/regional-failover.sh --env staging --profile sft-staging-admin --account-id <id> --execute --mode drill
#
# Script options, besides the common ones (ops/lib/common.sh):
#   --mode drill|real   drill: Tokyo is healthy and the failure is declared at the start; real: Tokyo is lost.
#                       It changes how the database is promoted and how DNS moves (the runbook says why).
#   --failed-at <time>  real mode: when Tokyo failed, ISO 8601 UTC (default: now). The recovery job's windows
#                       count back from it.
#
# Each step's commands are printed in a dry run; with --execute they run, and manual steps wait for the operator.
# The step names and budgets are architecture 7's; the drill log records each step's time and the RTO and RPO.
# Pending the AWS run: nothing here has run against AWS yet.
set -euo pipefail

DRILL=regional-failover
STEPS_DOC=docs/runbooks/regional-failover.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
  echo
  common_usage
}

parse_common "$@"
MODE=drill
FAILED_AT=""
set -- "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2 ;;
    --failed-at) FAILED_AT="${2:-}"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$MODE" =~ ^(drill|real)$ ]] || die "--mode must be drill or real"
[[ "$ENV_NAME" != dev ]] || die "dev has no Osaka pilot light; drill in staging, then prod"

# The failure's time, from which the recovery windows count back: 1 hour for the archive cursor and the re-import
# (#42, docs/operations/disaster-recovery.md), 24 hours for the outbox (architecture 5.3).
T0=$(date +%s)
FAILED_AT="${FAILED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
iso_minus() { # iso_minus <iso time> <seconds>
  local epoch
  epoch=$(date -u -j -f %Y-%m-%dT%H:%M:%SZ "$1" +%s 2>/dev/null || date -u -d "$1" +%s)
  date -u -r $((epoch - $2)) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$((epoch - $2))" +%Y-%m-%dT%H:%M:%SZ
}
REWIND_TO="$(iso_minus "$FAILED_AT" 3600)"
OUTBOX_SINCE="$(iso_minus "$FAILED_AT" 86400)"
OSAKA_CTX="$(kube_context "$OSAKA")"

confirm_execute
measure "Mode" "$MODE"
measure "Failure declared at (UTC)" "$FAILED_AT"

# ---- the steps of architecture 7 ----

decide() {
  if [[ "$MODE" == drill ]]; then
    manual "Announce the drill window (NFR-1: logged and reported apart). Start the drill writer: the synthetic probe" \
      "every minute, so the RPO has a recent write to lose."
  else
    manual "Confirm the regional failure: Route 53 health checks of Tokyo's load balancer failing, the AWS Health" \
      "Dashboard for ap-northeast-1, and alarms from the watchdog. Decide to fail over (it is always a person's decision)."
  fi
}

# The RPO's evidence: how far behind Osaka was when the writer moved (NFR-10). In a drill that is the promotion;
# in a real failover, the failure.
rpo_evidence() {
  local start end
  if [[ "$MODE" == drill ]]; then end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; else end="$FAILED_AT"; fi
  start="$(iso_minus "$end" 600)"
  run aws cloudwatch get-metric-statistics --region "$OSAKA" --namespace AWS/RDS \
    --metric-name AuroraGlobalDBRPOLag --dimensions "Name=DBClusterIdentifier,Value=$(db_cluster "$OSAKA")" \
    --start-time "$start" --end-time "$end" --period 60 --statistics Maximum
  for bucket in files large-files; do
    # RTC's replication metrics on Tokyo's rule: the latency and what was still pending (ADR-0012).
    run aws cloudwatch get-metric-statistics --region "$TOKYO" --namespace AWS/S3 \
      --metric-name ReplicationLatency --dimensions "Name=SourceBucket,Value=$(region_prefix "$TOKYO")-$bucket-$ACCOUNT_ID" \
      "Name=DestinationBucket,Value=$(region_prefix "$OSAKA")-$bucket-$ACCOUNT_ID" "Name=RuleId,Value=to-osaka" \
      --start-time "$start" --end-time "$end" --period 60 --statistics Maximum
  done
  manual "Write the largest AuroraGlobalDBRPOLag (database RPO) and ReplicationLatency (files RPO) above into the" \
    "drill log's RPO lines. In a real failover Tokyo's S3 metrics may not answer: then the RPO is the newest" \
    "audit event in Osaka against the failure time, from the recovery job's log in step 5."
}

fence() {
  run "$OPS_ROOT/failover-values.sh" fence --env "$ENV_NAME" --write
  # The surviving region's archive alone (#257): the API's security-critical records and the archive job write
  # Osaka's archive only, so download grants work while Tokyo's S3 can't be reached. A drill sets it too, so the
  # failback's back-fill of Tokyo is proved every time.
  run "$OPS_ROOT/failover-values.sh" surviving-osaka --env "$ENV_NAME" --write
  manual "Commit the two values files as one commit, 'ops: fence Tokyo and take $ENV_NAME Osaka out of pilot light'," \
    "and push it to main (the maintainer commits). Argo CD in Osaka syncs it; Tokyo converges to zero whenever it answers."
}

promote() {
  if [[ "$MODE" == drill ]]; then
    # Managed failover with data loss allowed, as in a real loss, so the drill measures the RPO it would lose.
    run aws rds failover-global-cluster --region "$OSAKA" --global-cluster-identifier "$(global_cluster)" \
      --target-db-cluster-identifier "arn:aws:rds:$OSAKA:$ACCOUNT_ID:cluster:$(db_cluster "$OSAKA")" --allow-data-loss
  else
    # Managed failover first; if it can't run because Tokyo doesn't answer, detach and promote (ADR-0011).
    if ! run aws rds failover-global-cluster --region "$OSAKA" --global-cluster-identifier "$(global_cluster)" \
      --target-db-cluster-identifier "arn:aws:rds:$OSAKA:$ACCOUNT_ID:cluster:$(db_cluster "$OSAKA")" \
      --allow-data-loss || ! $EXECUTE; then
      echo "   if managed failover is refused, detach and promote instead:"
      run aws rds remove-from-global-cluster --region "$OSAKA" --global-cluster-identifier "$(global_cluster)" \
        --db-cluster-identifier "arn:aws:rds:$OSAKA:$ACCOUNT_ID:cluster:$(db_cluster "$OSAKA")"
    fi
  fi
  run aws rds wait db-cluster-available --region "$OSAKA" --db-cluster-identifier "$(db_cluster "$OSAKA")"
  manual "Check that Osaka's cluster is the writer: aws rds describe-global-clusters --region $OSAKA" \
    "--global-cluster-identifier $(global_cluster) (IsWriter true for apne3), or, after a detach, that it is standalone."
  rpo_evidence
}

scale_osaka() {
  # Inputs only (#261): the system node group, GuardDuty's plan for Osaka's large-files bucket, and Osaka's alarms,
  # all set for the pilot light, by applies of Osaka's roots with the apply checklist's inputs (#247), which the
  # operator holds. Nothing in Git changes for them: the inputs are the failover's.
  manual "Apply infra/environments/$ENV_NAME/$OSAKA/cluster with TF_VAR_system_node_count=2;" \
    "infra/environments/$ENV_NAME/$OSAKA/data with TF_VAR_malware_protection_enabled=true; and" \
    "infra/environments/$ENV_NAME/$OSAKA/alarms with TF_VAR_heartbeat_enabled=true TF_VAR_pilot_light=false" \
    "TF_VAR_database_role=primary (and TF_VAR_probe_enabled=true where the probe runs; runbook step 4). In a drill," \
    "also Tokyo's alarms with TF_VAR_database_role=secondary."
  run kubectl --context "$OSAKA_CTX" -n sft rollout status deploy/api --timeout=20m
  run kubectl --context "$OSAKA_CTX" -n sft-operator rollout status deploy/operator-api --timeout=10m
}

generation_and_replay() {
  # One more than the highest generation in Osaka's archive, the cursor rewound an hour; then partitions and the
  # re-import and re-apply of every record of that hour (sft.service.recovery_replay).
  recovery_job "$OSAKA" "generation,partitions,replay" "$REWIND_TO" "$REWIND_TO"
  manual "Read the job's last lines into the drill log: generation, reapplied, not_reapplied, present, the newest" \
    "audit event before the failure (the database RPO in a real failover), and tell tenant admins of every" \
    "re-applied lockout and every unlock that wasn't re-applied (their members unlock again)."
}

standby_sign_in() {
  # Alongside the next two steps (architecture 7): after the re-apply, so no member it deactivated is enrolled.
  run kubectl --context "$OSAKA_CTX" -n sft create job --from=cronjob/standby-enrolment "standby-enrolment-$(date -u +%H%M%S)"
  manual "Sign in once through the standby pool with an SSO test member of the synthetic tenant."
}

outbox_and_workers() {
  recovery_job "$OSAKA" "outbox" "$OUTBOX_SINCE"
  run "$OPS_ROOT/failover-values.sh" release-workers --env "$ENV_NAME" --write
  manual "Commit and push the values change, 'ops: start $ENV_NAME Osaka's workers after the failover'."
  run kubectl --context "$OSAKA_CTX" -n sft rollout status deploy/relay --timeout=10m
  run kubectl --context "$OSAKA_CTX" -n sft rollout status deploy/notifier --timeout=10m
  run kubectl --context "$OSAKA_CTX" -n sft rollout status deploy/scan-worker-small --timeout=10m
}

dns_and_cdn() {
  if [[ "$MODE" == drill ]]; then
    # Tokyo's edge stack owns the API's record; its state is in Tokyo, which answers in a drill.
    manual "Apply infra/environments/$ENV_NAME/$TOKYO/edge with TF_VAR_api_alias_target set to Osaka's edge output" \
      "load_balancer (terraform -chdir=infra/environments/$ENV_NAME/$OSAKA/edge output -json load_balancer)."
  else
    manual "Tokyo's edge state may not answer: UPSERT the API's alias record in the shared zone to Osaka's load" \
      "balancer through the environment's DNS role (runbook step 7 has the command). Record the drift; failback's" \
      "edge apply puts it back under Terraform."
  fi
  manual "The web app: CloudFront's origin group fails over to Osaka's bundle bucket by itself; check one page load."
}

verify() {
  run kubectl --context "$OSAKA_CTX" -n sft create job --from=cronjob/synthetic-probe "probe-failover-$(date -u +%H%M%S)"
  run aws cloudwatch get-metric-statistics --region "$OSAKA" --namespace SecureFileTransfer/Probe \
    --metric-name ProbeSuccess --dimensions "Name=Environment,Value=$ENV_NAME" \
    --start-time "$FAILED_AT" --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --period 60 --statistics Minimum
  manual "Check the probe's email arrived from Osaka's SES, and a sign-in through the standby pool works."
}

# A drill marks itself in each region's Pushgateway (docs/runbooks/drill-in-progress.md): Tokyo's now, Osaka's once its
# observability stack has started with the fencing commit. A real failover pages as it should.
if [[ "$MODE" == drill ]]; then drill_marker start "$TOKYO"; fi
step 600 "Confirm the regional failure and decide to fail over" decide
step 120 "Fence Tokyo through Git; take Osaka out of pilot light" fence
step 300 "Promote the Osaka database" promote
step 1200 "Scale Osaka: system nodes, main and scan nodes, GuardDuty plan, heartbeat" scale_osaka
if [[ "$MODE" == drill ]]; then drill_marker start "$OSAKA"; fi
step 300 "New archive generation; re-import and re-apply security-critical changes" generation_and_replay
step 0 "Sign-in: enrol members without SSO in the standby pool (alongside)" standby_sign_in
step 300 "Re-publish the outbox's last 24 hours, then scale the workers up" outbox_and_workers
step 300 "Switch DNS and the CDN origin to Osaka" dns_and_cdn
step 300 "Verify with the synthetic probe, an email from Osaka and a standby sign-in" verify

measure "RTO: decision to verified service" "$(minutes $(($(date +%s) - T0))) (budget 57m, NFR-11: 1h)"
if [[ "$MODE" == drill ]]; then
  drill_marker end "$OSAKA"
  manual "Tokyo's observability stack stopped with the fencing commit, its marker with it. If Tokyo's Pushgateway"     "comes back with the marker, delete it there too (drill-in-progress.md)."
fi
finish
