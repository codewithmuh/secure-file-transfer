#!/usr/bin/env bash
# The planned failback, Osaka to Tokyo, after a regional failover (docs/runbooks/regional-failback.md; architecture
# 7; #42: S3 failback). Tokyo is healthy again, so nothing is lost: the database moves by switchover (RPO 0), the
# files come back by Batch Replication, and the service pauses its workers, not its API, while it moves.
#
#   ops/regional-failback.sh --env staging --profile sft-staging-admin                        # dry run
#   ops/regional-failback.sh --env staging --profile sft-staging-admin --account-id <id> --execute \
#     --failed-over-at 2026-12-01T03:00:00Z
#
# Script options, besides the common ones (ops/lib/common.sh):
#   --failed-over-at <time>  when the failover happened, ISO 8601 UTC: the files written in Osaka since then are
#                            copied back to Tokyo. Required with --execute.
#
# No NFR sets a failback time. The budgets are a first estimate for a maintenance window, for the first drill to
# measure and correct. Pending the AWS run.
set -euo pipefail

DRILL=regional-failback
STEPS_DOC=docs/runbooks/regional-failback.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  echo
  common_usage
}

parse_common "$@"
FAILED_OVER_AT=""
set -- "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --failed-over-at) FAILED_OVER_AT="${2:-}"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$ENV_NAME" != dev ]] || die "dev has no Osaka; there is nothing to fail back"
if $EXECUTE; then
  [[ "$FAILED_OVER_AT" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$ ]] || die "--failed-over-at <ISO 8601 UTC> is required"
fi
FAILED_OVER_AT="${FAILED_OVER_AT:-<failed-over-at>}"
HELD_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TOKYO_CTX="$(kube_context "$TOKYO")"
OSAKA_CTX="$(kube_context "$OSAKA")"

confirm_execute
T0=$(date +%s)

ready() {
  manual "Tokyo is healthy: AWS Health shows ap-northeast-1 recovered, and Tokyo's stacks are applied again in the" \
    "order of infra/README.md with its cluster in pilot light (the fenced values). Tokyo's state bucket answers."
  run aws rds describe-global-clusters --region "$OSAKA" --global-cluster-identifier "$(global_cluster)"
  manual "Tokyo's database is Osaka's secondary and caught up: after a managed failover Aurora brings the old cluster" \
    "back as a secondary by itself; after a detach, delete it (its snapshot stays 30 days for the reconciliation" \
    "report) and apply Tokyo's data root as the secondary (runbook step 2). Wait for AuroraGlobalDBReplicationLag < 1 s."
}

files_back() {
  # Objects written in Osaka while it was primary: S3 Batch Replication along the Osaka-to-Tokyo rule that the
  # failback apply adds (runbook step 3). Replicas keep their tags, so `scan` comes back with them.
  for bucket in files large-files; do
    run aws s3control create-job --region "$OSAKA" --account-id "$ACCOUNT_ID" --no-confirmation-required \
      --priority 10 --operation '{"S3ReplicateObject":{}}' --report '{"Enabled":false}' \
      --role-arn "arn:aws:iam::$ACCOUNT_ID:role/sft-$ENV_NAME-s3-batch-replication" \
      --manifest-generator "{\"S3JobManifestGenerator\":{\"SourceBucket\":\"arn:aws:s3:::sft-$ENV_NAME-apne3-$bucket-$ACCOUNT_ID\",\"EnableManifestOutput\":false,\"Filter\":{\"EligibleForReplication\":true,\"CreatedAfter\":\"$FAILED_OVER_AT\"}}}"
  done
  manual "Wait for both jobs to complete (aws s3control describe-job), and write their object counts in the drill log."
}

hold_osaka() {
  run "$OPS_ROOT/failover-values.sh" hold-osaka --env "$ENV_NAME" --write
  manual "Commit and push 'ops: hold $ENV_NAME Osaka's workers for the failback'. Uploads and downloads go on; scans," \
    "emails and lifecycle jobs wait."
  run kubectl --context "$OSAKA_CTX" -n sft rollout status deploy/relay --timeout=10m
}

switchover() {
  # A switchover, not a failover: Aurora waits for Tokyo to catch up, so nothing is lost (ADR-0011).
  run aws rds switchover-global-cluster --region "$OSAKA" --global-cluster-identifier "$(global_cluster)" \
    --target-db-cluster-identifier "arn:aws:rds:$TOKYO:$ACCOUNT_ID:cluster:$(db_cluster "$TOKYO")"
  run aws rds wait db-cluster-available --region "$TOKYO" --db-cluster-identifier "$(db_cluster "$TOKYO")"
  manual "Check IsWriter for apne1 in describe-global-clusters."
}

values_back() {
  run "$OPS_ROOT/failover-values.sh" failback --env "$ENV_NAME" --write
  manual "Commit and push 'ops: fence $ENV_NAME Osaka and take Tokyo out of pilot light'."
  run kubectl --context "$TOKYO_CTX" -n sft rollout status deploy/api --timeout=20m
}

generation_and_outbox() {
  # A new writer region starts a new archive generation; the re-import of the hour finds every record present
  # (nothing was lost) and proves it. Then the outbox since the hold, for what sat in Osaka's queues.
  recovery_job "$TOKYO" "generation,partitions,replay" "$HELD_AT" "$HELD_AT"
  recovery_job "$TOKYO" "outbox" "$HELD_AT"
  run "$OPS_ROOT/failover-values.sh" release-tokyo --env "$ENV_NAME" --write
  manual "Commit and push 'ops: start $ENV_NAME Tokyo's workers after the failback'."
  run kubectl --context "$TOKYO_CTX" -n sft rollout status deploy/notifier --timeout=10m
}

dns_back() {
  manual "Apply infra/environments/$ENV_NAME/$TOKYO/edge without TF_VAR_api_alias_target: the API's name points at" \
    "Tokyo again, and any record a real failover set by hand is back under Terraform."
}

osaka_pilot_light() {
  run aws eks update-nodegroup-config --region "$OSAKA" --cluster-name "$(eks_cluster "$OSAKA")" \
    --nodegroup-name "$(eks_cluster "$OSAKA")-system" --scaling-config minSize=1,maxSize=1,desiredSize=1
  manual "Apply Osaka's data root without TF_VAR_malware_protection_enabled (the plan goes), the alarms with the" \
    "heartbeat off, and drop the Osaka-to-Tokyo replication rule (runbook step 8)."
}

verify() {
  run kubectl --context "$TOKYO_CTX" -n sft create job --from=cronjob/synthetic-probe "probe-failback-$(date -u +%H%M%S)"
  manual "The probe passes from Tokyo; a member without SSO signs in with their original Tokyo credentials."
}

# A planned failback marks itself in Osaka's Pushgateway now and in Tokyo's once its stack is back
# (docs/runbooks/drill-in-progress.md): holding the workers sets off alerts on purpose.
drill_marker start "$OSAKA"
step 1800 "Tokyo ready: stacks applied, database caught up as Osaka's secondary" ready
step 1800 "Copy the files written in Osaka back to Tokyo" files_back
step 300 "Hold Osaka's workers" hold_osaka
step 300 "Switch the database over to Tokyo (no data loss)" switchover
step 600 "Fence Osaka, take Tokyo out of pilot light with its workers held" values_back
drill_marker start "$TOKYO"
step 600 "New archive generation, the outbox since the hold, then Tokyo's workers" generation_and_outbox
step 300 "Switch DNS back to Tokyo" dns_back
step 600 "Osaka back to its pilot light" osaka_pilot_light
step 300 "Verify with the synthetic probe and an original sign-in" verify

measure "Failback, first step to verified" "$(minutes $(($(date +%s) - T0)))"
drill_marker end "$TOKYO"
finish
