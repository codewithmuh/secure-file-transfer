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
#   --after-detach           the failover detached Osaka's cluster rather than failing over: Osaka's cluster becomes
#                            a new global database, sft-<env>-aurora-2, and Tokyo's is made again as its secondary
#                            (runbook step 1, #261).
#
# No NFR sets a failback time. The budgets are a first estimate for a maintenance window, for the first drill to
# measure and correct. Pending the AWS run.
set -euo pipefail

DRILL=regional-failback
STEPS_DOC=docs/runbooks/regional-failback.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  echo
  common_usage
}

parse_common "$@"
FAILED_OVER_AT=""
AFTER_DETACH=false
set -- "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --failed-over-at) FAILED_OVER_AT="${2:-}"; shift 2 ;;
    --after-detach) AFTER_DETACH=true; shift ;;
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
  if $AFTER_DETACH; then
    # Inputs only (#261): Osaka's detached cluster becomes a new global database; Tokyo's old cluster goes, with its
    # final snapshot, and a new one joins as Osaka's secondary.
    local old="sft-$ENV_NAME-aurora"
    SFT_AURORA_GENERATION=2
    run aws rds create-global-cluster --region "$OSAKA" --global-cluster-identifier "$(global_cluster)" \
      --source-db-cluster-identifier "arn:aws:rds:$OSAKA:$ACCOUNT_ID:cluster:$(db_cluster "$OSAKA")"
    manual "Apply infra/environments/$ENV_NAME/$OSAKA/data with TF_VAR_aurora_global_generation=2 (no change to the" \
      "cluster; the input records the new global database)."
    run aws rds modify-db-cluster --region "$TOKYO" --db-cluster-identifier "$(db_cluster "$TOKYO")" \
      --no-deletion-protection --apply-immediately
    run aws rds modify-global-cluster --region "$TOKYO" --global-cluster-identifier "$old" --no-deletion-protection
    manual "Apply infra/environments/$ENV_NAME/$TOKYO/data with TF_VAR_aurora_role=secondary" \
      "TF_VAR_aurora_global_generation=2: the old cluster goes with its final snapshot (kept 30 days, #42 gap 10), the" \
      "old global database $old with it, and a new cluster joins $(global_cluster). Keep both inputs in the apply" \
      "checklist until the next rebuild, and SFT_AURORA_GENERATION=2 for these scripts."
  else
    manual "After a managed failover Aurora brought Tokyo's old cluster back as Osaka's secondary by itself; its" \
      "snapshot from before stays 30 days for the reconciliation report (#42 gap 10)."
  fi
  run aws rds describe-global-clusters --region "$OSAKA" --global-cluster-identifier "$(global_cluster)"
  manual "Wait for AuroraGlobalDBReplicationLag under a second on Tokyo's cluster."
}

files_back() {
  # The reverse rule first (#262), so uploads during the window replicate too; then the objects written in Osaka
  # since the failover, by S3 Batch Replication along that rule. Replicas keep their tags, so `scan` comes back.
  manual "Apply infra/environments/$ENV_NAME/$OSAKA/data with TF_VAR_replicate_to_tokyo=true (and the failover's" \
    "TF_VAR_malware_protection_enabled=true): the to-tokyo rule on both files buckets."
  for bucket in files large-files; do
    run aws s3control create-job --region "$OSAKA" --account-id "$ACCOUNT_ID" --no-confirmation-required \
      --priority 10 --operation '{"S3ReplicateObject":{}}' --report '{"Enabled":false}' \
      --role-arn "arn:aws:iam::$ACCOUNT_ID:role/sft-$ENV_NAME-s3-batch-replication" \
      --manifest-generator "{\"S3JobManifestGenerator\":{\"SourceBucket\":\"arn:aws:s3:::$(region_prefix "$OSAKA")-$bucket-$ACCOUNT_ID\",\"EnableManifestOutput\":false,\"Filter\":{\"EligibleForReplication\":true,\"CreatedAfter\":\"$FAILED_OVER_AT\"}}}"
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
  # Both archives again (#257): the archive job back-fills Tokyo's with what Osaka's alone holds.
  run "$OPS_ROOT/failover-values.sh" both-regions --env "$ENV_NAME" --write
  manual "Commit and push 'ops: fence $ENV_NAME Osaka and take Tokyo out of pilot light'."
  run kubectl --context "$TOKYO_CTX" -n sft rollout status deploy/api --timeout=20m
}

generation_and_outbox() {
  # Tokyo's archive gets the failover's generation only with the back-fill (runbook step 10), so the generation step
  # keeps the cursor's, which a switchover needs no more than; the re-import finds every record Tokyo's archive holds
  # present (nothing was lost). Then the outbox since the hold, for what sat in Osaka's queues.
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
  # Inputs only (#261, #262): every root back to its defaults.
  manual "Apply infra/environments/$ENV_NAME/$OSAKA/cluster without TF_VAR_system_node_count (one node);" \
    "infra/environments/$ENV_NAME/$OSAKA/data without TF_VAR_malware_protection_enabled and TF_VAR_replicate_to_tokyo" \
    "(the plan and the to-tokyo rule go); infra/environments/$ENV_NAME/$OSAKA/alarms and $TOKYO/alarms without" \
    "TF_VAR_heartbeat_enabled, TF_VAR_pilot_light and TF_VAR_database_role (runbook step 8)."
}

backfill_check() {
  # #257's drill step: Tokyo's archive holds every batch Osaka's alone held during the failover, once, under its key.
  manual "max(audit_archive_single_region_ranges) is 0 and the archive job's last report shows backfilled. With the" \
    "ReadOnly profile, list both regions' audit archive under the failover's generation (list-objects-v2 --prefix" \
    "g<n>/, Key and Size, sorted) and diff them: empty, no gap and no duplicate. Tokyo's security-critical/v1/ holds" \
    "every record Osaka's does but the download.grant_intent ones. Write the counts in the drill log (runbook step 10)."
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
step 600 "Prove the archive back-fill: Tokyo's archive holds what Osaka's alone held (#257)" backfill_check

measure "Failback, first step to verified" "$(minutes $(($(date +%s) - T0)))"
drill_marker end "$TOKYO"
finish
