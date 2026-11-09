#!/usr/bin/env bash
# Point-in-time restore after data corruption or a bad migration (docs/runbooks/point-in-time-restore.md;
# architecture 6; NFR-11: any point in the last 14 days, accurate to 5 minutes, RTO 2 hours). Restores Tokyo's
# database to a new cluster, protects it in Osaka until it has a secondary again (#42), re-imports the archived audit
# events and re-applies the security-critical changes newer than the restore point (sft.service.recovery_replay),
# and moves the service onto it.
#
#   ops/point-in-time-restore.sh --env staging --profile sft-staging-admin --restore-to 2026-12-01T02:55:00Z
#   ops/point-in-time-restore.sh --env staging --profile sft-staging-admin --account-id <id> --execute \
#     --restore-to 2026-12-01T02:55:00Z
#
# Script options, besides the common ones (ops/lib/common.sh):
#   --restore-to <time>  the point to restore to, ISO 8601 UTC, inside the last 14 days: just before the damage.
#                        Required.
#   --drill              a drill: mark it in the Pushgateway, so the alerts it sets off on purpose are held back
#                        (docs/runbooks/drill-in-progress.md). A real restore pages as it should.
#
# Pending the AWS run.
set -euo pipefail

DRILL=point-in-time-restore
STEPS_DOC=docs/runbooks/point-in-time-restore.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
  echo
  common_usage
}

parse_common "$@"
RESTORE_TO=""
IS_DRILL=false
set -- "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --restore-to) RESTORE_TO="${2:-}"; shift 2 ;;
    --drill) IS_DRILL=true; shift ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$RESTORE_TO" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$ ]] || die "--restore-to <ISO 8601 UTC> is required"

SOURCE="$(db_cluster "$TOKYO")"
STAMP="$(date -u +%m%d%H%M)"
RESTORED="$SOURCE-r$STAMP"
OLD="$SOURCE-old$STAMP"
TOKYO_CTX="$(kube_context "$TOKYO")"
# The outbox window counts back 24 hours from the restore point (architecture 5.3).
epoch=$(date -u -j -f %Y-%m-%dT%H:%M:%SZ "$RESTORE_TO" +%s 2>/dev/null || date -u -d "$RESTORE_TO" +%s)
OUTBOX_SINCE="$(date -u -r $((epoch - 86400)) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$((epoch - 86400))" +%Y-%m-%dT%H:%M:%SZ)"

confirm_execute
T0=$(date +%s)
measure "Restore point (UTC)" "$RESTORE_TO"

decide() {
  manual "Name the damage and the restore point: the last good moment before it, from the deploy history or the" \
    "errors' start. Changes after it are lost except the security-critical ones and the audit records (NFR-11)."
  run "$OPS_ROOT/failover-values.sh" hold-tokyo --env "$ENV_NAME" --write
  manual "Commit and push 'ops: hold $ENV_NAME Tokyo's workers for a point-in-time restore'. The API keeps serving" \
    "on the damaged database until the cutover; the workers stop acting on it."
}

restore() {
  # A new cluster from the continuous backup, with the source's network, key and IAM authentication. The source
  # stays as it is until the cutover.
  run aws rds restore-db-cluster-to-point-in-time --region "$TOKYO" \
    --source-db-cluster-identifier "$SOURCE" --db-cluster-identifier "$RESTORED" \
    --restore-to-time "$RESTORE_TO" --db-subnet-group-name "$SOURCE" \
    --kms-key-id "alias/sft/$ENV_NAME/database" --enable-iam-database-authentication \
    --copy-tags-to-snapshot --deletion-protection
  manual "Pass the source's VPC security group (--vpc-security-group-ids, from describe-db-clusters) if the restore" \
    "didn't take it, and its DB cluster parameter group."
  run aws rds create-db-instance --region "$TOKYO" --db-cluster-identifier "$RESTORED" \
    --db-instance-identifier "$RESTORED-1" --engine aurora-postgresql --db-instance-class db.r8g.large
  run aws rds wait db-instance-available --region "$TOKYO" --db-instance-identifier "$RESTORED-1"
}

protect() {
  # The restored cluster has no copy outside Tokyo until a new Osaka secondary catches up, which can take hours:
  # one snapshot, copied to Osaka under Osaka's database key, covers that window (#42).
  [[ "$ENV_NAME" != dev ]] || { echo "   dev has no Osaka: nothing to copy"; return 0; }
  run aws rds create-db-cluster-snapshot --region "$TOKYO" --db-cluster-identifier "$RESTORED" \
    --db-cluster-snapshot-identifier "$RESTORED-guard"
  run aws rds wait db-cluster-snapshot-available --region "$TOKYO" --db-cluster-snapshot-identifier "$RESTORED-guard"
  run aws rds copy-db-cluster-snapshot --region "$OSAKA" --source-region "$TOKYO" \
    --source-db-cluster-snapshot-identifier "arn:aws:rds:$TOKYO:$ACCOUNT_ID:cluster-snapshot:$RESTORED-guard" \
    --target-db-cluster-snapshot-identifier "$RESTORED-guard" --kms-key-id "alias/sft/$ENV_NAME/database"
}

cutover() {
  # Swap the names, so the cluster endpoint the cluster-bootstrap stack gave the pods now names the restored
  # cluster: no Git or Terraform change is needed to move the service. Then end the old cluster's connections.
  run aws rds modify-db-cluster --region "$TOKYO" --db-cluster-identifier "$SOURCE" \
    --new-db-cluster-identifier "$OLD" --apply-immediately
  run aws rds wait db-cluster-available --region "$TOKYO" --db-cluster-identifier "$OLD"
  run aws rds modify-db-cluster --region "$TOKYO" --db-cluster-identifier "$RESTORED" \
    --new-db-cluster-identifier "$SOURCE" --apply-immediately
  run aws rds wait db-cluster-available --region "$TOKYO" --db-cluster-identifier "$SOURCE"
  manual "Reboot the old cluster's instances (aws rds reboot-db-instance), so every pooled connection opens again" \
    "on the endpoint, now the restored cluster's."
}

replay() {
  # A new archive generation (the restore reuses transaction IDs), the cursor back to the restore point, then the
  # re-import and re-apply of everything after it.
  recovery_job "$TOKYO" "generation,partitions,replay" "$RESTORE_TO" "$RESTORE_TO"
  manual "Read the job's counts into the drill log, and tell tenant admins of every unlock it didn't re-apply."
}

workers() {
  recovery_job "$TOKYO" "outbox" "$OUTBOX_SINCE"
  run "$OPS_ROOT/failover-values.sh" release-tokyo --env "$ENV_NAME" --write
  manual "Commit and push 'ops: start $ENV_NAME Tokyo's workers after the restore'."
}

verify() {
  run kubectl --context "$TOKYO_CTX" -n sft create job --from=cronjob/synthetic-probe "probe-restore-$(date -u +%H%M%S)"
  manual "The probe passes; a transfer the drill wrote after the restore point is gone and a revocation it made" \
    "after the restore point still stands (the replay re-applied it)."
}

secondary() {
  # Not in the RTO: the service is back. A new global database around the restored cluster and a new Osaka
  # secondary, in Terraform, as the runbook's step 9 says. The Osaka snapshot copy goes when the secondary is in sync.
  [[ "$ENV_NAME" != dev ]] || { echo "   dev has no Osaka secondary"; return 0; }
  manual "Bring Terraform in line (runbook step 9): import the restored cluster under the data root's address, make" \
    "the global database from it, and apply Osaka's data root, which creates the new secondary."
  manual "When AuroraGlobalDBReplicationLag is under a second, delete the snapshot copy $RESTORED-guard in Osaka and," \
    "after 7 days, the old cluster $OLD (keep its final snapshot for 30 days)."
}

if $IS_DRILL; then drill_marker start "$TOKYO"; fi
step 900 "Decide the restore point; hold the workers" decide
step 3000 "Restore to a new cluster and wait for its writer" restore
step 900 "Protect it in Osaka until it has a secondary" protect
step 600 "Move the service onto it" cutover
step 600 "New archive generation; re-import and re-apply after the restore point" replay
step 300 "Re-publish the outbox's 24 hours; start the workers" workers
step 300 "Verify" verify
measure "RTO: decision to verified service" "$(minutes $(($(date +%s) - T0))) (NFR-11: 2h)"
step 0 "A new Osaka secondary (after the RTO)" secondary
if $IS_DRILL; then drill_marker end "$TOKYO"; fi
finish
