#!/usr/bin/env bash
# The Availability Zone failure drill (docs/runbooks/az-failure.md; NFR-11: automatic recovery within 5 minutes;
# NFR-10: RPO 0). One Tokyo AZ is taken away from the service while the synthetic probe runs: the database's writer
# fails over to the reader in another AZ, and the zone's nodes go, so their pods are rescheduled in the other two.
# Nothing in the recovery is manual; the drill only injects the failure and times the service's own recovery.
#
#   ops/az-failure.sh --env staging --profile sft-staging-admin --az apne1-az1                 # dry run
#   ops/az-failure.sh --env staging --profile sft-staging-admin --account-id <id> --execute --az apne1-az1
#
# Script options, besides the common ones (ops/lib/common.sh):
#   --az <zone ID>          the AZ to lose, by zone ID (apne1-az1, apne1-az2 or apne1-az4): IDs are the same in
#                           every account, names aren't. Required.
#   --fis-template <id>     an AWS FIS experiment template that disrupts the zone's subnets (the runbook says how to
#                           make one). Without it, the zone's nodes are cordoned and drained instead, which loses the
#                           pods but not the network.
#
# Pending the AWS run.
set -euo pipefail

DRILL=az-failure
STEPS_DOC=docs/runbooks/az-failure.md
# shellcheck source-path=SCRIPTDIR source=lib/common.sh
source "$(dirname "$0")/lib/common.sh"

usage() {
  sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'
  echo
  common_usage
}

parse_common "$@"
AZ=""
FIS_TEMPLATE=""
set -- "${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --az) AZ="${2:-}"; shift 2 ;;
    --fis-template) FIS_TEMPLATE="${2:-}"; shift 2 ;;
    *) die "unknown option $1" ;;
  esac
done
[[ "$AZ" =~ ^apne1-az[0-9]$ ]] || die "--az <apne1-azN> is required: the Tokyo zone ID to lose"
TOKYO_CTX="$(kube_context "$TOKYO")"

confirm_execute

baseline() {
  run kubectl --context "$TOKYO_CTX" -n sft create job --from=cronjob/synthetic-probe "probe-az-before-$(date -u +%H%M%S)"
  run aws rds describe-db-clusters --region "$TOKYO" --db-cluster-identifier "$(db_cluster "$TOKYO")" \
    --query 'DBClusters[0].DBClusterMembers'
  manual "The probe passed, and the writer is in $AZ (if not, the drill still loses the reader's zone: note which)."
}

inject() {
  date -u +%s >"$LOG_FILE.injected"
  if [[ -n "$FIS_TEMPLATE" ]]; then
    run aws fis start-experiment --region "$TOKYO" --experiment-template-id "$FIS_TEMPLATE"
  else
    # Without FIS: the zone's nodes go, as they would with the zone. Karpenter replaces them in the other zones.
    run kubectl --context "$TOKYO_CTX" cordon -l "topology.k8s.aws/zone-id=$AZ"
    run kubectl --context "$TOKYO_CTX" drain -l "topology.k8s.aws/zone-id=$AZ" --ignore-daemonsets \
      --delete-emptydir-data --timeout=5m
  fi
  # The database's writer leaves the zone, as Aurora does by itself when the zone goes.
  run aws rds failover-db-cluster --region "$TOKYO" --db-cluster-identifier "$(db_cluster "$TOKYO")"
}

recovered() {
  # The service is back when the probe passes again and the API's 5xx rate is back to normal.
  run aws rds wait db-cluster-available --region "$TOKYO" --db-cluster-identifier "$(db_cluster "$TOKYO")"
  run kubectl --context "$TOKYO_CTX" -n sft rollout status deploy/api --timeout=5m
  run kubectl --context "$TOKYO_CTX" -n sft create job --from=cronjob/synthetic-probe "probe-az-after-$(date -u +%H%M%S)"
  manual "The probe passed. In Grafana's SLO dashboard (port-forward), read when 5xx returned to baseline: that time" \
    "minus the injection is the RTO. Write it in the drill log."
  if $EXECUTE; then
    measure "Injection to probe passing" "$(minutes $(($(date +%s) - $(cat "$LOG_FILE.injected"))))"
  fi
}

no_data_lost() {
  manual "RPO 0: every transfer the probe and the drill writer created before the injection is there, with its" \
    "files downloadable (the probe's log names them). Aurora keeps six copies across three AZs and S3 at least" \
    "three, so nothing should be missing; anything that is fails the drill."
}

restore() {
  if [[ -n "$FIS_TEMPLATE" ]]; then
    manual "The FIS experiment ends at its duration; check it stopped (aws fis get-experiment)."
  else
    run kubectl --context "$TOKYO_CTX" uncordon -l "topology.k8s.aws/zone-id=$AZ"
  fi
  manual "Move the writer back only if the runbook says so (it doesn't have to); record the final placement."
}

# The drill's marker: the alerts it sets off on purpose are held back, and its window is left out of the SLOs.
drill_marker start "$TOKYO"
step 300 "Baseline: probe passing, writer placement" baseline
step 60 "Lose $AZ: its subnets or nodes, and the writer" inject
step 300 "Automatic recovery: writer, pods, probe" recovered
step 300 "No data lost (RPO 0)" no_data_lost
step 600 "End the drill" restore
rm -f "$LOG_FILE.injected"
drill_marker end "$TOKYO"
finish
