#!/usr/bin/env bash
# The alert rules' unit tests (deploy/alerts/tests) and lint, with promtool from the pinned Prometheus image, and
# Alertmanager's routing (alertmanager.yaml) checked and its routes tested with amtool from the pinned Alertmanager
# image, as CI's deploy job runs them. Needs Docker. That every alert names a runbook that exists is
# deploy/tests/test_runbooks.py's job.
set -euo pipefail

PROMETHEUS_IMAGE="prom/prometheus:v3.15.1@sha256:fa3302279710be2f21a8301ec17a8b4f2301fd829bd113839b3b6b02b6f191a2"
ALERTMANAGER_IMAGE="prom/alertmanager:v0.34.2@sha256:39d8bb3966c694a124428a3a88fbcffd40bd069129ecd47c059f8a3f17c55f3b"
alerts="$(cd "$(dirname "$0")" && pwd)"

run() {
  local image=$1 tool=$2 dir=$3
  shift 3
  docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --volume "$dir:/alerts:ro" --workdir /alerts/tests \
    --entrypoint "$tool" "$image" "$@"
}

rules=() tests=()
for file in "$alerts"/*.rules.yaml; do rules+=("/alerts/$(basename "$file")"); done
for file in "$alerts"/tests/*.test.yaml; do tests+=("/alerts/tests/$(basename "$file")"); done
echo "== promtool check rules"
run "$PROMETHEUS_IMAGE" /bin/promtool "$alerts" check rules "${rules[@]}"
echo "== promtool test rules"
run "$PROMETHEUS_IMAGE" /bin/promtool "$alerts" test rules "${tests[@]}"

# Alertmanager's file with the placeholders the observability stack fills in, filled with obviously fake facts.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/tests"
sed -e 's/@ENVIRONMENT@/prod/g' -e 's/@REGION@/ap-northeast-1/g' -e 's/@REGION_SHORT@/apne1/g' \
  -e 's/@ACCOUNT_ID@/000000000000/g' "$alerts/alertmanager.yaml" > "$work/alertmanager.yaml"
chmod -R a+rX "$work"
if grep -q '@[A-Z_]*@' "$work/alertmanager.yaml"; then
  echo "alertmanager.yaml has a placeholder test.sh doesn't fill" >&2
  exit 1
fi

echo "== amtool check-config"
run "$ALERTMANAGER_IMAGE" /bin/amtool "$work" check-config /alerts/alertmanager.yaml

# Each line: the receiver an alert with these labels must reach, then its labels.
echo "== amtool config routes test"
while read -r receiver labels; do
  [[ -z $receiver || $receiver == \#* ]] && continue
  # shellcheck disable=SC2086 # the labels are separate arguments
  run "$ALERTMANAGER_IMAGE" /bin/amtool "$work" config routes test --config.file=/alerts/alertmanager.yaml \
    --verify.receivers="$receiver" $labels > /dev/null ||
    { echo "routes: {$labels} should reach $receiver" >&2; exit 1; }
  echo "ok: {$labels} -> $receiver"
done <<'ROUTES'
heartbeat alertname=Watchdog severity=heartbeat
page alertname=ErrorBudgetBurn severity=page slo=availability
ticket alertname=ErrorBudgetBurn severity=ticket slo=availability
page alertname=BreakGlassActive severity=page security=true
ticket alertname=DrillInProgress severity=ticket drill=regional-failover
# An alert without a severity is a mistake (deploy/tests/test_runbooks.py refuses one), but still reaches someone.
ticket alertname=Unlabelled
ROUTES
