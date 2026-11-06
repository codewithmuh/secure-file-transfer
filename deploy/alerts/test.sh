#!/usr/bin/env bash
# The alert rules' unit tests (deploy/alerts/tests) and lint, with promtool from the pinned Prometheus image, as CI's
# deploy job runs them. Needs Docker.
set -euo pipefail

PROMETHEUS_IMAGE="prom/prometheus:v3.15.1@sha256:fa3302279710be2f21a8301ec17a8b4f2301fd829bd113839b3b6b02b6f191a2"
alerts="$(cd "$(dirname "$0")" && pwd)"

run() {
  docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --volume "$alerts:/alerts:ro" --workdir /alerts/tests \
    --entrypoint /bin/promtool "$PROMETHEUS_IMAGE" "$@"
}

rules=() tests=()
for file in "$alerts"/*.rules.yaml; do rules+=("/alerts/$(basename "$file")"); done
for file in "$alerts"/tests/*.test.yaml; do tests+=("/alerts/tests/$(basename "$file")"); done
echo "== promtool check rules"
run check rules "${rules[@]}"
echo "== promtool test rules"
run test rules "${tests[@]}"
