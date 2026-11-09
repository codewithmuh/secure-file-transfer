#!/usr/bin/env bash
# Runs the design-load test (loadtest/k6/design-load.js) in the pinned k6 image: docs/operations/performance.md.
#
#   loadtest/run.sh local KEYS.json OUT_DIR                  # the scaled-down run against the local stack
#   loadtest/run.sh staging-1x KEYS.json OUT_DIR [i/N]       # staging, from the manual workflow, shard i of N
#
# The keys file is mounted read-only and named to k6 by path, so no key is on a command line. Staging profiles refuse
# any API that isn't https://api.staging.<...>: this test never runs against prod. The summary (JSON) lands in OUT_DIR.
set -euo pipefail

# grafana/k6 2.3.0 (2026-09-21), pinned by digest (T-68).
image="grafana/k6:2.3.0@sha256:2dd4756ec6e14e62778916e1eb850108e4b499304c02df56760fa0bdb0fba0b8"

profile="${1:?usage: loadtest/run.sh PROFILE KEYS_FILE OUT_DIR [SHARD/SHARDS]}"
keys="${2:?keys file}"
out="${3:?output directory}"
shard="${4:-}"
here="$(cd "$(dirname "$0")" && pwd)"
[[ -f "$here/profiles/$profile.json" ]] || { echo "no profile $profile" >&2; exit 2; }
[[ -f "$keys" ]] || { echo "no keys file" >&2; exit 2; }
mkdir -p "$out"

network=()
env=(-e K6_AUTO_EXTENSION_RESOLUTION=false -e K6_NO_USAGE_REPORT=true)
if [[ $profile == local ]]; then
  # The local stack's published ports. On Linux the container shares the host's network; on Docker Desktop it reaches
  # them as host.docker.internal, and part URLs and Mailpit's Host check are adjusted to match.
  if [[ "$(uname -s)" == Linux ]]; then
    network=(--network host)
    host=localhost
  else
    host=host.docker.internal
  fi
  env+=(
    -e "API_URL=${API_URL:-http://$host:8000}"
    -e "WEB_ORIGIN=${WEB_ORIGIN:-http://localhost:3000}"
    -e "MAILPIT_URL=${MAILPIT_URL:-http://$host:8025}"
    -e "MAILPIT_HOST_HEADER=${MAILPIT_HOST_HEADER:-localhost:8025}"
    -e "PART_HOST=${PART_HOST:-http://$host:9090}"
    -e "MAIL_DOMAIN=${MAIL_DOMAIN:-loadtest.sft.localhost}"
  )
else
  : "${API_URL:?API_URL is required}" "${WEB_ORIGIN:?WEB_ORIGIN is required}" "${MAIL_DOMAIN:?MAIL_DOMAIN is required}"
  if [[ ! $API_URL =~ ^https://api\.staging\. ]]; then
    echo "refused: $profile runs only against staging (https://api.staging.<domain>), never prod" >&2
    exit 2
  fi
  network=(--network host) # the mailbox bridge listens on the runner's loopback
  env+=(-e "API_URL=$API_URL" -e "WEB_ORIGIN=$WEB_ORIGIN" -e "MAIL_DOMAIN=$MAIL_DOMAIN"
    -e "MAILPIT_URL=${MAILPIT_URL:-http://127.0.0.1:8025}")
fi

segment=()
if [[ -n $shard ]]; then
  i="${shard%/*}"
  n="${shard#*/}"
  # k6 splits every scenario's rate and VUs: shard i runs the slice i/N to (i+1)/N, from its own runner's address,
  # so per-IP limits (NFR-14) see N addresses (docs/operations/performance.md).
  frac() { if (($1 == 0)); then echo 0; elif (($1 == n)); then echo 1; else echo "$1/$n"; fi; }
  sequence="0"
  for ((j = 1; j <= n; j++)); do sequence+=",$(frac "$j")"; done
  segment=(--execution-segment "$(frac "$i"):$(frac $((i + 1)))" --execution-segment-sequence "$sequence")
  env+=(-e "SHARD=$i")
fi

docker run --rm ${network[@]+"${network[@]}"} \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true --user "$(id -u):$(id -g)" \
  -v "$here:/loadtest:ro" -v "$(cd "$(dirname "$keys")" && pwd)/$(basename "$keys"):/run/keys.json:ro" \
  -v "$(cd "$out" && pwd):/out" -w /loadtest/k6 \
  "${env[@]}" -e PROFILE="../profiles/$profile.json" -e KEYS_FILE=/run/keys.json \
  -e SUMMARY_FILE="/out/summary-$profile${shard:+-${shard%/*}}.json" \
  "$image" run ${segment[@]+"${segment[@]}"} design-load.js
