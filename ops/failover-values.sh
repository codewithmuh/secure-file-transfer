#!/usr/bin/env bash
# The Git changes of a regional failover and failback, made by script so nobody edits a values file by hand under
# pressure (docs/runbooks/regional-failover.md, regional-failback.md; architecture 7; ADR-0004, T-78).
#
# Usage: ops/failover-values.sh <change> --env <dev|staging|prod> [--write]
#
#   fence            Tokyo: pilotLight true (fenced: every workload at zero, whether or not Tokyo answers).
#                    Osaka: pilotLight false, failover.holdWorkers true (the API and the migration job run; every
#                    worker stays at zero and every CronJob suspended until the security-critical changes are back).
#   release-workers  Osaka: failover.holdWorkers false (the workers scale up, the CronJobs resume).
#   hold-osaka       Osaka: failover.holdWorkers true (failback: stop Osaka's workers before the switchover).
#   failback         Osaka: pilotLight true (fenced). Tokyo: pilotLight false, failover.holdWorkers true.
#   hold-tokyo       Tokyo: failover.holdWorkers true (a point-in-time restore holds the workers while it runs).
#   release-tokyo    Tokyo: failover.holdWorkers false.
#   surviving-osaka  Osaka: auditArchive.survivingRegionOnly "ap-northeast-3" (a failover: the API's security-critical
#                    records and the archive job write Osaka's archive alone while Tokyo's can't be reached, #257).
#   both-regions     Osaka: auditArchive.survivingRegionOnly "" (a failback: both archives again; the archive job
#                    back-fills Tokyo with what Osaka alone holds, #257).
#   show             print both files' toggles.
#
# Without --write it prints the change as a diff and writes nothing. It only edits files under deploy/environments/;
# it never commits, pushes or reaches AWS, so it takes no --profile. The operator commits the result: each change is
# one commit, and Argo CD applies it in both clusters (deploy/README.md, "Nobody syncs or changes an Application by
# hand").
#
# The chart reads failover.holdWorkers and auditArchive.survivingRegionOnly (deploy/charts/sft/values.yaml); a values
# file without a block gets it appended. Only the lines `pilotLight: <bool>`, `  holdWorkers: <bool>` under
# `failover:` and `  survivingRegionOnly: "<region>"` under `auditArchive:` are touched.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  sed -n '5,22p' "$0" | sed 's/^# \{0,1\}//'
}

change="${1:-}"
[[ -n "$change" && "$change" != -* ]] || { usage >&2; exit 2; }
shift
env_name=""
write=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) env_name="${2:-}"; shift 2 ;;
    --write) write=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "error: unknown option $1" >&2; exit 2 ;;
  esac
done
[[ "$env_name" =~ ^(dev|staging|prod)$ ]] || { echo "error: --env must be dev, staging or prod" >&2; exit 2; }
OSAKA_REGION=ap-northeast-3
if [[ "$env_name" == dev && ! "$change" =~ ^(hold-tokyo|release-tokyo|show)$ ]]; then
  echo "error: dev has no Osaka: only hold-tokyo, release-tokyo and show apply there" >&2
  exit 2
fi

tokyo="$root/deploy/environments/$env_name/ap-northeast-1/values.yaml"
osaka="$root/deploy/environments/$env_name/ap-northeast-3/values.yaml"
for file in "$tokyo" "$osaka"; do
  [[ -f "$file" || ( "$env_name" == dev && "$file" == "$osaka" ) ]] || { echo "error: $file is missing" >&2; exit 2; }
done

# set_pilot_light <file> <true|false>: the top-level `pilotLight:` line, keeping any comment after the value.
set_pilot_light() {
  local file="$1" value="$2"
  grep -Eq '^pilotLight: (true|false)' "$file" || { echo "error: no top-level pilotLight in $file" >&2; exit 1; }
  sed -E "s/^pilotLight: (true|false)/pilotLight: $value/" "$file"
}

# set_hold_workers <file> <true|false>: `holdWorkers:` inside the top-level `failover:` block, appended if missing.
set_hold_workers() {
  local file="$1" value="$2"
  if grep -Eq '^failover:' "$file"; then
    awk -v value="$value" '
      /^[^ #]/ { inblock = ($0 ~ /^failover:/) }
      inblock && /^  holdWorkers: (true|false)/ { sub(/holdWorkers: (true|false)/, "holdWorkers: " value); found = 1 }
      { print }
      END { if (!found) exit 3 }
    ' "$file" || { echo "error: failover: in $file has no holdWorkers line" >&2; exit 1; }
  else
    cat "$file"
    printf '\n# Failover toggles (docs/runbooks/regional-failover.md), flipped by ops/failover-values.sh.\nfailover:\n  holdWorkers: %s\n' "$value"
  fi
}

# set_surviving <file> <region|none>: `survivingRegionOnly:` inside the top-level `auditArchive:` block (#257, the
# chart's AUDIT_ARCHIVE_SURVIVING_REGION), the block or the line added if missing. "none" writes "", both regions.
set_surviving() {
  local file="$1" value="$2" haskey
  [[ "$value" != none ]] || value=""
  haskey="$(awk '/^[^ #]/ { b = ($0 ~ /^auditArchive:/) } b && /^  survivingRegionOnly:/ { print 1; exit }' "$file")"
  if grep -Eq '^auditArchive:' "$file"; then
    awk -v value="$value" -v haskey="${haskey:-0}" '
      /^[^ #]/ { inblock = ($0 ~ /^auditArchive:/) }
      inblock && /^  survivingRegionOnly:/ { print "  survivingRegionOnly: \"" value "\""; next }
      { print }
      /^auditArchive:/ && haskey != 1 { print "  survivingRegionOnly: \"" value "\"" }
    ' "$file"
  else
    cat "$file"
    printf '\n# The audit archive while a region is lost (docs/runbooks/regional-failover.md), set by ops/failover-values.sh.\nauditArchive:\n  survivingRegionOnly: "%s"\n' "$value"
  fi
}

# apply <file> <filter...>: run the filters over the file, then show or write the result.
apply() {
  local file="$1"
  shift
  local current next
  current="$(mktemp)"
  next="$(mktemp)"
  cp "$file" "$current"
  while [[ $# -gt 0 ]]; do
    "$1" "$current" "$2" >"$next"
    cp "$next" "$current"
    shift 2
  done
  if cmp -s "$file" "$current"; then
    echo "unchanged: ${file#"$root"/}"
  elif $write; then
    cp "$current" "$file"
    echo "written:   ${file#"$root"/}"
  else
    diff -u --label "a/${file#"$root"/}" --label "b/${file#"$root"/}" "$file" "$current" || true
  fi
  rm -f "$current" "$next"
}

show() {
  local file="$1" hold surviving
  hold="$(awk '/^[^ #]/ { b = ($0 ~ /^failover:/) } b && /^  holdWorkers:/ { print $2 }' "$file" | head -1)"
  surviving="$(awk '/^[^ #]/ { b = ($0 ~ /^auditArchive:/) } b && /^  survivingRegionOnly:/ { print $2 }' "$file" | head -1)"
  printf '%s: %s; holdWorkers: %s; survivingRegionOnly: %s\n' "${file#"$root"/}" \
    "$(grep -E '^pilotLight:' "$file" | head -1)" "${hold:-absent (false)}" "${surviving:-absent (\"\")}"
}

case "$change" in
  fence)
    apply "$tokyo" set_pilot_light true
    apply "$osaka" set_pilot_light false set_hold_workers true
    ;;
  release-workers) apply "$osaka" set_hold_workers false ;;
  hold-osaka) apply "$osaka" set_hold_workers true ;;
  failback)
    apply "$osaka" set_pilot_light true set_hold_workers true
    apply "$tokyo" set_pilot_light false set_hold_workers true
    ;;
  hold-tokyo) apply "$tokyo" set_hold_workers true ;;
  release-tokyo) apply "$tokyo" set_hold_workers false ;;
  surviving-osaka) apply "$osaka" set_surviving "$OSAKA_REGION" ;;
  both-regions) apply "$osaka" set_surviving none ;;
  show)
    show "$tokyo"
    [[ "$env_name" == dev ]] || show "$osaka"
    ;;
  *) echo "error: unknown change '$change'" >&2; usage >&2; exit 2 ;;
esac
$write || [[ "$change" == show ]] || echo "(dry run: nothing written; add --write)"
