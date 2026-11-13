#!/usr/bin/env bash
# Check that every required status check in .github/rulesets/protect-main.json is a job that reports on every pull
# request (#59). A required check that never reports blocks every PR, which is what happened when the template's Go
# and image checks stayed in the ruleset after #46 removed those jobs. Also check that nobody may bypass the ruleset
# (#6): Release PRs get their checks from the release App's token (release.yml), so no exception is needed.
#
# A context passes when it is the literal `name:` of a job in a workflow that triggers on `pull_request` with no
# `paths`/`paths-ignore`/`branches` filter, and the job has no matrix (a matrix job reports under the expanded name,
# and a skipped one under the unexpanded `${{ ... }}` name).
#
# Usage: .github/scripts/check-ruleset.sh [ruleset.json]   (default: the repo's protect-main.json). Needs bash, awk, jq.
# CI runs it in the repo-checks job; run it locally from anywhere in the repository.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
ruleset=${1:-$root/.github/rulesets/protect-main.json}
workflows=$root/.github/workflows

# One line per job that always reports on a pull request: its name.
jobs=$(
  for wf in "$workflows"/*.yml; do
    awk '
      /^on:/ { section = "on"; next }
      /^jobs:/ { section = "jobs"; next }
      /^[^ #]/ { section = "" }
      section == "on" && /^  pull_request:/ { on_pr = 1; in_pr = 1; next }
      section == "on" && /^  [a-z_]+:/ { in_pr = 0 }
      section == "on" && in_pr && /^    (paths|paths-ignore|branches|branches-ignore):/ { filtered = 1 }
      section == "jobs" && /^  [A-Za-z0-9_-]+:/ { flush(); name = ""; matrix = 0; next }
      section == "jobs" && /^    name:/ { name = $0; sub(/^    name: */, "", name); gsub(/^"|"$/, "", name) }
      section == "jobs" && /^    strategy:/ { matrix = 1 }
      function flush() { if (name != "" && !matrix && name !~ /\$\{\{/) names[++n] = name }
      END {
        flush()
        if (on_pr && !filtered) for (i = 1; i <= n; i++) print names[i]
      }
    ' "$wf"
  done
)

failed=0
count=0
while IFS= read -r context; do
  count=$((count + 1))
  if grep -Fxq -- "$context" <<<"$jobs"; then
    echo "ok   required check reports on every PR: $context"
  else
    echo "FAIL required check is not a job that reports on every PR: $context"
    failed=1
  fi
done < <(jq -r '.rules[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context' "$ruleset")

if [[ $count -eq 0 ]]; then
  echo "FAIL $ruleset has no required status checks"
  exit 1
fi

bypass=$(jq '.bypass_actors | length' "$ruleset")
if [[ $bypass -eq 0 ]]; then
  echo "ok   nobody may bypass the ruleset"
else
  echo "FAIL the ruleset has $bypass bypass actor(s); every merge must pass the required checks (#6)"
  failed=1
fi
exit "$failed"
