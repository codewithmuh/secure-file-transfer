#!/usr/bin/env bash
# Apply the repository settings kept in Git to GitHub (#59). The maintainer runs it after a change to them merges; it
# needs `gh` signed in as a repository admin. Idempotent.
#
# - .github/rulesets/protect-main.json -> the protect-main ruleset (created if missing, else replaced)
# - CodeQL default setup for the languages in the repo: GitHub Actions, JavaScript/TypeScript and Python
#
# Usage: .github/scripts/apply-github-settings.sh [owner/repo]   (default: codewithmuh/secure-file-transfer)
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
repo=${1:-codewithmuh/secure-file-transfer}
ruleset=$root/.github/rulesets/protect-main.json

"$root/.github/scripts/check-ruleset.sh" "$ruleset" >/dev/null

name=$(jq -r .name "$ruleset")
id=$(gh api "repos/$repo/rulesets" --jq ".[] | select(.name == \"$name\") | .id")
if [[ -n $id ]]; then
  gh api -X PUT "repos/$repo/rulesets/$id" --input "$ruleset" --jq '"ruleset \(.name) (\(.id)) updated: \(.enforcement)"'
else
  gh api -X POST "repos/$repo/rulesets" --input "$ruleset" --jq '"ruleset \(.name) (\(.id)) created: \(.enforcement)"'
fi
gh api "repos/$repo/rules/branches/main" \
  --jq '.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[].context' |
  sed 's/^/  required: /'

gh api -X PATCH "repos/$repo/code-scanning/default-setup" \
  -f state=configured -f query_suite=default \
  -f 'languages[]=actions' -f 'languages[]=javascript-typescript' -f 'languages[]=python' \
  --jq '"CodeQL default setup: \(.run_url // "requested")"'
