#!/usr/bin/env bash
# Which of CI's two slow jobs a pull request can affect (#297): the Python suite (six shards, about 20 minutes) and the
# local stack with its journeys (about 25). A pull request that changes only what neither reads, the Terraform, the
# deploy config, the ops scripts, most docs or other workflows, skips them; the required check for the suite still
# reports, and passes. Only paths known to be irrelevant skip anything: every other path counts. A push to main, or a
# base commit that can't be found, runs everything.
#
# Usage: EVENT=pull_request PR_BASE=<sha> .github/scripts/ci-changes.sh   prints python=true|false and stack=true|false
#        .github/scripts/ci-changes.sh --test                              checks the path rules, with no git
set -euo pipefail

# What the Python suite reads besides its own code: the contract (test_app.py), two pages it checks against
# (test_permissions.py, test_sli_metrics.py), .gitleaks.toml (test_api_keys.py) and local/ (clamd's config). The
# local stack reads all of that, plus web/, the Makefile and compose.yaml.
ignored_by_both() {
  case "$1" in
    docs/api/* | docs/security/authn-authz.md | docs/operations/metrics.md) return 1 ;;
    infra/* | ops/* | deploy/* | loadtest/* | docs/*) return 0 ;;
    .github/workflows/ci.yml | .github/scripts/ci-changes.sh | .github/scripts/pytest-shard.py) return 1 ;;
    .github/*) return 0 ;;
    */*) return 1 ;;
    *.md) return 0 ;;
  esac
  return 1
}

ignored_by_python() {
  case "$1" in
    web/* | Makefile | compose.yaml) return 0 ;;
  esac
  ignored_by_both "$1"
}

# decide: read paths on stdin, print the two answers.
decide() {
  local path python=false stack=false
  while IFS= read -r path; do
    [[ -n "$path" ]] || continue
    ignored_by_both "$path" || stack=true
    ignored_by_python "$path" || python=true
  done
  echo "python=$python"
  echo "stack=$stack"
}

if [[ "${1:-}" == --test ]]; then
  failures=0
  expect() {
    local want="$1" got
    shift
    got="$(printf '%s\n' "$@" | decide | tr '\n' ' ')"
    [[ "$got" == "$want" ]] || { echo "FAIL: $* -> $got, want $want" >&2; failures=$((failures + 1)); }
  }
  expect "python=false stack=false " infra/modules/network/main.tf ops/rebuild.sh docs/runbooks/teardown.md README.md \
    .github/workflows/environment.yml deploy/charts/sft/values.yaml
  expect "python=false stack=true " ops/environment.sh Makefile
  expect "python=false stack=true " web/src/App.tsx
  expect "python=true stack=true " services/api/src/sft/main.py
  expect "python=true stack=true " docs/api/openapi.yaml
  expect "python=true stack=true " docs/security/authn-authz.md
  expect "python=true stack=true " .github/workflows/ci.yml
  expect "python=true stack=true " local/seed.py
  expect "python=true stack=true " .gitleaks.toml
  expect "python=true stack=true " some/new/place.txt
  expect "python=false stack=false "
  ((failures == 0)) || exit 1
  echo "ci-changes checks passed"
  exit 0
fi

event="${EVENT:-}"
base="${PR_BASE:-}"
if [[ "$event" != pull_request || -z "$base" || "$base" =~ ^0+$ ]] || ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  echo "python=true"
  echo "stack=true"
  exit 0
fi
# On a pull request HEAD is the merge commit, so this diff is exactly what the pull request changes.
git diff --name-only "$base" HEAD | decide
