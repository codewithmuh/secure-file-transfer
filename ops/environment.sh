#!/usr/bin/env bash
# `make aws-up|aws-down|aws-status ENV=<env>`: start the environment workflow on main for one environment, then follow
# it until it ends (.github/workflows/environment.yml; docs/runbooks/environment-up-down.md, #295). The work runs in
# GitHub as the environment's deploy role, never from this shell, so all this needs is the GitHub CLI signed in with
# write access to the repository. prod's runs wait for your approval in GitHub.
#
#   ops/environment.sh up dev        build dev (up to 2 hours)
#   ops/environment.sh down dev      destroy what dev bills for; asks you to type the name
#   ops/environment.sh status dev    what dev still has, read-only
set -euo pipefail

die() {
  echo "error: $*" >&2
  exit 2
}

action="${1:-}"
env="${2:-}"
[[ "$action" =~ ^(up|down|status)$ ]] || die "usage: ops/environment.sh up|down|status dev|staging|prod"
[[ "$env" =~ ^(dev|staging|prod)$ ]] || die "ENV must be dev, staging or prod, as in: make aws-$action ENV=dev"
command -v gh >/dev/null || die "needs the GitHub CLI (gh), signed in"

confirm=""
if [[ "$action" == down ]]; then
  echo "This destroys $env on AWS: every stack that bills, and its data (dev and staging keep no snapshot)."
  [[ "$env" != prod ]] || echo "For prod it is the final teardown: only the retained audit archive and the bootstrap stacks stay."
  read -r -p "Type '$env' to go on: " confirm
  [[ "$confirm" == "$env" ]] || die "not confirmed"
fi

since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
gh workflow run environment.yml --ref main -f environment="$env" -f action="$action" -f confirm="$confirm"
run=""
for _ in $(seq 1 30); do
  run="$(gh run list --workflow environment.yml --branch main --event workflow_dispatch --limit 10 \
    --json databaseId,createdAt --jq "[.[] | select(.createdAt >= \"$since\")] | last | .databaseId // empty")"
  [[ -z "$run" ]] || break
  sleep 2
done
[[ -n "$run" ]] || die "the run didn't show up; look with: gh run list --workflow environment.yml"
echo "Run: $(gh run view "$run" --json url --jq .url)"
[[ "$env" != prod ]] || echo "prod waits for your approval: open the run and review the deployment."
exec gh run watch "$run" --exit-status
