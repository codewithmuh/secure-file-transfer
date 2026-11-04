#!/usr/bin/env bash
# Dry run of the promotion logic (#107): .github/scripts/promotion.sh against a throwaway Git repository with the
# deploy config's shape (#106), and the trigger filters of build.yml. Needs only bash, git and awk: no GitHub, no AWS.
# CI runs it in the repo-checks job; run it locally from the repository root.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
promotion="$root/.github/scripts/promotion.sh"
build_yml="$root/.github/workflows/build.yml"
promote_yml="$root/.github/workflows/promote.yml"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

passed=0
failed=0
ok() {
  passed=$((passed + 1))
  echo "ok   $*"
}
not_ok() {
  failed=$((failed + 1))
  echo "FAIL $*"
}
expect_eq() { # NAME EXPECTED ACTUAL
  if [[ $2 == "$3" ]]; then ok "$1"; else not_ok "$1: expected '$2', got '$3'"; fi
}
expect_fail() { # NAME COMMAND...
  local name=$1
  shift
  if "$@" >/dev/null 2>&1; then not_ok "$name: expected a failure"; else ok "$name"; fi
}

p() { "$promotion" "$@"; }

zeros=sha256:0000000000000000000000000000000000000000000000000000000000000000
d1=sha256:1111111111111111111111111111111111111111111111111111111111111111
d2=sha256:2222222222222222222222222222222222222222222222222222222222222222
d3=sha256:3333333333333333333333333333333333333333333333333333333333333333
decoy=sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
bot="sft-promotion[bot]"

values() { # REGION: a values file in the shape #106 agreed, with a decoy digest outside the image block
  cat <<EOF
# Cluster values (test fixture).
image:
  registry: 111111111111.dkr.ecr.$1.amazonaws.com
  digest: $zeros # promotion edits only this line
other:
  digest: $decoy
EOF
}

commit() { # AUTHOR MESSAGE: commit everything as AUTHOR
  git add -A
  git -c user.name="$1" -c user.email="test@example.invalid" commit --quiet --allow-empty -m "$2"
}

cd "$work"
git init --quiet --initial-branch=main
git config user.name maintainer # for git revert; commit() sets its own author
git config user.email test@example.invalid
git config commit.gpgsign false
for cluster in dev/ap-northeast-1 staging/ap-northeast-1 staging/ap-northeast-3 prod/ap-northeast-1 prod/ap-northeast-3; do
  mkdir -p "deploy/environments/$cluster"
  values "${cluster#*/}" >"deploy/environments/$cluster/values.yaml"
done
mkdir -p services/api docs web infra
echo "print('v1')" >services/api/app.py
commit maintainer "initial"
initial=$(git rev-parse HEAD)

echo "# Reading and writing the digest"
expect_eq "get: the placeholder before the first build" "$zeros" "$(p get dev)"
expect_eq "get at a ref" "$zeros" "$(p get staging HEAD)"
p set dev "$d1"
expect_eq "set: dev pins the new digest" "$d1" "$(p get dev)"
expect_eq "set: changes exactly one line" "1" "$(git diff --numstat | awk '{ print $1 }')"
if grep -qF "  digest: $d1 # promotion edits only this line" deploy/environments/dev/ap-northeast-1/values.yaml; then
  ok "set: keeps the line's comment"
else
  not_ok "set: keeps the line's comment"
fi
expect_eq "set: leaves a digest outside the image block alone" "1" \
  "$(grep -c "  digest: $decoy" deploy/environments/dev/ap-northeast-1/values.yaml)"
expect_fail "set: refuses a malformed digest" p set dev sha256:abc
expect_fail "set: refuses the placeholder" p set dev "$zeros"
expect_fail "set: refuses an unknown environment" p set qa "$d1"
expect_fail "copy: only from the previous environment" p copy dev prod
expect_fail "copy: nothing to copy from a never-built environment" p copy staging prod
expect_eq "copy: dev to staging prints the digest" "$d1" "$(p copy dev staging)"
expect_eq "copy: every staging region" "2" "$(git diff --name-only -- deploy/environments/staging | wc -l | tr -d ' ')"
git checkout --quiet -- deploy/environments/staging

sed -i.bak "s/$zeros/$d2/" deploy/environments/prod/ap-northeast-3/values.yaml && rm -f deploy/environments/prod/ap-northeast-3/values.yaml.bak
expect_fail "get: fails when regions pin different digests" p get prod
git checkout --quiet -- deploy/environments/prod
mkdir -p deploy/environments/staging/ap-northeast-9
printf 'image:\n  digest: %s\n  digest: %s\n' "$d1" "$d2" >deploy/environments/staging/ap-northeast-9/values.yaml
expect_fail "get: fails on two digest lines in the image block" p get staging
printf 'image:\n  registry: x\n' >deploy/environments/staging/ap-northeast-9/values.yaml
expect_fail "get: fails on no digest line" p get staging
rm -rf deploy/environments/staging/ap-northeast-9

echo "# build.yml never runs on a promotion (the acceptance criterion of #107)"
before=$(git rev-parse HEAD)
commit "$bot" "chore: promote sft/app 111111111111 to dev" # the dev change from above, as the squash merge
expect_eq "should-build: a promotion merge by a person (paths filter)" "false" \
  "$(p should-build "$before" HEAD maintainer "$bot" 2>/dev/null)"
expect_eq "should-build: a promotion merge by the bot" "false" "$(p should-build "$before" HEAD "$bot" "$bot" 2>/dev/null)"
echo "print('v2')" >services/api/app.py
p set staging "$d1"
before=$(git rev-parse HEAD)
commit "$bot" "a bot commit that also changes code"
expect_eq "should-build: the bot's commit never builds, even with code" "false" \
  "$(p should-build "$before" HEAD "$bot" "$bot" 2>/dev/null)"
expect_eq "should-build: the same change by a person builds" "true" \
  "$(p should-build "$before" HEAD maintainer "$bot" 2>/dev/null)"
git reset --quiet --hard "$before"
for path in docs/a.md docs/design/x.png infra/main.tf web/src/app.tsx README.md services/api/README.md; do
  mkdir -p "$(dirname "$path")"
  echo change >"$path"
  b=$(git rev-parse HEAD)
  commit maintainer "change $path"
  expect_eq "should-build: $path alone doesn't build" "false" "$(p should-build "$b" HEAD maintainer "$bot" 2>/dev/null)"
done
for path in services/api/app.py .github/workflows/build.yml compose.yaml; do
  mkdir -p "$(dirname "$path")"
  echo "change" >>"$path"
  b=$(git rev-parse HEAD)
  commit maintainer "change $path"
  expect_eq "should-build: $path builds" "true" "$(p should-build "$b" HEAD maintainer "$bot" 2>/dev/null)"
done
expect_eq "should-build: no usable base commit builds" "true" \
  "$(p should-build 0000000000000000000000000000000000000000 HEAD maintainer "$bot" 2>/dev/null)"
expect_eq "should-build: no bot configured still filters paths" "false" \
  "$(p should-build "$initial" "$initial" maintainer "" 2>/dev/null)"

# build.yml's trigger filter must ignore exactly what should-build ignores.
expected_ignore='deploy/** docs/** infra/** web/** **.md'
actual_ignore=$(awk '
  /^    paths-ignore:/ { on = 1; next }
  on && /^      - / { gsub(/^      - "|"$/, ""); printf "%s ", $0; next }
  on { exit }
' "$build_yml" | sed 's/ $//')
expect_eq "build.yml: paths-ignore matches should-build" "$expected_ignore" "$actual_ignore"
if grep -qE "^on:$" "$build_yml" && ! grep -qE '^  (pull_request|pull_request_target|workflow_run):' "$build_yml"; then
  ok "build.yml: triggers only on push"
else
  not_ok "build.yml: triggers only on push"
fi
if grep -qF "needs.filter.outputs.build == 'true'" "$build_yml"; then
  ok "build.yml: the image job waits for the filter"
else
  not_ok "build.yml: the image job waits for the filter"
fi
if ! grep -qE '^  push:' "$promote_yml"; then
  ok "promote.yml: never runs on a push"
else
  not_ok "promote.yml: never runs on a push"
fi

echo "# promotion-gate"
git reset --quiet --hard "$initial"
p set dev "$d1"
commit "$bot" "dev d1"
main1=$(git rev-parse HEAD)

git switch --quiet -c pr-noop
echo "print('v3')" >services/api/app.py
commit maintainer "code only"
expect_eq "gate: a pull request outside the deploy config" "" "$(p gate "$main1" HEAD)"

git switch --quiet -c pr-staging "$main1"
p copy dev staging >/dev/null
commit "$bot" "staging d1"
expect_eq "gate: staging copies dev" "staging promote dev $d1" "$(p gate "$main1" HEAD)"
staging1=$(git rev-parse HEAD)

git switch --quiet -c pr-forged "$main1"
p set staging "$d2"
commit maintainer "staging d2, not dev's"
expect_fail "gate: staging with a digest dev doesn't pin" p gate "$main1" HEAD

git switch --quiet -c pr-split "$main1"
p set staging "$d1"
sed -i.bak "s/$d1/$d2/" deploy/environments/staging/ap-northeast-3/values.yaml && rm -f deploy/environments/staging/ap-northeast-3/values.yaml.bak
commit maintainer "Osaka on another digest"
expect_fail "gate: regions that disagree" p gate "$main1" HEAD

git switch --quiet main
git merge --quiet --ff-only "$staging1"
p set dev "$d3"
commit "$bot" "dev d3"
p copy dev staging >/dev/null
commit "$bot" "staging d3"
main2=$(git rev-parse HEAD)
expect_eq "gate: dev takes a new build" "dev build" "$(p gate "$staging1" "$(git rev-parse HEAD~1)")"

git switch --quiet -c pr-revert "$main2"
git revert --no-edit HEAD >/dev/null
expect_eq "gate: a revert to a digest staging ran passes at once" "staging rollback" "$(p gate "$main2" HEAD)"

git switch --quiet -c pr-behind "$main1"
echo "print('v4')" >services/api/app.py
commit maintainer "a branch from before staging and dev moved"
expect_eq "gate: a branch behind main changes nothing" "" "$(p gate "$main2" HEAD)"

git switch --quiet -c pr-prod "$main2"
p copy staging prod >/dev/null
commit "$bot" "prod d3"
expect_eq "gate: prod copies staging" "prod promote staging $d3" "$(p gate "$main2" HEAD)"

git switch --quiet -c pr-prod-from-dev "$main2"
p set dev "$d2"
p set prod "$d2"
commit maintainer "prod skips staging"
expect_fail "gate: prod can't skip staging" p gate "$main2" HEAD

echo
echo "$passed passed, $failed failed"
[[ $failed == 0 ]]
