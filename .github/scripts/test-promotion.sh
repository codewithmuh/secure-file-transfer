#!/usr/bin/env bash
# Dry run of the promotion logic (#107): .github/scripts/promotion.sh against a throwaway Git repository with the
# deploy config's shape (#106), the trigger filters and permissions of the workflows, and the GitHub and ECR commands
# against stand-ins for gh and aws. Needs only bash, git, awk and jq: no GitHub, no AWS.
# CI runs it in the repo-checks job; run it locally from the repository root.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
promotion="$root/.github/scripts/promotion.sh"
build_yml="$root/.github/workflows/build.yml"
promote_yml="$root/.github/workflows/promote.yml"
mark_yml="$root/.github/workflows/mark-deployed.yml"

work=$(mktemp -d)  # the repository
other=$(mktemp -d) # the stand-ins, and a clone for open-pr
trap 'rm -rf "$work" "$other"' EXIT

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
expect_fail_with() { # NAME MESSAGE COMMAND...: fails, and says MESSAGE
  local name=$1 message=$2 errors
  shift 2
  if errors=$("$@" 2>&1 >/dev/null); then
    not_ok "$name: expected a failure"
  elif [[ $errors == *"$message"* ]]; then
    ok "$name"
  else
    not_ok "$name: expected '$message', got '$errors'"
  fi
}
jobs_with() { # FILE PATTERN: the jobs of a workflow with a line that matches PATTERN
  awk -v pattern="$2" '
    /^jobs:/ { in_jobs = 1; next }
    in_jobs && /^  [A-Za-z0-9_-]+:/ { job = $1; sub(/:$/, "", job); next }
    in_jobs && job != "" && $0 ~ pattern { print job }
  ' "$1" | sort -u | tr '\n' ' ' | sed 's/ $//'
}

p() { "$promotion" "$@"; }

zeros=sha256:0000000000000000000000000000000000000000000000000000000000000000
d1=sha256:1111111111111111111111111111111111111111111111111111111111111111
d2=sha256:2222222222222222222222222222222222222222222222222222222222222222
d3=sha256:3333333333333333333333333333333333333333333333333333333333333333
d4=sha256:4444444444444444444444444444444444444444444444444444444444444444
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
expect_eq "pinned: nothing before the first build" "" "$(p pinned)"
p set dev "$d1"
expect_eq "set: dev pins the new digest" "$d1" "$(p get dev)"
expect_eq "pinned: every digest pinned, without the placeholder or the other block's" "$d1" "$(p pinned)"
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
# The gate runs the base commit's script, so a pull request can't rewrite its own gate (#132).
# shellcheck disable=SC2016 # the literal text of the workflow, not an expansion
if grep -qF 'git show "$BASE:.github/scripts/promotion.sh"' "$promote_yml" \
  && ! grep -qE '\.github/scripts/promotion\.sh gate' "$promote_yml"; then
  ok "promote.yml: promotion-gate runs the base commit's promotion.sh, not the pull request's"
else
  not_ok "promote.yml: promotion-gate runs the base commit's promotion.sh, not the pull request's"
fi
# mark-deployed.yml runs on a promotion merge, so it must never write to Git or open a pull request.
if grep -qE '^      - "deploy/environments/\*\*"$' "$mark_yml" && grep -qE '^    branches: \[main\]$' "$mark_yml" &&
  ! grep -qE '^  (pull_request|pull_request_target|workflow_run|workflow_dispatch):' "$mark_yml" &&
  ! grep -qE 'contents: write|pull-requests: write|open-pr|create-github-app-token' "$mark_yml"; then
  ok "mark-deployed.yml: runs on a deploy config change on main, and only tags"
else
  not_ok "mark-deployed.yml: runs on a deploy config change on main, and only tags"
fi

echo "# What the workflows may do"
expect_eq "build.yml: only the image job can get an OIDC token, so only it can sign" "image" \
  "$(jobs_with "$build_yml" 'id-token: write')"
expect_eq "build.yml: the image is built on Arm" "image" "$(jobs_with "$build_yml" 'runs-on: ubuntu-24.04-arm')"
# shellcheck disable=SC2016 # the workflow's own text, not shell expansions
if grep -qF 'PLATFORM: linux/arm64' "$build_yml" && grep -qF 'platforms: ${{ env.PLATFORM }}' "$build_yml" &&
  grep -qF 'TRIVY_PLATFORM: ${{ env.PLATFORM }}' "$build_yml"; then
  ok "build.yml: builds and scans linux/arm64, the nodes' platform"
else
  not_ok "build.yml: builds and scans linux/arm64, the nodes' platform"
fi
# shellcheck disable=SC2016 # as above
if grep -qF 'cosign verify --certificate-identity "$SIGNER"' "$build_yml" &&
  grep -qF "DIGEST: \${{ steps.build.outputs.digest || steps.earlier.outputs.digest }}" "$build_yml"; then
  ok "build.yml: verifies the signature of a new build and of a reused one"
else
  not_ok "build.yml: verifies the signature of a new build and of a reused one"
fi
expect_eq "build.yml: tags no build deployed (only mark-deployed.yml and promote.yml do, once a pin has landed)" "" \
  "$(grep -E 'promotion\.sh (mark-deployed|tag .*deployed)' "$build_yml" || true)"
expect_eq "workflows: no command's output read inside echo, where its failure is lost" "" \
  "$(grep -nE 'echo "[^"]*\$\(' "$build_yml" "$promote_yml" "$mark_yml" || true)"

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

git switch --quiet -c pr-decoy "$main2"
p set prod "$decoy" # the digest of the file's other block, as clamd's mirror would be
commit maintainer "prod on the other block's digest"
expect_fail_with "gate: a digest from another block of the file is no rollback" "nor one prod ran before" \
  p gate "$main2" HEAD

git switch --quiet -c pr-two "$main2"
p set dev "$d1"
p set staging "$d1"
commit maintainer "dev and staging back to d1"
expect_fail_with "gate: one pull request changes one environment's digest" "one environment per pull request" \
  p gate "$main2" HEAD

# main moves on: dev takes d2 (main3), a branch copies it to staging, then dev takes d4 (main4).
git switch --quiet -c main-later "$main2"
p set dev "$d2"
commit "$bot" "dev d2"
main3=$(git rev-parse HEAD)
git switch --quiet -c pr-stale "$main3"
p copy dev staging >/dev/null
commit "$bot" "staging d2"
expect_eq "gate: staging copies the digest dev pins on main" "staging promote dev $d2" "$(p gate "$main3" HEAD)"
git switch --quiet main-later
p set dev "$d4"
commit "$bot" "dev d4"
main4=$(git rev-parse HEAD)
expect_fail_with "gate: the previous environment's digest is read on main, not on the branch" \
  "neither the digest dev pins on main ($d4)" p gate "$main4" pr-stale

git switch --quiet -c pr-prod-from-dev "$main3"
p set prod "$d2"
commit maintainer "prod skips staging"
expect_fail_with "gate: prod can't skip staging" "neither the digest staging pins on main ($d3)" p gate "$main3" HEAD

# A branch pins staging to d2, then d4, and is merged with a merge commit: main went from d3 to d4, never d2.
git switch --quiet -c side "$main2"
p set staging "$d2"
commit maintainer "staging d2 on a branch"
p set staging "$d4"
commit maintainer "staging d4 on the branch"
git switch --quiet -c main-merged "$main2"
git merge --quiet --no-ff --no-edit side
merged=$(git rev-parse HEAD)
git switch --quiet -c pr-side-digest "$merged"
p set staging "$d2"
commit maintainer "staging d2"
expect_fail_with "gate: a digest only a merged branch pinned is no rollback" "nor one staging ran before" \
  p gate "$merged" HEAD

echo "# open-pr and the ECR commands, against stand-ins for gh and aws"
mkdir -p "$other/bin"
cat >"$other/bin/gh" <<'EOF'
#!/usr/bin/env bash
# Stands in for the GitHub CLI: logs each call and answers what open-pr asks.
echo "gh $*" >>"$STUB_LOG"
case $1 in
  api) echo 41898282 ;; # the bot's user ID
  pr) if [[ $2 == list && -f $STUB_DIR/open-pr ]]; then cat "$STUB_DIR/open-pr"; fi ;;
esac
EOF
cat >"$other/bin/aws" <<'EOF'
#!/usr/bin/env bash
# Stands in for the AWS CLI: logs each call and answers from the files in $STUB_DIR.
echo "aws $*" >>"$STUB_LOG"
case "$2 $*" in
  "describe-images "*imageTag=*)
    case $(cat "$STUB_DIR/find") in
      missing) echo "An error occurred (ImageNotFoundException) when calling the DescribeImages operation" >&2; exit 254 ;;
      denied) echo "An error occurred (AccessDeniedException) when calling the DescribeImages operation" >&2; exit 254 ;;
      *) cat "$STUB_DIR/find" ;;
    esac
    ;;
  "describe-images "*) cat "$STUB_DIR/tags" ;;
  "batch-get-image "*)
    echo '{"images": [{"imageManifest": "{}", "imageManifestMediaType": "application/vnd.oci.image.index.v1+json"}]}'
    ;;
esac
EOF
chmod +x "$other/bin/gh" "$other/bin/aws"
export PATH="$other/bin:$PATH" STUB_DIR="$other" STUB_LOG="$other/calls"
built=0123456789abcdef0123456789abcdef01234567 # a Git SHA

echo "$d1" >"$other/find"
expect_eq "find-build: the digest tagged with the commit" "$d1" "$(p find-build "$built")"
echo missing >"$other/find"
expect_eq "find-build: nothing when no image has the tag" "" "$(p find-build "$built")"
echo denied >"$other/find"
expect_fail_with "find-build: any other error fails, never 'not built yet'" "can't look up" p find-build "$built"

echo "[\"$built\"]" >"$other/tags"
: >"$STUB_LOG"
expect_eq "mark-deployed: prints the Git SHA the digest was built from" "$built" "$(p mark-deployed "$d1" 2>/dev/null)"
expect_eq "mark-deployed: tags the digest deployed-<git-sha>" "1" \
  "$(grep -c -- "put-image .*--image-tag deployed-$built --image-digest $d1" "$STUB_LOG")"
echo "[\"$built\", \"deployed-$built\"]" >"$other/tags"
: >"$STUB_LOG"
p mark-deployed "$d1" >/dev/null 2>&1
expect_eq "mark-deployed: a no-op for a digest already tagged deployed" "0" "$(grep -c put-image "$STUB_LOG" || true)"
echo null >"$other/tags"
expect_fail_with "mark-deployed: refuses a digest that isn't a build from main" "no Git SHA tag" p mark-deployed "$d1"

# open-pr against a bare repository standing in for GitHub; Git's insteadOf sends the https URL there.
git init --quiet --bare "$other/github/codewithmuh/sft.git"
git clone --quiet "$work" "$other/clone"
git -C "$other/clone" config commit.gpgsign false
open_pr() { # ENV DIGEST GIT_SHA, in the clone
  (cd "$other/clone" &&
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0="url.$other/github/.insteadOf" GIT_CONFIG_VALUE_0="https://github.com/" \
      GH_TOKEN=test BOT_SLUG=sft-promotion GITHUB_REPOSITORY=codewithmuh/sft "$promotion" open-pr "$@" >/dev/null 2>&1)
}
on_main() { # DIGEST-SETTING ARGS...: the clone back on main2, then `promotion.sh set ARGS`
  git -C "$other/clone" switch --quiet --discard-changes --detach "$main2"
  (cd "$other/clone" && "$promotion" set "$@")
}
proposed() { # ENV: the Git SHA the open proposal for ENV was built from, and the digest it pins
  local github="$other/github/codewithmuh/sft.git" branch="refs/heads/promote/$1" sha digest
  sha=$(git --git-dir="$github" log -1 --format=%B "$branch" | sed -n 's/^Built-From: //p')
  digest=$(git --git-dir="$github" show "$branch:deploy/environments/$1/ap-northeast-1/values.yaml" |
    sed -n '/^image:/,/^[^ ]/s/^  digest: \(sha256:[0-9a-f]*\).*/\1/p')
  echo "$sha $digest"
}
rm -f "$other/open-pr"
: >"$STUB_LOG"
git -C "$other/clone" switch --quiet --detach "$main2"
open_pr dev "$d3" "$main2"
expect_eq "open-pr: nothing to propose when main already pins the digest" "" "$(cat "$STUB_LOG")"

on_main dev "$d2"
open_pr dev "$d2" "$main2"
expect_eq "open-pr: proposes dev's new digest as the bot" "$main2 $d2" "$(proposed dev)"
echo 7 >"$other/open-pr" # the pull request is open now
on_main dev "$d1"
open_pr dev "$d1" "$main1"
expect_eq "open-pr: dev keeps a proposal built from a newer commit" "$main2 $d2" "$(proposed dev)"

rm -f "$other/open-pr"
on_main staging "$d2"
open_pr staging "$d2" "$main2"
echo 8 >"$other/open-pr"
: >"$STUB_LOG"
on_main staging "$d1"
open_pr staging "$d1" "$main1"
expect_eq "open-pr: a promotion by hand replaces staging's proposal, even with an older build" "$main1 $d1" \
  "$(proposed staging)"
expect_eq "open-pr: and updates its open pull request" "1" "$(grep -c '^gh pr edit 8 ' "$STUB_LOG")"

echo
echo "$passed passed, $failed failed"
[[ $failed == 0 ]]
