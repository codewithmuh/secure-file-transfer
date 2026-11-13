#!/usr/bin/env bash
# Dry run of the web app's release (#283): .github/scripts/web-release.sh against a throwaway Git repository with the
# pointers' shape, a built bundle, and stand-ins for aws (S3 as local directories) and curl; plus the workflows'
# triggers and which jobs may ask for an OIDC token. Needs only bash, git, jq and sed: no GitHub, no AWS. CI runs it in
# the repo-checks job; run it locally from the repository root.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
release="$root/.github/scripts/web-release.sh"
web_yml="$root/.github/workflows/web.yml"
deploy_yml="$root/.github/workflows/web-deploy.yml"
promote_yml="$root/.github/workflows/promote.yml"

# A throwaway repository's commits, and the ones web-release.sh makes in it, need an author; CI's runner has none.
export GIT_AUTHOR_NAME=maintainer GIT_AUTHOR_EMAIL=test@example.invalid
export GIT_COMMITTER_NAME=maintainer GIT_COMMITTER_EMAIL=test@example.invalid

work=$(mktemp -d)  # the repository
other=$(mktemp -d) # the stand-ins, the fake S3 and the build
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

r() { "$release" "$@"; }

zv=0000000000000000000000000000000000000000
zd=sha256:0000000000000000000000000000000000000000000000000000000000000000
v1=1111111111111111111111111111111111111111
v2=2222222222222222222222222222222222222222
v3=3333333333333333333333333333333333333333
d1=sha256:1111111111111111111111111111111111111111111111111111111111111111
d2=sha256:2222222222222222222222222222222222222222222222222222222222222222

commit() { # MESSAGE
  git add -A
  git -c user.name=maintainer -c user.email=test@example.invalid commit --quiet --allow-empty -m "$1"
}

cd "$work"
git init --quiet --initial-branch=main
git config commit.gpgsign false
for env in dev staging prod; do
  mkdir -p "deploy/environments/$env"
  cp "$root/deploy/environments/$env/web.yaml" "deploy/environments/$env/web.yaml"
done
commit "initial"

echo "# Reading and moving the pointers"
expect_eq "get: the zeros before the first release" "$zv $zd" "$(r get dev)"
expect_eq "get at a ref" "$zv $zd" "$(r get prod HEAD)"
r set dev "$v1" "$d1"
expect_eq "set: dev points at the new version" "$v1 $d1" "$(r get dev)"
expect_eq "set: changes exactly two lines" "2" "$(git diff --numstat | awk '{ print $1 }')"
expect_eq "set: keeps the comments" "$(grep -c '^#' "$root/deploy/environments/dev/web.yaml")" \
  "$(grep -c '^#' deploy/environments/dev/web.yaml)"
expect_fail_with "set: refuses a malformed version" "not a released version" r set dev abc "$d1"
expect_fail_with "set: refuses the zeros" "not a manifest digest" r set dev "$v1" "$zd"
expect_fail_with "copy: only from the previous environment" "promoted from staging" r copy dev prod
expect_fail_with "copy: nothing to copy from a never-released environment" "never been released" r copy staging prod
expect_eq "copy: dev to staging prints the pointer" "$v1 $d1" "$(r copy dev staging)"
git checkout --quiet -- deploy/environments/staging
printf 'version: %s\nversion: %s\nmanifest: %s\n' "$v1" "$v2" "$d1" >deploy/environments/prod/web.yaml
expect_fail_with "get: fails on two version lines" "exactly one" r get prod
git checkout --quiet -- deploy/environments/prod

echo "# promotion-gate"
commit "web: dev points at v1" # dev's pointer from above, merged
main1=$(git rev-parse HEAD)
git switch --quiet -c promote-web/staging
r copy dev staging >/dev/null
commit "chore: promote the web app to staging"
expect_eq "gate: copying dev's pointer to staging is a promotion" "staging promote dev $v1" "$(r gate "$main1" HEAD)"
git switch --quiet main
git merge --quiet --ff-only promote-web/staging
main2=$(git rev-parse HEAD)
expect_eq "gate: a branch that is only behind main changes nothing" "" "$(r gate "$main2" "$main1")"

git switch --quiet -c bad
r set staging "$v2" "$d2"
commit "staging at a version dev never had"
expect_fail_with "gate: refuses a staging pointer that isn't dev's" "promote only by copying dev" r gate "$main2" HEAD
git switch --quiet main

git switch --quiet -c two
r set dev "$v2" "$d2"
r set prod "$v1" "$d1"
commit "two environments at once"
expect_fail_with "gate: one environment per pull request" "one environment per pull request" r gate "$main2" HEAD
git switch --quiet main

git switch --quiet -c dev-build
r set dev "$v2" "$d2"
commit "chore: promote the web app to dev"
expect_eq "gate: a new dev build" "dev build" "$(r gate "$main2" HEAD)"
git switch --quiet main
git merge --quiet --ff-only dev-build
r copy dev staging >/dev/null
commit "staging at v2"
main3=$(git rev-parse HEAD)
git switch --quiet -c rollback
git revert --no-edit --quiet HEAD >/dev/null
expect_eq "gate: reverting staging to a version it ran before is a rollback" "staging rollback" "$(r gate "$main3" HEAD)"
git switch --quiet main

echo "# The bundle and its manifest"
dist="$other/dist"
mkdir -p "$dist/assets"
printf '<!doctype html><script type="module" src="/assets/index-abc123.js"></script>\n' >"$dist/index.html"
printf 'console.log("v3")\n' >"$dist/assets/index-abc123.js"
printf 'body{}\n' >"$dist/assets/index-def456.css"
printf '<svg/>\n' >"$dist/vite.svg"
printf '{"apiOrigin":"/v1"}\n' >"$dist/config.json" # the local stack's, from public/: never in a bundle
r manifest "$dist" "$v3" >"$other/manifest.json"
expect_eq "manifest: every file but config.json, sorted" "assets/index-abc123.js assets/index-def456.css index.html vite.svg" \
  "$(jq -r '[.files[].path] | join(" ")' "$other/manifest.json")"
expect_eq "manifest: names its version" "$v3" "$(jq -r .version "$other/manifest.json")"
expect_eq "manifest: hashed assets are immutable, the rest revalidated" \
  "public, max-age=31536000, immutable|no-cache" \
  "$(jq -r '[.files[] | select(.path == "assets/index-abc123.js" or .path == "index.html") | .cache_control] | join("|")' "$other/manifest.json")"
r manifest "$dist" "$v3" >"$other/again.json"
expect_eq "manifest: the same bundle gives the same manifest" "$(r digest "$other/manifest.json")" \
  "$(r digest "$other/again.json")"
printf 'x' >"$dist/assets/strange.bin"
expect_fail_with "manifest: refuses a file with no known content type" "no content type" r manifest "$dist" "$v3"
rm "$dist/assets/strange.bin"

# Stand-ins: aws for S3 (s3api head-object, get-object, put-object over $other/s3/<bucket>/<key>, checking each put's
# SHA-256 the way S3 does), and curl for the app's release.json (Tokyo's web bucket of the environment's account).
mkdir -p "$other/bin" "$other/s3"
cat >"$other/bin/aws" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "aws $*" >>"$STUB_LOG"
[[ $1 == s3api ]] || exit 2
op=$2
shift 2
bucket="" key="" body="" checksum="" out=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --bucket) bucket=$2; shift 2 ;;
    --key) key=$2; shift 2 ;;
    --body) body=$2; shift 2 ;;
    --checksum-sha256) checksum=$2; shift 2 ;;
    --content-type | --cache-control | --output) shift 2 ;;
    *) out=$1; shift ;;
  esac
done
object="$S3_ROOT/$bucket/$key"
case $op in
  head-object)
    [[ ${S3_DENY:-} != "$bucket" ]] || { echo "An error occurred (403) when calling the HeadObject operation: Forbidden" >&2; exit 254; }
    [[ -f $object ]] || { echo "An error occurred (404) when calling the HeadObject operation: Not Found" >&2; exit 254; }
    echo '{}' ;;
  get-object)
    [[ -f $object ]] || { echo "An error occurred (NoSuchKey) when calling the GetObject operation" >&2; exit 254; }
    cp "$object" "$out" ;;
  put-object)
    actual=$(openssl dgst -sha256 -binary "$body" | base64)
    [[ $actual == "$checksum" ]] || { echo "An error occurred (BadDigest)" >&2; exit 254; }
    mkdir -p "$(dirname "$object")"
    cp "$body" "$object" ;;
  *) exit 2 ;;
esac
EOF
cat >"$other/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
url=${*: -1}
host=${url#https://app.}
host=${host%%/*}
env=${host%%.*}
[[ $env == sft ]] && env=prod
cat "$S3_ROOT/sft-$env-apne1-web-123456789012/release.json"
EOF
chmod +x "$other/bin/aws" "$other/bin/curl"
export PATH="$other/bin:$PATH" S3_ROOT="$other/s3" STUB_LOG="$other/log" WEB_BUNDLE_BUCKET=store
export WEB_ACCOUNT_ID=123456789012 SFT_DOMAIN=example.com
export WEB_CONFIG='{"apiOrigin":"https://api.staging.sft.example.com/v1","uploadOrigin":"https://files.example.com","signInOrigin":"https://login.example.com","ssoSignIn":true}'

echo "# publish: build once"
: >"$STUB_LOG"
digest=$(r publish "$dist" "$other/manifest.json" "$v3" 2>/dev/null)
expect_eq "publish: prints the manifest's digest" "$(r digest "$other/manifest.json")" "$digest"
expect_eq "publish: the manifest is the last object written" "bundles/$v3/manifest.json" \
  "$(grep 'put-object' "$STUB_LOG" | tail -1 | sed 's/.*--key \([^ ]*\).*/\1/')"
expect_eq "publish: every file of the manifest, and the manifest" "5" "$(grep -c 'put-object' "$STUB_LOG")"
printf 'changed' >"$dist/vite.svg"
: >"$STUB_LOG"
expect_eq "publish: a re-run keeps the published bundle" "$digest" "$(r publish "$dist" "$other/manifest.json" "$v3" 2>/dev/null)"
expect_eq "publish: and writes nothing" "0" "$(grep -c 'put-object' "$STUB_LOG" || true)"
expect_fail_with "publish: a denied lookup is never 'not published'" "can't look up" \
  env S3_DENY=store "$release" publish "$dist" "$other/manifest.json" "$v3"
printf '<svg/>\n' >"$dist/vite.svg"

echo "# deploy: what Git pins, checked, into each Region, index.html last"
r set staging "$v3" "$digest"
: >"$STUB_LOG"
r deploy staging 2>/dev/null
writes=$(grep 'put-object' "$STUB_LOG" | sed 's/.*--bucket \([^ ]*\) --key \([^ ]*\).*/\1 \2/')
expect_eq "deploy: Osaka's files first, then Tokyo's, then index.html in each, then release.json" \
  "sft-staging-apne3-web-123456789012 assets/index-abc123.js
sft-staging-apne3-web-123456789012 assets/index-def456.css
sft-staging-apne3-web-123456789012 vite.svg
sft-staging-apne3-web-123456789012 config.json
sft-staging-apne1-web-123456789012 assets/index-abc123.js
sft-staging-apne1-web-123456789012 assets/index-def456.css
sft-staging-apne1-web-123456789012 vite.svg
sft-staging-apne1-web-123456789012 config.json
sft-staging-apne3-web-123456789012 index.html
sft-staging-apne3-web-123456789012 release.json
sft-staging-apne1-web-123456789012 index.html
sft-staging-apne1-web-123456789012 release.json" "$writes"
expect_eq "deploy: config.json is the environment's" "$(jq -c . <<<"$WEB_CONFIG")" \
  "$(cat "$other/s3/sft-staging-apne1-web-123456789012/config.json")"
expect_eq "served: release.json names what staging serves" "$v3 $digest" "$(r served staging)"
expect_eq "deploy: dev has Tokyo's bucket only" "sft-dev-apne1-web-123456789012" \
  "$(r set dev "$v3" "$digest" && r deploy dev 2>/dev/null && grep 'put-object' "$STUB_LOG" | grep -o 'sft-dev-[a-z0-9-]*' | sort -u)"
cp "$other/s3/store/bundles/$v3/index.html" "$other/index.html"
printf '<script src="https://evil.example/x.js"></script>' >"$other/s3/store/bundles/$v3/index.html"
expect_fail_with "deploy: refuses a stored file that isn't the manifest's" "doesn't match the manifest" r deploy staging
cp "$other/index.html" "$other/s3/store/bundles/$v3/index.html"
r set staging "$v3" "$d1"
expect_fail_with "deploy: refuses a manifest Git doesn't pin" "isn't the one staging pins" r deploy staging
r set staging "$v3" "$digest"
expect_fail_with "deploy: refuses a config.json of another shape" "WEB_CONFIG must be" \
  env WEB_CONFIG='{"apiOrigin":"http://x/v1"}' "$release" deploy staging
git checkout --quiet -- deploy/environments
expect_eq "deploy: an environment never released has nothing to deploy" "" "$(r deploy prod 2>/dev/null)"

echo "# The workflows"
expect_eq "web.yml builds on pushes that change the web app" "1" "$(grep -c '^      - "web/\*\*"$' "$web_yml")"
expect_eq "web-deploy.yml deploys when a pointer lands on main" "1" \
  "$(grep -c '^      - "deploy/environments/\*/web.yaml"$' "$deploy_yml")"
expect_eq "web.yml: only the publish job asks for an OIDC token" "publish" "$(jobs_with "$web_yml" 'id-token: write')"
expect_eq "web.yml: the publish job runs in the registry environment" "publish" "$(jobs_with "$web_yml" 'environment: registry')"
expect_eq "web.yml: the build job, which runs npm, has no AWS" "" "$(jobs_with "$web_yml" 'configure-aws-credentials' | grep -w build || true)"
expect_eq "web-deploy.yml: only the deploy job asks for an OIDC token" "deploy" "$(jobs_with "$deploy_yml" 'id-token: write')"
expect_eq "web-deploy.yml: the deploy job runs in web-<env>, not the deploy role's <env>" "deploy" \
  "$(jobs_with "$deploy_yml" 'environment: web-')"
# shellcheck disable=SC2016 # the workflow's own text, $BASE included
expect_eq "promote.yml: the gate runs web-release.sh from the base commit" "1" \
  "$(grep -c 'git show "\$BASE:.github/scripts/web-release.sh"' "$promote_yml")"

echo
echo "$passed passed, $failed failed"
[[ $failed == 0 ]]
